#include "_tree.h"
#include <copyfile.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <membership.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/attr.h>
#include <sys/unistd.h>
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define QUEUE_LIMIT 24
#define DEPTH_LIMIT 512

enum operation { CLONING, DELETING };
struct object_identity { dev_t device; ino_t inode; mode_t type; };
struct job {
    int source, destination;
    char *name;
    ino_t inode;
    struct job *parent;
    unsigned pending, depth;
    int deferred;
    struct object_identity source_identity, destination_identity;
    struct job *deferred_next;
};
struct link_record {
    struct stat source, destination;
    struct job *parent;
    char *name;
    struct link_record *next;
};
struct tree {
    pthread_mutex_t mutex;
    pthread_mutex_t links_mutex;
    struct link_record **links;
    size_t link_buckets, link_count;
    struct job *deferred_head, *deferred_tail;
    int link_source, link_destination, link_restore_error;
    pthread_cond_t available;
    struct job *queue[QUEUE_LIMIT];
    unsigned head, queued, live, exited;
    int parent_fd;
    enum operation operation;
    dev_t device;
    atomic_int error;
    char error_path[PATH_MAX];
};
struct path {
    char *owned;
    const char *name;
    int parent;
    int trailing_slash;
};

static int same_object(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
           (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}
static void path_error(char *output, size_t capacity, const char *path) {
    if (output && capacity) snprintf(output, capacity, "%s", path);
}
static void fail(struct tree *state, int error, int fd, const char *name) {
    pthread_mutex_lock(&state->mutex);
    if (!atomic_load(&state->error)) {
        char parent[PATH_MAX];
        if (fcntl(fd, F_GETPATH, parent)) strcpy(parent, "<open directory>");
        snprintf(state->error_path, sizeof(state->error_path), "%s%s%s", parent,
                 name ? "/" : "", name ? name : "");
        atomic_store(&state->error, error ? error : EIO);
        pthread_cond_broadcast(&state->available);
    }
    pthread_mutex_unlock(&state->mutex);
}
static int stopped(struct tree *state) { return atomic_load(&state->error) != 0; }

static int open_created_directory(int parent, const char *name) {
    if (mkdirat(parent, name, 0700)) return -1;
    struct stat created, opened;
    if (fstatat(parent, name, &created, AT_SYMLINK_NOFOLLOW)) return -1;
    if (!S_ISDIR(created.st_mode) || created.st_uid != geteuid()) { errno = ESTALE; return -1; }
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int error = 0;
    if (fstat(fd, &opened)) error = errno;
    else if (!same_object(&created, &opened)) error = ESTALE;
    if (error) { close(fd); errno = error; return -1; }
    return fd;
}

/* Only multiply-linked leaves enter this map. Shared retained jobs own their
 * path components; no per-inode descriptors or slash-joined PATH_MAX buffers. */
static void free_link(struct link_record *record) {
    if (record) { free(record->name); free(record); }
}
static struct object_identity object_identity(const struct stat *info) {
    return (struct object_identity){info->st_dev, info->st_ino, info->st_mode & S_IFMT};
}
static int matches_identity(const struct stat *info, const struct object_identity *expected) {
    return info->st_dev == expected->device && info->st_ino == expected->inode &&
        (info->st_mode & S_IFMT) == expected->type;
}
static size_t link_bucket(const struct stat *info, size_t buckets) {
    uint64_t hash = (uint64_t)info->st_ino ^ ((uint64_t)info->st_dev << 32);
    hash ^= hash >> 33; hash *= UINT64_C(0xff51afd7ed558ccd); hash ^= hash >> 33;
    return (size_t)hash & (buckets - 1);
}
/* Called under links_mutex, only for a new multiply-linked inode. */
static int reserve_links(struct tree *state) {
    if (state->link_buckets && state->link_count < state->link_buckets - state->link_buckets / 4) return 0;
    if (state->link_buckets > SIZE_MAX / 2 / sizeof(*state->links)) { errno = ENOMEM; return -1; }
    size_t capacity = state->link_buckets ? state->link_buckets * 2 : 64;
    struct link_record **table = calloc(capacity, sizeof(*table));
    if (!table) return -1;
    for (size_t i = 0; i < state->link_buckets; i++) {
        struct link_record *record = state->links[i];
        while (record) {
            struct link_record *next = record->next;
            size_t bucket = link_bucket(&record->source, capacity);
            record->next = table[bucket]; table[bucket] = record; record = next;
        }
    }
    free(state->links); state->links = table; state->link_buckets = capacity;
    return 0;
}
static int same_time(struct timespec a, struct timespec b) {
    return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}
static int unchanged_source(const struct stat *a, const struct stat *b) {
    return same_object(a, b) && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_flags == b->st_flags && a->st_gen == b->st_gen &&
        same_time(a->st_mtimespec, b->st_mtimespec) && same_time(a->st_ctimespec, b->st_ctimespec) &&
        same_time(a->st_birthtimespec, b->st_birthtimespec);
}
/* The marked ancestor chain remains owned until post-join metadata completes.
 * At most two traversal FDs exist at once, irrespective of depth/group count. */
static int link_directory(struct tree *state, const struct job *job, int source) {
    const struct job *parts[DEPTH_LIMIT];
    unsigned depth = job->depth;
    const struct job *root = job;
    for (unsigned i = depth; i; i--) { parts[i - 1] = root; root = root->parent; }
    int fd = fcntl(source ? state->link_source : state->link_destination, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct stat info;
    int error = fstat(fd, &info) ? errno : 0;
    if (!error && !matches_identity(&info, source ? &root->source_identity : &root->destination_identity)) error = ESTALE;
    if (error) { close(fd); errno = error; return -1; }
    for (unsigned i = 0; i < depth; i++) {
        int child = openat(fd, parts[i]->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        error = child < 0 ? errno : 0;
        if (!error && fstat(child, &info)) error = errno;
        if (!error && !matches_identity(&info, source ? &parts[i]->source_identity : &parts[i]->destination_identity)) error = ESTALE;
        if (close(fd) && !error) error = errno;
        if (error) { if (child >= 0) close(child); errno = error; return -1; }
        fd = child;
    }
    return fd;
}
/* Caller holds links_mutex. The active leaf's pending references keep this
 * whole chain alive, including live directory FDs, until marking completes. */
static struct link_record *remember_link(struct tree *state, struct job *job,
                                         const char *name, const struct stat *source) {
    struct link_record *record = calloc(1, sizeof(*record));
    if (!record) return NULL;
    record->source = *source; record->parent = job; record->name = strdup(name);
    if (!record->name) { free_link(record); return NULL; }
    struct job *root = job;
    for (struct job *ancestor = job; ancestor; ancestor = ancestor->parent) {
        root = ancestor;
        if (ancestor->deferred) continue;
        struct stat info;
        if (fstat(ancestor->source, &info)) { int error = errno; free_link(record); errno = error; return NULL; }
        ancestor->source_identity = object_identity(&info);
        if (fstat(ancestor->destination, &info)) { int error = errno; free_link(record); errno = error; return NULL; }
        ancestor->destination_identity = object_identity(&info);
    }
    if (state->link_source < 0) {
        state->link_source = fcntl(root->source, F_DUPFD_CLOEXEC, 0);
        if (state->link_source < 0) { int error = errno; free_link(record); errno = error; return NULL; }
        state->link_destination = fcntl(root->destination, F_DUPFD_CLOEXEC, 0);
        if (state->link_destination < 0) {
            int error = errno; close(state->link_source); state->link_source = -1;
            free_link(record); errno = error; return NULL;
        }
    }
    for (struct job *ancestor = job; ancestor; ancestor = ancestor->parent) ancestor->deferred = 1;
    return record;
}
static int checked_leaf(int parent, const char *name, const struct stat *expected, unsigned flags) {
    struct stat current;
    if (fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW)) return -1;
    if (!same_object(expected, &current) || current.st_uid != expected->st_uid || current.st_gid != expected->st_gid ||
        current.st_mode != expected->st_mode || current.st_flags != flags) { errno = ESTALE; return -1; }
    return 0;
}
/* Descriptor mutation remains preferred. The EACCES fallback is confined to
 * newly cloned, owned leaves below the still-private deferred destination root.
 * No-follow/identity guards detect replacement; they do not make pathname
 * mutation atomic against a caller concurrently replacing its own namespace. */
static int change_link_flags(int fd, int parent, const char *name,
                             const struct stat *expected, unsigned before, unsigned after, int *changed) {
    if (changed) *changed = 0;
    if (checked_leaf(parent, name, expected, before)) return -1;
    if (fd >= 0) {
        struct stat current;
        if (fstat(fd, &current)) return -1;
        if (!same_object(expected, &current) || current.st_flags != before) { errno = ESTALE; return -1; }
        if (fchflags(fd, after)) return -1;
    } else {
        if (expected->st_uid != geteuid()) { errno = EACCES; return -1; }
        struct attrlist attrs = {.bitmapcount = ATTR_BIT_MAP_COUNT, .commonattr = ATTR_CMN_FLAGS};
        uint32_t flags = after;
        if (setattrlistat(parent, name, &attrs, &flags, sizeof(flags), FSOPT_NOFOLLOW)) return -1;
    }
    if (changed) *changed = 1;
    return checked_leaf(parent, name, expected, after);
}
static int linked_clone(struct tree *state, struct job *job, const char *name,
                         int fd, const struct stat *identity, int flags) {
    size_t bucket = 0;
    int error = 0, source_parent = -1, first_source = -1, destination_parent = -1, first_destination = -1;
    struct stat current, prior, destination;
    pthread_mutex_lock(&state->links_mutex);
    if (state->link_buckets) bucket = link_bucket(identity, state->link_buckets);
    struct link_record *record = state->link_buckets ? state->links[bucket] : NULL;
    while (record && !same_object(&record->source, identity)) record = record->next;
    if (stopped(state)) { error = ECANCELED; goto done; }
    if (fstat(fd, &current)) { error = errno; goto done; }
    if (!unchanged_source(identity, &current)) { error = ESTALE; goto done; }
    if (!record) {
        if (reserve_links(state)) { error = errno; goto done; }
        bucket = link_bucket(identity, state->link_buckets);
        record = remember_link(state, job, name, identity);
        if (!record) { error = errno; goto done; }
        if (fclonefileat(fd, job->destination, name, CLONE_NOFOLLOW | CLONE_ACL)) error = errno;
        if (!error && fstatat(job->destination, name, &record->destination, AT_SYMLINK_NOFOLLOW)) error = errno;
        if (!error && (same_object(identity, &record->destination) ||
            (identity->st_mode & S_IFMT) != (record->destination.st_mode & S_IFMT))) error = ESTALE;
        if (!error && fstat(fd, &current)) error = errno;
        if (!error && !unchanged_source(identity, &current)) error = ESTALE;
        if (error) free_link(record);
        else { record->next = state->links[bucket]; state->links[bucket] = record; state->link_count++; }
        goto done;
    }
    if (!unchanged_source(&record->source, &current)) { error = ESTALE; goto done; }
    if ((source_parent = link_directory(state, record->parent, 1)) < 0) { error = errno; goto done; }
    if ((first_source = openat(source_parent, record->name, flags)) < 0) { error = errno; goto done; }
    if (fstat(first_source, &prior)) { error = errno; goto done; }
    if (!unchanged_source(&record->source, &prior)) { error = ESTALE; goto done; }
    if ((destination_parent = link_directory(state, record->parent, 0)) < 0) { error = errno; goto done; }
    if (fstatat(destination_parent, record->name, &destination, AT_SYMLINK_NOFOLLOW)) { error = errno; goto done; }
    if (!same_object(&record->destination, &destination) || same_object(identity, &destination) ||
        destination.st_uid != record->destination.st_uid || destination.st_gid != record->destination.st_gid ||
        destination.st_mode != record->destination.st_mode ||
        destination.st_flags != record->destination.st_flags) { error = ESTALE; goto done; }
    unsigned blocking = destination.st_flags & (UF_IMMUTABLE | UF_APPEND);
    if (blocking) {
        first_destination = openat(destination_parent, record->name, flags);
        if (first_destination < 0 && errno != EACCES) { error = errno; goto done; }
        int changed = 0;
        if (change_link_flags(first_destination, destination_parent, record->name,
                              &destination, destination.st_flags, destination.st_flags & ~blocking, &changed)) {
            error = errno;
            /* A post-clear identity failure may leave the original inode clear.
             * Restore only a verified original; never mutate a known replacement. */
            if (changed) {
                int restoration = 0;
                if (first_destination >= 0) {
                    if (fchflags(first_destination, destination.st_flags)) restoration = errno;
                } else if (change_link_flags(-1, destination_parent, record->name, &destination,
                                             destination.st_flags & ~blocking, destination.st_flags, NULL)) restoration = errno;
                if (restoration && !state->link_restore_error) state->link_restore_error = restoration;
            }
            goto done;
        }
    }
    if (checked_leaf(destination_parent, record->name, &destination, destination.st_flags & ~blocking)) error = errno;
    else if (linkat(destination_parent, record->name, job->destination, name, 0)) error = errno;
    if (blocking) {
        int restoration = 0;
        /* An open descriptor restores the original even if its pathname moved. */
        if (first_destination >= 0) {
            if (fchflags(first_destination, destination.st_flags)) restoration = errno;
        } else if (change_link_flags(-1, destination_parent, record->name, &destination,
                                     destination.st_flags & ~blocking, destination.st_flags, NULL)) restoration = errno;
        if (restoration) {
            if (!state->link_restore_error) state->link_restore_error = restoration;
            if (!error) error = restoration;
        }
    }
    if (!error && first_destination >= 0 && fstat(first_destination, &current)) error = errno;
    if (!error && first_destination >= 0 && (!same_object(&destination, &current) || current.st_flags != destination.st_flags)) error = ESTALE;
    if (!error && checked_leaf(destination_parent, record->name, &destination, destination.st_flags)) error = errno;
    if (!error && fstatat(job->destination, name, &current, AT_SYMLINK_NOFOLLOW)) error = errno;
    if (!error && !same_object(&destination, &current)) error = ESTALE;
    if (!error && fstat(fd, &current)) error = errno;
    if (!error && !unchanged_source(&record->source, &current)) error = ESTALE;
done:
    if (first_destination >= 0 && close(first_destination) && !error) error = errno;
    if (destination_parent >= 0 && close(destination_parent) && !error) error = errno;
    if (first_source >= 0 && close(first_source) && !error) error = errno;
    if (source_parent >= 0 && close(source_parent) && !error) error = errno;
    pthread_mutex_unlock(&state->links_mutex);
    errno = error;
    return error ? -1 : 0;
}

static int clone_leaf(struct tree *state, struct job *job, const char *name, unsigned type,
                      ino_t expected) {
    int parent = job->source, destination = job->destination;
    dev_t device = state->device;
    int flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | (type == DT_LNK ? O_SYMLINK : O_NOFOLLOW);
    int fd = openat(parent, name, flags);
    if (fd < 0) return -1;
    struct stat identity;
    int error = 0;
    if (fstat(fd, &identity)) error = errno;
    else if (identity.st_dev != device) error = EXDEV;
    else if ((expected && identity.st_ino != expected) ||
             (type == DT_REG ? !S_ISREG(identity.st_mode) : !S_ISLNK(identity.st_mode))) error = ESTALE;
    else if (identity.st_nlink > 1) {
        if (linked_clone(state, job, name, fd, &identity, flags)) error = errno;
    }
    else if (fclonefileat(fd, destination, name, CLONE_NOFOLLOW | CLONE_ACL)) error = errno;
    if (close(fd) && !error) error = errno;
    errno = error;
    return error ? -1 : 0;
}

static void finish(struct tree *state, struct job *job) {
    /* The producer holds one reference until enumeration finishes. */
    while (job) {
        pthread_mutex_lock(&state->mutex);
        if (--job->pending) { pthread_mutex_unlock(&state->mutex); return; }
        pthread_mutex_unlock(&state->mutex);
        int deferred = job->deferred;
        struct job *parent = job->parent;
        int parent_fd = parent ? parent->source : state->parent_fd;
        if (!stopped(state)) {
            if (state->operation == CLONING) {
                /* Apply permissions and timestamps only after all children finish. */
                if (!deferred && fcopyfile(job->source, job->destination, NULL, COPYFILE_METADATA))
                    fail(state, errno, job->source, NULL);
            } else {
                struct stat current;
                if (fstatat(parent_fd, job->name, &current, AT_SYMLINK_NOFOLLOW))
                    fail(state, errno, parent_fd, job->name);
                else if (current.st_dev != state->device || current.st_ino != job->inode ||
                         !S_ISDIR(current.st_mode)) fail(state, ESTALE, parent_fd, job->name);
                else if (unlinkat(parent_fd, job->name, AT_REMOVEDIR)) fail(state, errno, parent_fd, job->name);
            }
        }
        if (close(job->source)) fail(state, errno, parent_fd, job->name);
        if (job->destination >= 0 && close(job->destination)) fail(state, errno, parent_fd, job->name);
        if (deferred) job->source = job->destination = -1;
        else { free(job->name); free(job); }
        pthread_mutex_lock(&state->mutex);
        if (deferred) {
            if (state->deferred_tail) state->deferred_tail->deferred_next = job;
            else state->deferred_head = job;
            state->deferred_tail = job;
        }
        state->live--;
        pthread_cond_broadcast(&state->available);
        pthread_mutex_unlock(&state->mutex);
        job = parent;
    }
}
static void process(struct tree *state, struct job *job);
static void directory(struct tree *state, struct job *parent, const char *name, ino_t expected) {
    if (parent->depth + 1 >= DEPTH_LIMIT) { fail(state, ELOOP, parent->source, name); return; }
    int source = openat(parent->source, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (source < 0) { fail(state, errno, parent->source, name); return; }
    int destination = -1, error = 0;
    struct stat identity;
    if (fstat(source, &identity)) error = errno;
    else if (identity.st_dev != state->device) error = EXDEV;
    else if (expected && identity.st_ino != expected) error = ESTALE;
    else if (state->operation == CLONING &&
             (destination = open_created_directory(parent->destination, name)) < 0) error = errno;
    struct job *child = error ? NULL : calloc(1, sizeof(*child));
    if (!error && !child) error = ENOMEM;
    char *owned_name = error ? NULL : strdup(name);
    if (!error && !owned_name) error = ENOMEM;
    if (error) {
        close(source);
        if (destination >= 0) close(destination);
        free(child);
        fail(state, error, parent->source, name);
        return;
    }
    *child = (struct job){.source = source, .destination = destination, .name = owned_name,
        .inode = identity.st_ino, .parent = parent, .pending = 1, .depth = parent->depth + 1};
    pthread_mutex_lock(&state->mutex);
    parent->pending++;
    state->live++;
    if (state->queued < QUEUE_LIMIT) {
        state->queue[(state->head + state->queued++) % QUEUE_LIMIT] = child;
        pthread_cond_signal(&state->available);
        pthread_mutex_unlock(&state->mutex);
    } else {
        /* Bound the queue; overflow uses inline descent with the same depth limit. */
        pthread_mutex_unlock(&state->mutex);
        process(state, child);
    }
}
static void process(struct tree *state, struct job *job) {
    if (stopped(state)) { finish(state, job); return; }
    int copy = fcntl(job->source, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) { fail(state, errno, job->source, NULL); finish(state, job); return; }
    DIR *entries = fdopendir(copy);
    if (!entries) {
        int error = errno; close(copy); fail(state, error, job->source, NULL); finish(state, job); return;
    }
    while (!stopped(state)) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) fail(state, errno, job->source, NULL); break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        unsigned type = entry->d_type;
        if (type == DT_UNKNOWN) {
            struct stat info;
            if (fstatat(job->source, name, &info, AT_SYMLINK_NOFOLLOW)) {
                fail(state, errno, job->source, name); break;
            }
            type = S_ISDIR(info.st_mode) ? DT_DIR : S_ISREG(info.st_mode) ? DT_REG : S_ISLNK(info.st_mode) ? DT_LNK : DT_UNKNOWN;
        }
        if (type == DT_DIR) directory(state, job, name, entry->d_ino);
        else if (state->operation == DELETING) {
            if (unlinkat(job->source, name, 0)) fail(state, errno, job->source, name);
        } else if (type == DT_REG || type == DT_LNK) {
            if (clone_leaf(state, job, name, type, entry->d_ino))
                fail(state, errno, job->source, name);
        } else fail(state, ENOTSUP, job->source, name);
    }
    if (closedir(entries)) fail(state, errno, job->source, NULL);
    finish(state, job);
}
static void *worker(void *context) {
    struct tree *state = context;
    for (;;) {
        pthread_mutex_lock(&state->mutex);
        while (!state->queued && state->live) pthread_cond_wait(&state->available, &state->mutex);
        if (!state->live) {
            state->exited++;
            pthread_cond_broadcast(&state->available);
            pthread_mutex_unlock(&state->mutex);
            return NULL;
        }
        struct job *job = state->queue[state->head];
        state->head = (state->head + 1) % QUEUE_LIMIT;
        state->queued--;
        pthread_mutex_unlock(&state->mutex);
        process(state, job);
    }
}

/* Takes ownership of source and destination, including on failure. */
static int run_tree(int source, int destination, int parent, const char *name,
                    const struct stat *identity, enum operation operation, unsigned workers,
                    stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    struct job *root = calloc(1, sizeof(*root));
    char *owned_name = strdup(name);
    if (!root || !owned_name) {
        free(root); free(owned_name); close(source);
        if (destination >= 0) close(destination);
        errno = ENOMEM; return -1;
    }
    *root = (struct job){.source = source, .destination = destination, .name = owned_name,
                        .inode = identity->st_ino, .pending = 1};
    struct tree state = {.mutex = PTHREAD_MUTEX_INITIALIZER, .available = PTHREAD_COND_INITIALIZER,
        .links_mutex = PTHREAD_MUTEX_INITIALIZER, .link_source = -1, .link_destination = -1,
        .parent_fd = parent, .operation = operation, .device = identity->st_dev, .live = 1, .queued = 1};
    atomic_init(&state.error, 0);
    state.queue[0] = root;
    pthread_t threads[4];
    unsigned started = 0;
    for (; started < workers; started++) {
        int result = pthread_create(&threads[started], NULL, worker, &state);
        if (result) { fail(&state, result, parent, name); break; }
    }
    if (!started) worker(&state);
    pthread_mutex_lock(&state.mutex);
    while (state.exited < started) {
        pthread_mutex_unlock(&state.mutex);
        if (!stopped(&state) && cancel && cancel(context)) fail(&state, EINTR, parent, name);
        pthread_mutex_lock(&state.mutex);
        if (state.exited < started) {
            struct timespec delay = {.tv_nsec = 20000000};
            int result = pthread_cond_timedwait_relative_np(&state.available, &state.mutex, &delay);
            if (result && result != ETIMEDOUT) {
                pthread_mutex_unlock(&state.mutex);
                fail(&state, result, parent, name);
                pthread_mutex_lock(&state.mutex);
            }
        }
    }
    pthread_mutex_unlock(&state.mutex);
    for (unsigned i = 0; i < started; i++) {
        int result = pthread_join(threads[i], NULL);
        if (result) fail(&state, result, parent, name);
    }
    if (cancel && cancel(context)) fail(&state, EINTR, parent, name);
    /* Completion FIFO is child-before-parent. Keep all names/identities alive
     * until every metadata reopen completes; cancellation remains root-owned. */
    for (struct job *job = state.deferred_head; job; job = job->deferred_next) {
        if (!stopped(&state) && cancel && cancel(context)) fail(&state, EINTR, parent, name);
        if (stopped(&state)) continue;
        int input = link_directory(&state, job, 1);
        int output = input < 0 ? -1 : link_directory(&state, job, 0);
        int error = input < 0 || output < 0 ? errno : 0;
        if (!error && fcopyfile(input, output, NULL, COPYFILE_METADATA)) error = errno;
        if (output >= 0 && close(output) && !error) error = errno;
        if (input >= 0 && close(input) && !error) error = errno;
        if (error) fail(&state, error, parent, name);
    }
    for (struct job *job = state.deferred_head; job;) {
        struct job *next = job->deferred_next; free(job->name); free(job); job = next;
    }
    for (size_t i = 0; i < state.link_buckets; i++) {
        struct link_record *record = state.links[i];
        while (record) { struct link_record *next = record->next; free_link(record); record = next; }
    }
    free(state.links);
    if (state.link_source >= 0 && close(state.link_source)) fail(&state, errno, parent, name);
    if (state.link_destination >= 0 && close(state.link_destination)) fail(&state, errno, parent, name);
    if (state.link_restore_error) {
        size_t used = strlen(state.error_path);
        if (used > sizeof(state.error_path) - 96) used = sizeof(state.error_path) - 96;
        snprintf(state.error_path + used, sizeof(state.error_path) - used,
                 " [destination flag restoration failed: errno %d]", state.link_restore_error);
    }
    pthread_mutex_destroy(&state.links_mutex);
    int error = atomic_load(&state.error);
    if (error) path_error(error_path, capacity, state.error_path);
    pthread_cond_destroy(&state.available);
    pthread_mutex_destroy(&state.mutex);
    errno = error;
    return error ? -1 : 0;
}

static int open_path(const char *input, struct path *path, int allow_dot) {
    *path = (struct path){.parent = -1};
    if (!input || !*input) { errno = EINVAL; return -1; }
    path->owned = strdup(input);
    if (!path->owned) return -1;
    size_t length = strlen(path->owned);
    path->trailing_slash = path->owned[length - 1] == '/';
    while (length > 1 && path->owned[length - 1] == '/') path->owned[--length] = 0;
    char *slash = strrchr(path->owned, '/');
    path->name = slash ? slash + 1 : path->owned;
    if (!*path->name || (!allow_dot && (!strcmp(path->name, ".") || !strcmp(path->name, "..")))) {
        errno = EINVAL; return -1;
    }
    const char *parent = ".";
    if (slash) { *slash = 0; parent = *path->owned ? path->owned : "/"; }
    path->parent = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    return path->parent < 0 ? -1 : 0;
}
static int close_path(struct path *path, int error) {
    if (path->parent >= 0 && close(path->parent) && !error) error = errno;
    free(path->owned);
    return error;
}
static int outside_source(int parent, const struct stat *source) {
    int fd = fcntl(parent, F_DUPFD_CLOEXEC, 0);
    if (fd < 0) return -1;
    int error = 0;
    for (;;) {
        struct stat current, up;
        if (fstat(fd, &current)) { error = errno; break; }
        if (same_object(&current, source)) { error = EINVAL; break; }
        int next = openat(fd, "..", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) { error = errno; break; }
        if (fstat(next, &up)) { error = errno; close(next); break; }
        if (close(fd)) { error = errno; close(next); fd = -1; break; }
        fd = next;
        if (same_object(&current, &up)) break;
    }
    if (fd >= 0 && close(fd) && !error) error = errno;
    errno = error;
    return error ? -1 : 0;
}

static int check_acl(int fd, uid_t owner, int private) {
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    /* Darwin reports ENOENT when a pinned directory has no extended ACL. */
    if (!acl) { if (errno == ENOENT) { errno = 0; return 0; } if (!errno) errno = EIO; return -1; }
    int error = 0, have_user = 0;
    uuid_t user;
    acl_entry_t entry;
    acl_permset_mask_t known, mutations = ACL_ADD_FILE | ACL_ADD_SUBDIRECTORY | ACL_DELETE_CHILD |
        ACL_WRITE_ATTRIBUTES | ACL_WRITE_SECURITY | ACL_CHANGE_OWNER;
    if (acl_valid(acl)) error = errno ? errno : EIO;
    if (!error && acl_maximal_permset_mask_np(&known)) error = errno ? errno : EIO;
    for (int index = ACL_FIRST_ENTRY; !error; index = ACL_NEXT_ENTRY) {
        errno = 0;
        if (acl_get_entry(acl, index, &entry)) {
            /* Darwin uses EINVAL for the end of a valid ACL. */
            if (errno != EINVAL) error = errno ? errno : EIO;
            break;
        }
        acl_tag_t tag;
        acl_permset_mask_t permissions;
        if (acl_get_tag_type(entry, &tag) || acl_get_permset_mask_np(entry, &permissions)) { error = errno ? errno : EIO; break; }
        if (permissions & ~known) { error = EINVAL; break; }
        if (tag == ACL_EXTENDED_DENY) continue;
        if (tag != ACL_EXTENDED_ALLOW) { error = EINVAL; break; }
        if (!(private ? permissions : permissions & mutations)) continue;
        if (!have_user) {
            error = mbr_uid_to_uuid(owner, user);
            if (error) break;
            have_user = 1;
        }
        void *principal = acl_get_qualifier(entry);
        if (!principal) { error = errno ? errno : EIO; break; }
        if (uuid_compare(principal, user)) error = EPERM;
        acl_free(principal);
    }
    acl_free(acl);
    errno = error;
    return error ? -1 : 0;
}

/* Other users must not be able to replace our private staging directory. */
static int protected_parent(int fd, dev_t device) {
    struct stat st;
    if (fstat(fd, &st)) return -1;
    if (st.st_dev != device) { errno = EXDEV; return -1; }
    if ((st.st_uid != geteuid() && st.st_uid != 0) || (!(st.st_mode & S_ISVTX) && (st.st_mode & 0022))) {
        errno = EPERM; return -1;
    }
    return check_acl(fd, geteuid(), 0);
}

int stallion_private_directory(const char *path) {
    if (!path || !*path) { errno = EINVAL; return -1; }
    char *owned = strdup(path);
    if (!owned) return -1;
    size_t length = strlen(owned);
    while (length > 1 && owned[length - 1] == '/') owned[--length] = 0;
    int fd = open(owned, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int open_error = errno;
    free(owned);
    errno = open_error;
    if (fd < 0) return -1;
    struct stat st;
    int error = 0;
    if (fstat(fd, &st)) error = errno;
    else if (st.st_uid != getuid() || (st.st_mode & 0077)) error = EPERM;
    else if (check_acl(fd, getuid(), 1)) error = errno;
    if (close(fd) && !error) error = errno;
    errno = error;
    return error ? -1 : 0;
}
static int clear_acl(int fd) {
    acl_t acl = acl_init(0);
    if (!acl) return -1;
    int result = acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED), error = errno;
    acl_free(acl);
    errno = error;
    return result;
}
static int no_mounts(int fd) {
    char canonical[PATH_MAX];
    if (fcntl(fd, F_GETPATH, canonical)) return -1;
    struct statfs *mounts = NULL;
    int count = getmntinfo_r_np(&mounts, MNT_NOWAIT);
    if (!count) { if (!errno) errno = EIO; return -1; }
    size_t length = strlen(canonical);
    int error = 0;
    for (int i = 0; i < count; i++) {
        const char *mount = mounts[i].f_mntonname;
        if (!strncmp(canonical, mount, length) && (!mount[length] || mount[length] == '/')) { error = EBUSY; break; }
    }
    free(mounts);
    errno = error;
    return error ? -1 : 0;
}

static int clone_impl(const char *source_path, const char *destination_path, int directory_only,
                      unsigned workers, stallion_cancel_fn cancel, void *context,
                      char *error_path, size_t capacity) {
    if (error_path && capacity) error_path[0] = 0;
    if (workers < 1 || workers > 4) { errno = EINVAL; return -1; }
    if (cancel && cancel(context)) { errno = EINTR; return -1; }
    struct path source = {.parent = -1}, destination = {.parent = -1};
    int input = -1, output = -1, error = 0;
    struct stat identity, opened;
    if (open_path(source_path, &source, 1)) error = errno;
    if (!error && fstatat(source.parent, source.name, &identity, AT_SYMLINK_NOFOLLOW)) error = errno;
    if (!error && ((directory_only || source.trailing_slash) && !S_ISDIR(identity.st_mode))) error = ENOTDIR;
    if (!error && !S_ISDIR(identity.st_mode) && !S_ISREG(identity.st_mode) && !S_ISLNK(identity.st_mode)) error = ENOTSUP;
    if (!error) {
        int flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | (S_ISLNK(identity.st_mode) ? O_SYMLINK : O_NOFOLLOW);
        if ((input = openat(source.parent, source.name, flags)) < 0) error = errno;
        else if (fstat(input, &opened)) error = errno;
        else if (!same_object(&identity, &opened)) error = ESTALE;
    }
    if (!error && open_path(destination_path, &destination, 0)) error = errno;
    if (!error && destination.trailing_slash && !S_ISDIR(identity.st_mode)) error = ENOTDIR;
    if (!error && !S_ISDIR(identity.st_mode)) {
        /* A pinned leaf is created exclusively by the clone syscall itself. */
        if (cancel && cancel(context)) error = EINTR;
        else if (fclonefileat(input, destination.parent, destination.name, CLONE_NOFOLLOW | CLONE_ACL)) error = errno;
        goto done;
    }
    if (!error && protected_parent(destination.parent, identity.st_dev)) error = errno;
    if (!error && outside_source(destination.parent, &identity)) error = errno;
    if (!error && (output = open_created_directory(destination.parent, destination.name)) < 0) error = errno;
    /* Keep all children private until the final root-metadata copy. */
    if (!error && clear_acl(output)) error = errno;
    if (!error) {
        int result = run_tree(input, output, source.parent, source.name, &identity, CLONING,
                              workers, cancel, context, error_path, capacity);
        input = output = -1;
        if (result) error = errno;
    }
done:
    if (input >= 0 && close(input) && !error) error = errno;
    if (output >= 0 && close(output) && !error) error = errno;
    error = close_path(&source, error);
    error = close_path(&destination, error);
    if (error && (!error_path || !capacity || !error_path[0]))
        path_error(error_path, capacity, destination_path ? destination_path : "");
    errno = error;
    return error ? -1 : 0;
}
int stallion_clone(const char *source, const char *destination, unsigned workers,
                   stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    return clone_impl(source, destination, 0, workers, cancel, context, error_path, capacity);
}
int stallion_clone_tree(const char *source, const char *destination, unsigned workers,
                        stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    return clone_impl(source, destination, 1, workers, cancel, context, error_path, capacity);
}
int stallion_delete(const char *input, int recursive, int missing_ok, unsigned workers,
                    stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    if (error_path && capacity) error_path[0] = 0;
    if (workers < 1 || workers > 4) { errno = EINVAL; return -1; }
    if (cancel && cancel(context)) { errno = EINTR; return -1; }
    struct path path = {.parent = -1};
    int fd = -1, error = 0;
    struct stat identity, opened;
    if (open_path(input, &path, 0)) error = errno;
    if (!error && fstatat(path.parent, path.name, &identity, AT_SYMLINK_NOFOLLOW)) {
        error = errno;
        if (error == ENOENT && missing_ok) goto done;
    }
    if (!error && path.trailing_slash && !S_ISDIR(identity.st_mode)) error = ENOTDIR;
    if (!error && S_ISDIR(identity.st_mode)) {
        if (!recursive) error = EISDIR;
        else if ((fd = openat(path.parent, path.name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) error = errno;
        else if (fstat(fd, &opened)) error = errno;
        else if (!same_object(&identity, &opened)) error = ESTALE;
        else if (no_mounts(fd)) error = errno;
        else {
            int result = run_tree(fd, -1, path.parent, path.name, &identity, DELETING,
                                  workers, cancel, context, error_path, capacity);
            fd = -1;
            if (result) error = errno;
        }
    } else if (!error && unlinkat(path.parent, path.name, 0)) error = errno;
    if (fd >= 0 && close(fd) && !error) error = errno;
    goto finish;
done:
    error = 0;
finish:
    error = close_path(&path, error);
    if (error && error_path && capacity && !error_path[0]) path_error(error_path, capacity, input ? input : "");
    errno = error;
    return error ? -1 : 0;
}
