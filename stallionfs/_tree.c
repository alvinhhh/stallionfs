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
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#define QUEUE_LIMIT 24
#define DEPTH_LIMIT 512

enum operation { CLONING, DELETING };
struct job {
    int source, destination;
    char *name;
    struct stat identity;
    struct job *parent;
    unsigned pending, depth;
};
struct tree {
    pthread_mutex_t mutex;
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

static int clone_leaf(int parent, const char *name, int destination, unsigned type,
                      ino_t expected, dev_t device) {
    int flags = O_RDONLY | O_NONBLOCK | O_CLOEXEC | (type == DT_LNK ? O_SYMLINK : O_NOFOLLOW);
    int fd = openat(parent, name, flags);
    if (fd < 0) return -1;
    struct stat identity;
    int error = 0;
    if (fstat(fd, &identity)) error = errno;
    else if (identity.st_dev != device) error = EXDEV;
    else if ((expected && identity.st_ino != expected) ||
             (type == DT_REG ? !S_ISREG(identity.st_mode) : !S_ISLNK(identity.st_mode))) error = ESTALE;
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
        struct job *parent = job->parent;
        int parent_fd = parent ? parent->source : state->parent_fd;
        if (!stopped(state)) {
            if (state->operation == CLONING) {
                /* Apply permissions and timestamps only after all children finish. */
                if (fcopyfile(job->source, job->destination, NULL, COPYFILE_METADATA))
                    fail(state, errno, job->source, NULL);
            } else {
                struct stat current;
                if (fstatat(parent_fd, job->name, &current, AT_SYMLINK_NOFOLLOW))
                    fail(state, errno, parent_fd, job->name);
                else if (!same_object(&current, &job->identity)) fail(state, ESTALE, parent_fd, job->name);
                else if (unlinkat(parent_fd, job->name, AT_REMOVEDIR)) fail(state, errno, parent_fd, job->name);
            }
        }
        if (close(job->source)) fail(state, errno, parent_fd, job->name);
        if (job->destination >= 0 && close(job->destination)) fail(state, errno, parent_fd, job->name);
        free(job->name);
        free(job);
        pthread_mutex_lock(&state->mutex);
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
        .identity = identity, .parent = parent, .pending = 1, .depth = parent->depth + 1};
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
            if (clone_leaf(job->source, name, job->destination, type, entry->d_ino, state->device))
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
                        .identity = *identity, .pending = 1};
    struct tree state = {.mutex = PTHREAD_MUTEX_INITIALIZER, .available = PTHREAD_COND_INITIALIZER,
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
static int protected_parent(int fd) {
    struct stat st;
    if (fstat(fd, &st)) return -1;
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
    struct stat identity, opened, parent_identity;
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
    if (!error && fstat(destination.parent, &parent_identity)) error = errno;
    if (!error && parent_identity.st_dev != identity.st_dev) error = EXDEV;
    if (!error && protected_parent(destination.parent)) error = errno;
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
    if (error) path_error(error_path, capacity, destination_path ? destination_path : "");
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
