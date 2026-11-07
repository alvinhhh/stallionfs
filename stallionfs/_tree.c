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
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>
#include <uuid/uuid.h>

#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
#include <inttypes.h>

#define CPU_WORKERS 4
#if defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU
#define CPU_MARKER "stallionfs-delete-thread-cpu-v1"
#define CPU_SCHEMA 1
#define CPU_PROFILE_OPERATION DELETING
#define CPU_PHASE0_NAME "entry_unlinkat"
#define CPU_PHASE1_NAME "directory_unlinkat"
enum cpu_phase { CPU_UNLINK_ENTRY, CPU_UNLINK_DIRECTORY, CPU_PHASES };
#else
#define CPU_MARKER "stallionfs-thread-cpu-v2"
#define CPU_SCHEMA 2
#define CPU_PROFILE_OPERATION CLONING
#define CPU_PHASE0_NAME "fclonefileat"
#define CPU_PHASE1_NAME "directory_metadata"
enum cpu_phase { CPU_FCLONEFILEAT, CPU_DIRECTORY, CPU_PHASES };
#endif
enum cpu_status { CPU_OK, CPU_CLOCK, CPU_RANGE, CPU_NESTED, CPU_OVERFLOW, CPU_BOUND, CPU_JOIN, CPU_OPERATION };
struct cpu_counter { uint64_t calls, failures, ns; };
struct cpu_slot {
    uint64_t start, total;
    struct cpu_counter phase[CPU_PHASES];
    enum cpu_status status;
    unsigned active;
};
struct cpu_profile {
    int fd, enabled;
    enum cpu_status status;
    struct cpu_slot slots[CPU_WORKERS + 1];
    char path[PATH_MAX];
};
struct cpu_token { struct cpu_slot *slot; uint64_t start; unsigned phase, entered; };
static _Thread_local struct cpu_slot *cpu_current;

static int cpu_now(uint64_t *ns) {
    int saved = errno;
    struct timespec value;
    int valid = clock_gettime(CLOCK_THREAD_CPUTIME_ID, &value) == 0;
    if (valid) valid = value.tv_sec >= 0 && value.tv_nsec >= 0 && value.tv_nsec < 1000000000L &&
        (uint64_t)value.tv_sec <= (UINT64_MAX - (uint64_t)value.tv_nsec) / 1000000000ULL;
    if (valid) *ns = (uint64_t)value.tv_sec * 1000000000ULL + (uint64_t)value.tv_nsec;
    errno = saved;
    return valid;
}
static void cpu_add(struct cpu_slot *slot, uint64_t *value, uint64_t add) {
    if (UINT64_MAX - *value < add) slot->status = CPU_OVERFLOW;
    else *value += add;
}
static void cpu_start(struct cpu_slot *slot) {
    if (slot && !cpu_now(&slot->start)) slot->status = CPU_CLOCK;
}
static void cpu_stop(struct cpu_slot *slot) {
    if (!slot) return;
    uint64_t end;
    if (slot->active) slot->status = CPU_NESTED;
    if (!slot->status) {
        if (!cpu_now(&end)) slot->status = CPU_CLOCK;
        else if (end < slot->start) slot->status = CPU_RANGE;
        else slot->total = end - slot->start;
    }
}
static struct cpu_token cpu_enter(unsigned phase) {
    struct cpu_token token = {.slot = cpu_current, .phase = phase};
    if (!token.slot) return token;
    if (token.slot->active) { token.slot->status = CPU_NESTED; return token; }
    token.slot->active = phase + 1;
    token.entered = 1;
    cpu_add(token.slot, &token.slot->phase[phase].calls, 1);
    if (!token.slot->status && !cpu_now(&token.start)) token.slot->status = CPU_CLOCK;
    return token;
}
static void cpu_leave(struct cpu_token token, int failed) {
    if (!token.slot || !token.entered) return;
    struct cpu_counter *counter = &token.slot->phase[token.phase];
    uint64_t end;
    if (failed) cpu_add(token.slot, &counter->failures, 1);
    if (!token.slot->status) {
        if (!cpu_now(&end)) token.slot->status = CPU_CLOCK;
        else if (end < token.start) token.slot->status = CPU_RANGE;
        else cpu_add(token.slot, &counter->ns, end - token.start);
    }
    token.slot->active = 0;
}
#endif

#define QUEUE_LIMIT 24
#define DEPTH_LIMIT 512

/* Older SDKs can still build the weak-linked, runtime-gated copy operation. */
#if __MAC_OS_X_VERSION_MAX_ALLOWED < 130000
extern ssize_t freadlink(int, char *, size_t) __attribute__((weak_import, availability(macos, introduced=13.0)));
#endif

enum operation { CLONING, COPYING, DELETING };
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
static struct cpu_profile cpu_open(enum operation operation, unsigned workers) {
    int saved = errno;
    struct cpu_profile profile = {.fd = -1};
    const char *path = getenv("STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT");
    if (operation == CPU_PROFILE_OPERATION && path && path[0] && strlen(path) < PATH_MAX - sizeof(".pending")) {
        char pending[PATH_MAX];
        strcpy(profile.path, path);
        snprintf(pending, sizeof(pending), "%s.pending", path);
        struct stat info;
        if (lstat(path, &info) && errno == ENOENT)
            profile.fd = open(pending, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (profile.fd >= 0 && (fstat(profile.fd, &info) || !S_ISREG(info.st_mode) ||
            info.st_uid != geteuid() || (info.st_mode & 0777) != 0600)) {
            close(profile.fd); profile.fd = -1;
        }
        profile.status = workers <= CPU_WORKERS ? CPU_OK : CPU_BOUND;
        profile.enabled = profile.fd >= 0 && !profile.status;
    }
    errno = saved;
    return profile;
}
static void cpu_counter_json(FILE *stream, const struct cpu_counter *counter) {
    fprintf(stream, "{\"calls\":%" PRIu64 ",\"failures\":%" PRIu64 ",\"cpu_ns\":%" PRIu64 "}",
            counter->calls, counter->failures, counter->ns);
}
/* Called only after all worker joins, main finalization and the last clock read. */
static void cpu_report(struct cpu_profile *profile, unsigned requested, unsigned started, int error) {
    int saved = errno;
    if (profile->fd < 0) return;
    enum cpu_status status = profile->status;
    struct cpu_slot sum = {0};
    if (started > CPU_WORKERS) status = CPU_BOUND;
    if (!status) for (unsigned i = 0; i <= started; i++) {
        struct cpu_slot *slot = &profile->slots[i];
        if (slot->status) { status = slot->status; break; }
        uint64_t clone = slot->phase[0].ns, directory = slot->phase[1].ns;
        if (UINT64_MAX - clone < directory || clone + directory > slot->total) { status = CPU_RANGE; break; }
        cpu_add(&sum, &sum.total, slot->total);
        for (unsigned phase = 0; phase < CPU_PHASES; phase++) {
            cpu_add(&sum, &sum.phase[phase].calls, slot->phase[phase].calls);
            cpu_add(&sum, &sum.phase[phase].failures, slot->phase[phase].failures);
            cpu_add(&sum, &sum.phase[phase].ns, slot->phase[phase].ns);
        }
    }
    if (!status) status = sum.status;
    if (error) status = CPU_OPERATION;
    const char *names[] = {"available", "clock_read_invalid", "clock_range_invalid", "nested_phase",
                          "counter_overflow", "worker_bound", "join_failed", "operation_failed"};
    FILE *stream = fdopen(profile->fd, "w");
    int complete = 0;
    if (stream) {
        fprintf(stream, "{\"schema\":%d,\"marker\":\"" CPU_MARKER "\",\"status\":\"%s\","
                "\"workers_requested\":%u,\"workers_started\":%u,\"main_fallback\":%s,"
                "\"scope\":\"instrumented run_tree main and worker spans\",\"counters\":",
                CPU_SCHEMA, names[status], requested, started, started ? "false" : "true");
        if (status) fputs("null,\"slots\":[]}", stream);
        else {
            fprintf(stream, "{\"total_cpu_ns\":%" PRIu64 ",\"" CPU_PHASE0_NAME "\":", sum.total);
            cpu_counter_json(stream, &sum.phase[0]);
            fputs(",\"" CPU_PHASE1_NAME "\":", stream); cpu_counter_json(stream, &sum.phase[1]);
            fputs("},\"slots\":[", stream);
            for (unsigned i = 0; i <= started; i++) {
                struct cpu_slot *slot = &profile->slots[i];
                fprintf(stream, "%s{\"slot\":%u,\"total_cpu_ns\":%" PRIu64 ",\"" CPU_PHASE0_NAME "\":", i ? "," : "", i, slot->total);
                cpu_counter_json(stream, &slot->phase[0]);
                fputs(",\"" CPU_PHASE1_NAME "\":", stream); cpu_counter_json(stream, &slot->phase[1]);
                fputc('}', stream);
            }
            fputs("]}", stream);
        }
        complete = !ferror(stream) && !fflush(stream) && !fsync(fileno(stream));
        if (fclose(stream)) complete = 0;
    } else close(profile->fd);
    char pending[PATH_MAX];
    snprintf(pending, sizeof(pending), "%s.pending", profile->path);
    if (complete) link(pending, profile->path);
    unlink(pending);
    profile->fd = -1;
    errno = saved;
}
#endif
struct object_identity { dev_t device; ino_t inode; mode_t type; };
struct job {
    int source, destination;
    char *name;
    ino_t inode;
    struct job *parent;
    unsigned pending, depth;
    int deferred;
    struct object_identity source_identity, destination_identity;
    struct stat source_stat;
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
    enum stallion_copy_strategy copy_strategy;
    dev_t device;
    atomic_int error;
    char error_path[PATH_MAX];
};
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
struct cpu_worker_context { struct tree *state; struct cpu_slot *slot; int main_fallback; };
#endif
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
enum copy_completion { COPY_COMPLETION_INCOMPLETE, COPY_COMPLETION_COPYFILE, COPY_COMPLETION_CLONE };
struct copy_progress {
    enum copy_completion completion;
    struct tree *tree;
    stallion_cancel_fn cancel;
    void *context;
    int error;
    size_t started, finished;
};
static int copy_stopped(struct copy_progress *progress) {
    if (!progress->error && progress->tree && stopped(progress->tree))
        progress->error = atomic_load(&progress->tree->error);
    if (!progress->error && progress->cancel && progress->cancel(progress->context)) progress->error = EINTR;
    return progress->error != 0;
}
static int copy_status(int what, int stage, copyfile_state_t state,
                       const char *source, const char *destination, void *context) {
    (void)state; (void)source; (void)destination;
    struct copy_progress *progress = context;
    /* libcopyfile substitutes ECANCELED after QUIT; retain the actual failure. */
    if (stage == COPYFILE_ERR && !progress->error) progress->error = errno ? errno : EIO;
    if (copy_stopped(progress)) return COPYFILE_QUIT;
    if (what == COPYFILE_COPY_XATTR) {
        if (stage == COPYFILE_START) progress->started++;
        if (stage == COPYFILE_FINISH) progress->finished++;
    }
    return COPYFILE_CONTINUE;
}
/* One first-inode operation owns this snapshot, including ordered ACEs and flags. */
struct acl_snapshot { char *bytes; ssize_t length; int empty; };
static int snapshot_acl(int input, struct acl_snapshot *snapshot) {
    errno = 0;
    acl_t acl = acl_get_fd_np(input, ACL_TYPE_EXTENDED);
    if (!acl && errno == ENOENT) acl = acl_init(0);
    if (!acl) { if (!errno) errno = EIO; return -1; }
    int error = 0;
    acl_entry_t entry;
    errno = 0;
    if (acl_valid(acl)) error = errno ? errno : EIO;
    if (!error) {
        errno = 0;
        if (acl_get_entry(acl, ACL_FIRST_ENTRY, &entry)) {
            /* EINVAL marks the end of a validated Darwin ACL. */
            if (errno == EINVAL) snapshot->empty = 1;
            else error = errno ? errno : EIO;
        }
    }
    if (!error) {
        errno = 0;
        snapshot->length = acl_size(acl);
        if (snapshot->length <= 0) error = snapshot->length < 0 && errno ? errno : EIO;
    }
    if (!error) {
        errno = 0;
        snapshot->bytes = malloc((size_t)snapshot->length);
        if (!snapshot->bytes) error = errno ? errno : ENOMEM;
    }
    if (!error) {
        errno = 0;
        ssize_t copied = acl_copy_ext(snapshot->bytes, acl, snapshot->length);
        if (copied != snapshot->length) error = copied < 0 && errno ? errno : EIO;
    }
    acl_free(acl);
    if (error) { free(snapshot->bytes); snapshot->bytes = NULL; }
    errno = error;
    return error ? -1 : 0;
}
static int same_acl(int input, int output, const struct acl_snapshot *snapshot) {
    acl_t source = NULL;
    if (!snapshot) {
        errno = 0;
        source = acl_get_fd_np(input, ACL_TYPE_EXTENDED);
        if (!source && errno == ENOENT) source = acl_init(0);
        if (!source) { if (!errno) errno = EIO; return -1; }
    }
    errno = 0;
    acl_t destination = acl_get_fd_np(output, ACL_TYPE_EXTENDED);
    if (!destination && errno == ENOENT) destination = acl_init(0);
    int error = destination ? 0 : errno ? errno : EIO;
    ssize_t a_length = snapshot ? snapshot->length : 0, b_length = 0;
    char *a = NULL, *b = NULL;
    if (!error && !snapshot) {
        errno = 0;
        a_length = acl_size(source);
        if (a_length <= 0) error = a_length < 0 && errno ? errno : EIO;
    }
    if (!error) {
        errno = 0;
        b_length = acl_size(destination);
        if (b_length <= 0) error = b_length < 0 && errno ? errno : EIO;
    }
    if (!error && a_length != b_length) error = ENOTSUP;
    if (!error && !snapshot && !(a = malloc((size_t)a_length))) error = errno ? errno : ENOMEM;
    if (!error && !(b = malloc((size_t)b_length))) error = errno ? errno : ENOMEM;
    /* The external representation includes ordered ACEs and flags without name lookup. */
    if (!error && !snapshot) {
        errno = 0;
        ssize_t copied = acl_copy_ext(a, source, a_length);
        if (copied != a_length) error = copied < 0 && errno ? errno : EIO;
    }
    if (!error) {
        errno = 0;
        ssize_t copied = acl_copy_ext(b, destination, b_length);
        if (copied != b_length) error = copied < 0 && errno ? errno : EIO;
    }
    if (!error && memcmp(snapshot ? snapshot->bytes : a, b, (size_t)a_length)) error = ENOTSUP;
    free(a);
    free(b);
    if (source) acl_free(source);
    if (destination) acl_free(destination);
    errno = error;
    return error ? -1 : 0;
}
/* This post-copy verifier uses only held descriptors and public 32-bit positions.
 * Its conservative length ceiling does not preflight or bound the copy engine. */
static int same_resource_fork(int input, int output, unsigned char *source_value,
                               unsigned char *destination_value, struct copy_progress *progress) {
    const char *name = "com.apple.ResourceFork";
    if (copy_stopped(progress)) { errno = progress->error; return -1; }
    int error = 0;
    unsigned char *allocated = NULL;
    size_t capacity = 256;
    errno = 0;
    ssize_t source_length = fgetxattr(input, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
    if (source_length < 0) { errno = errno ? errno : EIO; return -1; }
    errno = 0;
    ssize_t destination_length = fgetxattr(output, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
    if (destination_length < 0) { errno = errno ? errno : EIO; return -1; }
    if (source_length != destination_length) { errno = ENOTSUP; return -1; }
    uint64_t length = (uint64_t)source_length, offset = 0;
    if (length > (uint64_t)UINT32_MAX + 1) { errno = EOVERFLOW; return -1; }
    if (length > capacity) {
        capacity = length < 65536 ? (size_t)length : 65536;
        if (capacity > SIZE_MAX / 2) { errno = EOVERFLOW; return -1; }
        errno = 0;
        allocated = malloc(capacity * 2);
        if (!allocated) { errno = errno ? errno : ENOMEM; return -1; }
        source_value = allocated;
        destination_value = allocated + capacity;
    }
    for (;;) {
        uint32_t position = 0;
        size_t amount = 0;
        if (!stallion_fork_chunk(length, offset, capacity, &position, &amount)) { error = EOVERFLOW; break; }
        if (!amount) break;
        if (copy_stopped(progress)) { error = progress->error; break; }
        errno = 0;
        ssize_t actual = fgetxattr(input, name, source_value, amount, position, XATTR_SHOWCOMPRESSION);
        if (actual < 0) { error = errno ? errno : EIO; break; }
        if ((size_t)actual != amount) { error = ESTALE; break; }
        if (copy_stopped(progress)) { error = progress->error; break; }
        errno = 0;
        actual = fgetxattr(output, name, destination_value, amount, position, XATTR_SHOWCOMPRESSION);
        if (actual < 0) { error = errno ? errno : EIO; break; }
        if ((size_t)actual != amount) { error = ESTALE; break; }
        if (memcmp(source_value, destination_value, amount)) { error = ENOTSUP; break; }
        /* amount <= length-offset, so this 64-bit addition cannot pass length. */
        offset += (uint64_t)amount;
    }
    if (!error && copy_stopped(progress)) error = progress->error;
    if (!error) {
        errno = 0;
        ssize_t actual = fgetxattr(input, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
        if (actual < 0) error = errno ? errno : EIO;
        else if (actual != source_length) error = ESTALE;
    }
    if (!error) {
        errno = 0;
        ssize_t actual = fgetxattr(output, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
        if (actual < 0) error = errno ? errno : EIO;
        else if (actual != destination_length) error = ESTALE;
    }
    if (!error && copy_stopped(progress)) error = progress->error;
    free(allocated);
    errno = error;
    return error ? -1 : 0;
}
/* Verify complete xattr bytes through held descriptors. */
static int same_xattrs(int input, int output, struct copy_progress *progress) {
    if (copy_stopped(progress)) { errno = progress->error; return -1; }
    unsigned char source_inline[256], destination_inline[256];
    ssize_t length = flistxattr(input, NULL, 0, XATTR_SHOWCOMPRESSION);
    if (length < 0) return -1;
    char *names = malloc((size_t)length + 1);
    if (!names) return -1;
    int error = 0;
    size_t count = 0;
    ssize_t actual = flistxattr(input, names, (size_t)length, XATTR_SHOWCOMPRESSION);
    if (actual < 0) error = errno;
    else if (actual != length) error = ESTALE;
    ssize_t destination_length = error ? -1 : flistxattr(output, NULL, 0, XATTR_SHOWCOMPRESSION);
    if (!error && destination_length < 0) error = errno;
    if (!error && destination_length != length) error = ENOTSUP;
    for (ssize_t offset = 0; !error && offset < length;) {
        if (copy_stopped(progress)) { error = progress->error; break; }
        const char *name = names + offset;
        size_t remaining = (size_t)(length - offset), size = strnlen(name, remaining);
        if (!size || size == remaining) { error = EIO; break; }
        offset += (ssize_t)size + 1;
        if (strcmp(name, "com.apple.quarantine") && strcmp(name, "com.apple.ResourceFork")) {
            count++;
            unsigned char *allocated = NULL;
            unsigned char *source_value = source_inline, *destination_value = destination_inline;
            errno = 0;
            ssize_t a = fgetxattr(input, name, source_value, sizeof(source_inline), 0, XATTR_SHOWCOMPRESSION);
            if (a < 0 && errno == ERANGE) {
                errno = 0;
                a = fgetxattr(input, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
                if (a < 0) error = errno ? errno : EIO;
                else if ((size_t)a <= sizeof(source_inline)) error = ESTALE;
                else if ((uintmax_t)a > SIZE_MAX / 2) error = EOVERFLOW;
                else {
                    errno = 0;
                    allocated = malloc((size_t)a * 2);
                    if (!allocated) error = errno ? errno : ENOMEM;
                    else {
                        source_value = allocated;
                        destination_value = allocated + (size_t)a;
                        if (copy_stopped(progress)) error = progress->error;
                        else {
                            errno = 0;
                            ssize_t actual = fgetxattr(input, name, source_value, (size_t)a, 0, XATTR_SHOWCOMPRESSION);
                            if (actual < 0) error = errno ? errno : EIO;
                            else if (actual != a) error = ESTALE;
                        }
                    }
                }
            } else if (a < 0) error = errno ? errno : EIO;
            else if ((size_t)a > sizeof(source_inline)) error = ESTALE;
            if (!error && copy_stopped(progress)) error = progress->error;
            if (!error) {
                errno = 0;
                size_t capacity = allocated ? (size_t)a : sizeof(destination_inline);
                ssize_t b = fgetxattr(output, name, destination_value, capacity, 0, XATTR_SHOWCOMPRESSION);
                if (b < 0) error = errno ? errno : EIO;
                else if (b != a) error = allocated ? ESTALE : ENOTSUP;
            }
            if (!error && memcmp(source_value, destination_value, (size_t)a)) error = ENOTSUP;
            free(allocated);
            continue;
        }
        if (!strcmp(name, "com.apple.ResourceFork")) {
            count++;
            if (same_resource_fork(input, output, source_inline, destination_inline, progress)) error = errno;
            continue;
        }
        ssize_t a = fgetxattr(input, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
        if (a < 0) { error = errno; break; }
        ssize_t b = fgetxattr(output, name, NULL, 0, 0, XATTR_SHOWCOMPRESSION);
        if (b < 0) { error = errno; break; }
        if (a != b) { error = ENOTSUP; break; }
        /* Quarantine bypasses the xattr callbacks and may be rewritten by copyfile. */
        if ((uintmax_t)a > (SIZE_MAX - 1) / 2) { error = EOVERFLOW; break; }
        char *values = malloc((size_t)a * 2 + 1);
        if (!values) { error = errno; break; }
        if (copy_stopped(progress)) error = progress->error;
        else if (fgetxattr(input, name, values, (size_t)a, 0, 0) != a) error = errno ? errno : ESTALE;
        if (!error && copy_stopped(progress)) error = progress->error;
        if (!error && fgetxattr(output, name, values + a, (size_t)a, 0, 0) != a) error = errno ? errno : ESTALE;
        if (!error && memcmp(values, values + a, (size_t)a)) error = ENOTSUP;
        free(values);
    }
    if (!error && copy_stopped(progress)) error = progress->error;
    if (!error) {
        if (progress->completion == COPY_COMPLETION_COPYFILE) {
            if (progress->started != count || progress->finished != count) error = EIO;
        } else if (progress->completion != COPY_COMPLETION_CLONE || progress->started || progress->finished) error = EIO;
    }
    free(names);
    errno = error;
    return error ? -1 : 0;
}
static int same_sparse_ranges(int input, int output, off_t size, struct copy_progress *progress) {
    for (off_t position = 0; position < size;) {
        if (copy_stopped(progress)) { errno = progress->error; return -1; }
        off_t a = lseek(input, position, SEEK_DATA);
        if (a < 0 && errno != ENXIO) return -1;
        if (a < 0) a = size;
        off_t b = lseek(output, position, SEEK_DATA);
        if (b < 0 && errno != ENXIO) return -1;
        if (b < 0) b = size;
        if (a != b) { errno = ENOTSUP; return -1; }
        if (a == size) break;
        if (a < position || a > size) { errno = EIO; return -1; }
        off_t hole = lseek(input, a, SEEK_HOLE);
        if (hole < 0) return -1;
        off_t other = lseek(output, b, SEEK_HOLE);
        if (other < 0) return -1;
        if (hole != other) { errno = ENOTSUP; return -1; }
        if (hole <= a || hole > size) { errno = EIO; return -1; }
        position = hole;
    }
    return 0;
}
struct copy_target { int parent; const char *name; const struct stat *opened; };
/* A GID-only result is available only after every other check has succeeded. */
static int verify_metadata(int input, int output, const struct stat *identity,
                             struct copy_progress *progress, const struct acl_snapshot *acl,
                             int allow_gid_difference, const struct copy_target *target) {
    struct stat after, destination;
    int error = 0, gid_difference = 0;
    if (copy_stopped(progress)) error = progress->error;
    if (!error && progress->completion != COPY_COMPLETION_COPYFILE && progress->completion != COPY_COMPLETION_CLONE) error = EIO;
    if (!error && fstat(output, &destination)) error = errno;
    if (!error) {
        gid_difference = identity->st_gid != destination.st_gid;
        if (identity->st_mode != destination.st_mode || identity->st_uid != destination.st_uid ||
            (gid_difference && !allow_gid_difference) || identity->st_flags != destination.st_flags ||
            !same_time(identity->st_mtimespec, destination.st_mtimespec) ||
            (!S_ISDIR(identity->st_mode) && identity->st_size != destination.st_size)) error = ENOTSUP;
    }
    if (!error && same_acl(input, output, acl)) error = errno;
    if (!error && same_xattrs(input, output, progress)) error = errno;
    if (!error && S_ISREG(identity->st_mode) && same_sparse_ranges(input, output, identity->st_size, progress)) error = errno;
    if (!error && fstat(input, &after)) error = errno;
    if (!error && !unchanged_source(identity, &after)) error = ESTALE;
    if (!error && copy_stopped(progress)) error = progress->error;
    if (!error && target) {
        struct stat named;
        if (fstatat(target->parent, target->name, &named, AT_SYMLINK_NOFOLLOW)) error = errno;
        else if (!same_object(target->opened, &named)) error = ESTALE;
    }
    errno = error;
    return error ? -1 : gid_difference;
}
static int ordinary_metadata(int input, int output, const struct stat *identity,
                              copyfile_flags_t flags, struct copy_progress *progress,
                              const struct acl_snapshot *acl, const struct copy_target *target) {
    struct stat before, destination;
    int error = 0;
    progress->completion = COPY_COMPLETION_INCOMPLETE;
    if (copy_stopped(progress)) { errno = progress->error; return -1; }
    if (fstat(input, &before)) return -1;
    if (!unchanged_source(identity, &before)) { errno = ESTALE; return -1; }
    /* Block allocation screens candidates; only the hole query can clear sparse copying. */
    if ((flags & COPYFILE_DATA_SPARSE) && S_ISREG(before.st_mode) && before.st_size > 0 &&
        before.st_blocks >= 0 && (uintmax_t)before.st_blocks >=
        (uintmax_t)before.st_size / 512 + ((uintmax_t)before.st_size % 512 != 0)) {
        int saved = errno;
        off_t hole = lseek(input, 0, SEEK_HOLE);
        if (hole >= 0) {
            errno = 0;
            if (lseek(input, 0, SEEK_SET) != 0) { if (!errno) errno = EIO; return -1; }
            if (hole == before.st_size) flags &= ~COPYFILE_DATA_SPARSE;
        }
        errno = saved;
    }
    copyfile_state_t copy = copyfile_state_alloc();
    if (!copy) return -1;
    if (copyfile_state_set(copy, COPYFILE_STATE_STATUS_CB, (void *)copy_status) ||
        copyfile_state_set(copy, COPYFILE_STATE_STATUS_CTX, progress)) error = errno ? errno : EIO;
    /* Set tracking before copied ownership, ACLs, or immutable flags can prevent it. */
    if (!error && (before.st_flags & UF_TRACKED)) {
        if (fstat(output, &destination)) error = errno;
        else if (!(destination.st_flags & UF_TRACKED) &&
            fchflags(output, destination.st_flags | UF_TRACKED)) error = errno;
        flags |= COPYFILE_PRESERVE_DST_TRACKED;
    }
    if (!error && fcopyfile(input, output, copy, flags)) error = progress->error ? progress->error : errno ? errno : EIO;
    if (copyfile_state_free(copy) && !error) error = errno ? errno : EIO;
    if (!error && copy_stopped(progress)) error = progress->error;
    if (!error) progress->completion = COPY_COMPLETION_COPYFILE;
    if (error) { errno = error; return -1; }
    return verify_metadata(input, output, identity, progress, acl, 0, target);
}
static int clear_acl(int fd) {
    acl_t acl = acl_init(0);
    if (!acl) return -1;
    int result = acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED), error = errno;
    acl_free(acl);
    errno = error;
    return result;
}
static int first_inode(enum operation operation, struct tree *tree, int input, int parent,
                        const char *name, const struct stat *identity,
                        stallion_cancel_fn cancel, void *context) {
    if (operation == CLONING) {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    !(defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU)
        struct cpu_token token = cpu_enter(CPU_FCLONEFILEAT);
#endif
        int result = fclonefileat(input, parent, name, CLONE_NOFOLLOW | CLONE_ACL);
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    !(defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU)
        int error = errno;
        cpu_leave(token, result != 0);
        errno = error;
#endif
        return result;
    }
    struct copy_progress progress = {.tree = tree, .cancel = cancel, .context = context};
    if (copy_stopped(&progress)) { errno = progress.error; return -1; }
    int output = -1, error = 0, cloned = 0;
    struct stat created, opened, current;
    struct acl_snapshot snapshot = {0};
    const struct acl_snapshot *acl = NULL;
    if (tree && tree->copy_strategy == STALLION_COPY_AUTO && S_ISREG(identity->st_mode) &&
        identity->st_uid == geteuid() && (identity->st_mode & (S_IRUSR | S_IWUSR)) == (S_IRUSR | S_IWUSR) &&
        !(identity->st_mode & (S_ISUID | S_ISGID)) && !identity->st_flags) {
        if (fstat(input, &current)) { error = errno; goto done; }
        if (!unchanged_source(identity, &current)) { error = ESTALE; goto done; }
        if (snapshot_acl(input, &snapshot)) { error = errno; goto done; }
        acl = &snapshot;
        if (snapshot.empty) {
            if (copy_stopped(&progress)) { error = progress.error; goto done; }
            if (fstat(input, &current)) { error = errno; goto done; }
            if (!unchanged_source(identity, &current)) { error = ESTALE; goto done; }
            if (!fclonefileat(input, parent, name, CLONE_NOFOLLOW | CLONE_ACL)) {
                cloned = 1;
                /* Observed entry/descriptor agreement relies on the stable private tree;
                 * it cannot recover provenance after replacement before this lookup. */
                if (fstatat(parent, name, &created, AT_SYMLINK_NOFOLLOW)) { error = errno; goto done; }
                if (!S_ISREG(created.st_mode) || same_object(identity, &created)) { error = ESTALE; goto done; }
                output = openat(parent, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
                if (output < 0) { error = errno; goto done; }
                if (fstat(output, &opened)) { error = errno; goto done; }
                if (!same_object(&created, &opened)) { error = ESTALE; goto done; }
                progress.completion = COPY_COMPLETION_CLONE;
            } else {
                int clone_error = errno ? errno : EIO;
                if (clone_error != ENOTSUP && clone_error != EOPNOTSUPP && clone_error != EXDEV) {
                    error = clone_error; goto done;
                }
                if (!fstatat(parent, name, &created, AT_SYMLINK_NOFOLLOW)) { error = clone_error; goto done; }
                if (errno != ENOENT) { error = errno; goto done; }
                if (copy_stopped(&progress)) { error = progress.error; goto done; }
            }
        }
    }
    if (S_ISREG(identity->st_mode) && !cloned) {
        output = openat(parent, name, O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_RDWR, 0600);
        if (output < 0) { error = errno; goto done; }
    } else if (!S_ISREG(identity->st_mode)) {
        if (identity->st_size <= 0 || (uintmax_t)identity->st_size >= SIZE_MAX) { error = EIO; goto done; }
        size_t capacity = (size_t)identity->st_size + 1;
        char *target = malloc(capacity);
        if (!target) { error = errno; goto done; }
        ssize_t length = -1;
        if (__builtin_available(macOS 13.0, *)) length = freadlink(input, target, capacity);
        else errno = ENOTSUP;
        if (length < 0) error = errno;
        else if ((size_t)length != capacity - 1 || memchr(target, 0, (size_t)length)) error = ESTALE;
        else {
            target[length] = 0;
            if (symlinkat(target, parent, name)) error = errno;
        }
        free(target);
        if (!error && fstatat(parent, name, &created, AT_SYMLINK_NOFOLLOW)) error = errno;
        if (!error && (!S_ISLNK(created.st_mode) || created.st_uid != geteuid())) error = ESTALE;
        if (!error && (output = openat(parent, name, O_RDONLY | O_SYMLINK | O_CLOEXEC)) < 0) error = errno;
        if (!error && fstat(output, &opened)) error = errno;
        if (!error && !same_object(&created, &opened)) error = ESTALE;
    }
    if (!error && fstat(output, &opened)) error = errno;
    if (!error && (same_object(identity, &opened) ||
        (identity->st_mode & S_IFMT) != (opened.st_mode & S_IFMT))) error = ESTALE;
    if (!error && fstatat(parent, name, &created, AT_SYMLINK_NOFOLLOW)) error = errno;
    if (!error && !same_object(&opened, &created)) error = ESTALE;
    /* Root leaves can inherit ACLs; tree children have ACL-empty private parents. */
    if (!error && !tree && clear_acl(output)) error = errno;
    const struct copy_target target = {parent, name, &opened};
    if (!error && cloned) {
        if (copy_stopped(&progress)) error = progress.error;
        if (!error && fstat(input, &current)) error = errno;
        if (!error && !unchanged_source(identity, &current)) error = ESTALE;
        int verified = error ? -1 : verify_metadata(input, output, identity, &progress, acl, 1, &target);
        if (!error && verified < 0) error = errno;
        if (!error && verified) {
            /* Full preverification, including the private entry identity, admitted
             * only GID. Broad application needs a new real completion and verifier. */
            progress.completion = COPY_COMPLETION_INCOMPLETE;
            if (ordinary_metadata(input, output, identity, COPYFILE_METADATA, &progress, acl, &target)) error = errno;
        }
    } else if (!error && ordinary_metadata(input, output, identity,
        S_ISREG(identity->st_mode) ? COPYFILE_ALL | COPYFILE_DATA_SPARSE : COPYFILE_METADATA, &progress, acl, &target)) error = errno;
done:
    if (output >= 0 && close(output) && !error) error = errno;
    free(snapshot.bytes);
    errno = error;
    return error ? -1 : 0;
}
static int directory_metadata(struct tree *state, struct job *job, int input, int output,
                               stallion_cancel_fn cancel, void *context) {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    !(defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU)
    if (state->operation == CLONING) {
        struct cpu_token token = cpu_enter(CPU_DIRECTORY);
        int result = fcopyfile(input, output, NULL, COPYFILE_METADATA);
        cpu_leave(token, result != 0);
        return result;
    }
#else
    if (state->operation == CLONING) return fcopyfile(input, output, NULL, COPYFILE_METADATA);
#endif
    struct copy_progress progress = {.tree = state, .cancel = cancel, .context = context};
    return ordinary_metadata(input, output, &job->source_stat, COPYFILE_METADATA, &progress, NULL, NULL);
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
        if (first_inode(state->operation, state, fd, job->destination, name, identity, NULL, NULL)) error = errno;
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
    else if (first_inode(state->operation, state, fd, destination, name, &identity, NULL, NULL)) error = errno;
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
            if (state->operation != DELETING) {
                /* Apply permissions and timestamps only after all children finish. */
                if (!deferred && directory_metadata(state, job, job->source, job->destination, NULL, NULL))
                    fail(state, errno, job->source, NULL);
            } else {
                struct stat current;
                if (fstatat(parent_fd, job->name, &current, AT_SYMLINK_NOFOLLOW))
                    fail(state, errno, parent_fd, job->name);
                else if (current.st_dev != state->device || current.st_ino != job->inode ||
                         !S_ISDIR(current.st_mode)) fail(state, ESTALE, parent_fd, job->name);
                else {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU
                    struct cpu_token token = cpu_enter(CPU_UNLINK_DIRECTORY);
#endif
                    int removed = unlinkat(parent_fd, job->name, AT_REMOVEDIR);
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU
                    int saved = errno;
                    cpu_leave(token, removed != 0);
                    errno = saved;
#endif
                    if (removed) fail(state, errno, parent_fd, job->name);
                }
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
    else if (state->operation != DELETING &&
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
        .inode = identity.st_ino, .source_stat = identity, .parent = parent, .pending = 1, .depth = parent->depth + 1};
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
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU
            struct cpu_token token = cpu_enter(CPU_UNLINK_ENTRY);
#endif
            int removed = unlinkat(job->source, name, 0);
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU && \
    defined(STALLIONFS_DIAGNOSTIC_DELETE_CPU) && STALLIONFS_DIAGNOSTIC_DELETE_CPU
            int saved = errno;
            cpu_leave(token, removed != 0);
            errno = saved;
#endif
            if (removed) fail(state, errno, job->source, name);
        } else if (type == DT_REG || type == DT_LNK) {
            if (clone_leaf(state, job, name, type, entry->d_ino))
                fail(state, errno, job->source, name);
        } else fail(state, ENOTSUP, job->source, name);
    }
    if (closedir(entries)) fail(state, errno, job->source, NULL);
    finish(state, job);
}
static void *worker(void *context) {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
    struct cpu_worker_context *diagnostic = context;
    struct tree *state = diagnostic->state;
    struct cpu_slot *previous = cpu_current;
    cpu_current = diagnostic->slot;
    if (!diagnostic->main_fallback) cpu_start(cpu_current);
#else
    struct tree *state = context;
#endif
    for (;;) {
        pthread_mutex_lock(&state->mutex);
        while (!state->queued && state->live) pthread_cond_wait(&state->available, &state->mutex);
        if (!state->live) {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
            if (!diagnostic->main_fallback) cpu_stop(cpu_current);
            cpu_current = previous;
#endif
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
                    const struct stat *identity, enum operation operation, enum stallion_copy_strategy strategy, unsigned workers,
                    stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    struct job *root = calloc(1, sizeof(*root));
    char *owned_name = strdup(name);
    if (!root || !owned_name) {
        free(root); free(owned_name); close(source);
        if (destination >= 0) close(destination);
        errno = ENOMEM; return -1;
    }
    *root = (struct job){.source = source, .destination = destination, .name = owned_name,
                        .inode = identity->st_ino, .source_stat = *identity, .pending = 1};
    struct tree state = {.mutex = PTHREAD_MUTEX_INITIALIZER, .available = PTHREAD_COND_INITIALIZER,
        .links_mutex = PTHREAD_MUTEX_INITIALIZER, .link_source = -1, .link_destination = -1,
        .parent_fd = parent, .operation = operation, .copy_strategy = strategy, .device = identity->st_dev, .live = 1, .queued = 1};
    atomic_init(&state.error, 0);
    state.queue[0] = root;
    pthread_t threads[4];
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
    struct cpu_profile profile = cpu_open(operation, workers);
    struct cpu_slot *previous = cpu_current;
    cpu_current = profile.enabled ? &profile.slots[0] : NULL;
    cpu_start(cpu_current);
    struct cpu_worker_context diagnostic[sizeof(threads) / sizeof(threads[0])];
#endif
    unsigned started = 0;
    for (; started < workers; started++) {
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
        diagnostic[started] = (struct cpu_worker_context){.state = &state,
            .slot = profile.enabled && started < CPU_WORKERS ? &profile.slots[started + 1] : NULL};
        int result = pthread_create(&threads[started], NULL, worker, &diagnostic[started]);
#else
        int result = pthread_create(&threads[started], NULL, worker, &state);
#endif
        if (result) { fail(&state, result, parent, name); break; }
    }
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
    if (!started) {
        diagnostic[0] = (struct cpu_worker_context){.state = &state, .slot = cpu_current, .main_fallback = 1};
        worker(&diagnostic[0]);
    }
#else
    if (!started) worker(&state);
#endif
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
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
        if (result) profile.status = CPU_JOIN;
#endif
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
        if (!error && directory_metadata(&state, job, input, output, cancel, context)) error = errno;
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
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU) && STALLIONFS_DIAGNOSTIC_THREAD_CPU
    cpu_stop(cpu_current);
    cpu_current = previous;
    cpu_report(&profile, workers, started, error);
#endif
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

static int check_acl(int fd, uid_t owner, int private, int leaf_copy, int namespace) {
    acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    /* Darwin reports ENOENT when a pinned directory has no extended ACL. */
    if (!acl) { if (errno == ENOENT) { errno = 0; return 0; } if (!errno) errno = EIO; return -1; }
    int error = 0, have_user = 0;
    uuid_t user;
    acl_entry_t entry;
    acl_permset_mask_t known, mutations = ACL_ADD_FILE | ACL_ADD_SUBDIRECTORY | ACL_DELETE_CHILD |
        ACL_WRITE_ATTRIBUTES | ACL_WRITE_SECURITY | ACL_CHANGE_OWNER;
    if (namespace) mutations |= ACL_DELETE;
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
        int inherited = 0;
        /* An inherited grant can open a leaf before its ACL is cleared. */
        if (leaf_copy && permissions) {
            acl_flagset_t flags;
            if (acl_get_flagset_np(entry, &flags)) { error = errno ? errno : EIO; break; }
            inherited = acl_get_flag_np(flags, ACL_ENTRY_FILE_INHERIT);
            if (inherited < 0) { error = errno ? errno : EIO; break; }
        }
        if (!(private ? permissions : permissions & mutations) && !inherited) continue;
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
static int protected_parent(int fd, dev_t device, enum operation operation, int leaf_copy) {
    struct stat st;
    if (fstat(fd, &st)) return -1;
    if (operation == CLONING && st.st_dev != device) { errno = EXDEV; return -1; }
    if ((st.st_uid != geteuid() && st.st_uid != 0) || (!(st.st_mode & S_ISVTX) && (st.st_mode & 0022))) {
        errno = EPERM; return -1;
    }
    return check_acl(fd, geteuid(), 0, leaf_copy, 0);
}

int stallion_protected_directory_fd(int fd, int private) {
    struct stat st;
    if (fstat(fd, &st)) return -1;
    if (!S_ISDIR(st.st_mode)) { errno = ENOTDIR; return -1; }
    if (!private) {
        if ((st.st_uid != geteuid() && st.st_uid != 0) ||
            (!(st.st_mode & S_ISVTX) && (st.st_mode & 0022))) { errno = EPERM; return -1; }
        /* An ACL on this ancestor must not permit its own removal either. */
        return check_acl(fd, geteuid(), 0, 0, 1);
    }
    if (st.st_uid != getuid() || (st.st_mode & 0077)) { errno = EPERM; return -1; }
    return check_acl(fd, getuid(), 1, 0, 0);
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
    int error = stallion_protected_directory_fd(fd, 1) ? errno : 0;
    if (close(fd) && !error) error = errno;
    errno = error;
    return error ? -1 : 0;
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

static int clone_impl(const char *source_path, const char *destination_path, int directory_only, enum operation operation, enum stallion_copy_strategy strategy,
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
    if (!error && operation == COPYING && protected_parent(destination.parent, identity.st_dev, operation,
                                                          !S_ISDIR(identity.st_mode))) error = errno;
    if (!error && !S_ISDIR(identity.st_mode)) {
        /* Both creation paths refuse an existing final entry. */
        if (cancel && cancel(context)) error = EINTR;
        else if (first_inode(operation, NULL, input, destination.parent, destination.name, &identity, cancel, context)) error = errno;
        goto done;
    }
    if (!error && operation == CLONING && protected_parent(destination.parent, identity.st_dev, operation, 0)) error = errno;
    if (!error && outside_source(destination.parent, &identity)) error = errno;
    if (!error && (output = open_created_directory(destination.parent, destination.name)) < 0) error = errno;
    /* Keep all children private until the final root-metadata copy. */
    if (!error && clear_acl(output)) error = errno;
    if (!error) {
        int result = run_tree(input, output, source.parent, source.name, &identity, operation, strategy,
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
int stallion_copy(const char *source, const char *destination, unsigned workers,
                  stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    return stallion_copy_with_strategy(source, destination, STALLION_COPY_MATERIALIZED, workers,
                                       cancel, context, error_path, capacity);
}
int stallion_copy_with_strategy(const char *source, const char *destination, enum stallion_copy_strategy strategy,
                                unsigned workers, stallion_cancel_fn cancel, void *context,
                                char *error_path, size_t capacity) {
    if (strategy != STALLION_COPY_MATERIALIZED && strategy != STALLION_COPY_AUTO) {
        path_error(error_path, capacity, destination ? destination : "");
        errno = EINVAL; return -1;
    }
    if (__builtin_available(macOS 13.0, *))
        return clone_impl(source, destination, 0, COPYING, strategy, workers, cancel, context, error_path, capacity);
    path_error(error_path, capacity, destination ? destination : "");
    errno = ENOTSUP;
    return -1;
}
int stallion_clone(const char *source, const char *destination, unsigned workers,
                   stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    return clone_impl(source, destination, 0, CLONING, STALLION_COPY_MATERIALIZED, workers, cancel, context, error_path, capacity);
}
int stallion_clone_tree(const char *source, const char *destination, unsigned workers,
                        stallion_cancel_fn cancel, void *context, char *error_path, size_t capacity) {
    return clone_impl(source, destination, 1, CLONING, STALLION_COPY_MATERIALIZED, workers, cancel, context, error_path, capacity);
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
            int result = run_tree(fd, -1, path.parent, path.name, &identity, DELETING, STALLION_COPY_MATERIALIZED,
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
