#include "_tree.h"
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct scan_pool;
struct parallel;
struct scan {
    struct stallion_scan_stats *stats;
    dev_t device;
    int bulk, error;
    stallion_cancel_fn cancel;
    void *context;
    char *error_path;
    size_t error_capacity;
    struct scan_pool *pool;
    struct parallel *parallel;
};

#define SCAN_QUEUE_LIMIT 24
struct scan_job { int fd; char *path; unsigned depth; };
struct scan_worker { struct scan_pool *pool; struct stallion_scan_stats stats; };
struct scan_pool {
    pthread_mutex_t mutex;
    pthread_cond_t available, progress;
    struct scan_job queue[SCAN_QUEUE_LIMIT];
    unsigned head, queued, started, exited;
    int done;
    atomic_int error;
    dev_t device;
    char *error_path;
    size_t error_capacity;
    pthread_t threads[4];
    struct scan_worker workers[4];
};
struct parallel {
    unsigned workers;
    int pending;
    struct scan_job first;
    struct scan_pool *pool;
};

static int fail(struct scan *s, int error, const char *path) {
    if (!s->error) {
        s->error = error ? error : EIO;
        if (s->pool) {
            struct scan_pool *pool = s->pool;
            pthread_mutex_lock(&pool->mutex);
            if (!atomic_load(&pool->error)) {
                if (pool->error_path && pool->error_capacity)
                    snprintf(pool->error_path, pool->error_capacity, "%s", path);
                atomic_store(&pool->error, s->error);
                pthread_cond_broadcast(&pool->available);
                pthread_cond_signal(&pool->progress);
            }
            pthread_mutex_unlock(&pool->mutex);
        } else if (s->error_path && s->error_capacity)
            snprintf(s->error_path, s->error_capacity, "%s", path);
    }
    return -1;
}

static int cancelled(struct scan *s, const char *path) {
    if (s->pool && atomic_load(&s->pool->error)) return -1;
    return s->cancel && s->cancel(s->context) ? fail(s, EINTR, path) : 0;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s);
static int dispatch(struct scan_job job, struct scan *s);
static int discard(struct scan_job job, struct scan *s);

static int visit(int fd, const char *path, const char *name, unsigned type,
                 off_t size, unsigned depth, struct scan *s, struct scan_job *pending) {
    if (type == VREG) {
        if (size < 0 || UINT64_MAX - s->stats->logical_bytes < (uint64_t)size)
            return fail(s, EOVERFLOW, path);
        s->stats->files++;
        s->stats->logical_bytes += size;
    } else if (type == VLNK) s->stats->symlinks++;
    else if (type != VDIR) s->stats->other++;
    else {
        s->stats->directories++;
        char *child_path = NULL;
        if (asprintf(&child_path, "%s/%s", path, name) < 0)
            return fail(s, ENOMEM, path);
        int child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int result = 0;
        if (child < 0) result = fail(s, errno, child_path);
        else {
            struct stat st;
            if (fstat(child, &st)) {
                result = fail(s, errno, child_path);
                close(child);
            } else if (st.st_dev != s->device) {
                s->stats->skipped_mounts++;
                if (close(child)) result = fail(s, errno, child_path);
            } else if (!depth && s->parallel && s->parallel->workers > 1) {
                /* Dispatch owns the pinned descriptor and diagnostic path. */
                return dispatch((struct scan_job){child, child_path, depth + 1}, s);
            } else if (pending) {
                *pending = (struct scan_job){child, child_path, depth + 1};
                return 0;
            } else result = walk(child, child_path, depth + 1, s);
        }
        free(child_path);
        return result;
    }
    return 0;
}

// getattrlist fields use 4-byte alignment. File length is omitted for directories.
struct __attribute__((packed, aligned(4))) attributes {
    uint32_t length;
    attribute_set_t returned;
    uint32_t error;
    attrreference_t name;
    fsobj_type_t type;
};

static int walk_bulk(int fd, const char *path, unsigned depth, struct scan *s) {
    const size_t capacity = 65536;
    unsigned char *buffer = malloc(capacity);
    if (!buffer) return fail(s, ENOMEM, path);
    struct attrlist requested = {0};
    requested.bitmapcount = ATTR_BIT_MAP_COUNT;
    requested.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    requested.fileattr = ATTR_FILE_DATALENGTH;
    int result = 0;
    /* Avoid retaining parent buffers along a chain of single-child directories. */
    struct scan_job pending = {.fd = -1};
    struct scan_job *defer = !depth && s->parallel ? NULL : &pending;
    for (;;) {
        if (cancelled(s, path)) { result = -1; break; }
        int count = getattrlistbulk(fd, &requested, buffer, capacity, FSOPT_PACK_INVAL_ATTRS);
        if (count < 0) { result = fail(s, errno, path); break; }
        if (!count) break;
        size_t offset = 0;
        for (int i = 0; i < count; i++) {
            struct attributes a;
            off_t size = 0;
            if (offset > capacity - sizeof(a)) goto invalid;
            memcpy(&a, buffer + offset, sizeof(a));
            if (a.length < sizeof(a) || a.length > capacity - offset) goto invalid;
            if (a.error) { result = fail(s, a.error, path); goto done; }
            unsigned required = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
            if ((a.returned.commonattr & required) != required) goto invalid;
            size_t fixed = sizeof(a);
            if (a.returned.fileattr & ATTR_FILE_DATALENGTH) {
                fixed += sizeof(size);
                if (a.length < fixed) goto invalid;
                memcpy(&size, buffer + offset + sizeof(a), sizeof(size));
            } else if (a.type == VREG) goto invalid;
            int64_t start = (int64_t)offsetof(struct attributes, name) + a.name.attr_dataoffset;
            if (start < (int64_t)fixed || start >= a.length || !a.name.attr_length ||
                a.name.attr_length > a.length - start) goto invalid;
            const char *name = (const char *)(buffer + offset + start);
            if (name[a.name.attr_length - 1] || !name[0] ||
                memchr(name, '/', a.name.attr_length - 1) ||
                memchr(name, 0, a.name.attr_length - 1) ||
                !strcmp(name, ".") || !strcmp(name, "..")) goto invalid;
            if (a.type == VDIR && pending.fd >= 0) {
                struct scan_job job = pending;
                pending.fd = -1;
                defer = NULL;
                result = walk(job.fd, job.path, job.depth, s);
                free(job.path);
                if (result) goto done;
            }
            if (visit(fd, path, name, a.type, size, depth, s, defer)) { result = -1; goto done; }
            offset += a.length;
        }
    }
    goto done;
invalid:
    result = fail(s, EIO, path);
done:
    free(buffer);
    if (pending.fd >= 0) {
        if (result || cancelled(s, path)) {
            discard(pending, s);
            result = -1;
        } else {
            result = walk(pending.fd, pending.path, pending.depth, s);
            free(pending.path);
        }
    }
    return result;
}

// Private reference implementation for correctness and performance comparisons.
static int walk_posix(int fd, const char *path, unsigned depth, struct scan *s) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return fail(s, errno, path);
    DIR *directory = fdopendir(copy);
    if (!directory) { int error = errno; close(copy); return fail(s, error, path); }
    int result = 0;
    unsigned checked = 0;
    for (;;) {
        if (!(checked++ % 256) && cancelled(s, path)) { result = -1; break; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = fail(s, errno, path); break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            result = fail(s, errno, path);
            break;
        }
        unsigned type = S_ISREG(st.st_mode) ? VREG : S_ISDIR(st.st_mode) ? VDIR : S_ISLNK(st.st_mode) ? VLNK : VNON;
        if (visit(fd, path, entry->d_name, type, st.st_size, depth, s, NULL)) { result = -1; break; }
    }
    if (closedir(directory) && !result) result = fail(s, errno, path);
    return result;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s) {
    // Bounded recursion; use an explicit traversal stack if 512 levels are needed.
    int result = depth >= 512 ? fail(s, ELOOP, path) :
        s->bulk ? walk_bulk(fd, path, depth, s) : walk_posix(fd, path, depth, s);
    if (close(fd) && !result) result = fail(s, errno, path);
    return result;
}

static int discard(struct scan_job job, struct scan *s) {
    int result = close(job.fd) ? fail(s, errno, job.path) : 0;
    free(job.path);
    return result;
}

static void *scan_worker(void *context) {
    struct scan_worker *worker = context;
    struct scan_pool *pool = worker->pool;
    struct scan s = {.stats = &worker->stats, .bulk = 1, .device = pool->device, .pool = pool};
    for (;;) {
        pthread_mutex_lock(&pool->mutex);
        while (!pool->queued && !pool->done)
            pthread_cond_wait(&pool->available, &pool->mutex);
        if (!pool->queued) {
            pool->exited++;
            pthread_cond_signal(&pool->progress);
            pthread_mutex_unlock(&pool->mutex);
            return NULL;
        }
        struct scan_job job = pool->queue[pool->head];
        int was_full = pool->queued == SCAN_QUEUE_LIMIT;
        pool->head = (pool->head + 1) % SCAN_QUEUE_LIMIT;
        pool->queued--;
        if (was_full) pthread_cond_signal(&pool->progress);
        pthread_mutex_unlock(&pool->mutex);
        if (atomic_load(&pool->error)) discard(job, &s);
        else {
            walk(job.fd, job.path, job.depth, &s);
            free(job.path);
        }
    }
}

static struct scan_pool *start_pool(struct scan *s, unsigned workers) {
    struct scan_pool *pool = calloc(1, sizeof(*pool));
    if (!pool) return NULL;
    if (pthread_mutex_init(&pool->mutex, NULL)) { free(pool); return NULL; }
    if (pthread_cond_init(&pool->available, NULL)) {
        pthread_mutex_destroy(&pool->mutex); free(pool); return NULL;
    }
    if (pthread_cond_init(&pool->progress, NULL)) {
        pthread_cond_destroy(&pool->available);
        pthread_mutex_destroy(&pool->mutex); free(pool); return NULL;
    }
    atomic_init(&pool->error, 0);
    pool->device = s->device;
    pool->error_path = s->error_path;
    pool->error_capacity = s->error_capacity;
    for (; pool->started < workers; pool->started++) {
        struct scan_worker *worker = &pool->workers[pool->started];
        worker->pool = pool;
        if (pthread_create(&pool->threads[pool->started], NULL, scan_worker, worker)) break;
    }
    if (pool->started) return pool;
    pthread_cond_destroy(&pool->progress);
    pthread_cond_destroy(&pool->available);
    pthread_mutex_destroy(&pool->mutex);
    free(pool);
    return NULL;
}

/* Only the caller produces jobs; workers recursively consume pinned subtrees. */
static int enqueue(struct scan_job job, struct scan *s) {
    struct scan_pool *pool = s->pool;
    pthread_mutex_lock(&pool->mutex);
    while (pool->queued == SCAN_QUEUE_LIMIT && !atomic_load(&pool->error)) {
        pthread_mutex_unlock(&pool->mutex);
        cancelled(s, job.path);
        pthread_mutex_lock(&pool->mutex);
        if (pool->queued == SCAN_QUEUE_LIMIT && !atomic_load(&pool->error)) {
            struct timespec delay = {.tv_nsec = 20000000};
            int error = pthread_cond_timedwait_relative_np(&pool->progress, &pool->mutex, &delay);
            if (error && error != ETIMEDOUT) {
                pthread_mutex_unlock(&pool->mutex);
                fail(s, error, job.path);
                pthread_mutex_lock(&pool->mutex);
            }
        }
    }
    int stopped = atomic_load(&pool->error);
    if (!stopped) {
        pool->queue[(pool->head + pool->queued++) % SCAN_QUEUE_LIMIT] = job;
        pthread_cond_signal(&pool->available);
    }
    pthread_mutex_unlock(&pool->mutex);
    if (stopped) { discard(job, s); return -1; }
    return 0;
}

static int dispatch(struct scan_job job, struct scan *s) {
    struct parallel *parallel = s->parallel;
    if (!parallel->pool && !parallel->pending) {
        parallel->first = job;
        parallel->pending = 1;
        return 0;
    }
    if (!parallel->pool) {
        parallel->pool = start_pool(s, parallel->workers);
        parallel->pending = 0;
        if (!parallel->pool) {
            /* Thread limits affect throughput, not scan availability. */
            parallel->workers = 1;
            int result = walk(parallel->first.fd, parallel->first.path, parallel->first.depth, s);
            free(parallel->first.path);
            if (result) { discard(job, s); return -1; }
            result = walk(job.fd, job.path, job.depth, s);
            free(job.path);
            return result;
        }
        s->pool = parallel->pool;
        if (enqueue(parallel->first, s)) { discard(job, s); return -1; }
    }
    return enqueue(job, s);
}

static int finish_parallel(struct scan *s, const char *path) {
    struct parallel *parallel = s->parallel;
    if (parallel->pending) {
        struct scan_job job = parallel->first;
        if (s->error) return discard(job, s);
        int result = walk(job.fd, job.path, job.depth, s);
        free(job.path);
        return result;
    }
    struct scan_pool *pool = parallel->pool;
    if (!pool) return 0;
    pthread_mutex_lock(&pool->mutex);
    pool->done = 1;
    pthread_cond_broadcast(&pool->available);
    while (pool->exited < pool->started) {
        pthread_mutex_unlock(&pool->mutex);
        cancelled(s, path);
        pthread_mutex_lock(&pool->mutex);
        if (pool->exited < pool->started) {
            struct timespec delay = {.tv_nsec = 20000000};
            int error = pthread_cond_timedwait_relative_np(&pool->progress, &pool->mutex, &delay);
            if (error && error != ETIMEDOUT) {
                pthread_mutex_unlock(&pool->mutex);
                fail(s, error, path);
                pthread_mutex_lock(&pool->mutex);
            }
        }
    }
    pthread_mutex_unlock(&pool->mutex);
    for (unsigned i = 0; i < pool->started; i++) {
        int error = pthread_join(pool->threads[i], NULL);
        if (error) fail(s, error, path);
    }
    if (!atomic_load(&pool->error)) {
        for (unsigned i = 0; i < pool->started; i++) {
            struct stallion_scan_stats *from = &pool->workers[i].stats;
#define ADD(field) if (UINT64_MAX - s->stats->field < from->field) fail(s, EOVERFLOW, path); else s->stats->field += from->field
            ADD(files); ADD(directories); ADD(symlinks); ADD(other); ADD(logical_bytes); ADD(skipped_mounts);
#undef ADD
        }
    }
    int error = atomic_load(&pool->error);
    s->pool = NULL;
    pthread_cond_destroy(&pool->progress);
    pthread_cond_destroy(&pool->available);
    pthread_mutex_destroy(&pool->mutex);
    free(pool);
    if (error) s->error = error;
    return error ? -1 : 0;
}

int stallion_scan(const char *path, int bulk, unsigned workers, struct stallion_scan_stats *stats,
                   stallion_cancel_fn cancel, void *context,
                   char *error_path, size_t error_capacity) {
    if (error_path && error_capacity) error_path[0] = 0;
    if (stats) *stats = (struct stallion_scan_stats){0};
    if (!path || !stats || workers < 1 || workers > 4) { errno = EINVAL; return -1; }
    struct stallion_scan_stats totals = {0};
    struct parallel parallel = {.workers = workers};
    struct scan s = {.stats = &totals, .bulk = bulk, .cancel = cancel, .context = context,
                     .error_path = error_path, .error_capacity = error_capacity,
                     .parallel = bulk && workers > 1 ? &parallel : NULL};
    int result = -1;
    if (!cancelled(&s, path)) {
        char *trimmed = NULL;
        size_t length = strlen(path);
        if (length > 1 && path[length - 1] == '/') {
            /* A trailing slash must not bypass final-component O_NOFOLLOW. */
            trimmed = strdup(path);
            if (!trimmed) fail(&s, ENOMEM, path);
            else while (length > 1 && trimmed[length - 1] == '/') trimmed[--length] = 0;
        }
        if (!s.error) {
            int fd = open(trimmed ? trimmed : path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) fail(&s, errno, path);
            else {
                struct stat st;
                if (fstat(fd, &st)) { fail(&s, errno, path); close(fd); }
                else { s.device = st.st_dev; result = walk(fd, path, 0, &s); }
            }
        }
        free(trimmed);
    }
    if (s.parallel && finish_parallel(&s, path)) result = -1;
    if (!result && cancelled(&s, path)) result = -1;
    if (!result) *stats = totals;
    errno = s.error;
    return result;
}
