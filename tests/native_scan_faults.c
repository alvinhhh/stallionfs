/* Compile only _walk.c with renamed syscalls; wrappers call the real APIs. */
#include "_tree.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <unistd.h>

enum { NONE, CANCEL_ENTRY, CANCEL_FINAL, CLOSE_DIRECTORY, CLOSE_SKIPPED,
       CLOSE_ROOT, ROOT_ERROR, THREAD_FIRST, THREAD_THIRD,
       WORKER_CLOSE, CANCEL_BACKPRESSURE, CANCEL_WAIT, WORKER_ERROR, PINNED_RENAME, AGGREGATE_OVERFLOW };
static int mode, root_fd = -1, skipped_fd = -1;
static atomic_int opens, root_closed, injected, thread_calls, started, joined;
static dev_t root_device;
#ifndef STALLION_TEST_CLI
static pthread_t caller;
static atomic_int waiters, gate;
static int before_fds;
static char moved_path[PATH_MAX], outside_path[PATH_MAX], renamed_from[PATH_MAX];
#endif

int stallion_test_open(const char *path, int flags, ...) {
    int fd;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags);
        int permissions = va_arg(args, int); va_end(args);
        fd = open(path, flags, permissions);
    } else fd = open(path, flags);
    opens++;
    if (root_fd < 0 && fd >= 0) root_fd = fd;
    return fd;
}

/* Match the stat header's Intel inode ABI when _walk.c renames fstat. */
int stallion_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(stallion_test_fstat);
int stallion_test_fstat(int fd, struct stat *st) {
    int result = fstat(fd, st);
    if (!result && fd == root_fd && !root_closed) root_device = st->st_dev;
    if (!result && mode == CLOSE_SKIPPED && fd != root_fd) {
        st->st_dev = root_device + 1;
        skipped_fd = fd;
    }
    return result;
}

int stallion_test_close(int fd) {
    int result = close(fd);
#ifndef STALLION_TEST_CLI
    int expected = 0;
    if (!result && mode == WORKER_CLOSE && !pthread_equal(pthread_self(), caller) &&
        atomic_compare_exchange_strong(&injected, &expected, 1)) { errno = EIO; return -1; }
#endif
    if (fd == root_fd) root_closed = 1;
    if (!result && mode == CLOSE_ROOT && fd == root_fd) {
        injected++; errno = EIO; return -1;
    }
    if (!result && mode == CLOSE_SKIPPED && fd == skipped_fd) {
        injected++; errno = EIO; return -1;
    }
    return result;
}

int stallion_test_closedir(DIR *directory) {
    int result = closedir(directory);
    if (!result && mode == CLOSE_DIRECTORY) { injected++; errno = EIO; return -1; }
    return result;
}

int stallion_test_getattrlistbulk(int fd, struct attrlist *attrs, void *buffer,
                                size_t size, uint64_t options) {
#ifndef STALLION_TEST_CLI
    if (!pthread_equal(pthread_self(), caller) && mode >= CANCEL_BACKPRESSURE) {
        waiters++;
        while (!gate) usleep(1000);
        waiters--;
        int expected = 0;
        if (mode == WORKER_ERROR && atomic_compare_exchange_strong(&injected, &expected, 1)) {
            errno = EIO; return -1;
        }
        if (mode == PINNED_RENAME && atomic_compare_exchange_strong(&injected, &expected, 1)) {
            assert(fcntl(fd, F_GETPATH, renamed_from) == 0);
            assert(rename(renamed_from, moved_path) == 0);
            assert(symlink(outside_path, renamed_from) == 0);
        }
    }
#endif
    int result = getattrlistbulk(fd, attrs, buffer, size, options);
#ifndef STALLION_TEST_CLI
    if (mode == AGGREGATE_OVERFLOW && result > 0 && !pthread_equal(pthread_self(), caller)) {
        struct __attribute__((packed, aligned(4))) attributes {
            uint32_t length; attribute_set_t returned; uint32_t error;
            attrreference_t name; fsobj_type_t type;
        };
        size_t offset = 0;
        for (int i = 0; i < result; i++) {
            struct attributes entry;
            assert(offset <= size - sizeof(entry));
            memcpy(&entry, (char *)buffer + offset, sizeof(entry));
            assert(entry.length <= size - offset);
            if (entry.type == VREG) {
                off_t length = INT64_MAX;
                assert(entry.returned.fileattr & ATTR_FILE_DATALENGTH);
                assert(entry.length >= sizeof(entry) + sizeof(length));
                memcpy((char *)buffer + offset + sizeof(entry), &length, sizeof(length));
                injected++;
            }
            offset += entry.length;
        }
    }
#endif
    if (mode == ROOT_ERROR && fd == root_fd && result == 0) {
        injected++; errno = EIO; return -1;
    }
#ifdef STALLION_TEST_CLI
    if (result > 0 && !injected++) raise(SIGINT);
#endif
    return result;
}

int stallion_test_pthread_create(pthread_t *thread, const pthread_attr_t *attributes,
                                void *(*function)(void *), void *context) {
    int call = ++thread_calls;
    if ((mode == THREAD_FIRST && call == 1) || (mode == THREAD_THIRD && call == 3)) return EAGAIN;
    int result = pthread_create(thread, attributes, function, context);
    if (!result) started++;
    return result;
}

int stallion_test_pthread_join(pthread_t thread, void **result) {
    int error = pthread_join(thread, result);
    if (!error) joined++;
    return error;
}

#ifndef STALLION_TEST_CLI
static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 4096; fd++) if (fcntl(fd, F_GETFD) != -1) count++;
    return count;
}

static int cancelled(void *context) {
    assert(pthread_equal(pthread_self(), *(pthread_t *)context));
    if (waiters && ((mode == CANCEL_BACKPRESSURE || mode == WORKER_ERROR) && !root_closed)) {
        assert(descriptors() <= before_fds + 32);
        gate = 1;
        return mode == CANCEL_BACKPRESSURE;
    }
    if (waiters && root_closed && (mode == CANCEL_WAIT || mode == PINNED_RENAME)) {
        gate = 1;
        return mode == CANCEL_WAIT;
    }
    if (mode == AGGREGATE_OVERFLOW && waiters == 4 && root_closed) gate = 1;
    return mode == CANCEL_ENTRY || (mode == CANCEL_FINAL && root_closed);
}

static void reset(int fault) {
    mode = fault; root_fd = skipped_fd = -1;
    opens = root_closed = injected = thread_calls = started = joined = waiters = gate = 0;
}

static struct stallion_scan_stats run(const char *path, int bulk, unsigned workers, int expected_error) {
    int before = descriptors();
    before_fds = before;
    char error[PATH_MAX] = {0};
    struct stallion_scan_stats stats;
    memset(&stats, 0x7f, sizeof(stats));
    int result = stallion_scan(path, bulk, workers, &stats, cancelled, &caller, error, sizeof(error));
    int saved = errno;
    assert(result == (expected_error ? -1 : 0));
    assert(saved == expected_error);
    assert(descriptors() == before && started == joined && !waiters);
    if (expected_error) {
        struct stallion_scan_stats zero = {0};
        assert(!memcmp(&stats, &zero, sizeof(stats)));
        if (expected_error != EINVAL) assert(error[0]);
    }
    return stats;
}

static void make_tree(const char *path, unsigned count) {
    assert(mkdir(path, 0700) == 0);
    int root = open(path, O_RDONLY | O_DIRECTORY);
    assert(root >= 0);
    for (unsigned i = 0; i < count; i++) {
        char name[32]; snprintf(name, sizeof(name), "%u", i);
        assert(mkdirat(root, name, 0700) == 0);
        int child = openat(root, name, O_RDONLY | O_DIRECTORY);
        assert(child >= 0);
        int file = openat(child, "file", O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(file >= 0 && write(file, "x", 1) == 1);
        assert(close(file) == 0 && close(child) == 0);
    }
    assert(close(root) == 0);
}

static void remove_tree(const char *path, unsigned count) {
    int root = open(path, O_RDONLY | O_DIRECTORY);
    assert(root >= 0);
    for (unsigned i = 0; i < count; i++) {
        char name[32]; snprintf(name, sizeof(name), "%u", i);
        struct stat identity;
        assert(fstatat(root, name, &identity, AT_SYMLINK_NOFOLLOW) == 0);
        if (S_ISLNK(identity.st_mode)) assert(unlinkat(root, name, 0) == 0);
        else {
            int child = openat(root, name, O_RDONLY | O_DIRECTORY);
            assert(child >= 0 && unlinkat(child, "file", 0) == 0 && close(child) == 0);
            assert(unlinkat(root, name, AT_REMOVEDIR) == 0);
        }
    }
    assert(close(root) == 0 && rmdir(path) == 0);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char path[PATH_MAX], child[PATH_MAX];
    assert(snprintf(path, sizeof(path), "%s/scan-fixture", argv[1]) < (int)sizeof(path));
    assert(snprintf(child, sizeof(child), "%s/child", path) < (int)sizeof(child));
    assert(mkdir(path, 0700) == 0 && mkdir(child, 0700) == 0);
    caller = pthread_self();
    for (int bulk = 0; bulk <= 1; bulk++) {
        for (int fault = CANCEL_ENTRY; fault <= ROOT_ERROR; fault++) {
            if ((bulk && fault == CLOSE_DIRECTORY) || (!bulk && fault == ROOT_ERROR)) continue;
            reset(fault);
            run(path, bulk, 4, fault <= CANCEL_FINAL ? EINTR : EIO);
            if (fault == CANCEL_ENTRY) assert(!opens && !root_closed);
            if (fault == CANCEL_FINAL) assert(opens && root_closed);
            if (fault >= CLOSE_DIRECTORY) assert(injected);
        }
    }
    reset(NONE); run(path, 1, 4, 0); assert(!thread_calls);
    reset(NONE); run(child, 1, 4, 0); assert(!thread_calls);
    assert(rmdir(child) == 0 && rmdir(path) == 0);
    reset(NONE); run(NULL, 1, 4, EINVAL); assert(!opens);
    reset(NONE); run(argv[1], 1, 0, EINVAL); assert(!opens);
    reset(NONE); run(argv[1], 1, 5, EINVAL); assert(!opens);

    make_tree(path, 64);
    for (int fault = THREAD_FIRST; fault <= THREAD_THIRD; fault++) {
        reset(fault);
        struct stallion_scan_stats stats = run(path, 1, 4, 0);
        assert(stats.files == 64 && stats.directories == 64 && stats.logical_bytes == 64);
        assert(started == (fault == THREAD_FIRST ? 0 : 2));
    }
    reset(CANCEL_BACKPRESSURE); run(path, 1, 4, EINTR); assert(gate && started);
    reset(WORKER_ERROR); run(path, 1, 4, EIO); assert(gate && injected);
    reset(WORKER_CLOSE); run(path, 1, 4, EIO); assert(injected);
    remove_tree(path, 64);

    make_tree(path, 4);
    reset(AGGREGATE_OVERFLOW); run(path, 1, 4, EOVERFLOW); assert(gate && injected == 4);
    remove_tree(path, 4);

    make_tree(path, 2);
    reset(CANCEL_WAIT); run(path, 1, 4, EINTR); assert(gate && root_closed);
    assert(snprintf(moved_path, sizeof(moved_path), "%s/moved", argv[1]) < (int)sizeof(moved_path));
    assert(snprintf(outside_path, sizeof(outside_path), "%s/outside", argv[1]) < (int)sizeof(outside_path));
    make_tree(outside_path, 1);
    reset(PINNED_RENAME);
    struct stallion_scan_stats stats = run(path, 1, 4, 0);
    assert(injected && stats.files == 2 && stats.directories == 2 && stats.logical_bytes == 2);
    int moved = open(moved_path, O_RDONLY | O_DIRECTORY);
    assert(moved >= 0 && unlinkat(moved, "file", 0) == 0 && close(moved) == 0 && rmdir(moved_path) == 0);
    remove_tree(path, 2);
    remove_tree(outside_path, 1);

    /* Keep the process's descriptor limit out of the global depth-limit check. */
    struct rlimit saved_limit, limit;
    assert(getrlimit(RLIMIT_NOFILE, &saved_limit) == 0);
    limit = saved_limit;
    if (limit.rlim_cur < 2048) limit.rlim_cur = 2048;
    assert(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    make_tree(path, 2);
    int parents[512];
    int root = open(path, O_RDONLY | O_DIRECTORY);
    assert(root >= 0);
    parents[0] = openat(root, "0", O_RDONLY | O_DIRECTORY);
    assert(parents[0] >= 0 && close(root) == 0);
    for (unsigned i = 1; i < 512; i++) {
        assert(mkdirat(parents[i - 1], "x", 0700) == 0);
        parents[i] = openat(parents[i - 1], "x", O_RDONLY | O_DIRECTORY);
        assert(parents[i] >= 0);
    }
    reset(NONE); run(path, 1, 1, ELOOP);
    reset(NONE); run(path, 1, 4, ELOOP);
    for (unsigned i = 511; i > 0; i--)
        assert(close(parents[i]) == 0 && unlinkat(parents[i - 1], "x", AT_REMOVEDIR) == 0);
    assert(close(parents[0]) == 0);
    remove_tree(path, 2);
    assert(setrlimit(RLIMIT_NOFILE, &saved_limit) == 0);
    puts("scan cancellation, close errors and descriptor cleanup passed");
    return 0;
}
#endif
