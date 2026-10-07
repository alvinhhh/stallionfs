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
#include <stdio.h>
#include <string.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <unistd.h>

enum { NONE, CANCEL_ENTRY, CANCEL_FINAL, CLOSE_DIRECTORY, CLOSE_SKIPPED };
static int mode, root_fd = -1, opens, root_closed, skipped_fd = -1, injected;
static dev_t root_device;

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
    if (!result && fd == root_fd) root_device = st->st_dev;
    if (!result && mode == CLOSE_SKIPPED && fd != root_fd) {
        st->st_dev = root_device + 1;
        skipped_fd = fd;
    }
    return result;
}

int stallion_test_close(int fd) {
    int result = close(fd);
    if (fd == root_fd) root_closed = 1;
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
    int result = getattrlistbulk(fd, attrs, buffer, size, options);
#ifdef STALLION_TEST_CLI
    if (result > 0 && !injected++) raise(SIGINT);
#endif
    return result;
}

#ifndef STALLION_TEST_CLI
static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) != -1) count++;
    return count;
}

static int cancelled(void *context) {
    assert(pthread_equal(pthread_self(), *(pthread_t *)context));
    return mode == CANCEL_ENTRY || (mode == CANCEL_FINAL && root_closed);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    char path[PATH_MAX], child[PATH_MAX];
    assert(snprintf(path, sizeof(path), "%s/scan-fixture", argv[1]) < (int)sizeof(path));
    assert(snprintf(child, sizeof(child), "%s/child", path) < (int)sizeof(child));
    assert(mkdir(path, 0700) == 0 && mkdir(child, 0700) == 0);
    pthread_t caller = pthread_self();
    for (int bulk = 0; bulk <= 1; bulk++) {
        for (int fault = CANCEL_ENTRY; fault <= CLOSE_SKIPPED; fault++) {
            if (bulk && fault == CLOSE_DIRECTORY) continue;
            mode = fault; root_fd = skipped_fd = -1; opens = root_closed = injected = 0;
            int before = descriptors();
            char error[PATH_MAX] = {0};
            struct stallion_scan_stats stats;
            int result = stallion_scan(path, bulk, &stats, cancelled, &caller, error, sizeof(error));
            int saved = errno;
            assert(result == -1);
            assert(saved == (fault <= CANCEL_FINAL ? EINTR : EIO));
            assert(error[0] && descriptors() == before);
            if (fault == CANCEL_ENTRY) assert(!opens && !root_closed);
            if (fault == CANCEL_FINAL) assert(opens && root_closed);
            if (fault >= CLOSE_DIRECTORY) assert(injected);
            if (fault == CLOSE_SKIPPED) assert(stats.skipped_mounts == 1);
        }
    }
    assert(rmdir(child) == 0 && rmdir(path) == 0);
    puts("scan cancellation, close errors and descriptor cleanup passed");
    return 0;
}
#endif
