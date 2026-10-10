/* Test-only syscall wrappers. Compile only _tree.c with the symbol substitutions below. */
#include "_tree.h"
#include <assert.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *fault;
static pthread_t caller;
static char outside[PATH_MAX], source[PATH_MAX];
static struct stat destination_parent;
static atomic_int entered, release_worker, cancelled, active, swaps, starts, created, joined;
static int cancel(void *unused) { (void)unused; assert(pthread_equal(pthread_self(), caller)); return atomic_load(&cancelled); }
static void pause_worker(void) {
    if (strcmp(fault, "cancel")) return;
    if (pthread_equal(pthread_self(), caller)) {
        while (atomic_load(&entered) != 1) usleep(1000);
        return;
    }
    int expected = 0;
    if (!atomic_compare_exchange_strong(&entered, &expected, -1)) return;
    atomic_fetch_add(&active, 1);
    atomic_store(&entered, 1);
    while (!atomic_load(&release_worker)) usleep(1000);
    atomic_fetch_sub(&active, 1);
}
static int copy_error(void) {
    if (!strcmp(fault, "enospc")) { errno = ENOSPC; return -1; }
    if (!strcmp(fault, "unsupported")) { errno = ENOTSUP; return -1; }
    return 0;
}
int stallion_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(stallion_test_fstat);
int stallion_test_fstat(int fd, struct stat *st) {
    int result = fstat(fd, st);
    if (!result && !strncmp(fault, "parent-", 7) &&
        st->st_dev == destination_parent.st_dev && st->st_ino == destination_parent.st_ino) {
        if (!strcmp(fault, "parent-stat")) { errno = EIO; return -1; }
        st->st_mode = (st->st_mode & ~S_ISVTX) | 0022;
        if (!strcmp(fault, "parent-device")) st->st_dev ^= 1;
    }
    return result;
}
int stallion_test_fclonefileat(int source, int destination, const char *name, uint32_t flags) {
    if (copy_error()) return -1;
    pause_worker();
    return fclonefileat(source, destination, name, flags);
}
int stallion_test_unlinkat(int fd, const char *name, int flags) {
    if (!flags) pause_worker();
    int result = unlinkat(fd, name, flags);
    if (!result && !flags && !strcmp(fault, "swap-postorder") && !atomic_exchange(&swaps, 1)) {
        char held[PATH_MAX];
        assert(snprintf(held, sizeof(held), "%s-held", source) < (int)sizeof(held));
        assert(rename(source, held) == 0);
        assert(rename(outside, source) == 0);
    }
    return result;
}
int stallion_test_openat(int fd, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    int directory_swap = (flags & O_DIRECTORY) && !strcmp(name, "swap-here") &&
        (!strcmp(fault, "swap-link") || !strcmp(fault, "swap-directory"));
    int leaf_swap = !strcmp(name, "leaf-swap") &&
        (!strcmp(fault, "swap-file-directory") || !strcmp(fault, "swap-file-fifo"));
    int destination_swap = (flags & O_DIRECTORY) && !strcmp(name, "destination") && !strcmp(fault, "swap-destination");
    if ((directory_swap || leaf_swap || destination_swap) && !atomic_exchange(&swaps, 1)) {
        assert(renameat(fd, name, fd, "original-held") == 0);
        if (!strcmp(fault, "swap-link")) assert(symlinkat(outside, fd, name) == 0);
        else if (!strcmp(fault, "swap-file-fifo")) assert(mkfifoat(fd, name, 0600) == 0);
        else assert(renameat(AT_FDCWD, outside, fd, name) == 0);
    }
    return openat(fd, name, flags, mode);
}
int stallion_test_pthread_create(pthread_t *thread, const pthread_attr_t *attrs, void *(*entry)(void *), void *arg) {
    int count = atomic_fetch_add(&starts, 1);
    if (!strcmp(fault, "thread-first") || (!strcmp(fault, "thread-third") && count == 2)) return EAGAIN;
    int result = pthread_create(thread, attrs, entry, arg);
    if (!result) atomic_fetch_add(&created, 1);
    return result;
}
int stallion_test_pthread_join(pthread_t thread, void **result) {
    int error = pthread_join(thread, result);
    if (!error) atomic_fetch_add(&joined, 1);
    return error;
}
static int descriptors(void) {
    int total = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) >= 0) total++;
    return total;
}
static void file(const char *parent, const char *name) {
    char path[PATH_MAX]; snprintf(path, sizeof(path), "%s/%s", parent, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600); assert(fd >= 0);
    assert(write(fd, "sentinel", 8) == 8); assert(close(fd) == 0);
}
static void sentinel(const char *parent) {
    char path[PATH_MAX], value[9] = {0}; snprintf(path, sizeof(path), "%s/sentinel", parent);
    int fd = open(path, O_RDONLY | O_NOFOLLOW); assert(fd >= 0);
    assert(read(fd, value, 8) == 8 && !strcmp(value, "sentinel")); assert(close(fd) == 0);
}
static void *cancel_worker(void *unused) {
    (void)unused;
    while (atomic_load(&entered) != 1) usleep(1000);
    atomic_store(&cancelled, 1);
    /* The syscall remains blocked after cancellation; returning early is observable. */
    usleep(30000);
    atomic_store(&release_worker, 1);
    return NULL;
}
static void check(const char *base, int deleting, const char *kind) {
    char root[PATH_MAX], destination[PATH_MAX], child[PATH_MAX], error_path[PATH_MAX];
    snprintf(root, sizeof(root), "%s/%s-%s", base, deleting ? "delete" : "clone", kind);
    assert(mkdir(root, 0700) == 0);
    assert(stat(root, &destination_parent) == 0);
    snprintf(source, sizeof(source), "%s/source", root); assert(mkdir(source, 0700) == 0);
    snprintf(destination, sizeof(destination), "%s/destination", root);
    snprintf(outside, sizeof(outside), "%s/outside", root); assert(mkdir(outside, 0700) == 0); file(outside, "sentinel");
    snprintf(child, sizeof(child), "%s/swap-here", source); assert(mkdir(child, 0700) == 0); file(child, "sentinel");
    for (int i = 0; i < 6; i++) {
        snprintf(child, sizeof(child), "%s/child-%d", source, i); assert(mkdir(child, 0700) == 0); file(child, "sentinel");
    }
    if (!strcmp(kind, "swap-file-directory") || !strcmp(kind, "swap-file-fifo")) file(source, "leaf-swap");
    fault = kind;
    caller = pthread_self();
    atomic_store(&entered, 0); atomic_store(&release_worker, 0); atomic_store(&cancelled, 0);
    atomic_store(&active, 0); atomic_store(&swaps, 0); atomic_store(&starts, 0);
    atomic_store(&created, 0); atomic_store(&joined, 0);
    pthread_t helper;
    if (!strcmp(kind, "cancel")) assert(pthread_create(&helper, NULL, cancel_worker, NULL) == 0);
    int before = descriptors();
    int result = deleting ? stallion_delete(source, 1, 0, 4, cancel, NULL, error_path, sizeof(error_path)) :
        stallion_clone(source, destination, 4, cancel, NULL, error_path, sizeof(error_path));
    int error = errno;
    assert(result == -1);
    assert(atomic_load(&active) == 0);
    assert(atomic_load(&created) == atomic_load(&joined));
    assert(descriptors() == before);
    if (!strncmp(kind, "parent-", 7)) {
        assert(error == (!strcmp(kind, "parent-stat") ? EIO : !strcmp(kind, "parent-device") ? EXDEV : EPERM));
        struct stat st;
        assert(lstat(destination, &st) == -1 && errno == ENOENT);
        assert(atomic_load(&starts) == 0);
        sentinel(child);
    }
    else if (!strcmp(kind, "cancel")) { assert(error == EINTR); assert(pthread_join(helper, NULL) == 0); }
    else if (!strcmp(kind, "enospc")) assert(error == ENOSPC);
    else if (!strcmp(kind, "unsupported")) assert(error == ENOTSUP);
    else if (!strncmp(kind, "thread-", 7)) assert(error == EAGAIN);
    else if (!strcmp(kind, "swap-postorder")) {
        assert(deleting && error == ESTALE && atomic_load(&swaps) == 1);
        sentinel(source);
        printf("PASS delete postorder root replacement: outside directory unchanged\n");
        return;
    }
    else {
        assert(atomic_load(&swaps) == 1);
        if (!strcmp(kind, "swap-destination")) {
            assert(error == ESTALE);
            sentinel(destination);
            DIR *dir = opendir(destination); assert(dir);
            struct dirent *entry; int count = 0;
            while ((entry = readdir(dir))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) count++;
            assert(count == 1); assert(closedir(dir) == 0);
            printf("PASS clone destination replacement: outside directory unchanged\n");
            return;
        }
        if (!strcmp(kind, "swap-directory") || !strcmp(kind, "swap-file-directory")) {
            assert(error == ESTALE || error == ENOTSUP || error == EISDIR);
            snprintf(outside, sizeof(outside), "%s/%s", source,
                     !strcmp(kind, "swap-directory") ? "swap-here" : "leaf-swap");
        } else if (!strcmp(kind, "swap-file-fifo")) assert(error == ESTALE || error == ENOTSUP);
        else assert(error == ELOOP || error == ENOTDIR);
        sentinel(outside);
        snprintf(child, sizeof(child), "%s/original-held", source);
        if (strcmp(kind, "swap-file-directory") && strcmp(kind, "swap-file-fifo")) sentinel(child);
        else { struct stat st; assert(lstat(child, &st) == 0 && S_ISREG(st.st_mode) && st.st_size == 8); }
    }
    printf("PASS %s %s: failure preserved, workers joined, descriptors closed\n", deleting ? "delete" : "clone", kind);
}
int main(int argc, char **argv) {
    assert(argc == 2);
    for (int deleting = 0; deleting < 2; deleting++) {
        check(argv[1], deleting, "swap-link"); check(argv[1], deleting, "swap-directory");
        check(argv[1], deleting, "thread-first"); check(argv[1], deleting, "thread-third");
        check(argv[1], deleting, "cancel");
    }
    check(argv[1], 0, "swap-file-directory");
    check(argv[1], 0, "swap-file-fifo");
    check(argv[1], 0, "swap-destination");
    check(argv[1], 0, "enospc"); check(argv[1], 0, "unsupported");
    check(argv[1], 0, "parent-stat");
    check(argv[1], 0, "parent-device");
    check(argv[1], 0, "parent-mode");
    check(argv[1], 1, "swap-postorder");
    return 0;
}
