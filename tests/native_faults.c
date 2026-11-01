/* Test-only syscall wrappers. Compile only _tree.c with the symbol substitutions below. */
#include "_tree.h"
#include <assert.h>
#include <copyfile.h>
#include <sys/xattr.h>
#include <sys/acl.h>
#include <membership.h>
#include <uuid/uuid.h>
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
static atomic_int copy_calls;
static atomic_int preflight_probes, preflight_rewinds;
static int preflight_saved_errno;
static int acl_fault_call;
static atomic_int acl_size_calls, acl_export_calls;
static atomic_int entered, release_worker, cancelled, active, swaps, starts, created, joined;
enum xattr_fault { XATTR_EQUAL, XATTR_CORRUPT, XATTR_READ_ERROR, XATTR_READ_NO_ERRNO,
                   XATTR_SHORT_READ, XATTR_ALLOC_ERROR, XATTR_QUERY_ERROR, XATTR_QUERY_SHRINK };
static const struct xattr_case {
    const char *name;
    size_t size;
    enum xattr_fault action;
    int read_call, error;
} xattr_cases[] = {
    {"bytes-8", 8, XATTR_CORRUPT, 0, ENOTSUP},
    {"bytes-256", 256, XATTR_CORRUPT, 0, ENOTSUP},
    {"bytes-257", 257, XATTR_CORRUPT, 0, ENOTSUP},
    {"bytes-4097", 4097, XATTR_CORRUPT, 0, ENOTSUP},
    {"empty", 0, XATTR_EQUAL, 0, 0},
    {"equal-256", 256, XATTR_EQUAL, 0, 0},
    {"equal-257", 257, XATTR_EQUAL, 0, 0},
    {"source-error", 257, XATTR_READ_ERROR, 2, EACCES},
    {"destination-error", 257, XATTR_READ_ERROR, 3, EDQUOT},
    {"read-no-errno", 8, XATTR_READ_NO_ERRNO, 1, EIO},
    {"source-short", 257, XATTR_SHORT_READ, 2, ESTALE},
    {"destination-short", 257, XATTR_SHORT_READ, 3, ESTALE},
    {"destination-growth", 257, XATTR_READ_ERROR, 3, ERANGE},
    {"allocation-error", 257, XATTR_ALLOC_ERROR, 0, ENOMEM},
    {"query-error", 257, XATTR_QUERY_ERROR, 0, EACCES},
    {"query-shrink", 257, XATTR_QUERY_SHRINK, 0, ESTALE},
};
static const struct xattr_case *xattr_case;
static int xattr_ready, xattr_reads, xattr_queries, xattr_allocations, xattr_frees, xattr_allocation_errors;
static int xattr_starts, xattr_finishes, xattr_mutations;
static void *xattr_allocation;
static copyfile_callback_t xattr_callback;
static const unsigned char xattr_pattern[] = {0x00, 0xff, 0x80, 0x41};
void *stallion_test_malloc(size_t size) {
    int value_buffer = xattr_case && xattr_ready && xattr_case->size > 256 && size == xattr_case->size * 2;
    if (value_buffer && xattr_case->action == XATTR_ALLOC_ERROR) {
        xattr_allocation_errors++; errno = ENOMEM; return NULL;
    }
    void *result = malloc(size);
    if (value_buffer && result) {
        assert(!xattr_allocation); xattr_allocation = result; xattr_allocations++;
    }
    return result;
}
void stallion_test_free(void *pointer) {
    if (pointer && pointer == xattr_allocation) {
        xattr_allocation = NULL; xattr_frees++;
    }
    free(pointer);
}
ssize_t stallion_test_fgetxattr(int fd, const char *name, void *value, size_t size,
                               uint32_t position, int options) {
    if (xattr_case && xattr_ready && !strcmp(name, "user.stallion-test") && !value) {
        xattr_queries++;
        if (xattr_case->action == XATTR_QUERY_ERROR) { errno = xattr_case->error; return -1; }
        if (xattr_case->action == XATTR_QUERY_SHRINK) return 256;
    }
    if (xattr_case && xattr_ready && value && !strcmp(name, "user.stallion-test")) {
        xattr_reads++;
        if (xattr_reads == xattr_case->read_call) {
            if (xattr_case->action == XATTR_READ_ERROR) { errno = xattr_case->error; return -1; }
            if (xattr_case->action == XATTR_READ_NO_ERRNO) { errno = 0; return -1; }
            if (xattr_case->action == XATTR_SHORT_READ) {
                ssize_t result = fgetxattr(fd, name, value, size, position, options);
                assert(result > 0); errno = EBUSY; return result - 1;
            }
        }
    }
    return fgetxattr(fd, name, value, size, position, options);
}
static int xattr_status(int what, int stage, copyfile_state_t state,
                         const char *input, const char *output, void *context) {
    if (what == COPYFILE_COPY_XATTR) {
        if (stage == COPYFILE_START) xattr_starts++;
        if (stage == COPYFILE_FINISH) xattr_finishes++;
    }
    return xattr_callback(what, stage, state, input, output, context);
}
ssize_t stallion_test_acl_size(acl_t acl) {
    if (atomic_fetch_add(&acl_size_calls, 1) + 1 == acl_fault_call) {
        if (!strcmp(fault, "acl-size-error")) { errno = EACCES; return -1; }
        if (!strcmp(fault, "acl-size-no-errno")) return -1;
        if (!strcmp(fault, "acl-size-zero")) return 0;
    }
    return acl_size(acl);
}
ssize_t stallion_test_acl_copy_ext(void *buffer, acl_t acl, ssize_t size) {
    if (atomic_fetch_add(&acl_export_calls, 1) + 1 == acl_fault_call) {
        if (!strcmp(fault, "acl-export-error")) { errno = EACCES; return -1; }
        if (!strcmp(fault, "acl-export-no-errno")) return -1;
        if (!strcmp(fault, "acl-export-zero")) return 0;
        if (!strcmp(fault, "acl-export-short")) return size - 1;
    }
    return acl_copy_ext(buffer, acl, size);
}
static acl_t leaf_acl(const char *change) {
    acl_t acl = acl_init(2); assert(acl);
    uuid_t owner;
    assert(mbr_uid_to_uuid(geteuid(), owner) == 0);
    for (int i = 0; i < 2; i++) {
        acl_entry_t entry;
        assert(acl_create_entry(&acl, &entry) == 0);
        assert(acl_set_tag_type(entry, i == 0 && !strcmp(change, "acl-tag") ? ACL_EXTENDED_DENY : ACL_EXTENDED_ALLOW) == 0);
        uuid_t qualifier; uuid_copy(qualifier, owner);
        if (i == 0 && !strcmp(change, "acl-uuid")) qualifier[0] ^= 1;
        assert(acl_set_qualifier(entry, qualifier) == 0);
        int index = !strcmp(change, "acl-order") ? 1 - i : i;
        acl_permset_mask_t rights = index ? ACL_READ_ATTRIBUTES : ACL_WRITE_DATA;
        if (i == 0 && !strcmp(change, "acl-permission")) rights = ACL_APPEND_DATA;
        assert(acl_set_permset_mask_np(entry, rights) == 0);
        if (i == 0 && !strcmp(change, "acl-entry-flags")) {
            acl_flagset_t flags;
            assert(acl_get_flagset_np(entry, &flags) == 0);
            assert(acl_add_flag_np(flags, ACL_ENTRY_INHERITED) == 0);
        }
    }
    if (!strcmp(change, "acl-flags")) {
        acl_flagset_t flags;
        assert(acl_get_flagset_np(acl, &flags) == 0);
        assert(acl_add_flag_np(flags, ACL_FLAG_NO_INHERIT) == 0);
    }
    return acl;
}
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
    if (!result && !strcmp(fault, "preflight-sparse-unscreened") && S_ISREG(st->st_mode)) {
        struct stat actual;
        assert(stat(source, &actual) == 0);
        if (st->st_dev == actual.st_dev && st->st_ino == actual.st_ino)
            st->st_blocks = st->st_size / 512 + (st->st_size % 512 != 0);
    }
    return result;
}
int stallion_test_fclonefileat(int source, int destination, const char *name, uint32_t flags) {
    if (copy_error()) return -1;
    pause_worker();
    return fclonefileat(source, destination, name, flags);
}
int stallion_test_fcopyfile(int from, int to, copyfile_state_t state, copyfile_flags_t flags) {
    atomic_fetch_add(&copy_calls, 1);
    if (!strncmp(fault, "preflight-", 10)) {
        assert(!(flags & (COPYFILE_CLONE | COPYFILE_CLONE_FORCE)));
        if (strcmp(fault, "preflight-symlink")) {
            assert(lseek(from, 0, SEEK_CUR) == 0);
            assert((flags & COPYFILE_ALL) == COPYFILE_ALL);
            int dense = !strcmp(fault, "preflight-dense") || !strcmp(fault, "preflight-source-mutation");
            assert(!!(flags & COPYFILE_DATA_SPARSE) == !dense);
        } else assert(flags == COPYFILE_METADATA);
        if (!strcmp(fault, "preflight-probe-error")) assert(errno == preflight_saved_errno);
    }
    if (copy_error()) return -1;
    pause_worker();
    if (!strcmp(fault, "callback-error")) {
        copyfile_callback_t callback = NULL;
        void *context = NULL;
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CB, &callback) == 0);
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CTX, &context) == 0);
        errno = ENOSPC;
        assert(callback(COPYFILE_COPY_XATTR, COPYFILE_ERR, state, NULL, NULL, context) == COPYFILE_QUIT);
        errno = ECANCELED;
        return -1;
    }
    if (!strcmp(fault, "silent-acl")) flags &= ~COPYFILE_ACL;
    if (!strcmp(fault, "silent-xattr")) flags &= ~COPYFILE_XATTR;
    if (!strcmp(fault, "dense-copy")) flags &= ~COPYFILE_DATA_SPARSE;
    if (xattr_case) {
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CB, &xattr_callback) == 0 && xattr_callback);
        assert(copyfile_state_set(state, COPYFILE_STATE_STATUS_CB, (void *)xattr_status) == 0);
    }
    int result = fcopyfile(from, to, state, flags);
    if (xattr_case) {
        assert(copyfile_state_set(state, COPYFILE_STATE_STATUS_CB, (void *)xattr_callback) == 0);
        if (!result) {
            if (xattr_case->action == XATTR_CORRUPT) {
                unsigned char value[4097];
                assert(xattr_case->size > 0 && xattr_case->size <= sizeof(value));
                assert(fgetxattr(to, "user.stallion-test", value, xattr_case->size, 0, 0) == (ssize_t)xattr_case->size);
                value[xattr_case->size - 1] ^= 0x5a;
                assert(fsetxattr(to, "user.stallion-test", value, xattr_case->size, 0, 0) == 0);
                xattr_mutations++;
            }
            xattr_ready = 1;
        }
    }
    if (!result && (!strcmp(fault, "acl-permission") || !strcmp(fault, "acl-order") ||
                    !strcmp(fault, "acl-tag") || !strcmp(fault, "acl-uuid") ||
                    !strcmp(fault, "acl-entry-flags") || !strcmp(fault, "acl-flags"))) {
        acl_t original = acl_get_fd_np(from, ACL_TYPE_EXTENDED), changed = leaf_acl(fault);
        assert(original && acl_size(original) == acl_size(changed));
        assert(acl_set_fd_np(to, changed, ACL_TYPE_EXTENDED) == 0);
        acl_free(original); acl_free(changed);
    }
    if (!result && !strcmp(fault, "dense-copy")) {
        struct stat copied;
        assert(fstat(to, &copied) == 0);
        char zeros[4096] = {0};
        for (off_t position = 4096; position < 1048576; position += sizeof(zeros))
            assert(pwrite(to, zeros, sizeof(zeros), position) == sizeof(zeros));
        struct timespec times[2] = {copied.st_atimespec, copied.st_mtimespec};
        assert(futimens(to, times) == 0);
        assert(lseek(from, 0, SEEK_HOLE) < 1048576);
        assert(lseek(to, 0, SEEK_HOLE) >= 1048576);
    }
    if (!result && !strcmp(fault, "silent-stat")) assert(fchmod(to, 0640) == 0);
    if (!result && !strcmp(fault, "source-change")) {
        struct timespec times[2] = {{100, 0}, {100, 0}};
        assert(futimens(from, times) == 0);
    }
    if (!result && !strcmp(fault, "callback-incomplete")) {
        copyfile_callback_t callback = NULL;
        void *context = NULL;
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CB, &callback) == 0);
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CTX, &context) == 0);
        assert(callback(COPYFILE_COPY_XATTR, COPYFILE_START, state, NULL, NULL, context) == COPYFILE_CONTINUE);
    }
    return result;
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
    int result = openat(fd, name, flags, mode);
    if (result >= 0 && !strcmp(fault, "source-alias") && !strcmp(name, "output")) {
        assert(close(result) == 0);
        assert(unlinkat(fd, name, 0) == 0);
        assert(linkat(AT_FDCWD, source, fd, name, 0) == 0);
        result = openat(fd, name, flags & ~(O_CREAT | O_EXCL), mode);
    }
    return result;
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
static void check(const char *base, int operation, const char *kind) {
    int deleting = operation == 1, copying = operation == 2;
    char root[PATH_MAX], destination[PATH_MAX], child[PATH_MAX], error_path[PATH_MAX];
    snprintf(root, sizeof(root), "%s/%s-%s", base, deleting ? "delete" : copying ? "copy" : "clone", kind);
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
    if (!deleting && (!strcmp(kind, "cancel") || !strcmp(kind, "enospc") || !strcmp(kind, "unsupported"))) {
        char first[PATH_MAX], alias[PATH_MAX];
        snprintf(first, sizeof(first), "%s/swap-here/sentinel", source);
        snprintf(alias, sizeof(alias), "%s/shared-sentinel", source);
        assert(linkat(AT_FDCWD, first, AT_FDCWD, alias, 0) == 0);
    }
    fault = kind;
    caller = pthread_self();
    atomic_store(&entered, 0); atomic_store(&release_worker, 0); atomic_store(&cancelled, 0);
    atomic_store(&active, 0); atomic_store(&swaps, 0); atomic_store(&starts, 0);
    atomic_store(&created, 0); atomic_store(&joined, 0);
    pthread_t helper;
    if (!strcmp(kind, "cancel")) assert(pthread_create(&helper, NULL, cancel_worker, NULL) == 0);
    int before = descriptors();
    int result = deleting ? stallion_delete(source, 1, 0, 4, cancel, NULL, error_path, sizeof(error_path)) :
        (copying ? stallion_copy : stallion_clone)(source, destination, 4, cancel, NULL, error_path, sizeof(error_path));
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
            printf("PASS %s destination replacement: outside directory unchanged\n", copying ? "copy" : "clone");
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
    printf("PASS %s %s: failure preserved, workers joined, descriptors closed\n", deleting ? "delete" : copying ? "copy" : "clone", kind);
}
static int root_cancel(void *unused) {
    (void)unused;
    assert(pthread_equal(pthread_self(), caller));
    return atomic_fetch_add(&starts, 1) >= 4;
}
static void copy_leaf_fault(const char *base, const char *kind, int symlink_source) {
    char root[PATH_MAX], input[PATH_MAX], output[PATH_MAX], path[PATH_MAX];
    snprintf(root, sizeof(root), "%s/copy-leaf-%s-%d-%d", base, kind, symlink_source, acl_fault_call);
    assert(mkdir(root, 0700) == 0);
    snprintf(input, sizeof(input), "%s/input", root);
    snprintf(output, sizeof(output), "%s/output", root);
    if (symlink_source) assert(symlink("missing-target", input) == 0);
    else file(root, "input");
    int fd = open(input, O_RDONLY | O_CLOEXEC | (symlink_source ? O_SYMLINK : O_NOFOLLOW));
    assert(fd >= 0);
    assert(fsetxattr(fd, "user.stallion-test", "metadata", 8, 0, 0) == 0);
    if (!strcmp(kind, "silent-acl") || (!strncmp(kind, "acl-", 4) && strcmp(kind, "acl-empty"))) {
        acl_t acl = leaf_acl("");
        assert(acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0);
        acl_free(acl);
    }
    struct stat original;
    assert(fstat(fd, &original) == 0);
    assert(close(fd) == 0);
    if (!strcmp(kind, "dense-copy")) {
        fd = open(input, O_WRONLY);
        assert(fd >= 0 && lseek(fd, 1048576, SEEK_SET) == 1048576 && write(fd, "end", 3) == 3);
        assert(fsync(fd) == 0);
        struct fpunchhole hole = {.fp_offset = 4096, .fp_length = 1048576 - 4096};
        assert(fcntl(fd, F_PUNCHHOLE, &hole) == 0);
        assert(fsync(fd) == 0);
        assert(close(fd) == 0);
    }
    assert(stat(root, &destination_parent) == 0);
    assert(snprintf(source, sizeof(source), "%s", input) < (int)sizeof(source));
    fault = kind;
    caller = pthread_self();
    atomic_store(&copy_calls, 0);
    atomic_store(&starts, 0);
    atomic_store(&cancelled, 0);
    acl_size_calls = acl_export_calls = 0;
    int before = descriptors();
    int result = stallion_copy(input, output, 4, !strcmp(kind, "root-cancel") ? root_cancel : cancel,
                              NULL, path, sizeof(path));
    int error = errno;
    int success = !strcmp(kind, "acl-empty") || !strcmp(kind, "acl-equal");
    assert(result == (success ? 0 : -1));
    assert(descriptors() == before);
    if (!strncmp(kind, "acl-size-", 9)) {
        assert(acl_size_calls == acl_fault_call && acl_export_calls == 0);
    } else if (!strncmp(kind, "acl-", 4)) {
        assert(acl_size_calls == 2);
        assert(acl_export_calls == (!strncmp(kind, "acl-export-", 11) ? acl_fault_call : 2));
    }
    assert(error == (success ? 0 :
                     (!strcmp(kind, "acl-size-error") || !strcmp(kind, "acl-export-error")) ? EACCES :
                     (!strncmp(kind, "acl-size-", 9) || !strncmp(kind, "acl-export-", 11)) ? EIO :
                     !strcmp(kind, "callback-error") ? ENOSPC :
                     (!strcmp(kind, "source-change") || !strcmp(kind, "source-alias")) ? ESTALE :
                     !strcmp(kind, "parent-mode") ? EPERM :
                     !strcmp(kind, "callback-incomplete") ? EIO :
                     !strcmp(kind, "root-cancel") ? EINTR : ENOTSUP));
    struct stat st;
    if (!strcmp(kind, "parent-mode")) assert(lstat(output, &st) == -1 && errno == ENOENT);
    else assert(lstat(output, &st) == 0);
    if (!strcmp(kind, "parent-mode") || !strcmp(kind, "source-alias")) {
        assert(copy_calls == 0);
        assert(lstat(input, &st) == 0 && st.st_mode == original.st_mode && st.st_flags == original.st_flags &&
               st.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec && st.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec);
    }
    printf("PASS copy leaf %s (%s, ACL call %d): result checked, output contract respected, descriptors closed\n",
           kind, symlink_source ? "symlink" : "regular", acl_fault_call);
}
off_t stallion_test_lseek(int fd, off_t offset, int whence) {
    if (!strncmp(fault, "preflight-", 10) && !atomic_load(&copy_calls)) {
        if (whence == SEEK_HOLE && offset == 0) {
            atomic_fetch_add(&preflight_probes, 1);
            preflight_saved_errno = errno;
            assert(lseek(fd, 0, SEEK_CUR) == 0);
            if (!strcmp(fault, "preflight-probe-error")) { errno = EDQUOT; return -1; }
            if (!strcmp(fault, "preflight-early-hole")) return lseek(fd, 0, SEEK_SET);
        }
        if (whence == SEEK_SET && offset == 0 && atomic_load(&preflight_probes)) {
            atomic_fetch_add(&preflight_rewinds, 1);
            if (!strcmp(fault, "preflight-rewind-error")) { errno = EACCES; return -1; }
            if (!strcmp(fault, "preflight-rewind-no-errno")) { errno = 0; return -1; }
            if (!strcmp(fault, "preflight-rewind-nonzero")) { assert(lseek(fd, 1, SEEK_SET) == 1); errno = 0; return 1; }
            off_t result = lseek(fd, offset, whence);
            if (!strcmp(fault, "preflight-source-mutation")) {
                struct timespec times[2] = {{100, 0}, {100, 0}};
                assert(futimens(fd, times) == 0);
            }
            return result;
        }
    }
    return lseek(fd, offset, whence);
}
static void dense_preflight_case(const char *base, const char *kind) {
    char root[PATH_MAX], input[PATH_MAX], output[PATH_MAX], path[PATH_MAX], name[80];
    assert(snprintf(name, sizeof(name), "preflight-%s", kind) < (int)sizeof(name));
    assert(snprintf(root, sizeof(root), "%s/%s", base, name) < (int)sizeof(root));
    assert(mkdir(root, 0700) == 0);
    snprintf(input, sizeof(input), "%s/input", root);
    snprintf(output, sizeof(output), "%s/output", root);
    if (!strcmp(kind, "symlink")) assert(symlink("missing-target", input) == 0);
    else file(root, "input");
    int fd = open(input, O_RDONLY | O_CLOEXEC | (!strcmp(kind, "symlink") ? O_SYMLINK : O_NOFOLLOW));
    assert(fd >= 0);
    assert(fsetxattr(fd, "user.stallion-test", "metadata", 8, 0, 0) == 0);
    assert(close(fd) == 0);
    if (!strcmp(kind, "empty")) assert(truncate(input, 0) == 0);
    if (!strncmp(kind, "sparse-", 7)) {
        fd = open(input, O_RDWR | O_CLOEXEC); assert(fd >= 0);
        assert(lseek(fd, 1048576, SEEK_SET) == 1048576 && write(fd, "end", 3) == 3);
        assert(fsync(fd) == 0);
        struct fpunchhole hole = {.fp_offset = 4096, .fp_length = 1048576 - 4096};
        assert(fcntl(fd, F_PUNCHHOLE, &hole) == 0 && fsync(fd) == 0);
        assert(lseek(fd, 0, SEEK_HOLE) < 1048576);
        struct stat info; assert(fstat(fd, &info) == 0);
        assert(info.st_blocks < info.st_size / 512);
        assert(close(fd) == 0);
    }
    assert(stat(root, &destination_parent) == 0);
    assert(snprintf(source, sizeof(source), "%s", input) < (int)sizeof(source));
    fault = name; caller = pthread_self();
    atomic_store(&copy_calls, 0); atomic_store(&preflight_probes, 0); atomic_store(&preflight_rewinds, 0);
    atomic_store(&starts, 0); atomic_store(&cancelled, 0);
    int before = descriptors();
    int result = stallion_copy(input, output, 4, cancel, NULL, path, sizeof(path));
    int error = errno;
    int rewind_failure = !strncmp(kind, "rewind-", 7), mutation = !strcmp(kind, "source-mutation");
    assert(result == (rewind_failure || mutation ? -1 : 0));
    assert(descriptors() == before);
    assert(copy_calls == (rewind_failure ? 0 : 1));
    int probe = strcmp(kind, "empty") && strcmp(kind, "symlink") && strcmp(kind, "sparse-screened");
    assert(preflight_probes == probe);
    assert(preflight_rewinds == (probe && strcmp(kind, "probe-error")));
    if (rewind_failure) assert(error == (!strcmp(kind, "rewind-error") ? EACCES : EIO));
    else if (mutation) assert(error == ENOTSUP || error == ESTALE);
    else assert(error == 0);
    struct stat info; assert(lstat(output, &info) == 0);
    if (!rewind_failure && !mutation && strcmp(kind, "symlink") && strcmp(kind, "empty")) {
        fd = open(output, O_RDONLY | O_CLOEXEC); assert(fd >= 0);
        char data[8]; assert(read(fd, data, 8) == 8 && !memcmp(data, "sentinel", 8));
        assert(close(fd) == 0);
    }
    printf("PASS dense preflight %s: flags, offsets, error/guards and descriptors checked\n", kind);
}
static void xattr_value_cases(const char *base, int characterize) {
    for (size_t index = 0; index < sizeof(xattr_cases) / sizeof(*xattr_cases); index++) {
        xattr_case = &xattr_cases[index];
        if (characterize && xattr_case->action != XATTR_CORRUPT) continue;
        char root[PATH_MAX], input[PATH_MAX], output[PATH_MAX], error_path[PATH_MAX];
        assert(snprintf(root, sizeof(root), "%s/xattr-%s", base, xattr_case->name) < (int)sizeof(root));
        assert(mkdir(root, 0700) == 0); file(root, "input");
        snprintf(input, sizeof(input), "%s/input", root);
        snprintf(output, sizeof(output), "%s/output", root);
        unsigned char expected[4097], source_value[4097], destination_value[4097];
        assert(xattr_case->size <= sizeof(expected));
        for (size_t i = 0; i < xattr_case->size; i++) expected[i] = xattr_pattern[i % sizeof(xattr_pattern)];
        int input_fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(input_fd >= 0);
        assert(fsetxattr(input_fd, "user.stallion-test", expected, xattr_case->size, 0, 0) == 0);
        struct stat original, after, copied;
        assert(fstat(input_fd, &original) == 0 && stat(root, &destination_parent) == 0);
        fault = "xattr-values"; caller = pthread_self();
        atomic_store(&copy_calls, 0); atomic_store(&starts, 0); atomic_store(&cancelled, 0);
        xattr_ready = xattr_reads = xattr_queries = xattr_allocations = xattr_frees = xattr_allocation_errors = 0;
        xattr_starts = xattr_finishes = xattr_mutations = 0; xattr_allocation = NULL;
        int before = descriptors();
        int result = stallion_copy(input, output, 4, cancel, NULL, error_path, sizeof(error_path));
        int error = errno;
        assert(descriptors() == before && copy_calls == 1 && xattr_ready);
        assert(xattr_starts > 0 && xattr_starts == xattr_finishes);
        int output_fd = open(output, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(output_fd >= 0);
        assert(fstat(input_fd, &after) == 0 && fstat(output_fd, &copied) == 0);
        assert(original.st_dev == after.st_dev && original.st_ino == after.st_ino && original.st_mode == after.st_mode &&
               original.st_uid == after.st_uid && original.st_gid == after.st_gid && original.st_nlink == after.st_nlink &&
               original.st_size == after.st_size && original.st_flags == after.st_flags && original.st_gen == after.st_gen &&
               original.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec && original.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
               original.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec && original.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec &&
               original.st_birthtimespec.tv_sec == after.st_birthtimespec.tv_sec && original.st_birthtimespec.tv_nsec == after.st_birthtimespec.tv_nsec);
        assert(original.st_dev != copied.st_dev || original.st_ino != copied.st_ino);
        assert(fgetxattr(input_fd, "user.stallion-test", NULL, 0, 0, 0) == (ssize_t)xattr_case->size);
        assert(fgetxattr(output_fd, "user.stallion-test", NULL, 0, 0, 0) == (ssize_t)xattr_case->size);
        assert(fgetxattr(input_fd, "user.stallion-test", source_value, xattr_case->size, 0, 0) == (ssize_t)xattr_case->size);
        assert(fgetxattr(output_fd, "user.stallion-test", destination_value, xattr_case->size, 0, 0) == (ssize_t)xattr_case->size);
        for (size_t i = 0; i < xattr_case->size; i++) {
            assert(source_value[i] == expected[i]);
            unsigned char wanted = expected[i];
            if (xattr_case->action == XATTR_CORRUPT && i == xattr_case->size - 1) wanted ^= 0x5a;
            assert(destination_value[i] == wanted);
        }
        char data[8];
        assert(pread(input_fd, data, sizeof(data), 0) == sizeof(data) && !memcmp(data, "sentinel", sizeof(data)));
        assert(pread(output_fd, data, sizeof(data), 0) == sizeof(data) && !memcmp(data, "sentinel", sizeof(data)));
        assert(close(input_fd) == 0 && close(output_fd) == 0);
        assert(!xattr_allocation && xattr_allocations == xattr_frees);
        int expected_error = characterize ? 0 : xattr_case->error;
        fprintf(stderr, "%s xattr %s: result=%d errno=%d mutation=%d callbacks=%d/%d reads=%d queries=%d allocations=%d frees=%d source_unchanged=1\n",
                characterize ? "CHARACTERIZE" : "VERIFY", xattr_case->name, result, error, xattr_mutations,
                xattr_starts, xattr_finishes, xattr_reads, xattr_queries, xattr_allocations, xattr_frees);
        assert(result == (expected_error ? -1 : 0) && error == expected_error);
        assert(xattr_mutations == (xattr_case->action == XATTR_CORRUPT));
        if (characterize) assert(xattr_reads == 0 && xattr_queries == 2 && xattr_allocations == 0);
        else {
            assert(xattr_queries == (xattr_case->size > 256));
            if (xattr_case->action == XATTR_ALLOC_ERROR) {
                assert(xattr_allocation_errors == 1 && xattr_reads == 1 && xattr_allocations == 0);
            } else if (xattr_case->action == XATTR_QUERY_ERROR || xattr_case->action == XATTR_QUERY_SHRINK) {
                assert(xattr_reads == 1 && xattr_allocations == 0);
            } else {
                int reads = xattr_case->read_call ? xattr_case->read_call : (xattr_case->size > 256 ? 3 : 2);
                assert(xattr_reads == reads);
                assert(xattr_allocations == (xattr_case->size > 256));
            }
        }
    }
    xattr_case = NULL;
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3);
    if (argc == 3) {
        if (__builtin_available(macOS 13.0, *)) {
            assert(!strcmp(argv[2], "--xattr-values") || !strcmp(argv[2], "--xattr-characterize"));
            xattr_value_cases(argv[1], !strcmp(argv[2], "--xattr-characterize"));
            return 0;
        }
        fprintf(stderr, "xattr copy faults require macOS 13 or later\n");
        return 77;
    }
    int operations = 2;
    if (__builtin_available(macOS 13.0, *)) operations = 3;
    for (int deleting = 0; deleting < operations; deleting++) {
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
    if (__builtin_available(macOS 13.0, *)) {
        check(argv[1], 2, "swap-file-directory"); check(argv[1], 2, "swap-file-fifo");
        check(argv[1], 2, "swap-destination");
        check(argv[1], 2, "enospc"); check(argv[1], 2, "unsupported");
        check(argv[1], 2, "parent-stat"); check(argv[1], 2, "parent-mode");
        const char *copy_faults[] = {"silent-stat", "silent-acl", "silent-xattr", "callback-error", "callback-incomplete",
                                   "source-change", "root-cancel", "parent-mode", "source-alias"};
        for (int symlink_source = 0; symlink_source < 2; symlink_source++)
            for (size_t i = 0; i < sizeof(copy_faults) / sizeof(*copy_faults); i++)
                copy_leaf_fault(argv[1], copy_faults[i], symlink_source);
        copy_leaf_fault(argv[1], "dense-copy", 0);
        const char *acl_cases[] = {"acl-empty", "acl-equal", "acl-permission", "acl-order", "acl-tag",
                                   "acl-uuid", "acl-entry-flags", "acl-flags"};
        const char *acl_errors[] = {"acl-size-error", "acl-size-no-errno", "acl-size-zero",
                                    "acl-export-error", "acl-export-no-errno", "acl-export-zero", "acl-export-short"};
        for (int symlink_source = 0; symlink_source < 2; symlink_source++) {
            for (size_t i = 0; i < sizeof(acl_cases) / sizeof(*acl_cases); i++)
                copy_leaf_fault(argv[1], acl_cases[i], symlink_source);
            for (acl_fault_call = 1; acl_fault_call <= 2; acl_fault_call++)
                for (size_t i = 0; i < sizeof(acl_errors) / sizeof(*acl_errors); i++)
                    copy_leaf_fault(argv[1], acl_errors[i], symlink_source);
            acl_fault_call = 0;
        }
        const char *preflight_cases[] = {"dense", "probe-error", "rewind-error", "rewind-no-errno", "rewind-nonzero",
                                         "empty", "symlink", "early-hole", "sparse-unscreened", "sparse-screened", "source-mutation"};
        for (size_t i = 0; i < sizeof(preflight_cases) / sizeof(*preflight_cases); i++)
            dense_preflight_case(argv[1], preflight_cases[i]);
        xattr_value_cases(argv[1], 0);
    }
    return 0;
}
