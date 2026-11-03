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
#include <sys/param.h>
#include <unistd.h>

static const char *fault;
static pthread_t caller;
static char outside[PATH_MAX], source[PATH_MAX];
static struct stat destination_parent;
static atomic_int copy_calls;
static int auto_testing;
enum completion_fault { COMPLETION_PARTIAL_EIO, COMPLETION_PARTIAL_ENOSPC,
    COMPLETION_CLOSE_LEAF, COMPLETION_CLOSE_DIRECTORY, COMPLETION_CLOSE_DEFERRED,
    COMPLETION_ROOT_EACCES, COMPLETION_ROOT_EIO, COMPLETION_DEFERRED_EACCES,
    COMPLETION_DEFERRED_EIO, COMPLETION_SOURCE_PRE_METADATA };
static int completion_testing, completion_expected_directories;
static enum completion_fault completion_fault;
static struct stat completion_source_root, completion_destination_root, completion_destination_leaf;
static atomic_int completion_partial, completion_root_calls, completion_child_directories;
static atomic_int completion_leaf_copies, completion_close_errors, completion_leaf_verified;
static atomic_int completion_root_engine, completion_root_verified, completion_mutations;
static int completion_same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        (a->st_mode & S_IFMT) == (b->st_mode & S_IFMT);
}
static atomic_int auto_clones, auto_successes, auto_exdev, auto_metadata, auto_data, auto_reopens;
static atomic_int auto_cancel_observed;
static int auto_rf_starts, auto_rf_finishes;
static char auto_destination[PATH_MAX];
static struct stat auto_source_identity;
static acl_t auto_source_acl;
static int auto_acl_pending;
static int auto_input, auto_output, auto_source_checks, auto_destination_stats;
static int auto_gid_changes, auto_uid_faults, auto_preverified_path;
static atomic_int auto_ready;
static struct stat auto_output_identity;
static gid_t auto_normalization_gid;
static void transfer_ready(int from, int to, int regular);
static void final_swap(void) {
    char held[PATH_MAX]; assert(snprintf(held, sizeof(held), "%s-held", auto_destination) < (int)sizeof(held));
    assert(rename(auto_destination, held) == 0);
    int fd = open(auto_destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
}
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
enum fork_fault { FORK_EQUAL, FORK_CORRUPT, FORK_READ_ERROR, FORK_SHORT, FORK_ZERO,
                  FORK_ALLOC_ERROR, FORK_QUERY_ERROR, FORK_GROW, FORK_SHRINK, FORK_CANCEL, FORK_OVERSIZE };
static const struct fork_case {
    const char *name;
    size_t size;
    enum fork_fault action;
    unsigned call;
    int error;
    size_t byte;
} fork_cases[] = {
    {"empty", 0, FORK_EQUAL, 0, 0, 0},
    {"one", 1, FORK_EQUAL, 0, 0, 0},
    {"inline-boundary", 256, FORK_EQUAL, 0, 0, 0},
    {"heap-boundary", 257, FORK_EQUAL, 0, 0, 0},
    {"full-chunk", 65536, FORK_EQUAL, 0, 0, 0},
    {"short-tail", 65537, FORK_EQUAL, 0, 0, 0},
    {"three-chunks", 131073, FORK_EQUAL, 0, 0, 0},
    {"first-byte", 131073, FORK_CORRUPT, 0, ENOTSUP, 0},
    {"middle-byte", 131073, FORK_CORRUPT, 0, ENOTSUP, 65537},
    {"last-byte", 131073, FORK_CORRUPT, 0, ENOTSUP, 131072},
    {"source-read-error", 65537, FORK_READ_ERROR, 3, EACCES, 0},
    {"destination-read-error", 65537, FORK_READ_ERROR, 4, EDQUOT, 0},
    {"source-short", 131073, FORK_SHORT, 3, ESTALE, 0},
    {"destination-zero", 131073, FORK_ZERO, 4, ESTALE, 0},
    {"allocation-error", 257, FORK_ALLOC_ERROR, 0, ENOMEM, 0},
    {"initial-no-errno", 1, FORK_QUERY_ERROR, 1, EIO, 0},
    {"final-query-error", 65537, FORK_QUERY_ERROR, 3, EACCES, 0},
    {"final-source-growth", 65537, FORK_GROW, 3, ESTALE, 0},
    {"final-destination-shrink", 65537, FORK_SHRINK, 4, ESTALE, 0},
    {"cancel-between-chunks", 131073, FORK_CANCEL, 2, EINTR, 0},
    {"cancel-after-last-chunk", 65537, FORK_CANCEL, 4, EINTR, 0},
    {"above-verifier-limit", 16, FORK_OVERSIZE, 0, EOVERFLOW, 0},
};
static const struct fork_case *fork_case;
static int fork_ready, fork_input, fork_output, fork_mutations;
static unsigned fork_reads, fork_queries, fork_allocations, fork_frees, fork_allocation_errors;
static uint64_t fork_source_bytes, fork_destination_bytes;
static void *fork_allocation;
static unsigned char fork_byte(size_t offset) {
    return (unsigned char)(offset ^ (offset >> 8) ^ (offset >> 16) ^ 0xa5);
}
static ssize_t fork_read(int fd, void *value, size_t size, uint32_t position, int options) {
    assert(fd == fork_input || fd == fork_output);
    assert(options == XATTR_SHOWCOMPRESSION);
    if (!value) {
        assert(size == 0 && position == 0);
        fork_queries++;
        if (fork_case->action == FORK_OVERSIZE) return (ssize_t)((uint64_t)UINT32_MAX + 2);
        if (fork_queries == fork_case->call) {
            if (fork_case->action == FORK_QUERY_ERROR) {
                errno = !strcmp(fork_case->name, "initial-no-errno") ? 0 : fork_case->error;
                return -1;
            }
            if (fork_case->action == FORK_GROW) return (ssize_t)fork_case->size + 1;
            if (fork_case->action == FORK_SHRINK) return (ssize_t)fork_case->size - 1;
        }
        return fgetxattr(fd, "com.apple.ResourceFork", NULL, 0, 0, options);
    }
    fork_reads++;
    uint64_t *completed = fd == fork_input ? &fork_source_bytes : &fork_destination_bytes;
    assert(*completed < fork_case->size && position == *completed);
    size_t left = fork_case->size - (size_t)*completed;
    assert(size == (left < 65536 ? left : 65536));
    if (fork_reads == fork_case->call && fork_case->action == FORK_READ_ERROR) {
        errno = fork_case->error; return -1;
    }
    ssize_t result = fgetxattr(fd, "com.apple.ResourceFork", value, size, position, options);
    if (result >= 0 && fork_reads == fork_case->call) {
        if (fork_case->action == FORK_SHORT) { assert(result > 1); result--; errno = EBUSY; }
        if (fork_case->action == FORK_ZERO) { result = 0; errno = EBUSY; }
        if (fork_case->action == FORK_CANCEL) {
            atomic_store(&cancelled, 1);
            if (auto_testing) {
                /* The public cancellation callback stays on the invoking thread.
                 * Match the existing fallback-cancellation handshake before the next verifier poll. */
                while (!atomic_load(&auto_cancel_observed)) usleep(1000);
                usleep(30000);
            }
        }
    }
    if (result >= 0) *completed += (uint64_t)result;
    return result;
}
void *stallion_test_malloc(size_t size) {
    if (auto_testing && !strcmp(fault, "auto-acl-allocation") && acl_size_calls == 1) {
        errno = ENOMEM; return NULL;
    }
    int value_buffer = xattr_case && xattr_ready && xattr_case->size > 256 && size == xattr_case->size * 2;
    if (value_buffer && xattr_case->action == XATTR_ALLOC_ERROR) {
        xattr_allocation_errors++; errno = ENOMEM; return NULL;
    }
    size_t fork_capacity = fork_case && fork_case->size < 65536 ? fork_case->size : 65536;
    int fork_buffer = fork_case && fork_ready && fork_queries == 2 && fork_reads == 0 &&
        fork_case->size > 256 && size == fork_capacity * 2;
    if (fork_buffer && fork_case->action == FORK_ALLOC_ERROR) {
        fork_allocation_errors++; errno = ENOMEM; return NULL;
    }
    void *result = malloc(size);
    if (fork_buffer && result) {
        assert(!fork_allocation); fork_allocation = result; fork_allocations++;
    }
    if (value_buffer && result) {
        assert(!xattr_allocation); xattr_allocation = result; xattr_allocations++;
    }
    return result;
}
void stallion_test_free(void *pointer) {
    if (pointer && pointer == fork_allocation) {
        fork_allocation = NULL; fork_frees++;
    }
    if (pointer && pointer == xattr_allocation) {
        xattr_allocation = NULL; xattr_frees++;
    }
    free(pointer);
}
ssize_t stallion_test_fgetxattr(int fd, const char *name, void *value, size_t size,
                               uint32_t position, int options) {
    if (fork_case && fork_ready && !strcmp(name, "com.apple.ResourceFork"))
        return fork_read(fd, value, size, position, options);
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
        if (auto_testing) {
            const char *name = NULL;
            assert(copyfile_state_get(state, COPYFILE_STATE_XATTRNAME, &name) == 0 && name);
            if (!strcmp(name, "com.apple.ResourceFork")) {
                if (stage == COPYFILE_START) auto_rf_starts++;
                if (stage == COPYFILE_FINISH) auto_rf_finishes++;
            }
        }
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
acl_t stallion_test_acl_get_fd_np(int fd, acl_type_t type) {
    struct stat info;
    int source_acl = auto_testing && fstat(fd, &info) == 0 && info.st_dev == auto_source_identity.st_dev &&
        info.st_ino == auto_source_identity.st_ino;
    if (source_acl && !strcmp(fault, "auto-acl-read-error")) { errno = EACCES; return NULL; }
    if (source_acl && !strcmp(fault, "auto-acl-read-no-errno")) { errno = 0; return NULL; }
    acl_t acl = acl_get_fd_np(fd, type);
    if (source_acl) { auto_source_acl = acl; auto_acl_pending = 1; }
    return acl;
}
int stallion_test_acl_valid(acl_t acl) {
    if (auto_acl_pending) { auto_source_acl = acl; auto_acl_pending = 0; }
    if (auto_testing && acl == auto_source_acl && !strcmp(fault, "auto-acl-invalid")) { errno = EINVAL; return -1; }
    return acl_valid(acl);
}
int stallion_test_acl_get_entry(acl_t acl, int entry_id, acl_entry_t *entry) {
    if (auto_testing && acl == auto_source_acl && !strcmp(fault, "auto-acl-entry-error")) { errno = EIO; return -1; }
    return acl_get_entry(acl, entry_id, entry);
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
static int cancel(void *unused) {
    (void)unused; assert(pthread_equal(pthread_self(), caller));
    int result = atomic_load(&cancelled);
    if (auto_testing && result) atomic_store(&auto_cancel_observed, 1);
    return result;
}
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
    if (!result && completion_testing && completion_root_engine && completion_same(st, &completion_source_root))
        atomic_store(&completion_root_verified, 1);
    if (!result && auto_testing && auto_ready) {
        if (fd == auto_output && completion_same(st, &auto_output_identity)) {
            auto_destination_stats++;
            if (!strcmp(fault, "auto-uid-mismatch") && auto_destination_stats == 3) {
                st->st_uid ^= 1; auto_uid_faults++;
            }
        }
        /* Only the held source's post-reopen precheck and final verifier guard
         * advance this marker; metadata-only normalization adds the next pair. */
        if (fd == auto_input && completion_same(st, &auto_source_identity)) {
            auto_source_checks++;
            if (auto_source_checks == 2) {
                if (!strcmp(fault, "auto-final-swap")) final_swap();
                if (completion_testing) atomic_store(&completion_leaf_copies, 1);
            }
        }
    }
    return result;
}
int stallion_test_fclonefileat(int source, int destination, const char *name, uint32_t flags) {
    if (auto_testing) {
        atomic_fetch_add(&auto_clones, 1);
        assert(flags == (CLONE_NOFOLLOW | CLONE_ACL));
        if (!strcmp(fault, "callback-error") || !strcmp(fault, "callback-incomplete")) { errno = ENOTSUP; return -1; }
        if (completion_testing && (completion_fault == COMPLETION_PARTIAL_EIO || completion_fault == COMPLETION_PARTIAL_ENOSPC)) {
            errno = ENOTSUP; return -1;
        }
        if (!strcmp(fault, "auto-unsupported")) { errno = ENOTSUP; return -1; }
        if (!strcmp(fault, "auto-exdev")) { errno = EXDEV; return -1; }
        if (!strcmp(fault, "auto-cancel-fallback")) {
            atomic_store(&cancelled, 1);
            while (!atomic_load(&auto_cancel_observed)) usleep(1000);
            usleep(30000);
            errno = ENOTSUP; return -1;
        }
        if (!strcmp(fault, "auto-entry-left")) {
            int fd = openat(destination, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            assert(fd >= 0 && write(fd, "keep", 4) == 4 && close(fd) == 0);
            errno = ENOTSUP; return -1;
        }
        if (!strcmp(fault, "auto-absence-error") || !strcmp(fault, "auto-fallback-race")) {
            errno = ENOTSUP; return -1;
        }
        const struct { const char *name; int error; } errors[] = {
            {"auto-eexist", EEXIST}, {"auto-eacces", EACCES}, {"auto-eperm", EPERM}, {"auto-einval", EINVAL},
            {"auto-eio", EIO}, {"auto-enospc", ENOSPC}, {"auto-eintr", EINTR}, {"auto-estale", ESTALE}
        };
        for (size_t i = 0; i < sizeof(errors) / sizeof(*errors); i++)
            if (!strcmp(fault, errors[i].name)) { errno = errors[i].error; return -1; }
    }
    if (copy_error()) return -1;
    pause_worker();
    int result = fclonefileat(source, destination, name, flags);
    int error = errno;
    if (!result && auto_testing) auto_input = source;
    if (auto_testing) {
        if (!result) atomic_fetch_add(&auto_successes, 1);
        else if (error == EXDEV) atomic_fetch_add(&auto_exdev, 1);
    }
    if (!result && completion_testing && completion_fault == COMPLETION_SOURCE_PRE_METADATA) {
        struct stat info; assert(fstat(source, &info) == 0);
        assert(fchflags(source, info.st_flags | UF_NODUMP) == 0);
        atomic_fetch_add(&completion_mutations, 1);
    }
    errno = error;
    return result;
}
/* Real clone/reopen and real copyfile completion share the same value-fault
 * setup; no callback is manufactured for a clone-completed transfer. */
static void transfer_ready(int from, int to, int regular) {
    if (fork_case && regular) {
        fork_input = from; fork_output = to;
        if (fork_case->action == FORK_CORRUPT) {
            assert(fork_case->size <= 131073 && fork_case->byte < fork_case->size);
            struct stat metadata; assert(fstat(to, &metadata) == 0);
            unsigned char *value = malloc(fork_case->size); assert(value);
            assert(fgetxattr(to, "com.apple.ResourceFork", value, fork_case->size, 0, 0) == (ssize_t)fork_case->size);
            value[fork_case->byte] ^= 0x5a;
            assert(fsetxattr(to, "com.apple.ResourceFork", value, fork_case->size, 0, 0) == 0);
            assert(fgetxattr(to, "com.apple.ResourceFork", NULL, 0, 0, 0) == (ssize_t)fork_case->size);
            /* Isolate a content-only fault on this fresh destination; keep every production guard. */
            struct timespec times[] = {metadata.st_atimespec, metadata.st_mtimespec};
            assert(futimens(to, times) == 0);
            free(value); fork_mutations++;
        }
        fork_ready = 1;
    }
    if ((xattr_case || auto_testing) && regular) {
        if (xattr_case && xattr_case->action == XATTR_CORRUPT) {
            unsigned char value[4097];
            assert(xattr_case->size > 0 && xattr_case->size <= sizeof(value));
            assert(fgetxattr(to, "user.stallion-test", value, xattr_case->size, 0, 0) == (ssize_t)xattr_case->size);
            value[xattr_case->size - 1] ^= 0x5a;
            assert(fsetxattr(to, "user.stallion-test", value, xattr_case->size, 0, 0) == 0);
            xattr_mutations++;
        }
        xattr_ready = 1;
    }
    if (auto_testing && regular && (!strcmp(fault, "auto-acl-corrupt") || !strcmp(fault, "auto-gid-acl"))) {
        acl_t changed = leaf_acl(""); assert(acl_set_fd_np(to, changed, ACL_TYPE_EXTENDED) == 0); acl_free(changed);
    }
    if ((!strcmp(fault, "acl-permission") || !strcmp(fault, "acl-order") ||
                    !strcmp(fault, "acl-tag") || !strcmp(fault, "acl-uuid") ||
                    !strcmp(fault, "acl-entry-flags") || !strcmp(fault, "acl-flags"))) {
        acl_t original = acl_get_fd_np(from, ACL_TYPE_EXTENDED), changed = leaf_acl(fault);
        assert(original && acl_size(original) == acl_size(changed));
        assert(acl_set_fd_np(to, changed, ACL_TYPE_EXTENDED) == 0);
        acl_free(original); acl_free(changed);
    }
    if (!strcmp(fault, "dense-copy")) {
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
    if (!strcmp(fault, "silent-stat")) assert(fchmod(to, 0640) == 0);
    if (!strcmp(fault, "source-change")) {
        struct timespec times[2] = {{100, 0}, {100, 0}};
        assert(futimens(from, times) == 0);
    }
    if (auto_testing && regular && !strcmp(fault, "auto-gid-xattr")) {
        assert(fsetxattr(to, "user.stallion-test", "metadatz", 8, 0, 0) == 0);
    }
}
int stallion_test_fcopyfile(int from, int to, copyfile_state_t state, copyfile_flags_t flags) {
    atomic_fetch_add(&copy_calls, 1);
    struct stat input_info;
    assert(fstat(from, &input_info) == 0);
    int regular = S_ISREG(input_info.st_mode);
    if (auto_testing && regular) {
        assert(!(flags & (COPYFILE_CLONE | COPYFILE_CLONE_FORCE)));
        if (flags == COPYFILE_METADATA) {
            assert(auto_successes > 0);
            if (!strncmp(fault, "auto-gid-", 9)) assert(auto_source_checks == 3 && auto_preverified_path == 1);
            atomic_fetch_add(&auto_metadata, 1);
        } else {
            assert((flags & COPYFILE_ALL) == COPYFILE_ALL); atomic_fetch_add(&auto_data, 1);
        }
    }
    if (completion_testing && regular &&
        (completion_fault == COMPLETION_PARTIAL_EIO || completion_fault == COMPLETION_PARTIAL_ENOSPC)) {
        char prefix[4];
        assert(pread(from, prefix, sizeof(prefix), 0) == sizeof(prefix));
        assert(pwrite(to, prefix, sizeof(prefix), 0) == sizeof(prefix));
        atomic_fetch_add(&completion_partial, 1);
        errno = completion_fault == COMPLETION_PARTIAL_EIO ? EIO : ENOSPC;
        return -1;
    }
    int completion_root = completion_testing && S_ISDIR(input_info.st_mode) &&
        completion_same(&input_info, &completion_source_root);
    if (completion_root) {
        struct stat output_info; assert(fstat(to, &output_info) == 0);
        assert(completion_same(&output_info, &completion_destination_root));
        assert(completion_leaf_copies == 1 && completion_child_directories == completion_expected_directories);
        atomic_fetch_add(&completion_root_calls, 1);
        if (completion_fault == COMPLETION_ROOT_EACCES || completion_fault == COMPLETION_DEFERRED_EACCES) { errno = EACCES; return -1; }
        if (completion_fault == COMPLETION_ROOT_EIO || completion_fault == COMPLETION_DEFERRED_EIO) { errno = EIO; return -1; }
    }
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
    if ((xattr_case || fork_case || auto_testing) && regular) {
        assert(copyfile_state_get(state, COPYFILE_STATE_STATUS_CB, &xattr_callback) == 0 && xattr_callback);
        assert(copyfile_state_set(state, COPYFILE_STATE_STATUS_CB, (void *)xattr_status) == 0);
    }
    int result = fcopyfile(from, to, state, flags);
    if (!result && completion_testing) {
        if (regular) {
            assert(fstat(to, &completion_destination_leaf) == 0);
            atomic_fetch_add(&completion_leaf_copies, 1);
        } else if (completion_root) atomic_store(&completion_root_engine, 1);
        else if (S_ISDIR(input_info.st_mode)) atomic_fetch_add(&completion_child_directories, 1);
    }
    if ((xattr_case || fork_case || auto_testing) && regular)
        assert(copyfile_state_set(state, COPYFILE_STATE_STATUS_CB, (void *)xattr_callback) == 0);
    if (!result && !(auto_testing && auto_successes)) transfer_ready(from, to, regular);
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
int stallion_test_fstatat(int fd, const char *name, struct stat *info, int flags) __DARWIN_INODE64(stallion_test_fstatat);
int stallion_test_fstatat(int fd, const char *name, struct stat *info, int flags) {
    if (auto_testing && auto_clones && !auto_successes && !strcmp(name, "eligible") &&
        !strcmp(fault, "auto-absence-error")) {
        assert(flags == AT_SYMLINK_NOFOLLOW); errno = EACCES; return -1;
    }
    int result = fstatat(fd, name, info, flags);
    if (!result && auto_testing && auto_ready && fd >= 0 && !strcmp(name, "eligible") &&
        !strncmp(fault, "auto-gid-", 9) && auto_source_checks == 2) {
        struct stat output; assert(fstat(auto_output, &output) == 0 && completion_same(info, &output));
        auto_preverified_path++;
    }
    if (!result && completion_testing && completion_leaf_copies && completion_same(info, &completion_destination_leaf))
        atomic_store(&completion_leaf_verified, 1);
    return result;
}
/* Only _tree.c is substituted. The designated descriptor is really closed first;
 * reporting EIO afterward exercises error propagation without leaking the fd. */
int stallion_test_close(int fd) {
    struct stat info;
    int inject = 0;
    if (completion_testing && !completion_close_errors && fstat(fd, &info) == 0) {
        if (completion_fault == COMPLETION_CLOSE_LEAF && completion_leaf_verified &&
            completion_same(&info, &completion_destination_leaf)) inject = 1;
        if ((completion_fault == COMPLETION_CLOSE_DIRECTORY || completion_fault == COMPLETION_CLOSE_DEFERRED) &&
            completion_root_verified && completion_same(&info, &completion_destination_root)) inject = 1;
    }
    int result = close(fd), error = errno;
    if (inject) {
        assert(result == 0 && atomic_fetch_add(&completion_close_errors, 1) == 0);
        errno = EIO; return -1;
    }
    errno = error;
    return result;
}
int stallion_test_openat(int fd, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    if (auto_testing && !strcmp(name, "eligible") && auto_clones) {
        if (flags & O_CREAT) {
            assert((flags & (O_EXCL | O_NOFOLLOW)) == (O_EXCL | O_NOFOLLOW));
            if (!strcmp(fault, "auto-fallback-race")) {
                int inserted = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                assert(inserted >= 0 && write(inserted, "keep", 4) == 4 && close(inserted) == 0);
            }
        } else if (flags & O_RDWR) {
            atomic_fetch_add(&auto_reopens, 1);
            assert(flags == (O_RDWR | O_NOFOLLOW | O_CLOEXEC));
            if (!strcmp(fault, "auto-reopen-error")) { errno = EACCES; return -1; }
            if (!strcmp(fault, "auto-reopen-swap")) {
                assert(renameat(fd, name, fd, "cloned-held") == 0);
                int inserted = openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                assert(inserted >= 0 && write(inserted, "keep", 4) == 4 && close(inserted) == 0);
            }
        }
    }
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
    if (result >= 0 && auto_testing && auto_successes && !strcmp(name, "eligible") && (flags & O_RDWR)) {
        auto_output = result; auto_source_checks = auto_destination_stats = 0;
        if (!strncmp(fault, "auto-gid-", 9)) {
            assert(fchown(result, (uid_t)-1, getegid()) == 0);
            struct stat changed; assert(fstat(result, &changed) == 0);
            assert(changed.st_gid == getegid() && changed.st_gid != auto_source_identity.st_gid);
            auto_gid_changes++;
        }
        transfer_ready(auto_input, result, 1);
        assert(fstat(result, &auto_output_identity) == 0);
        auto_ready = 1;
        if (completion_testing) assert(fstat(result, &completion_destination_leaf) == 0);
    }
    if (result >= 0 && completion_testing && (flags & O_DIRECTORY) && !strcmp(name, "output"))
        assert(fstat(result, &completion_destination_root) == 0);
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
    int deleting = operation == 1, copying = operation >= 2;
    char root[PATH_MAX], destination[PATH_MAX], child[PATH_MAX], error_path[PATH_MAX];
    snprintf(root, sizeof(root), "%s/%s-%s", base, deleting ? "delete" : operation == 3 ? "copy-auto" : copying ? "copy" : "clone", kind);
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
        (operation == 3 ? stallion_copy_with_strategy(source, destination, STALLION_COPY_AUTO, 4, cancel, NULL, error_path, sizeof(error_path)) :
         (copying ? stallion_copy : stallion_clone)(source, destination, 4, cancel, NULL, error_path, sizeof(error_path)));
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
static void xattr_value_cases(const char *base, int characterize, int automatic) {
    for (size_t index = 0; index < sizeof(xattr_cases) / sizeof(*xattr_cases); index++) {
        xattr_case = &xattr_cases[index];
        if (characterize && xattr_case->action != XATTR_CORRUPT) continue;
        char root[PATH_MAX], input[PATH_MAX], output[PATH_MAX], error_path[PATH_MAX];
        assert(snprintf(root, sizeof(root), "%s/xattr-%s-%s", base, automatic ? "auto" : "materialized", xattr_case->name) < (int)sizeof(root));
        assert(mkdir(root, 0700) == 0);
        char tree[PATH_MAX], destination_tree[PATH_MAX];
        snprintf(tree, sizeof(tree), "%s/input", root);
        snprintf(destination_tree, sizeof(destination_tree), "%s/output", root);
        if (automatic) {
            assert(mkdir(tree, 0700) == 0); file(tree, "eligible");
            snprintf(input, sizeof(input), "%s/eligible", tree);
            snprintf(output, sizeof(output), "%s/eligible", destination_tree);
        } else { file(root, "input"); snprintf(input, sizeof(input), "%s", tree); snprintf(output, sizeof(output), "%s", destination_tree); }
        unsigned char expected[4097], source_value[4097], destination_value[4097];
        assert(xattr_case->size <= sizeof(expected));
        for (size_t i = 0; i < xattr_case->size; i++) expected[i] = xattr_pattern[i % sizeof(xattr_pattern)];
        int input_fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(input_fd >= 0);
        assert(fsetxattr(input_fd, "user.stallion-test", expected, xattr_case->size, 0, 0) == 0);
        if (automatic) assert(fsetxattr(input_fd, "com.apple.ResourceFork", "resource", 8, 0, 0) == 0);
        struct stat original, after, copied;
        assert(fstat(input_fd, &original) == 0 && stat(root, &destination_parent) == 0);
        fault = "xattr-values"; caller = pthread_self();
        atomic_store(&copy_calls, 0); atomic_store(&starts, 0); atomic_store(&cancelled, 0);
        xattr_ready = xattr_reads = xattr_queries = xattr_allocations = xattr_frees = xattr_allocation_errors = 0;
        xattr_starts = xattr_finishes = xattr_mutations = 0; xattr_allocation = NULL;
        auto_testing = automatic; auto_source_identity = original;
        auto_clones = auto_successes = auto_metadata = auto_data = auto_reopens = 0;
        auto_rf_starts = auto_rf_finishes = 0; auto_ready = auto_gid_changes = auto_uid_faults = auto_preverified_path = 0; auto_source_checks = auto_destination_stats = 0;
        int before = descriptors();
        int result = automatic ? stallion_copy_with_strategy(tree, destination_tree, STALLION_COPY_AUTO, 4,
                                                             cancel, NULL, error_path, sizeof(error_path)) :
                                 stallion_copy(input, output, 4, cancel, NULL, error_path, sizeof(error_path));
        int error = errno;
        assert(descriptors() == before && (automatic ? auto_data == 0 && auto_metadata == 0 : copy_calls == 1) && xattr_ready);
        if (automatic) assert(auto_clones == 1 && auto_successes == 1 && auto_metadata == 0 && auto_data == 0 &&
                              auto_reopens == 1 && auto_rf_starts == 0 && auto_rf_finishes == 0);
        auto_testing = 0;
        assert(automatic ? (xattr_starts == 0 && xattr_finishes == 0) :
                           (xattr_starts > 0 && xattr_starts == xattr_finishes));
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
static void auto_case(const char *base, const char *kind, int expected_error, int expected_clones,
                       int expected_successes, int expected_metadata, int expected_data) {
    char root[PATH_MAX], tree[PATH_MAX], target[PATH_MAX], input[PATH_MAX], path[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/%s", base, kind) < (int)sizeof(root));
    assert(mkdir(root, 0700) == 0); file(root, "sentinel");
    snprintf(tree, sizeof(tree), "%s/input", root); assert(mkdir(tree, 0700) == 0); file(tree, "eligible");
    snprintf(input, sizeof(input), "%s/eligible", tree);
    snprintf(target, sizeof(target), "%s/output", root);
    snprintf(auto_destination, sizeof(auto_destination), "%s/eligible", target);
    int fd = open(input, O_RDWR | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    assert(pwrite(fd, "end", 3, 1048576) == 3 && fsync(fd) == 0);
    struct fpunchhole hole = {.fp_offset = 4096, .fp_length = 1048576 - 4096};
    assert(fcntl(fd, F_PUNCHHOLE, &hole) == 0 && fsync(fd) == 0);
    assert(fsetxattr(fd, "user.stallion-test", "metadata", 8, 0, 0) == 0);
    assert(fsetxattr(fd, "com.apple.ResourceFork", "resource", 8, 0, 0) == 0);
    acl_t acl = !strcmp(kind, "auto-excluded-acl") ? leaf_acl("") : acl_init(0); assert(acl);
    assert(acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0); acl_free(acl);
    if (!strncmp(kind, "auto-gid-", 9)) {
        gid_t groups[NGROUPS_MAX]; int count = getgroups(NGROUPS_MAX, groups);
        assert(count >= 0); auto_normalization_gid = getegid();
        for (int i = 0; i < count; i++) if (groups[i] != getegid()) { auto_normalization_gid = groups[i]; break; }
        if (auto_normalization_gid == getegid() && geteuid() == 0) auto_normalization_gid ^= 1;
        assert(auto_normalization_gid != getegid());
        assert(fchown(fd, (uid_t)-1, auto_normalization_gid) == 0);
        struct stat grouped; assert(fstat(fd, &grouped) == 0 && grouped.st_gid == auto_normalization_gid);
    }
    if (!strcmp(kind, "auto-excluded-flags")) assert(fchflags(fd, UF_NODUMP) == 0);
    if (!strcmp(kind, "auto-excluded-readonly")) assert(fchmod(fd, 0400) == 0);
    if (!strcmp(kind, "auto-excluded-setid")) {
        assert(fchown(fd, (uid_t)-1, getegid()) == 0);
        struct stat grouped;
        assert(fstat(fd, &grouped) == 0 && grouped.st_gid == getegid());
        assert(fchmod(fd, 06700) == 0);
    }
    if (!strcmp(kind, "auto-excluded-owner")) { assert(geteuid() == 0 && fchown(fd, 1, (gid_t)-1) == 0); }
    if (!strcmp(kind, "auto-excluded-symlink")) {
        assert(close(fd) == 0 && unlink(input) == 0 && symlink("missing-target", input) == 0);
        fd = open(input, O_RDONLY | O_SYMLINK | O_CLOEXEC); assert(fd >= 0);
    }
    assert(fstat(fd, &auto_source_identity) == 0);
    if (!strcmp(kind, "auto-excluded-setid")) assert((auto_source_identity.st_mode & 06000) == 06000);
    assert(close(fd) == 0);
    if (!strcmp(kind, "auto-success")) {
        char alias[PATH_MAX]; snprintf(alias, sizeof(alias), "%s/alias", tree); assert(link(input, alias) == 0);
        snprintf(alias, sizeof(alias), "%s/external", root); assert(link(input, alias) == 0);
        assert(lstat(input, &auto_source_identity) == 0);
    }
    snprintf(source, sizeof(source), "%s", input);
    auto_testing = 1; fault = kind; caller = pthread_self(); auto_acl_pending = 0; auto_source_acl = NULL;
    copy_calls = starts = created = joined = cancelled = auto_cancel_observed = 0;
    auto_clones = auto_successes = auto_exdev = auto_metadata = auto_data = auto_reopens = 0;
    acl_size_calls = acl_export_calls = 0; auto_rf_starts = auto_rf_finishes = 0; auto_ready = auto_gid_changes = auto_uid_faults = auto_preverified_path = 0; auto_source_checks = auto_destination_stats = 0;
    int before = descriptors();
    int root_leaf = !strcmp(kind, "auto-excluded-root");
    int result = stallion_copy_with_strategy(root_leaf ? input : tree, target, STALLION_COPY_AUTO, 1,
                                             cancel, NULL, path, sizeof(path));
    int error = errno;
    auto_testing = 0; auto_acl_pending = 0; auto_source_acl = NULL;
    assert(result == (expected_error ? -1 : 0) && error == expected_error);
    assert(auto_clones == expected_clones && auto_successes == expected_successes &&
           auto_metadata == expected_metadata && auto_data == expected_data);
    assert(descriptors() == before && created == joined && active == 0);
    if (expected_metadata) assert(auto_rf_starts > 0 && auto_rf_starts == auto_rf_finishes);
    else if (expected_successes) assert(auto_rf_starts == 0 && auto_rf_finishes == 0);
    if (!strncmp(kind, "auto-gid-", 9)) assert(auto_gid_changes == 1 &&
        auto_preverified_path == !strcmp(kind, "auto-gid-normalize"));
    if (!strcmp(kind, "auto-uid-mismatch")) assert(auto_uid_faults == 1);
    if (!strcmp(kind, "auto-gid-normalize")) assert(auto_source_checks == 4);
    struct stat after, output;
    assert(lstat(input, &after) == 0 && after.st_dev == auto_source_identity.st_dev && after.st_ino == auto_source_identity.st_ino &&
           after.st_mode == auto_source_identity.st_mode && after.st_uid == auto_source_identity.st_uid &&
           after.st_gid == auto_source_identity.st_gid && after.st_size == auto_source_identity.st_size &&
           after.st_flags == auto_source_identity.st_flags && after.st_nlink == auto_source_identity.st_nlink);
    if (strcmp(kind, "source-change")) {
        assert(after.st_mtimespec.tv_sec == auto_source_identity.st_mtimespec.tv_sec &&
               after.st_mtimespec.tv_nsec == auto_source_identity.st_mtimespec.tv_nsec &&
               after.st_ctimespec.tv_sec == auto_source_identity.st_ctimespec.tv_sec &&
               after.st_ctimespec.tv_nsec == auto_source_identity.st_ctimespec.tv_nsec);
    }
    const char *leaf = root_leaf ? target : auto_destination;
    int exists = lstat(leaf, &output) == 0;
    if (!expected_error) {
        assert(exists && (after.st_dev != output.st_dev || after.st_ino != output.st_ino));
        assert(after.st_size == output.st_size && after.st_mode == output.st_mode && after.st_flags == output.st_flags &&
               after.st_uid == output.st_uid && after.st_gid == output.st_gid);
        if (S_ISREG(after.st_mode)) {
            int a = open(input, O_RDONLY | O_NOFOLLOW), b = open(leaf, O_RDONLY | O_NOFOLLOW); assert(a >= 0 && b >= 0);
            char data[8]; assert(pread(b, data, 8, 0) == 8 && !memcmp(data, "sentinel", 8));
            assert(lseek(a, 0, SEEK_HOLE) == lseek(b, 0, SEEK_HOLE));
            assert(lseek(a, 4096, SEEK_DATA) == lseek(b, 4096, SEEK_DATA));
            assert(close(a) == 0 && close(b) == 0);
        }
        if (!strcmp(kind, "auto-success")) {
            char alias[PATH_MAX]; struct stat linked;
            snprintf(alias, sizeof(alias), "%s/alias", target); assert(lstat(alias, &linked) == 0);
            assert(linked.st_ino == output.st_ino && output.st_nlink == 2 && after.st_nlink == 3);
        }
    } else {
        int partial = expected_successes || expected_data || !strcmp(kind, "auto-entry-left") || !strcmp(kind, "auto-fallback-race");
        assert(exists == !!partial);
        assert(lstat(target, &output) == 0 && S_ISDIR(output.st_mode));
        if (!strcmp(kind, "auto-entry-left") || !strcmp(kind, "auto-fallback-race") ||
            !strcmp(kind, "auto-reopen-swap") || !strcmp(kind, "auto-final-swap")) {
            int held = open(auto_destination, O_RDONLY | O_NOFOLLOW); char data[4];
            assert(held >= 0 && read(held, data, 4) == 4 && !memcmp(data, "keep", 4) && close(held) == 0);
        }
    }
    sentinel(root);
    fprintf(stderr, "VERIFY auto %s: errno=%d clone=%d success=%d metadata=%d data=%d reopen=%d RF=%d/%d joined=%d/%d gid_changes=%d uid_faults=%d source_checks=%d preverified_path=%d\n",
            kind, error, auto_clones, auto_successes, auto_metadata, auto_data, auto_reopens,
            auto_rf_starts, auto_rf_finishes, joined, created, auto_gid_changes, auto_uid_faults, auto_source_checks, auto_preverified_path);
}
static void auto_cases(const char *base) {
    char absent[PATH_MAX], path[PATH_MAX]; struct stat info;
    snprintf(absent, sizeof(absent), "%s/invalid-strategy-output", base);
    assert(stallion_copy_with_strategy(base, absent, (enum stallion_copy_strategy)42, 1,
                                      NULL, NULL, path, sizeof(path)) == -1 && errno == EINVAL);
    assert(lstat(absent, &info) == -1 && errno == ENOENT);
    auto_case(base, "auto-success", 0, 1, 1, 0, 0);
    auto_case(base, "auto-unsupported", 0, 1, 0, 0, 1);
    auto_case(base, "auto-exdev", 0, 1, 0, 0, 1);
    const struct { const char *name; int error; } fatal[] = {
        {"auto-eexist", EEXIST}, {"auto-eacces", EACCES}, {"auto-eperm", EPERM}, {"auto-einval", EINVAL},
        {"auto-eio", EIO}, {"auto-enospc", ENOSPC}, {"auto-eintr", EINTR}, {"auto-estale", ESTALE},
        {"auto-entry-left", ENOTSUP}, {"auto-absence-error", EACCES}, {"auto-fallback-race", EEXIST},
        {"auto-cancel-fallback", EINTR}
    };
    for (size_t i = 0; i < sizeof(fatal) / sizeof(*fatal); i++) auto_case(base, fatal[i].name, fatal[i].error, 1, 0, 0, 0);
    auto_case(base, "auto-reopen-error", EACCES, 1, 1, 0, 0);
    auto_case(base, "auto-reopen-swap", ESTALE, 1, 1, 0, 0);
    auto_case(base, "auto-final-swap", ESTALE, 1, 1, 0, 0);
    auto_case(base, "auto-acl-corrupt", ENOTSUP, 1, 1, 0, 0);
    auto_case(base, "source-change", ESTALE, 1, 1, 0, 0);
    auto_case(base, "dense-copy", ENOTSUP, 1, 1, 0, 0);
    auto_case(base, "callback-error", ENOSPC, 1, 0, 0, 1);
    auto_case(base, "callback-incomplete", EIO, 1, 0, 0, 1);
    auto_case(base, "auto-gid-normalize", 0, 1, 1, 1, 0);
    auto_case(base, "auto-gid-xattr", ENOTSUP, 1, 1, 0, 0);
    auto_case(base, "auto-gid-acl", ENOTSUP, 1, 1, 0, 0);
    auto_case(base, "auto-uid-mismatch", ENOTSUP, 1, 1, 0, 0);
    auto_case(base, "auto-acl-read-error", EACCES, 0, 0, 0, 0);
    auto_case(base, "auto-acl-read-no-errno", EIO, 0, 0, 0, 0);
    auto_case(base, "auto-acl-invalid", EINVAL, 0, 0, 0, 0);
    auto_case(base, "auto-acl-entry-error", EIO, 0, 0, 0, 0);
    auto_case(base, "auto-acl-allocation", ENOMEM, 0, 0, 0, 0);
    const char *serialization[] = {"acl-size-error", "acl-size-no-errno", "acl-size-zero",
        "acl-export-error", "acl-export-no-errno", "acl-export-zero", "acl-export-short"};
    acl_fault_call = 1;
    for (size_t i = 0; i < sizeof(serialization) / sizeof(*serialization); i++)
        auto_case(base, serialization[i], !strcmp(serialization[i], "acl-size-error") ||
                  !strcmp(serialization[i], "acl-export-error") ? EACCES : EIO, 0, 0, 0, 0);
    acl_fault_call = 0;
    const char *excluded[] = {"auto-excluded-root", "auto-excluded-symlink", "auto-excluded-readonly",
        "auto-excluded-flags", "auto-excluded-acl", "auto-excluded-setid"};
    for (size_t i = 0; i < sizeof(excluded) / sizeof(*excluded); i++)
        auto_case(base, excluded[i], 0, 0, 0, 0, strcmp(excluded[i], "auto-excluded-symlink") != 0);
    if (geteuid() == 0) auto_case(base, "auto-excluded-owner", 0, 0, 0, 0, 1);
}
static void auto_cross_volume(const char *input, const char *output) {
    auto_testing = 1; fault = "auto-cross-volume"; caller = pthread_self();
    cancelled = copy_calls = created = joined = auto_clones = auto_successes = auto_exdev = 0;
    auto_metadata = auto_data = auto_reopens = 0; auto_rf_starts = auto_rf_finishes = 0; auto_ready = auto_gid_changes = auto_uid_faults = auto_preverified_path = 0; auto_source_checks = auto_destination_stats = 0;
    char path[PATH_MAX]; int before = descriptors();
    int result = stallion_copy_with_strategy(input, output, STALLION_COPY_AUTO, 1, cancel, NULL, path, sizeof(path));
    int error = errno; auto_testing = 0;
    fprintf(stderr, "VERIFY real cross-volume auto: result=%d errno=%d clone=%d EXDEV=%d metadata=%d data=%d joined=%d/%d\n",
            result, error, auto_clones, auto_exdev, auto_metadata, auto_data, joined, created);
    assert(result == 0 && error == 0 && auto_clones > 0 && auto_exdev == auto_clones && auto_successes == 0 &&
           auto_metadata == 0 && auto_data > 0 && auto_reopens == 0 && descriptors() == before && created == joined);
}
static void fork_cursor_cases(void) {
    /* Literal edge cases exercise the production calculation, not OS-sized forks. */
    const struct {
        uint64_t length, offset;
        size_t capacity;
        int valid;
        uint32_t position;
        size_t amount;
    } cases[] = {
        {0, 0, 256, 1, 0xdeadbeef, 0},
        {1, 0, 256, 1, 0, 1},
        {4294967296ULL, 4294901760ULL, 65536, 1, 4294901760U, 65536},
        {4294967296ULL, 4294967295ULL, 65536, 1, 4294967295U, 1},
        {4294967296ULL, 4294967296ULL, 65536, 1, 0xdeadbeef, 0},
        {4294967297ULL, 0, 65536, 0, 0xdeadbeef, 12345},
        {10, 11, 256, 0, 0xdeadbeef, 12345},
        {1, 0, 0, 0, 0xdeadbeef, 12345},
    };
    assert(sizeof(ssize_t) >= sizeof(uint64_t));
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        uint32_t position = 0xdeadbeef;
        size_t amount = 12345;
        assert(stallion_fork_chunk(cases[i].length, cases[i].offset, cases[i].capacity, &position, &amount) == cases[i].valid);
        assert(position == cases[i].position && amount == cases[i].amount);
    }
    puts("PASS ResourceFork cursor arithmetic: eight literal boundary cases; no OS-size qualification");
}
static int fork_listed(int fd) {
    char names[1024];
    ssize_t length = flistxattr(fd, names, sizeof(names), XATTR_SHOWCOMPRESSION);
    assert(length >= 0);
    for (size_t offset = 0; offset < (size_t)length;) {
        size_t size = strnlen(names + offset, (size_t)length - offset);
        assert(size && size < (size_t)length - offset);
        if (!strcmp(names + offset, "com.apple.ResourceFork")) return 1;
        offset += size + 1;
    }
    return 0;
}
static void fork_source_unchanged(const struct stat *a, const struct stat *b) {
    assert(a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
           a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink &&
           a->st_size == b->st_size && a->st_flags == b->st_flags && a->st_gen == b->st_gen &&
           a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
           a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec &&
           a->st_birthtimespec.tv_sec == b->st_birthtimespec.tv_sec && a->st_birthtimespec.tv_nsec == b->st_birthtimespec.tv_nsec);
}
static void fork_value_cases(const char *base, int automatic) {
    fork_cursor_cases();
    unsigned completed_cases = 0, unavailable = 0;
    for (size_t index = 0; index < sizeof(fork_cases) / sizeof(*fork_cases); index++) {
        fork_case = &fork_cases[index];
        char root[PATH_MAX], input[PATH_MAX], output[PATH_MAX], error_path[PATH_MAX];
        assert(snprintf(root, sizeof(root), "%s/resource-fork-%s%s", base, automatic ? "auto-" : "", fork_case->name) < (int)sizeof(root));
        assert(mkdir(root, 0700) == 0);
        char tree[PATH_MAX], destination_tree[PATH_MAX];
        snprintf(tree, sizeof(tree), "%s/input", root);
        snprintf(destination_tree, sizeof(destination_tree), "%s/output", root);
        if (automatic) {
            assert(mkdir(tree, 0700) == 0); file(tree, "eligible");
            snprintf(input, sizeof(input), "%s/eligible", tree);
            snprintf(output, sizeof(output), "%s/eligible", destination_tree);
        } else { file(root, "input"); snprintf(input, sizeof(input), "%s", tree); snprintf(output, sizeof(output), "%s", destination_tree); }
        assert(fork_case->size <= 131073);
        size_t allocation = fork_case->size ? fork_case->size : 1;
        unsigned char *expected = malloc(allocation), *source_value = malloc(allocation), *destination_value = malloc(allocation);
        assert(expected && source_value && destination_value);
        for (size_t i = 0; i < fork_case->size; i++) expected[i] = fork_byte(i);
        int input_fd = open(input, O_RDWR | O_NOFOLLOW | O_CLOEXEC); assert(input_fd >= 0);
        if (automatic) {
            acl_t acl = acl_init(0); assert(acl);
            assert(acl_set_fd_np(input_fd, acl, ACL_TYPE_EXTENDED) == 0); acl_free(acl);
            assert(fchmod(input_fd, 0600) == 0 && fchflags(input_fd, 0) == 0);
        }
        errno = 0;
        int setup = fsetxattr(input_fd, "com.apple.ResourceFork", expected, fork_case->size, 0, 0);
        int setup_error = setup < 0 ? errno : 0;
        if (!fork_case->size && ((setup < 0 && (setup_error == ENOATTR || setup_error == ENOTSUP || setup_error == EINVAL)) ||
                                 (setup == 0 && !fork_listed(input_fd)))) {
            fprintf(stderr, "UNAVAILABLE ResourceFork empty: not exposed by real setup; errno=%d; retained=%s\n", setup_error, root);
            assert(close(input_fd) == 0); free(expected); free(source_value); free(destination_value);
            unavailable++; continue;
        }
        assert(setup == 0 && fork_listed(input_fd));
        assert(fgetxattr(input_fd, "com.apple.ResourceFork", NULL, 0, 0, 0) == (ssize_t)fork_case->size);
        struct stat original, after, copied, named;
        assert(fstat(input_fd, &original) == 0 && stat(root, &destination_parent) == 0);
        if (automatic) assert(original.st_uid == geteuid() && (original.st_mode & 07777) == 0600 && original.st_flags == 0);
        fault = "resource-fork-values"; caller = pthread_self();
        atomic_store(&copy_calls, 0); atomic_store(&starts, 0); atomic_store(&cancelled, 0);
        fork_ready = fork_mutations = 0;
        fork_reads = fork_queries = fork_allocations = fork_frees = fork_allocation_errors = 0;
        fork_source_bytes = fork_destination_bytes = 0; fork_allocation = NULL;
        xattr_starts = xattr_finishes = 0;
        auto_testing = automatic; auto_source_identity = original; auto_acl_pending = 0; auto_source_acl = NULL;
        auto_clones = auto_successes = auto_metadata = auto_data = auto_reopens = auto_cancel_observed = 0;
        created = joined = 0; auto_rf_starts = auto_rf_finishes = 0; auto_ready = auto_gid_changes = auto_uid_faults = auto_preverified_path = 0; auto_source_checks = auto_destination_stats = 0;
        int before = descriptors();
        int result = automatic ? stallion_copy_with_strategy(tree, destination_tree, STALLION_COPY_AUTO, 1,
                                                             cancel, NULL, error_path, sizeof(error_path)) :
                                 stallion_copy(input, output, 4, cancel, NULL, error_path, sizeof(error_path));
        int error = errno;
        auto_testing = 0; auto_acl_pending = 0; auto_source_acl = NULL;
        assert(descriptors() == before && (automatic ? auto_data == 0 && auto_metadata == 0 : copy_calls == 1) && fork_ready);
        if (automatic) assert(auto_clones == 1 && auto_successes == 1 && auto_metadata == 0 && auto_data == 0 &&
                              auto_reopens == 1 && auto_rf_starts == 0 && auto_rf_finishes == 0 && created == joined);
        if (automatic && fork_case->action == FORK_CANCEL) assert(auto_cancel_observed == 1);
        assert(automatic ? (xattr_starts == 0 && xattr_finishes == 0) :
                           (xattr_starts > 0 && xattr_starts == xattr_finishes));
        int output_fd = open(output, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(output_fd >= 0);
        assert(fstat(input_fd, &after) == 0 && fstat(output_fd, &copied) == 0);
        fork_source_unchanged(&original, &after);
        assert(original.st_dev != copied.st_dev || original.st_ino != copied.st_ino);
        assert(fgetxattr(input_fd, "com.apple.ResourceFork", NULL, 0, 0, 0) == (ssize_t)fork_case->size);
        assert(fgetxattr(output_fd, "com.apple.ResourceFork", NULL, 0, 0, 0) == (ssize_t)fork_case->size);
        assert(fgetxattr(input_fd, "com.apple.ResourceFork", source_value, fork_case->size, 0, 0) == (ssize_t)fork_case->size);
        assert(fgetxattr(output_fd, "com.apple.ResourceFork", destination_value, fork_case->size, 0, 0) == (ssize_t)fork_case->size);
        for (size_t i = 0; i < fork_case->size; i++) {
            assert(source_value[i] == expected[i]);
            unsigned char wanted = expected[i];
            if (fork_case->action == FORK_CORRUPT && i == fork_case->byte) wanted ^= 0x5a;
            assert(destination_value[i] == wanted);
        }
        char data[8];
        assert(pread(input_fd, data, sizeof(data), 0) == sizeof(data) && !memcmp(data, "sentinel", sizeof(data)));
        assert(pread(output_fd, data, sizeof(data), 0) == sizeof(data) && !memcmp(data, "sentinel", sizeof(data)));
        assert(fstat(input_fd, &after) == 0); fork_source_unchanged(&original, &after);
        assert(lstat(input, &named) == 0 && named.st_dev == original.st_dev && named.st_ino == original.st_ino);
        assert(lstat(output, &named) == 0 && named.st_dev == copied.st_dev && named.st_ino == copied.st_ino);
        assert(fstat(output_fd, &named) == 0 && named.st_dev == copied.st_dev && named.st_ino == copied.st_ino);
        assert(close(input_fd) == 0 && close(output_fd) == 0);
        free(expected); free(source_value); free(destination_value);
        assert(!fork_allocation && fork_allocations == fork_frees);
        fprintf(stderr, "VERIFY ResourceFork %s: result=%d errno=%d mutation=%d callbacks=%d/%d reads=%u queries=%u allocations=%u frees=%u source_unchanged=1\n",
                fork_case->name, result, error, fork_mutations, xattr_starts, xattr_finishes,
                fork_reads, fork_queries, fork_allocations, fork_frees);
        assert(result == (fork_case->error ? -1 : 0) && error == fork_case->error);
        if (automatic)
            fprintf(stderr, "VERIFY ResourceFork auto transport %s: clone=%d success=%d metadata=%d data=%d reopen=%d RF=%d/%d joined=%d/%d cancel_observed=%d\n",
                    fork_case->name, auto_clones, auto_successes, auto_metadata, auto_data, auto_reopens,
                    auto_rf_starts, auto_rf_finishes, joined, created, auto_cancel_observed);
        assert(fork_mutations == (fork_case->action == FORK_CORRUPT));
        unsigned chunks = (unsigned)((fork_case->size + 65535) / 65536);
        if (fork_case->action == FORK_OVERSIZE) {
            assert(fork_reads == 0 && fork_queries == 2 && fork_allocations == 0);
        } else if (fork_case->action == FORK_ALLOC_ERROR) {
            assert(fork_reads == 0 && fork_queries == 2 && fork_allocation_errors == 1 && fork_allocations == 0);
        } else if (fork_case->action == FORK_QUERY_ERROR && fork_case->call == 1) {
            assert(fork_reads == 0 && fork_queries == 1 && fork_allocations == 0);
        } else {
            assert(fork_allocations == (fork_case->size > 256));
            if (fork_case->action == FORK_CORRUPT) {
                assert(fork_reads == 2 * (fork_case->byte / 65536 + 1) && fork_queries == 2);
            } else if (fork_case->action == FORK_READ_ERROR || fork_case->action == FORK_SHORT ||
                       fork_case->action == FORK_ZERO || fork_case->action == FORK_CANCEL) {
                assert(fork_reads == fork_case->call && fork_queries == 2);
            } else {
                assert(fork_reads == chunks * 2 && fork_source_bytes == fork_case->size && fork_destination_bytes == fork_case->size);
                if (fork_case->action == FORK_QUERY_ERROR || fork_case->action == FORK_GROW || fork_case->action == FORK_SHRINK)
                    assert(fork_queries == fork_case->call);
                else assert(fork_queries == 4);
            }
        }
        completed_cases++;
    }
    fork_case = NULL;
    if (automatic)
        printf("PASS ResourceFork auto values: %u cases; unavailable real setup=%u; no OS4GiB claim\n", completed_cases, unavailable);
    else
        printf("PASS ResourceFork values: %u cases; unavailable real setup=%u; no OS4GiB claim\n", completed_cases, unavailable);
}
static void completion_case(const char *base, const char *kind, enum completion_fault injection,
                              int deferred, unsigned workers, int expected_error) {
    char root[PATH_MAX], tree[PATH_MAX], target[PATH_MAX], directory[PATH_MAX], input[PATH_MAX], output[PATH_MAX];
    char alias[PATH_MAX], path[PATH_MAX];
    assert(snprintf(root, sizeof(root), "%s/completion-%s-%u", base, kind, workers) < (int)sizeof(root));
    assert(mkdir(root, 0700) == 0); file(root, "sentinel");
    snprintf(tree, sizeof(tree), "%s/input", root); assert(mkdir(tree, 0700) == 0);
    snprintf(target, sizeof(target), "%s/output", root);
    snprintf(directory, sizeof(directory), "%s/a", tree); assert(mkdir(directory, 0700) == 0); file(directory, "eligible");
    snprintf(input, sizeof(input), "%s/a/eligible", tree);
    snprintf(output, sizeof(output), "%s/a/eligible", target);
    if (deferred) {
        snprintf(directory, sizeof(directory), "%s/b", tree); assert(mkdir(directory, 0700) == 0);
        snprintf(alias, sizeof(alias), "%s/b/alias", tree); assert(link(input, alias) == 0);
    }
    int fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    acl_t acl = acl_init(0); assert(acl);
    assert(acl_set_fd_np(fd, acl, ACL_TYPE_EXTENDED) == 0); acl_free(acl);
    assert(fsetxattr(fd, "user.stallion-test", "metadata", 8, 0, 0) == 0);
    assert(fsetxattr(fd, "com.apple.ResourceFork", "resource", 8, 0, 0) == 0);
    struct stat original_leaf, original_root, original_sentinel, after, copied;
    assert(fstat(fd, &original_leaf) == 0 && close(fd) == 0);
    assert(stat(tree, &original_root) == 0);
    snprintf(path, sizeof(path), "%s/sentinel", root); assert(lstat(path, &original_sentinel) == 0);
    assert(original_leaf.st_uid == geteuid() && (original_leaf.st_mode & 07777) == 0600 && original_leaf.st_flags == 0);
    assert(original_leaf.st_nlink == (deferred ? 2 : 1));
    completion_source_root = original_root; auto_source_identity = original_leaf;
    memset(&completion_destination_root, 0, sizeof(completion_destination_root));
    memset(&completion_destination_leaf, 0, sizeof(completion_destination_leaf));
    completion_testing = auto_testing = 1; completion_fault = injection; completion_expected_directories = deferred ? 2 : 1;
    fault = kind; caller = pthread_self(); auto_source_acl = NULL; auto_acl_pending = 0;
    copy_calls = starts = created = joined = cancelled = active = auto_cancel_observed = 0;
    auto_clones = auto_successes = auto_exdev = auto_metadata = auto_data = auto_reopens = 0;
    auto_rf_starts = auto_rf_finishes = 0; auto_ready = auto_gid_changes = auto_uid_faults = auto_preverified_path = 0; auto_source_checks = auto_destination_stats = 0;
    completion_partial = completion_root_calls = completion_child_directories = completion_leaf_copies = 0;
    completion_close_errors = completion_leaf_verified = completion_root_engine = completion_root_verified = completion_mutations = 0;
    int before = descriptors();
    int result = stallion_copy_with_strategy(tree, target, STALLION_COPY_AUTO, workers, cancel, NULL, path, sizeof(path));
    int error = errno;
    completion_testing = auto_testing = 0; auto_source_acl = NULL; auto_acl_pending = 0;
    assert(result == -1 && error == expected_error);
    assert(descriptors() == before && created == joined && active == 0);
    assert(auto_clones == 1);
    int partial = injection == COMPLETION_PARTIAL_EIO || injection == COMPLETION_PARTIAL_ENOSPC;
    int mutation = injection == COMPLETION_SOURCE_PRE_METADATA;
    int closing = injection == COMPLETION_CLOSE_LEAF || injection == COMPLETION_CLOSE_DIRECTORY || injection == COMPLETION_CLOSE_DEFERRED;
    int late = closing && injection != COMPLETION_CLOSE_LEAF;
    late = late || injection == COMPLETION_ROOT_EACCES || injection == COMPLETION_ROOT_EIO ||
        injection == COMPLETION_DEFERRED_EACCES || injection == COMPLETION_DEFERRED_EIO;
    assert(auto_successes == !partial && auto_data == partial && auto_metadata == 0);
    assert(completion_partial == partial && completion_mutations == mutation && completion_close_errors == closing);
    assert(completion_root_calls == late);
    if (!partial) assert(auto_rf_starts == 0 && auto_rf_finishes == 0);
    if (closing) assert(injection == COMPLETION_CLOSE_LEAF ? completion_leaf_verified == 1 : completion_root_verified == 1);
    assert(lstat(tree, &after) == 0); fork_source_unchanged(&original_root, &after);
    assert(lstat(input, &after) == 0);
    if (mutation) {
        struct stat expected = original_leaf;
        assert(after.st_flags == (original_leaf.st_flags | UF_NODUMP));
        expected.st_flags = after.st_flags; expected.st_ctimespec = after.st_ctimespec;
        fork_source_unchanged(&expected, &after);
    } else fork_source_unchanged(&original_leaf, &after);
    if (deferred) {
        snprintf(alias, sizeof(alias), "%s/b/alias", tree);
        assert(lstat(alias, &after) == 0); fork_source_unchanged(&original_leaf, &after);
    }
    assert(lstat(target, &copied) == 0 && S_ISDIR(copied.st_mode));
    assert(lstat(output, &copied) == 0 && S_ISREG(copied.st_mode) && !completion_same(&original_leaf, &copied));
    fd = open(output, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    char bytes[8]; size_t expected_size = partial ? 4 : 8;
    assert(copied.st_size == (off_t)expected_size && pread(fd, bytes, expected_size, 0) == (ssize_t)expected_size &&
           !memcmp(bytes, "sentinel", expected_size));
    if (!partial && !mutation) {
        assert(copied.st_mode == original_leaf.st_mode && copied.st_uid == original_leaf.st_uid &&
               copied.st_gid == original_leaf.st_gid && copied.st_flags == original_leaf.st_flags);
        assert(fgetxattr(fd, "user.stallion-test", bytes, 8, 0, 0) == 8 && !memcmp(bytes, "metadata", 8));
        assert(fgetxattr(fd, "com.apple.ResourceFork", bytes, 8, 0, 0) == 8 && !memcmp(bytes, "resource", 8));
    }
    assert(close(fd) == 0);
    fd = open(input, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    assert(pread(fd, bytes, 8, 0) == 8 && !memcmp(bytes, "sentinel", 8));
    assert(fgetxattr(fd, "user.stallion-test", bytes, 8, 0, 0) == 8 && !memcmp(bytes, "metadata", 8));
    assert(fgetxattr(fd, "com.apple.ResourceFork", bytes, 8, 0, 0) == 8 && !memcmp(bytes, "resource", 8));
    assert(close(fd) == 0);
    if (late) {
        assert(completion_leaf_copies == 1 && completion_child_directories == completion_expected_directories);
        if (deferred) {
            struct stat linked; snprintf(alias, sizeof(alias), "%s/b/alias", target);
            assert(lstat(alias, &linked) == 0 && completion_same(&copied, &linked) && copied.st_nlink == 2);
        }
        assert(stallion_copy_with_strategy(tree, target, STALLION_COPY_AUTO, workers, NULL, NULL, path, sizeof(path)) == -1 && errno == EEXIST);
        assert(descriptors() == before);
    }
    sentinel(root); snprintf(path, sizeof(path), "%s/sentinel", root);
    assert(lstat(path, &after) == 0); fork_source_unchanged(&original_sentinel, &after);
    fprintf(stderr, "VERIFY completion %s jobs=%u: errno=%d clone=%d success=%d metadata=%d data=%d partial=%d close_error=%d root_calls=%d leaf_verified=%d root_verified=%d child_dirs=%d mutation=%d joined=%d/%d\n",
            kind, workers, error, auto_clones, auto_successes, auto_metadata, auto_data, completion_partial,
            completion_close_errors, completion_root_calls, completion_leaf_verified, completion_root_verified,
            completion_child_directories, completion_mutations, joined, created);
}
static void completion_cases(const char *base) {
    const struct { const char *name; enum completion_fault injection; int deferred, error; } cases[] = {
        {"fallback-partial-eio", COMPLETION_PARTIAL_EIO, 0, EIO},
        {"fallback-partial-enospc", COMPLETION_PARTIAL_ENOSPC, 0, ENOSPC},
        {"close-leaf", COMPLETION_CLOSE_LEAF, 0, EIO},
        {"close-directory", COMPLETION_CLOSE_DIRECTORY, 0, EIO},
        {"close-deferred-directory", COMPLETION_CLOSE_DEFERRED, 1, EIO},
        {"root-metadata-eacces", COMPLETION_ROOT_EACCES, 0, EACCES},
        {"root-metadata-eio", COMPLETION_ROOT_EIO, 0, EIO},
        {"deferred-root-metadata-eacces", COMPLETION_DEFERRED_EACCES, 1, EACCES},
        {"deferred-root-metadata-eio", COMPLETION_DEFERRED_EIO, 1, EIO},
        {"source-pre-metadata", COMPLETION_SOURCE_PRE_METADATA, 0, ESTALE}
    };
    for (unsigned workers = 1; workers <= 4; workers += 3)
        for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++)
            completion_case(base, cases[i].name, cases[i].injection, cases[i].deferred, workers, cases[i].error);
    puts("PASS completion faults: 10 cases at jobs1/4; no durability or CLI fault claim");
}
int main(int argc, char **argv) {
    assert(argc == 2 || argc == 3 || argc == 5);
    if (argc == 5) {
        assert(!strcmp(argv[2], "--auto-cross-volume"));
        if (__builtin_available(macOS 13.0, *)) { auto_cross_volume(argv[3], argv[4]); return 0; }
        return 77;
    }
    if (argc == 3) {
        if (__builtin_available(macOS 13.0, *)) {
            if (!strcmp(argv[2], "--completion-faults")) { completion_cases(argv[1]); return 0; }
            if (!strcmp(argv[2], "--resource-forks")) { fork_value_cases(argv[1], 0); return 0; }
            assert(!strcmp(argv[2], "--xattr-values") || !strcmp(argv[2], "--xattr-characterize"));
            xattr_value_cases(argv[1], !strcmp(argv[2], "--xattr-characterize"), 0);
            return 0;
        }
        fprintf(stderr, "xattr copy faults require macOS 13 or later\n");
        return 77;
    }
    int operations = 2;
    if (__builtin_available(macOS 13.0, *)) operations = 4;
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
        xattr_value_cases(argv[1], 0, 0);
        xattr_value_cases(argv[1], 0, 1);
        auto_cases(argv[1]);
        fork_value_cases(argv[1], 1);
    }
    return 0;
}
