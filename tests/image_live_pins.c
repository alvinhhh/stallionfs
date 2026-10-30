/* Disposable-image core tests. This TU includes the core for bounded lifetime
 * accounting/context assertions; link fskit_write_hooks.c separately, unchanged.
 * No FSKit, installed extension or mount is involved. */
#define _DARWIN_C_SOURCE 1
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "fskit_write_hooks.h"
void sfs_diag_fault(int, int);
int sfs_diag_hit(void);
int sfs_diag_fences(void);
static int close_failure;
static int partial_slot;
static int pin_test_close(int);
static ssize_t pin_test_pwrite(int, const void *, size_t, off_t);
#define SFS_IMAGE_DIAGNOSTIC_TESTING 1
#define malloc sfs_diag_malloc
#define calloc sfs_diag_calloc
#define pread sfs_diag_pread
#define pwrite pin_test_pwrite
#define fcntl sfs_diag_fcntl
#define clock_gettime sfs_diag_clock_gettime
#define close pin_test_close
#include "../filesystem/image.c"
#undef malloc
#undef calloc
#undef pread
#undef pwrite
#undef fcntl
#undef clock_gettime
#undef close
static int pin_test_close(int fd) {
    int e = close(fd);
    if (close_failure) { close_failure = 0; errno = EIO; return -1; }
    return e;
}
static ssize_t pin_test_pwrite(int fd, const void *bytes, size_t size, off_t at) {
    if (partial_slot && at < 8192) {
        if (partial_slot == 1) { partial_slot = 2; return pwrite(fd, bytes, size > 19 ? 19 : size, at); }
        errno = ENOSPC; return -1;
    }
    return sfs_diag_pwrite(fd, bytes, size, at);
}
static sfs_result receipt;
static unsigned sequence;
static const char *parent;
#define OK(call) assert((call) == SFS_OK)
static sfs_metadata_initial initial(unsigned kind) {
    sfs_metadata_initial m = { .mode = kind == SFS_DIRECTORY ? 0040750u : kind == SFS_SYMLINK ? 0120777u : 0100640u,
        .uid = (uint32_t)geteuid(), .gid = (uint32_t)getegid(), .flags = SFS_FLAGS_SUPPORTED,
        .restore = 7, .birth = {1000, 1}, .access = {1001, 2}, .modification = {1002, 3} };
    return m;
}
static sfs_image *fresh(unsigned minor, char name[48], unsigned slots) {
    assert(snprintf(name, 48, "pins-%u.sfs", sequence++) < 48);
    sfs_image *h = NULL; sfs_metadata_initial root = initial(SFS_DIRECTORY);
    sfs_diag_fault(0, 0);
    if (minor == 2) OK(sfs_image_create(parent, name, UINT64_C(67108864), &h, &receipt));
    else OK(sfs_image_create_metadata_version(parent, name, UINT64_C(67108864), minor, &root, &h, &receipt));
    if (slots) OK(sfs_image_pin_configure(h, slots, UINT64_C(1048576), &receipt));
    return h;
}
static sfs_inode add(sfs_image *h, sfs_inode directory, const char *name, unsigned kind) {
    sfs_inode id = 0; sfs_metadata_initial m = initial(kind);
    if (kind == SFS_SYMLINK) OK(sfs_image_symlink_metadata(h, directory, name, strlen(name), "../opaque-target", 16, &m, &id, &receipt));
    else OK(sfs_image_add_metadata(h, directory, name, strlen(name), kind, &m, &id, &receipt));
    return id;
}
static void commit(sfs_image *h) {
    sfs_diag_fault(0, 0); OK(sfs_image_commit(h, &receipt));
    assert(receipt.fence_attempted == 3 && receipt.fence_succeeded == 3 && !receipt.transaction_active);
    assert(sfs_diag_fences() == 2);
}
static void verify(sfs_image *h) {
    sfs_verify_budget b = { .raw_cells = 100000, .metadata_read_bytes = UINT64_C(104857600),
        .metadata_hash_bytes = UINT64_C(104857600), .checks = UINT64_C(10000000),
        .auxiliary_bytes = UINT64_C(104857600), .auxiliary_io_bytes = UINT64_C(104857600) };
    OK(sfs_image_verify(h, &b, &receipt)); assert(receipt.coverage == SFS_COVERAGE_FULL_REACHABLE);
}
static void bytes(sfs_image *h, sfs_pin pin, const void *expected, size_t size) {
    uint8_t b[16385]; size_t count = 99; assert(size <= sizeof(b));
    memset(b, 0xa5, sizeof(b)); sfs_image_clear_read_cache(h);
    OK(sfs_image_pin_read(h, pin, 0, b, sizeof(b), &count, &receipt));
    assert(count == size && !memcmp(b, expected, size));
}
static sfs_pin named_pin(sfs_image *h, const char *name, sfs_inode *id) {
    OK(sfs_image_begin(h, &receipt)); *id = add(h, 1, name, SFS_FILE);
    OK(sfs_image_write(h, *id, 0, "old", 3, &receipt)); commit(h);
    sfs_pin pin; OK(sfs_image_pin_acquire(h, *id, &pin, &receipt));
    return pin;
}
static sfs_pin detached(sfs_image *h, const char *name, sfs_inode *id) {
    sfs_pin pin = named_pin(h, name, id);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_unlink_expected(h, 1, name, strlen(name), *id, &receipt)); commit(h);
    return pin;
}
static void contents_aliases_snapshots(void) {
    char name[48]; sfs_image *h = fresh(6, name, 8); sfs_inode id;
    OK(sfs_image_begin(h, &receipt)); id = add(h, 1, "file", SFS_FILE);
    uint8_t data[12289]; for (size_t i = 0; i < sizeof(data); ++i) data[i] = (uint8_t)(17 * i + 3);
    OK(sfs_image_write(h, id, 0, data, sizeof(data), &receipt));
    OK(sfs_image_set_xattr(h, id, "own", 3, data, 8193, &receipt));
    sfs_inode unrelated = add(h, 1, "unrelated", SFS_FILE);
    OK(sfs_image_set_xattr(h, unrelated, "secret", 6, "other", 5, &receipt));
    OK(sfs_image_link(h, id, 1, "alias", 5, &receipt)); commit(h);
    sfs_pin pin, untouched = {0}; OK(sfs_image_pin_acquire(h, id, &pin, &receipt));
    assert(sfs_image_pin_acquire(h, id, &untouched, &receipt) == SFS_EXISTS && !untouched.instance);
    sfs_view before; OK(sfs_image_begin(h, &receipt)); OK(sfs_image_snapshot(h, "before", 6, &before, &receipt)); commit(h);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_unlink(h, 1, "file", 4, &receipt)); commit(h);
    sfs_pin_stat st; OK(sfs_image_pin_stat(h, pin, &st, &receipt)); assert(st.linked && st.metadata.link_count == 1);
    /* Latest pending batch must be captured in full, beyond the last raw cell. */
    OK(sfs_image_begin(h, &receipt)); data[9000] = 99;
    OK(sfs_image_pin_write(h, pin, 9000, data + 9000, 1, &receipt));
    OK(sfs_image_unlink_expected(h, 1, "alias", 5, id, &receipt));
    OK(sfs_image_pin_stat(h, pin, &st, &receipt)); assert(st.linked);
    OK(sfs_image_abort(h, &receipt)); data[9000] = (uint8_t)(17 * 9000 + 3); bytes(h, pin, data, sizeof(data));
    OK(sfs_image_begin(h, &receipt)); data[9000] = 99;
    OK(sfs_image_pin_write(h, pin, 9000, data + 9000, 1, &receipt));
    OK(sfs_image_unlink(h, 1, "alias", 5, &receipt)); commit(h);
    OK(sfs_image_pin_stat(h, pin, &st, &receipt));
    assert(!st.linked && !st.metadata.link_count && !st.metadata.entry.parent && !st.metadata.entry.name_length);
    assert(st.metadata.mode == 0100640u && st.metadata.flags == SFS_FLAGS_SUPPORTED && st.metadata.birth.seconds == 1000);
    assert(st.metadata.uid == (uint32_t)geteuid() && st.metadata.gid == (uint32_t)getegid() && st.metadata.access.seconds == 1001);
    bytes(h, pin, data, sizeof(data));
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_write(h, pin, 0, "Q", 1, &receipt));
    sfs_metadata_update named_update = { .fields = SFS_META_MODE, .mode = 0100600u };
    assert(sfs_image_set_metadata(h, id, &named_update, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_write(h, id, 0, "X", 1, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_resize(h, id, 1, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_set_xattr(h, id, "own", 3, "bad", 3, &receipt) == SFS_NOT_FOUND);
    OK(sfs_image_abort(h, &receipt)); bytes(h, pin, data, sizeof(data));
    uint8_t x[8193]; size_t count; uint64_t size;
    OK(sfs_image_pin_xattr_size(h, pin, "own", 3, &size, &receipt)); assert(size == sizeof(x));
    OK(sfs_image_pin_read_xattr(h, pin, "own", 3, 0, x, sizeof(x), &count, &receipt)); assert(count == sizeof(x));
    for (size_t i = 0; i < sizeof(x); ++i) assert(x[i] == (uint8_t)(17 * i + 3));
    assert(sfs_image_pin_xattr_size(h, pin, "secret", 6, &size, &receipt) == SFS_NOT_FOUND);
    sfs_image_information info; OK(sfs_image_get_information(h, &info, &receipt));
    sfs_xattr_entry xe; int found;
    OK(sfs_image_pin_next_xattr(h, pin, info.committed.generation, info.committed.root_digest, NULL, 0, &xe, &found, &receipt));
    assert(found && xe.name_length == 3 && !memcmp(xe.name, "own", 3));
    OK(sfs_image_pin_next_xattr(h, pin, info.committed.generation, info.committed.root_digest, "own", 3, &xe, &found, &receipt)); assert(!found);
    reference ns = h->live.ns.ref; uint64_t generation = h->current.generation;
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_resize(h, pin, 4097, &receipt));
    OK(sfs_image_pin_resize(h, pin, sizeof(data), &receipt));
    OK(sfs_image_pin_set_xattr(h, pin, "own", 3, "new", 3, &receipt));
    sfs_metadata_update update = { .fields = SFS_META_MODE, .mode = 0100600u };
    OK(sfs_image_pin_set_metadata(h, pin, &update, &receipt));
    bytes(h, pin, data, sizeof(data)); commit(h);
    assert(same_ref(&h->live.ns.ref, &ns) && h->current.generation == generation + 1);
    memset(data + 4097, 0, sizeof(data) - 4097); bytes(h, pin, data, sizeof(data));
    OK(sfs_image_pin_stat(h, pin, &st, &receipt)); assert(st.metadata.mode == 0100600u);
    OK(sfs_image_pin_read_xattr(h, pin, "own", 3, 0, x, sizeof(x), &count, &receipt)); assert(count == 3 && !memcmp(x, "new", 3));
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_remove_xattr(h, pin, "own", 3, &receipt));
    sfs_view after; OK(sfs_image_snapshot(h, "after", 5, &after, &receipt));
    sfs_inode replacement = add(h, 1, "file", SFS_FILE); assert(replacement > unrelated); commit(h);
    assert(sfs_image_pin_xattr_size(h, pin, "own", 3, &size, &receipt) == SFS_NOT_FOUND);
    sfs_entry entry; assert(sfs_image_stat(h, after, id, &entry, &receipt) == SFS_NOT_FOUND);
    uint8_t old[12289]; OK(sfs_image_read(h, before, id, 0, old, sizeof(old), &count, &receipt));
    assert(count == sizeof(old)); for (size_t i = 0; i < sizeof(old); ++i) assert(old[i] == (uint8_t)(17 * i + 3));
    verify(h); OK(sfs_image_pin_release(h, pin, &receipt));
    assert(sfs_image_pin_release(h, pin, &receipt) == SFS_INVALID);
    OK(sfs_image_close(h, &receipt)); OK(sfs_image_open(parent, name, &h, &receipt));
    OK(sfs_image_pin_configure(h, 8, 1048576, &receipt));
    assert(sfs_image_pin_stat(h, pin, &st, &receipt) == SFS_INVALID);
    assert(sfs_image_stat(h, 0, id, &entry, &receipt) == SFS_NOT_FOUND);
    OK(sfs_image_lookup(h, 0, 1, "file", 4, &entry, &receipt)); assert(entry.inode == replacement);
    verify(h); OK(sfs_image_close(h, &receipt));
}
static void replacement_and_types(void) {
    char name[48]; sfs_image *h = fresh(6, name, 8);
    OK(sfs_image_begin(h, &receipt)); sfs_inode src = add(h, 1, "src", SFS_FILE), dst = add(h, 1, "dst", SFS_FILE);
    OK(sfs_image_write(h, src, 0, "source", 6, &receipt)); OK(sfs_image_write(h, dst, 0, "target", 6, &receipt));
    OK(sfs_image_link(h, src, 1, "same", 4, &receipt)); commit(h);
    sfs_pin sp, dp; OK(sfs_image_pin_acquire(h, src, &sp, &receipt)); OK(sfs_image_pin_acquire(h, dst, &dp, &receipt));
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_rename_replace(h, 1, "src", 3, src, 1, "same", 4, src, &receipt)); commit(h);
    sfs_entry e; OK(sfs_image_lookup(h, 0, 1, "src", 3, &e, &receipt));
    OK(sfs_image_begin(h, &receipt));
    assert(sfs_image_unlink_expected(h, 1, "dst", 3, src, &receipt) == SFS_STATE);
    assert(sfs_image_rename_replace(h, 1, "src", 3, src, 1, "dst", 3, 0, &receipt) == SFS_STATE);
    /* Second edit's clock failure must not leave destination-only deletion. */
    sfs_diag_fault(6, 2); assert(sfs_image_rename_replace(h, 1, "src", 3, src, 1, "dst", 3, dst, &receipt) == SFS_TIME_UNAVAILABLE);
    assert(sfs_diag_hit() == 1 && !receipt.transaction_active); sfs_diag_fault(0, 0);
    OK(sfs_image_lookup(h, 0, 1, "dst", 3, &e, &receipt)); assert(e.inode == dst); bytes(h, dp, "target", 6);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_rename_replace(h, 1, "src", 3, src, 1, "dst", 3, dst, &receipt)); commit(h);
    bytes(h, dp, "target", 6); bytes(h, sp, "source", 6);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_write(h, dp, 0, "orphan", 6, &receipt)); commit(h);
    bytes(h, sp, "source", 6); bytes(h, dp, "orphan", 6);
    OK(sfs_image_lookup(h, 0, 1, "dst", 3, &e, &receipt)); assert(e.inode == src);
    OK(sfs_image_begin(h, &receipt)); sfs_inode victim = add(h, 1, "victim", SFS_FILE), another = add(h, 1, "another", SFS_FILE);
    OK(sfs_image_write(h, victim, 0, "shared", 6, &receipt)); OK(sfs_image_link(h, victim, 1, "survivor", 8, &receipt)); commit(h);
    sfs_pin vp; OK(sfs_image_pin_acquire(h, victim, &vp, &receipt));
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_rename_replace(h, 1, "another", 7, another, 1, "victim", 6, victim, &receipt)); commit(h);
    sfs_pin_stat shared; OK(sfs_image_pin_stat(h, vp, &shared, &receipt)); assert(shared.linked && shared.metadata.link_count == 1);
    bytes(h, vp, "shared", 6); OK(sfs_image_pin_release(h, vp, &receipt));
    OK(sfs_image_begin(h, &receipt));
    OK(sfs_image_rename_replace(h, 1, "victim", 6, another, 1, "absent", 6, 0, &receipt)); commit(h);
    assert(sfs_image_lookup(h, 0, 1, "victim", 6, &e, &receipt) == SFS_NOT_FOUND);
    OK(sfs_image_lookup(h, 0, 1, "absent", 6, &e, &receipt)); assert(e.inode == another);
    OK(sfs_image_begin(h, &receipt)); sfs_inode d1 = add(h, 1, "d1", SFS_DIRECTORY), d2 = add(h, 1, "d2", SFS_DIRECTORY);
    sfs_inode nonempty = add(h, 1, "nonempty", SFS_DIRECTORY); (void)add(h, nonempty, "child", SFS_FILE);
    sfs_inode l1 = add(h, 1, "l1", SFS_SYMLINK), l2 = add(h, 1, "l2", SFS_SYMLINK);
    OK(sfs_image_set_xattr(h, d2, "dir", 3, "directory", 9, &receipt));
    OK(sfs_image_set_xattr(h, l2, "link", 4, "symlink", 7, &receipt)); commit(h);
    sfs_pin dirpin, linkpin; OK(sfs_image_pin_acquire(h, d2, &dirpin, &receipt)); OK(sfs_image_pin_acquire(h, l2, &linkpin, &receipt));
    OK(sfs_image_begin(h, &receipt));
    assert(sfs_image_rename_replace(h, 1, "d1", 2, d1, 1, "nonempty", 8, nonempty, &receipt) == SFS_STATE);
    assert(sfs_image_rename_replace(h, 1, "d1", 2, d1, 1, "dst", 3, src, &receipt) == SFS_INVALID);
    assert(sfs_image_rename_replace(h, 1, "d1", 2, d1, d1, "cycle", 5, 0, &receipt) == SFS_INVALID);
    assert(sfs_image_remove(h, 1, &receipt) == SFS_INVALID);
    OK(sfs_image_rename_replace(h, 1, "d1", 2, d1, 1, "d2", 2, d2, &receipt));
    OK(sfs_image_rename_replace(h, 1, "l1", 2, l1, 1, "l2", 2, l2, &receipt)); commit(h);
    sfs_pin_stat st; OK(sfs_image_pin_stat(h, dirpin, &st, &receipt)); assert(!st.linked && st.metadata.entry.kind == SFS_DIRECTORY);
    char target[32]; size_t n; OK(sfs_image_pin_readlink(h, linkpin, target, sizeof(target), &n, &receipt)); assert(n == 16 && !memcmp(target, "../opaque-target", n));
    OK(sfs_image_pin_read_xattr(h, dirpin, "dir", 3, 0, target, sizeof(target), &n, &receipt)); assert(n == 9 && !memcmp(target, "directory", n));
    OK(sfs_image_pin_read_xattr(h, linkpin, "link", 4, 0, target, sizeof(target), &n, &receipt)); assert(n == 7 && !memcmp(target, "symlink", n));
    OK(sfs_image_begin(h, &receipt)); assert(sfs_image_pin_write(h, dirpin, 0, "x", 1, &receipt) == SFS_INVALID);
    assert(sfs_image_pin_resize(h, linkpin, 1, &receipt) == SFS_INVALID); OK(sfs_image_abort(h, &receipt));
    verify(h); OK(sfs_image_close(h, &receipt));
}
static void reservations_and_limits(void) {
    char name[48]; sfs_image *h = fresh(6, name, 0);
    assert(sfs_image_pin_configure(h, 2, 1, &receipt) == SFS_LIMIT && receipt.limit_reason == SFS_LIMIT_PIN_RESOURCES && !h->pins);
    sfs_diag_fault(7, 1); assert(sfs_image_pin_configure(h, 2, 1048576, &receipt) == SFS_NOMEM && !h->pins); sfs_diag_fault(0, 0);
    OK(sfs_image_pin_configure(h, 2, 1048576, &receipt)); uint64_t charged = h->pins->bytes;
    sfs_pin reserved, root, absent = {0}; OK(sfs_image_pin_reserve(h, &reserved, &receipt));
    OK(sfs_image_pin_acquire(h, 1, &root, &receipt));
    assert(sfs_image_pin_reserve(h, &absent, &receipt) == SFS_LIMIT && receipt.limit_reason == SFS_LIMIT_PIN_RESOURCES && !absent.instance);
    OK(sfs_image_begin(h, &receipt)); assert(sfs_image_commit(h, &receipt) == SFS_STATE);
    sfs_inode id = add(h, 1, "new", SFS_FILE); OK(sfs_image_pin_bind(h, reserved, id, &receipt));
    assert(sfs_image_pin_release(h, root, &receipt) == SFS_BUSY); OK(sfs_image_abort(h, &receipt));
    sfs_pin_stat st; assert(sfs_image_pin_stat(h, reserved, &st, &receipt) == SFS_INVALID);
    sfs_pin next; OK(sfs_image_pin_reserve(h, &next, &receipt)); assert(next.slot == reserved.slot && next.incarnation > reserved.incarnation);
    OK(sfs_image_begin(h, &receipt)); id = add(h, 1, "new", SFS_FILE); OK(sfs_image_pin_bind(h, next, id, &receipt)); commit(h);
    OK(sfs_image_pin_stat(h, next, &st, &receipt)); assert(st.linked && st.metadata.entry.inode == id && h->pins->bytes == charged);
    sfs_pin bad = next; bad.session[0] ^= 1; assert(sfs_image_pin_stat(h, bad, &st, &receipt) == SFS_INVALID);
    OK(sfs_image_pin_release(h, root, &receipt));
    char other_name[48]; sfs_image *other = fresh(6, other_name, 2);
    assert(sfs_image_pin_stat(other, next, &st, &receipt) == SFS_INVALID); OK(sfs_image_close(other, &receipt));
    OK(sfs_image_close(h, &receipt));
    h = fresh(6, name, 1); h->pins->slots[0].incarnation = UINT64_MAX - 1;
    OK(sfs_image_pin_acquire(h, 1, &root, &receipt)); assert(root.incarnation == UINT64_MAX);
    OK(sfs_image_pin_release(h, root, &receipt)); assert(h->pins->free_head == PIN_NONE);
    assert(sfs_image_pin_acquire(h, 1, &absent, &receipt) == SFS_LIMIT && receipt.limit_reason == SFS_LIMIT_PIN_RESOURCES);
    assert(sfs_image_pin_stat(h, root, &st, &receipt) == SFS_INVALID); OK(sfs_image_close(h, &receipt));
    for (unsigned minor = 2; minor < 6; ++minor) {
        h = fresh(minor, name, 0); sfs_pin zero = {0};
        sfs_diag_fault(7, 1); assert(sfs_image_pin_configure(h, 2, 1048576, &receipt) == SFS_UNSUPPORTED); assert(!sfs_diag_hit() && !h->pins);
        assert(sfs_image_pin_acquire(h, 1, &zero, &receipt) == SFS_UNSUPPORTED);
        assert(sfs_image_pin_reserve(h, &zero, &receipt) == SFS_UNSUPPORTED);
        assert(sfs_image_pin_stat(h, zero, &st, &receipt) == SFS_UNSUPPORTED);
        assert(sfs_image_pin_write(h, zero, 0, "x", 1, &receipt) == SFS_UNSUPPORTED);
        assert(sfs_image_pin_bind(h, zero, 1, &receipt) == SFS_UNSUPPORTED);
        assert(sfs_image_pin_release(h, zero, &receipt) == SFS_UNSUPPORTED);
        sfs_diag_fault(0, 0); OK(sfs_image_close(h, &receipt));
    }
}
static void abort_capacity_and_faults(void) {
    char name[48]; sfs_image *h = fresh(6, name, 4); sfs_inode id; sfs_pin pin = detached(h, "file", &id);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_write(h, pin, 8192, "new", 3, &receipt));
    bytes(h, pin, "old", 3); OK(sfs_image_abort(h, &receipt)); bytes(h, pin, "old", 3);
    uint64_t physical = h->eof; OK(sfs_image_begin(h, &receipt)); sfs_image_diagnostic_capacity(h, physical + CELL);
    assert(sfs_image_pin_write(h, pin, 0, "new", 3, &receipt) == SFS_LIMIT && receipt.limit_reason == SFS_LIMIT_APPEND_CAPACITY);
    assert(!receipt.transaction_active && h->eof == physical); sfs_image_diagnostic_capacity(h, 0); bytes(h, pin, "old", 3);
    OK(sfs_image_close(h, &receipt));
    h = fresh(6, name, 4); pin = detached(h, "large", &id); uint64_t charged = h->pins->bytes;
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_resize(h, pin, SFS_FILE_MAX, &receipt)); commit(h);
    char hole = 1; size_t count; OK(sfs_image_pin_read(h, pin, SFS_FILE_MAX - 1, &hole, 1, &count, &receipt));
    assert(count == 1 && hole == 0 && h->pins->bytes == charged);
    OK(sfs_image_begin(h, &receipt)); assert(sfs_image_pin_write(h, pin, SFS_FILE_MAX, "x", 1, &receipt) == SFS_LIMIT);
    assert(receipt.limit_reason == SFS_LIMIT_FILE_SIZE && !receipt.transaction_active);
    verify(h); OK(sfs_image_close(h, &receipt));
    h = fresh(6, name, 4); pin = detached(h, "host-full", &id); OK(sfs_image_begin(h, &receipt));
    sfs_diag_fault(1, 1); assert(sfs_image_pin_write(h, pin, 0, "new", 3, &receipt) == SFS_IO);
    assert(sfs_diag_hit() && receipt.system_errno == ENOSPC && receipt.poisoned && !receipt.transaction_active);
    sfs_diag_fault(0, 0); OK(sfs_image_pin_release(h, pin, &receipt)); OK(sfs_image_close(h, &receipt));
    for (int operation = 0; operation < 5; ++operation) {
        int reached_success = 0;
        for (int at = 1; at <= 128; ++at) {
            h = fresh(6, name, 4); pin = operation == 4 ? named_pin(h, "file", &id) : detached(h, "file", &id); OK(sfs_image_begin(h, &receipt));
            if (operation == 3) OK(sfs_image_pin_write(h, pin, 0, "new", 3, &receipt));
            sfs_diag_fault(7, at); enum sfs_status e;
            if (operation == 0) e = sfs_image_pin_write(h, pin, 0, "new", 3, &receipt);
            else if (operation == 1) e = sfs_image_pin_resize(h, pin, 1, &receipt);
            else if (operation == 2) e = sfs_image_pin_set_xattr(h, pin, "value", 5, "new", 3, &receipt);
            else if (operation == 3) e = sfs_image_commit(h, &receipt);
            else e = sfs_image_unlink_expected(h, 1, "file", 4, id, &receipt);
            int hit = sfs_diag_hit(); sfs_diag_fault(0, 0);
            if (hit) { assert(e == SFS_NOMEM); assert(!h->poisoned); bytes(h, pin, "old", 3); if (h->transaction) OK(sfs_image_abort(h, &receipt)); }
            else { assert(e == SFS_OK); if (h->transaction) OK(sfs_image_abort(h, &receipt)); if (operation == 3) bytes(h, pin, "new", 3); reached_success = 1; }
            verify(h); OK(sfs_image_close(h, &receipt)); if (reached_success) break;
        }
        assert(reached_success);
    }
    for (int fault = 1; fault <= 3; ++fault) {
        h = fresh(6, name, 4); pin = detached(h, "file", &id);
        OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_write(h, pin, 0, "new", 3, &receipt));
        sfs_diag_fault(fault == 2 ? 0 : 4, fault == 3 ? 2 : 1); partial_slot = fault == 2;
        enum sfs_status e = sfs_image_commit(h, &receipt); assert(sfs_diag_hit() || partial_slot == 2); partial_slot = 0;
        assert(e == (fault == 1 ? SFS_IO : SFS_OUTCOME_UNKNOWN) && receipt.poisoned && !receipt.transaction_active);
        assert(receipt.fence_attempted == (fault == 3 ? 3u : 1u) && receipt.fence_succeeded == (fault == 1 ? 0u : 1u));
        sfs_diag_fault(0, 0); sfs_pin_stat st; assert(sfs_image_pin_stat(h, pin, &st, &receipt) == SFS_POISONED);
        assert(sfs_image_begin(h, &receipt) == SFS_POISONED); OK(sfs_image_pin_release(h, pin, &receipt));
        close_failure = 1; assert(sfs_image_close(h, &receipt) == SFS_IO); /* Handle consumed. */
    }
}
static void detached_integrity(void) {
    char name[48]; sfs_image *h = fresh(6, name, 4); sfs_inode id; sfs_pin pin = detached(h, "file", &id);
    /* Unrelated newer IDs/generations must not replace the captured context. */
    for (unsigned i = 0; i < 3; ++i) { char child[8]; assert(snprintf(child, sizeof(child), "n%u", i) < 8); OK(sfs_image_begin(h, &receipt)); (void)add(h, 1, child, SFS_FILE); commit(h); }
    bytes(h, pin, "old", 3); reader r = current_reader(h, 0); node n; reference attrs; uint64_t next;
    OK(pin_committed(&r, pin, &n, &attrs, &next)); uint8_t row[MAX_ROW]; int found; key k = number_key(0);
    OK(index_get(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &k, row, &found)); assert(found);
    reference raw; assert(decode_ref(row + 8, &raw)); uint8_t changed = 0x77; assert(pwrite(h->fd, &changed, 1, (off_t)raw.offset) == 1);
    sfs_image_clear_read_cache(h); char b[3]; size_t count;
    assert(sfs_image_pin_read(h, pin, 0, b, sizeof(b), &count, &receipt) == SFS_CORRUPT);
    assert(receipt.poisoned && count == 0); OK(sfs_image_pin_release(h, pin, &receipt)); OK(sfs_image_close(h, &receipt));
    h = fresh(6, name, 4); pin = named_pin(h, "xattrs", &id);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_set_xattr(h, id, "value", 5, "protected", 9, &receipt)); commit(h);
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_unlink(h, 1, "xattrs", 6, &receipt)); commit(h);
    r = current_reader(h, 0); OK(xattr_read_target(&r, 0, 0, &pin, "value", 5, row));
    reference extent; assert(decode_ref(row + 280, &extent)); k = number_key(0);
    OK(index_get(&r, extent, MAP_EXTENT, UINT64_MAX, 9, &k, row, &found)); assert(found && decode_ref(row + 8, &raw));
    assert(pwrite(h->fd, &changed, 1, (off_t)raw.offset) == 1); sfs_image_clear_read_cache(h);
    char value[9]; assert(sfs_image_pin_read_xattr(h, pin, "value", 5, 0, value, sizeof(value), &count, &receipt) == SFS_CORRUPT);
    assert(receipt.poisoned && count == 0); OK(sfs_image_pin_release(h, pin, &receipt)); OK(sfs_image_close(h, &receipt));
}
static void complete_bytes(sfs_image *h, sfs_pin pin, const uint8_t *expected, size_t size) {
    uint8_t buffer[16384]; size_t count; sfs_image_clear_read_cache(h);
    for (size_t offset = 0; offset < size; offset += sizeof(buffer)) {
        size_t amount = size - offset; if (amount > sizeof(buffer)) amount = sizeof(buffer);
        OK(sfs_image_pin_read(h, pin, offset, buffer, amount, &count, &receipt));
        assert(count == amount && !memcmp(buffer, expected + offset, amount));
    }
    OK(sfs_image_pin_read(h, pin, size, buffer, 1, &count, &receipt)); assert(count == 0);
}
#define WIDE_BLOCKS 272u
#define WIDE_SIZE (WIDE_BLOCKS * CELL)
static void wide_write(sfs_image *h, sfs_pin pin, const uint8_t *data, int fail_rollover) {
    pin_slot *owner; OK(pin_resolve(h, pin, &owner));
    for (unsigned call = 0; call < 17; ++call) {
        uint64_t previous = 0;
        if (call == 16) {
            assert(h->batch && h->batch->detached == owner && h->batch->low == 0 && h->batch->high == 255);
            previous = h->batch->number;
            if (fail_rollover) sfs_diag_fault(7, 1);
        }
        enum sfs_status e = sfs_image_pin_write(h, pin, (uint64_t)call * 65536, data + call * 65536u, 65536, &receipt);
        if (call == 16 && fail_rollover) {
            assert(e == SFS_NOMEM && sfs_diag_hit() == 1 && receipt.transaction_active && !receipt.poisoned);
            assert(h->batch && h->batch->number == previous);
            sfs_diag_fault(0, 0); return;
        }
        assert(e == SFS_OK);
        if (call == 16) assert(h->batch->detached == owner && h->batch->number != previous && h->batch->low == 256 && h->batch->high == 271);
    }
}
static void alternating_batches(sfs_image *h, sfs_pin a, sfs_pin b, sfs_inode linked, uint8_t tag) {
    uint8_t av[32], bv[32], cv[32]; memset(av, tag, sizeof(av)); memset(bv, tag + 1, sizeof(bv)); memset(cv, tag + 2, sizeof(cv));
    OK(sfs_image_pin_write(h, a, 100, av, sizeof(av), &receipt));
    OK(sfs_image_pin_write(h, b, 8192, bv, sizeof(bv), &receipt));
    OK(sfs_image_write(h, linked, 4096, cv, sizeof(cv), &receipt));
    assert(h->batch && !h->batch->detached);
    OK(sfs_image_pin_write(h, a, WIDE_SIZE - sizeof(av), av, sizeof(av), &receipt));
    OK(sfs_image_pin_write(h, b, 0, bv, 3, &receipt));
    OK(sfs_image_write(h, linked, 0, cv, 3, &receipt));
    assert(h->batch && !h->batch->detached && h->batch->inode.e.inode == linked);
}
static void no_resurrection(sfs_image *h, sfs_inode a, sfs_inode b, sfs_inode linked) {
    sfs_entry e;
    assert(sfs_image_lookup(h, 0, 1, "wide", 4, &e, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_lookup(h, 0, 1, "other", 5, &e, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_stat(h, 0, a, &e, &receipt) == SFS_NOT_FOUND);
    assert(sfs_image_stat(h, 0, b, &e, &receipt) == SFS_NOT_FOUND);
    OK(sfs_image_lookup(h, 0, 1, "linked", 6, &e, &receipt)); assert(e.inode == linked);
}
static void rollover_leaf_boundaries_and_target_switches(void) {
    char name[48]; sfs_image *h = fresh(6, name, 4); sfs_inode aid, bid, cid;
    sfs_pin a = detached(h, "wide", &aid), b = detached(h, "other", &bid), c = named_pin(h, "linked", &cid);
    uint8_t *expected = malloc(WIDE_SIZE); assert(expected);
    for (size_t i = 0; i < WIDE_SIZE; ++i) expected[i] = (uint8_t)((i * 37u + i / CELL * 11u + 19u) & 255u);
    /* Fail exactly when the same detached batch first spans256 logical blocks. */
    OK(sfs_image_begin(h, &receipt)); wide_write(h, a, expected, 1);
    bytes(h, a, "old", 3); OK(sfs_image_abort(h, &receipt)); bytes(h, a, "old", 3);
    no_resurrection(h, aid, bid, cid);
    OK(sfs_image_begin(h, &receipt)); wide_write(h, a, expected, 0); commit(h);
    complete_bytes(h, a, expected, WIDE_SIZE); no_resurrection(h, aid, bid, cid);
    /* Locate a real second leaf's first key rather than assume a split shape. */
    reader r = current_reader(h, 0); node inode; reference attrs; uint64_t next;
    OK(pin_committed(&r, a, &inode, &attrs, &next)); const uint8_t *root;
    OK(root_page(&r, &inode.extent, MAP_EXTENT, UINT64_MAX, inode.e.size, &root));
    assert(page_level(root) == 1 && page_count(root) >= 2);
    uint64_t boundary = from_big(row_at(root, MAP_EXTENT, 1, r.a.minor) + 8);
    assert(boundary > 0 && boundary < WIDE_BLOCKS);
    uint8_t crossing[37]; memset(crossing, 0xe3, sizeof(crossing)); uint64_t offset = boundary * CELL - 9;
    OK(sfs_image_begin(h, &receipt)); OK(sfs_image_pin_write(h, a, offset, crossing, sizeof(crossing), &receipt)); commit(h);
    memcpy(expected + offset, crossing, sizeof(crossing)); complete_bytes(h, a, expected, WIDE_SIZE);
    uint8_t expected_b[8224] = {0}, expected_c[4128] = {0};
    OK(sfs_image_begin(h, &receipt)); alternating_batches(h, a, b, cid, 41);
    complete_bytes(h, a, expected, WIDE_SIZE); bytes(h, b, "old", 3); bytes(h, c, "old", 3); commit(h);
    memset(expected + 100, 41, 32); memset(expected + WIDE_SIZE - 32, 41, 32);
    memset(expected_b, 42, 3); memset(expected_b + 8192, 42, 32);
    memset(expected_c, 43, 3); memset(expected_c + 4096, 43, 32);
    complete_bytes(h, a, expected, WIDE_SIZE); complete_bytes(h, b, expected_b, sizeof(expected_b)); complete_bytes(h, c, expected_c, sizeof(expected_c));
    no_resurrection(h, aid, bid, cid);
    OK(sfs_image_begin(h, &receipt)); alternating_batches(h, a, b, cid, 81); OK(sfs_image_abort(h, &receipt));
    complete_bytes(h, a, expected, WIDE_SIZE); complete_bytes(h, b, expected_b, sizeof(expected_b)); complete_bytes(h, c, expected_c, sizeof(expected_c));
    no_resurrection(h, aid, bid, cid);
    OK(sfs_image_begin(h, &receipt)); alternating_batches(h, a, b, cid, 121);
    uint64_t physical = h->eof; sfs_image_diagnostic_capacity(h, physical + CELL);
    assert(sfs_image_pin_write(h, a, 0, crossing, sizeof(crossing), &receipt) == SFS_LIMIT);
    assert(receipt.limit_reason == SFS_LIMIT_APPEND_CAPACITY && !receipt.transaction_active && !receipt.poisoned && h->eof == physical);
    sfs_image_diagnostic_capacity(h, 0);
    complete_bytes(h, a, expected, WIDE_SIZE); complete_bytes(h, b, expected_b, sizeof(expected_b)); complete_bytes(h, c, expected_c, sizeof(expected_c));
    no_resurrection(h, aid, bid, cid); verify(h); free(expected); OK(sfs_image_close(h, &receipt));
}
int main(int argc, char **argv) {
    assert(argc == 2 && argv[1][0] == '/'); parent = argv[1]; umask(077);
    assert(mkdir(parent, 0700) == 0);
    contents_aliases_snapshots(); replacement_and_types(); reservations_and_limits();
    abort_capacity_and_faults(); detached_integrity();
    rollover_leaf_boundaries_and_target_switches();
    puts("PASS live-pins"); return 0;
}
