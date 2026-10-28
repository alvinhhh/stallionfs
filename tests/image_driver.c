/* Test-only syscall substitutions apply to image.c, never to this driver. */
#include "image.h"
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static void verification(void);
static char root[PATH_MAX];
static const char *fault = "";
static int target, reads, writes, fulls, syncs, slots, records, locks, closes, hit;
static int competing, cut, model, cut_at, events;
static unsigned char *durable;
static size_t durable_size;
static int tracked_fd = -1, locked_fd = -1;
static char order[256];
static uint64_t read_at[2];
static uint64_t watch_at[2], watch_size[2], watch_bytes[2];
static unsigned watch_count, watch_reads[2];

static void raw_write(int fd, const void *p, size_t n, off_t at) {
    const unsigned char *b = p;
    while (n) { ssize_t w = pwrite(fd, b, n, at); assert(w > 0); b += w; at += w; n -= (size_t)w; }
}
static unsigned char *bytes(const char *name, size_t *size) {
    int fd = openat(AT_FDCWD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    struct stat st; assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 && (uint64_t)st.st_size <= SFS_IMAGE_MAX);
    *size = (size_t)st.st_size;
    unsigned char *p = malloc(*size ? *size : 1); assert(p);
    size_t n = 0;
    while (n < *size) { ssize_t r = pread(fd, p + n, *size - n, (off_t)n); assert(r > 0); n += (size_t)r; }
    assert(close(fd) == 0); return p;
}
static void unchanged(const char *name, const unsigned char *before, size_t n) {
    size_t size; unsigned char *now = bytes(name, &size);
    assert(size == n && !memcmp(before, now, n)); free(now);
}
static void save(const char *name, const unsigned char *p, size_t n) {
    int fd = open(name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); assert(fd >= 0);
    raw_write(fd, p, n, 0); assert(close(fd) == 0);
}
static int descriptors(void) {
    int count = 0; for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) >= 0) count++; return count;
}
static void reset(const char *kind, int nth) {
    fault = kind; target = nth; reads = writes = fulls = syncs = slots = records = locks = closes = hit = events = 0;
    competing = cut = model = 0; tracked_fd = -1; order[0] = 0;
    free(durable); durable = NULL; durable_size = 0;
}
static int is(const char *kind) { return !strcmp(fault, kind); }
static void event(char c) { size_t n = strlen(order); if (n + 1 < sizeof(order)) { order[n] = c; order[n + 1] = 0; } }
static void capture(int fd) {
    struct stat st; assert(fstat(fd, &st) == 0 && st.st_size >= 0 && (uint64_t)st.st_size <= SFS_IMAGE_MAX);
    free(durable); durable_size = (size_t)st.st_size; durable = malloc(durable_size ? durable_size : 1); assert(durable);
    size_t n = 0;
    while (n < durable_size) { ssize_t r = pread(fd, durable + n, durable_size - n, (off_t)n); assert(r > 0); n += (size_t)r; }
}
static void stop_at(int fd, const void *torn, size_t n, off_t offset) {
    if (!cut || ++events != cut_at) return;
    if (model) {
        assert(durable);
        assert(ftruncate(fd, (off_t)durable_size) == 0); raw_write(fd, durable, durable_size, 0);
        if (torn && n) raw_write(fd, torn, n, offset);
    } else if (torn && n) raw_write(fd, torn, n, offset);
    _exit(91);
}
static void competitor(void) {
    pid_t child = fork(); assert(child >= 0);
    if (!child) {
        fault = ""; competing = cut = model = 0;
        if (tracked_fd >= 0) assert(close(tracked_fd) == 0);
        sfs_image *other = NULL; sfs_result r;
        enum sfs_status s = sfs_image_open(root, "image", &other, &r);
        assert(s != SFS_OK && other == NULL); _exit(0);
    }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
ssize_t sfs_test_pread(int fd, void *p, size_t n, off_t at) {
    reads++;
    if (is("slot_reads") || is("candidate_reads")) {
        for (unsigned i = 0; i < 2; i++) {
            uint64_t offset = is("slot_reads") ? i * UINT64_C(4096) : read_at[i];
            if ((target & (1 << i)) && (uint64_t)at == offset) {
                hit++; errno = i ? ENXIO : EIO; return -1;
            }
        }
    }
    if (is("read_eintr") && !hit++) { errno = EINTR; return -1; }
    if (is("read_error") && reads == target) { hit++; errno = EIO; return -1; }
    if (is("read_short") && n > 17) n = 17;
    ssize_t result = pread(fd, p, n, at);
    if (result > 0) for (unsigned i = 0; i < watch_count; i++) {
        uint64_t start = (uint64_t)at, end = start + (size_t)result;
        uint64_t lower = start > watch_at[i] ? start : watch_at[i];
        uint64_t upper = end < watch_at[i] + watch_size[i] ? end : watch_at[i] + watch_size[i];
        if (upper > lower) { watch_bytes[i] += upper - lower; watch_reads[i]++; }
    }
    if (result >= 0 && (is("slot_reads") || is("candidate_reads"))) errno = ERANGE;
    return result;
}
ssize_t sfs_test_pwrite(int fd, const void *p, size_t n, off_t at) {
    assert(fd == locked_fd); tracked_fd = fd; writes++;
    int slot = at < 8192;
    if (slot) { slots++; event(at < 4096 ? '0' : '1'); } else records++;
    if (is("write_eintr") && !hit++) { errno = EINTR; return -1; }
    if ((is("write_error") || is("write_zero") || is("enospc")) && writes == target) {
        hit++; errno = is("enospc") ? ENOSPC : EIO; return is("write_zero") ? 0 : -1;
    }
    if (is("record_error") && !slot) { hit++; errno = EIO; return -1; }
    if (is("slot_error") && slot && slots == target) { hit++; errno = EIO; return -1; }
    if (is("slot_torn") && slot && slots == target) {
        size_t part = n < 73 ? n : 73; raw_write(fd, p, part, at); hit++; errno = ENOSPC; return -1;
    }
    if (is("write_short") && n > 13) n = 13;
    /* Fixed model events: first record, first fence, slot prefix, second fence. */
    if (cut && slot) stop_at(fd, p, n < 73 ? n : 73, at);
    ssize_t result = pwrite(fd, p, n, at);
    if (result > 0 && cut && !slot && records == 1) stop_at(fd, NULL, 0, 0);
    return result;
}
int sfs_test_fcntl(int fd, int command, ...) {
    assert(command == F_FULLFSYNC);
    tracked_fd = fd; fulls++; event('F');
    if (competing) competitor();
    if (is("full") && fulls == target) { hit++; errno = EIO; return -1; }
    int result = fcntl(fd, command);
    if (!result && model) capture(fd);
    if (!result && cut) stop_at(fd, NULL, 0, 0);
    return result;
}
int sfs_test_fsync(int fd) {
    syncs++; event('D');
    if (is("parent_sync")) { hit++; errno = EIO; return -1; }
    return fsync(fd);
}
int sfs_test_flock(int fd, int operation) {
    locks++; tracked_fd = fd;
    if (is("lock")) { hit++; errno = EWOULDBLOCK; return -1; }
    if (competing && locks == 1 && writes == 0) competitor();
    int rc = flock(fd, operation);
    if (!rc && (operation & LOCK_EX)) locked_fd = fd;
    return rc;
}
int sfs_test_close(int fd) {
    closes++; struct stat st; assert(fstat(fd, &st) == 0);
    int fail = (is("close") && closes == target) || (is("parent_close") && S_ISDIR(st.st_mode));
    int result = close(fd);
    if (fd == locked_fd) locked_fd = -1;
    if (fail) { hit++; errno = EIO; return -1; }
    return result;
}
int sfs_test_openat(int fd, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (is("create") && (flags & O_CREAT)) { hit++; errno = EACCES; return -1; }
    return openat(fd, name, flags, mode);
}
int sfs_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(sfs_test_fstat);
int sfs_test_fstat(int fd, struct stat *st) { return fstat(fd, st); }
int sfs_test_fstatat(int fd, const char *name, struct stat *st, int flags) __DARWIN_INODE64(sfs_test_fstatat);
int sfs_test_fstatat(int fd, const char *name, struct stat *st, int flags) {
    int rc = fstatat(fd, name, st, flags);
    if (!rc && is("identity") && fulls >= 3) { st->st_ino++; hit++; }
    return rc;
}
int sfs_test_fstatfs(int fd, struct statfs *st) __DARWIN_INODE64(sfs_test_fstatfs);
int sfs_test_fstatfs(int fd, struct statfs *st) {
    int rc = fstatfs(fd, st);
    if (!rc && is("unsupported")) { strcpy(st->f_fstypename, "not-apfs"); hit++; }
    if (!rc && is("readonly")) { st->f_flags |= MNT_RDONLY; hit++; }
    return rc;
}
static void ok(enum sfs_status status, const sfs_result *r) {
    if (status != SFS_OK) fprintf(stderr, "status=%d phase=%d errno=%d generation=%llu\n", status, r->phase, r->system_errno, (unsigned long long)r->generation);
    assert(status == SFS_OK && r->status == SFS_OK);
}
#define OK(call) ok((call), &r)
static void create(sfs_image **h) { sfs_result r; OK(sfs_image_create(root, "image", h, &r)); assert(r.generation == 1); }
static void close_image(sfs_image *h) { sfs_result r; OK(sfs_image_close(h, &r)); }
static void open_image(sfs_image **h) { sfs_result r; OK(sfs_image_open(root, "image", h, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); }
static void directory(const char *name) {
    int n = snprintf(root, sizeof(root), "sfs-image-%s-XXXXXX", name); assert(n > 0 && n < (int)sizeof(root));
    assert(mkdtemp(root)); assert(chmod(root, 0700) == 0);
    char *absolute = realpath(root, NULL); assert(absolute); assert(strlen(absolute) < sizeof(root)); strcpy(root, absolute); free(absolute);
    assert(chdir(root) == 0);
    fprintf(stderr, "Fixture retained until suite success: %s\n", root);
}
static void receipt(const char *name, const sfs_result *r) {
    printf("{\"case\":\"%s\",\"status\":%d,\"phase\":%d,\"system_errno\":%d,\"generation\":%llu,\"committed_end\":%llu,\"physical_end\":%llu,\"root\":\"",
           name, r->status, r->phase, r->system_errno, (unsigned long long)r->generation, (unsigned long long)r->committed_end, (unsigned long long)r->physical_end);
    for (size_t i = 0; i < 32; i++) printf("%02x", r->root_digest[i]);
    puts("\"}"); fflush(stdout);
}
static sfs_inode add(sfs_image *h, sfs_inode parent, const char *name, enum sfs_kind kind) {
    sfs_inode id; sfs_result r; OK(sfs_image_add(h, parent, name, strlen(name), kind, &id, &r)); return id;
}
static void expect(sfs_image *h, sfs_view view, sfs_inode id, const char *text) {
    unsigned char b[128]; memset(b, 0xA5, sizeof(b)); size_t got; sfs_result r;
    OK(sfs_image_read(h, view, id, 0, b, sizeof(b), &got, &r));
    assert(got == strlen(text) && !memcmp(b, text, got) && b[got] == 0xA5);
}
static void initial_files(sfs_image *h, sfs_inode *a, sfs_inode *b) {
    sfs_result r; OK(sfs_image_begin(h, &r));
    *a = add(h, SFS_ROOT_INODE, "a", SFS_FILE); *b = add(h, SFS_ROOT_INODE, "b", SFS_FILE);
    OK(sfs_image_write(h, *a, 0, "old-a", 5, &r)); OK(sfs_image_write(h, *b, 0, "old-b", 5, &r));
    OK(sfs_image_commit(h, &r)); assert(r.generation == 2);
}
static void change_files(sfs_image *h, sfs_inode a, sfs_inode b) {
    sfs_result r; OK(sfs_image_begin(h, &r));
    OK(sfs_image_write(h, a, 0, "new-a", 5, &r)); OK(sfs_image_write(h, b, 0, "new-b", 5, &r));
}
static void basic(void) {
    sfs_image *h = NULL; sfs_result r; reset("", 0); competing = 1; create(&h);
    assert(fulls == 3 && syncs == 1 && slots == 2 && locks == 1 && !strcmp(order, "F01FDF"));
    competing = 0; OK(sfs_image_verify(h, &r)); receipt("creation-acknowledged", &r);
    sfs_inode a, b; initial_files(h, &a, &b); size_t old_size; unsigned char *old = bytes("image", &old_size);
    change_files(h, a, b); sfs_view view; OK(sfs_image_snapshot(h, "before", 6, &view, &r));
    expect(h, 0, a, "old-a"); /* Staged writes are invisible until publication. */
    OK(sfs_image_commit(h, &r)); assert(r.generation == 3); receipt("atomic", &r);
    expect(h, 0, a, "new-a"); expect(h, 0, b, "new-b"); expect(h, view, a, "old-a"); expect(h, view, b, "old-b");
    size_t size; unsigned char *now = bytes("image", &size);
    assert(size > old_size && !memcmp(old + 8192, now + 8192, old_size - 8192)); free(old); free(now);
    sfs_cookie cookie = {0}; sfs_entry entry; int found, count = 0;
    do { OK(sfs_image_next(h, 0, SFS_ROOT_INODE, &cookie, &entry, &found, &r)); count += found; } while (found);
    assert(count == 2);
    OK(sfs_image_begin(h, &r));
    sfs_inode dir = add(h, SFS_ROOT_INODE, "dir", SFS_DIRECTORY);
    OK(sfs_image_rename(h, a, dir, "renamed", 7, &r));
    OK(sfs_image_write(h, b, 1, "XYZ", 3, &r)); OK(sfs_image_resize(h, b, 8, &r));
    OK(sfs_image_commit(h, &r));
    assert(sfs_image_next(h, 0, SFS_ROOT_INODE, &cookie, &entry, &found, &r) != SFS_OK);
    unsigned char ranged[8] = {0xA5}; size_t got;
    OK(sfs_image_read(h, 0, b, 1, ranged, 7, &got, &r)); assert(got == 7 && !memcmp(ranged, "XYZb\0\0\0", 7));
    OK(sfs_image_read(h, 0, b, UINT64_MAX, ranged, 0, &got, &r)); assert(got == 0);
    OK(sfs_image_verify(h, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); receipt("verify", &r);
    close_image(h); open_image(&h);
    OK(sfs_image_snapshot_view(h, "before", 6, &view, &r)); expect(h, view, a, "old-a"); expect(h, view, b, "old-b");
    OK(sfs_image_lookup(h, 0, dir, "renamed", 7, &entry, &r)); assert(entry.inode == a);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_remove(h, a, &r)); OK(sfs_image_abort(h, &r));
    OK(sfs_image_stat(h, 0, a, &entry, &r)); close_image(h);
}
static void retain(int index) { char name[64]; snprintf(name, sizeof(name), "retained-%d", index); assert(rename("image", name) == 0); }
static void inspect_unchanged(int *candidates) {
    size_t n; unsigned char *before = bytes("image", &n); sfs_image *h = NULL; sfs_result r; sfs_recovery recovery;
    enum sfs_status status = sfs_image_inspect(root, "image", &h, &recovery, &r);
    *candidates = 0;
    if (h) {
        assert(status == SFS_OK || status == SFS_RECOVERY_REQUIRED || status == SFS_CORRUPT);
        for (unsigned i = 0; i < 2; i++) if (recovery.slots[i].status == SFS_OK) {
            (*candidates)++; OK(sfs_image_select(h, i, &r));
            assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE);
            assert(sfs_image_begin(h, &r) != SFS_OK);
        }
        close_image(h);
    } else assert(status != SFS_OK);
    unchanged("image", before, n); free(before);
}
static void creation(void) {
    const char *cases[] = {"unsupported", "readonly", "create", "lock", "record_error", "full", "slot_torn", "slot_error", "slot_torn", "full", "parent_sync", "full", "identity", "parent_close"};
    const int nth[] = {0,0,0,0,0,1,1,2,2,2,0,3,0,0};
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); i++) {
        reset(cases[i], nth[i]); sfs_image *h = NULL; sfs_result r;
        enum sfs_status status = sfs_image_create(root, "image", &h, &r);
        receipt(cases[i], &r); assert(status != SFS_OK && h == NULL && hit);
        if (i < 3) { assert(access("image", F_OK) == -1 && errno == ENOENT); continue; }
        struct stat st; assert(lstat("image", &st) == 0 && S_ISREG(st.st_mode));
        if (i == 3) assert(st.st_size == 0 && records == 0 && slots == 0);
        if (i == 4 || i == 5) assert(slots == 0);
        if (i >= 6) assert(status == SFS_OUTCOME_UNKNOWN);
        reset("", 0); int candidates; inspect_unchanged(&candidates);
        if (i == 6) assert(candidates == 0);
        if (i == 7 || i == 8) assert(candidates == 1);
        if (i >= 9) assert(candidates == 2);
        retain((int)i);
    }
    for (int i = 0; i < 2; i++) {
        reset(i ? "write_zero" : "enospc", 1); sfs_image *failed = NULL; sfs_result failure;
        assert(sfs_image_create(root, "image", &failed, &failure) == SFS_IO && failed == NULL && hit && slots == 0);
        assert(failure.system_errno == (i ? EIO : ENOSPC)); retain(20 + i);
    }
    for (int i = 0; i < 2; i++) {
        reset(i ? "write_short" : "write_eintr", 0); sfs_image *created; create(&created);
        assert(fulls == 3 && syncs == 1); close_image(created); retain(22 + i);
    }
    reset("", 0); sfs_image *h; create(&h); close_image(h);
    size_t n; unsigned char *before = bytes("image", &n); sfs_result r; h = NULL;
    assert(sfs_image_create(root, "image", &h, &r) == SFS_EXISTS && h == NULL); unchanged("image", before, n);
    assert(symlink("image", "alias") == 0);
    assert(sfs_image_open(root, "alias", &h, &r) != SFS_OK && h == NULL); unchanged("image", before, n);
    assert(link("image", "hardlink") == 0);
    assert(sfs_image_open(root, "image", &h, &r) != SFS_OK && h == NULL); unchanged("image", before, n); assert(unlink("hardlink") == 0);
    assert(chmod("image", 0644) == 0); assert(sfs_image_open(root, "image", &h, &r) != SFS_OK); unchanged("image", before, n); assert(chmod("image", 0600) == 0);
    assert(mkfifo("fifo", 0600) == 0); assert(sfs_image_open(root, "fifo", &h, &r) != SFS_OK && h == NULL);
    assert(chmod(root, 0755) == 0); assert(sfs_image_create(root, "private-refusal", &h, &r) != SFS_OK); assert(access("private-refusal", F_OK) == -1); assert(chmod(root, 0700) == 0);
    open_image(&h); sfs_image *other = NULL; assert(sfs_image_open(root, "image", &other, &r) == SFS_BUSY && other == NULL); close_image(h);
    unchanged("image", before, n); free(before);
    assert(rename("image", "creation-complete") == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { reset("", 0); sfs_image *created; create(&created); _exit(91); }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 91);
    open_image(&h); OK(sfs_image_verify(h, &r)); assert(r.generation == 1); receipt("creation-success-reply-lost", &r); close_image(h);
}
static void io(void) {
    sfs_image *h; sfs_result r; sfs_inode a, b; reset("", 0); create(&h); initial_files(h, &a, &b); close_image(h);
    size_t n; unsigned char *baseline = bytes("image", &n); assert(rename("image", "baseline") == 0);
    const char *cases[] = {"write_eintr", "write_short", "write_zero", "enospc", "write_error", "full", "slot_torn", "full"};
    const int nth[] = {0,0,1,1,1,1,1,2};
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); i++) {
        save("image", baseline, n); reset("", 0); open_image(&h); change_files(h, a, b); reset(cases[i], nth[i]);
        enum sfs_status status = sfs_image_commit(h, &r); receipt(cases[i], &r);
        if (i < 2) { assert(status == SFS_OK && r.generation == 3); }
        else {
            assert(status != SFS_OK && hit);
            assert(status == (i >= 6 ? SFS_OUTCOME_UNKNOWN : SFS_IO));
            assert(r.system_errno == (i == 3 || i == 6 ? ENOSPC : EIO));
            assert(sfs_image_begin(h, &r) == SFS_POISONED);
        }
        reset("", 0); close_image(h);
        h = NULL; status = sfs_image_open(root, "image", &h, &r);
        if (i == 6) { assert(status == SFS_RECOVERY_REQUIRED && h == NULL); int candidates; inspect_unchanged(&candidates); assert(candidates == 1); }
        else {
            OK(status); expect(h, 0, a, i < 2 || i == 7 ? "new-a" : "old-a"); expect(h, 0, b, i < 2 || i == 7 ? "new-b" : "old-b"); close_image(h);
        }
        retain((int)i);
    }
    save("image", baseline, n);
    const char *read_faults[] = {"read_eintr", "read_short", "read_error"};
    for (int i = 0; i < 3; i++) {
        reset(read_faults[i], 1); h = NULL; enum sfs_status s = sfs_image_open(root, "image", &h, &r);
        if (i < 2) { OK(s); expect(h, 0, a, "old-a"); close_image(h); }
        else assert(s != SFS_OK && h == NULL && hit);
        unchanged("image", baseline, n);
    }
    reset("", 0); open_image(&h); reset("close", 1); assert(sfs_image_close(h, &r) != SFS_OK && hit); reset("", 0); open_image(&h); close_image(h);
    free(baseline); verification();
}
static void check_candidate(sfs_image *h, uint64_t generation, sfs_inode a, sfs_inode b) {
    assert(generation == 3 || generation == 4);
    expect(h, 0, a, generation == 3 ? "old-a" : "new-a"); expect(h, 0, b, generation == 3 ? "old-b" : "new-b");
    sfs_result r; sfs_view view; OK(sfs_image_snapshot_view(h, "before", 6, &view, &r));
    expect(h, view, a, "old-a"); expect(h, view, b, "old-b");
}
static void cuts(void) {
    sfs_image *h; sfs_result r; sfs_inode a, b; reset("", 0); create(&h); initial_files(h, &a, &b);
    OK(sfs_image_begin(h, &r)); sfs_view view; OK(sfs_image_snapshot(h, "before", 6, &view, &r)); OK(sfs_image_commit(h, &r)); close_image(h);
    size_t n; unsigned char *baseline = bytes("image", &n); assert(rename("image", "baseline") == 0);
    for (int modeled = 0; modeled < 2; modeled++) for (int point = 1; point <= 4; point++) {
        save("image", baseline, n); pid_t child = fork(); assert(child >= 0);
        if (!child) {
            reset("", 0); open_image(&h); change_files(h, a, b);
            int fd = open("image", O_RDWR | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); capture(fd); assert(close(fd) == 0);
            cut = 1; model = modeled; cut_at = point;
            sfs_image_commit(h, &r); _exit(92);
        }
        int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 91);
        reset("", 0); h = NULL; enum sfs_status s = sfs_image_open(root, "image", &h, &r);
        if (point == 1) {
            struct stat st; assert(stat("image", &st) == 0);
            assert((size_t)st.st_size == n + (modeled ? 0 : 64));
        }
        printf("{\"cut\":%d,\"model\":%s,\"child_exit\":91,\"acknowledged\":false,\"open_status\":%d}\n", point, modeled ? "true" : "false", s);
        if (point == 3) {
            assert(s == SFS_RECOVERY_REQUIRED && h == NULL);
            size_t z; unsigned char *prior = bytes("image", &z); sfs_recovery recovery;
            OK(sfs_image_inspect(root, "image", &h, &recovery, &r));
            assert(recovery.latest_may_be_unknown);
            int selected = 0;
            for (unsigned slot = 0; slot < 2; slot++) if (recovery.slots[slot].status == SFS_OK) {
                OK(sfs_image_select(h, slot, &r)); check_candidate(h, r.generation, a, b); selected++;
            }
            assert(selected == 1); close_image(h); unchanged("image", prior, z); free(prior);
        } else { OK(s); assert(r.generation == (point == 4 ? 4 : 3)); check_candidate(h, r.generation, a, b); close_image(h); }
        retain(modeled * 4 + point);
    }
    free(baseline);
}
static uint32_t get32(const unsigned char *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint64_t get64(const unsigned char *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static void put32(unsigned char *p, uint32_t v) { for (int i = 0; i < 4; i++, v >>= 8) p[i] = (unsigned char)v; }
static void put64(unsigned char *p, uint64_t v) { for (int i = 0; i < 8; i++, v >>= 8) p[i] = (unsigned char)v; }
static void slot_hash(unsigned char *slot) { unsigned char sum[32]; memset(slot + 112, 0, 32); CC_SHA256(slot, 4096, sum); memcpy(slot + 112, sum, 32); }
static unsigned char *record(unsigned char *image, const unsigned char *ref, size_t size) {
    uint64_t at = get64(ref + 8), n = get64(ref + 16); assert(at >= 8192 && at <= size && n >= 64 && n <= size - at); return image + at;
}
static void ref_hash(unsigned char *image, unsigned char *ref, size_t size) {
    unsigned char *p = record(image, ref, size); uint64_t n = get64(ref + 16); assert(n <= UINT32_MAX); CC_SHA256(p, (CC_LONG)n, ref + 24);
}
static unsigned char *manifest_entry(unsigned char *ns, unsigned index) {
    unsigned char *p = ns + 80; assert(index < get32(ns + 64));
    while (index--) p += 88 + get32(p + 20);
    return p;
}
static void parser(void) {
    reset("", 0); sfs_image *h; sfs_result r; sfs_inode a, b; create(&h); initial_files(h, &a, &b);
    OK(sfs_image_begin(h, &r)); sfs_inode d = add(h, SFS_ROOT_INODE, "d", SFS_DIRECTORY); add(h, d, "e", SFS_DIRECTORY); OK(sfs_image_commit(h, &r));
    change_files(h, a, b); sfs_view view; OK(sfs_image_snapshot(h, "old", 3, &view, &r)); OK(sfs_image_commit(h, &r)); assert(r.generation == 4); close_image(h);
    size_t n; unsigned char *baseline = bytes("image", &n); assert(rename("image", "baseline") == 0);
    const char *cases[] = {
        "one-slot-checksum", "both-slot-checksum", "root-checksum", "current-data", "snapshot-data", "truncate",
        "uuid-pair", "version-pair", "features-pair", "equal-generation", "gap", "zero-generation", "wrap-generation", "parity", "decreasing-end",
        "slot-reserved", "unknown-major", "unknown-minor", "unknown-flags", "root-offset-overflow", "root-offset-slot", "root-length-overflow", "root-type", "root-reserved",
        "record-reserved", "record-uuid", "record-type", "manifest-count", "manifest-next-inode", "duplicate-id", "duplicate-name", "bad-parent", "parent-cycle", "name-length", "nul-name", "slash-name", "bad-kind", "bad-file-size", "payload-offset-overflow", "payload-after-end", "payload-type", "payload-length", "catalog-count", "catalog-name-length", "snapshot-root-type", "snapshot-root-cycle"
    };
    for (size_t c = 0; c < sizeof(cases)/sizeof(*cases); c++) {
        const char *kind = cases[c]; unsigned char *p = malloc(n); assert(p); memcpy(p, baseline, n); size_t fixture_size = n;
        /* Generation 4 is in slot 0; every changed ancestor is deliberately rehashed. */
        unsigned char *slot = p, *root_ref = slot + 48, *commit = record(p, root_ref, n);
        unsigned char *ns_ref = commit + 64, *catalog_ref = commit + 120;
        unsigned char *ns = record(p, ns_ref, n), *catalog = record(p, catalog_ref, n);
        unsigned char *first = manifest_entry(ns, 0), *second = manifest_entry(ns, 1);
        int seal_ns = 0, seal_catalog = 0, seal_commit = 0, seal_slot = 0;
        if (!strcmp(kind, "one-slot-checksum")) p[112] ^= 1;
        else if (!strcmp(kind, "both-slot-checksum")) { p[112] ^= 1; p[4096 + 112] ^= 1; }
        else if (!strcmp(kind, "root-checksum")) commit[64] ^= 1;
        else if (!strcmp(kind, "current-data")) record(p, first + 32, n)[64] ^= 1;
        else if (!strcmp(kind, "snapshot-data")) {
            unsigned char *old_ns = record(p, catalog + 80, n);
            record(p, manifest_entry(old_ns, 0) + 32, n)[64] ^= 1;
        } else if (!strcmp(kind, "truncate")) fixture_size = 4096 + 17;
        else if (!strcmp(kind, "uuid-pair")) { p[4096 + 24] ^= 1; slot_hash(p + 4096); }
        else if (!strcmp(kind, "version-pair")) { put32(p + 4096 + 12, 2); slot_hash(p + 4096); }
        else if (!strcmp(kind, "features-pair")) { put64(p + 4096 + 16, 1); slot_hash(p + 4096); }
        else if (!strcmp(kind, "equal-generation")) { put64(p + 40, 1); put64(p + 4096 + 40, 1); slot_hash(p); slot_hash(p + 4096); }
        else if (!strcmp(kind, "gap")) { put64(p + 40, 6); seal_slot = 1; }
        else if (!strcmp(kind, "zero-generation")) { put64(p + 40, 0); seal_slot = 1; }
        else if (!strcmp(kind, "wrap-generation")) { put64(p + 40, UINT64_MAX); seal_slot = 1; }
        else if (!strcmp(kind, "parity")) { put64(p + 40, 3); put64(p + 4096 + 40, 2); slot_hash(p); slot_hash(p + 4096); }
        else if (!strcmp(kind, "decreasing-end")) { put64(p + 104, get64(p + 4096 + 104)); seal_slot = 1; }
        else if (!strcmp(kind, "slot-reserved")) { p[200] = 1; seal_slot = 1; }
        else if (!strcmp(kind, "unknown-major")) { put32(p + 8, 99); seal_slot = 1; }
        else if (!strcmp(kind, "unknown-minor")) { put32(p + 12, 99); seal_slot = 1; }
        else if (!strcmp(kind, "unknown-flags")) { put64(p + 16, 1); seal_slot = 1; }
        else if (!strcmp(kind, "root-offset-overflow")) { put64(root_ref + 8, UINT64_MAX - 4095); seal_slot = 1; }
        else if (!strcmp(kind, "root-offset-slot")) { put64(root_ref + 8, 4096); seal_slot = 1; }
        else if (!strcmp(kind, "root-length-overflow")) { put64(root_ref + 16, UINT64_MAX); seal_slot = 1; }
        else if (!strcmp(kind, "root-type")) { put32(root_ref, 2); seal_slot = 1; }
        else if (!strcmp(kind, "root-reserved")) { put32(root_ref + 4, 1); seal_slot = 1; }
        else if (!strcmp(kind, "record-reserved")) { ns[40] = 1; seal_ns = 1; }
        else if (!strcmp(kind, "record-uuid")) { ns[24] ^= 1; seal_ns = 1; }
        else if (!strcmp(kind, "record-type")) { put32(ns + 8, 3); seal_ns = 1; }
        else if (!strcmp(kind, "manifest-count")) { put32(ns + 64, UINT32_MAX); seal_ns = 1; }
        else if (!strcmp(kind, "manifest-next-inode")) { put64(ns + 72, 1); seal_ns = 1; }
        else if (!strcmp(kind, "duplicate-id")) { put64(second, get64(first)); seal_ns = 1; }
        else if (!strcmp(kind, "duplicate-name")) { second[88] = first[88]; seal_ns = 1; }
        else if (!strcmp(kind, "bad-parent")) { put64(first + 8, UINT64_MAX); seal_ns = 1; }
        else if (!strcmp(kind, "parent-cycle")) { put64(manifest_entry(ns, 2) + 8, get64(manifest_entry(ns, 3))); seal_ns = 1; }
        else if (!strcmp(kind, "name-length")) { put32(first + 20, UINT32_MAX); seal_ns = 1; }
        else if (!strcmp(kind, "nul-name")) { first[88] = 0; seal_ns = 1; }
        else if (!strcmp(kind, "slash-name")) { first[88] = '/'; seal_ns = 1; }
        else if (!strcmp(kind, "bad-kind")) { put32(first + 16, 99); seal_ns = 1; }
        else if (!strcmp(kind, "bad-file-size")) { put64(first + 24, SFS_FILE_MAX + 1); seal_ns = 1; }
        else if (!strcmp(kind, "payload-offset-overflow")) { put64(first + 40, UINT64_MAX - 4095); seal_ns = 1; }
        else if (!strcmp(kind, "payload-after-end")) { put64(first + 40, get64(slot + 104)); seal_ns = 1; }
        else if (!strcmp(kind, "payload-type")) { put32(first + 32, 2); seal_ns = 1; }
        else if (!strcmp(kind, "payload-length")) { put64(first + 48, UINT64_MAX); seal_ns = 1; }
        else if (!strcmp(kind, "catalog-count")) { put32(catalog + 64, UINT32_MAX); seal_catalog = 1; }
        else if (!strcmp(kind, "catalog-name-length")) { put32(catalog + 72, UINT32_MAX); seal_catalog = 1; }
        else if (!strcmp(kind, "snapshot-root-type")) { put32(catalog + 80, 4); seal_catalog = 1; }
        else if (!strcmp(kind, "snapshot-root-cycle")) { memcpy(catalog + 80, root_ref, 56); seal_catalog = 1; }
        else assert(0);
        if (seal_ns) { ref_hash(p, ns_ref, n); seal_commit = 1; }
        if (seal_catalog) { ref_hash(p, catalog_ref, n); seal_commit = 1; }
        if (seal_commit) { ref_hash(p, root_ref, n); seal_slot = 1; }
        if (seal_slot) slot_hash(slot);
        save("image", p, fixture_size); reset("", 0); h = NULL;
        enum sfs_status status = sfs_image_open(root, "image", &h, &r);
        receipt(kind, &r); assert((status == SFS_CORRUPT || status == SFS_RECOVERY_REQUIRED || status == SFS_UNSUPPORTED) && h == NULL);
        unchanged("image", p, fixture_size); int candidates; inspect_unchanged(&candidates);
        if (c == 0) assert(candidates == 1);
        if (c == 1) assert(candidates == 0);
        retain((int)c); free(p);
    }
    free(baseline);
}
static void verification(void) {
    assert(rename("image", "io-original") == 0); reset("", 0);
    sfs_image *h; sfs_result r; sfs_inode a, b; create(&h); initial_files(h, &a, &b);
    OK(sfs_image_begin(h, &r)); sfs_view view;
    OK(sfs_image_snapshot(h, "before", 6, &view, &r)); OK(sfs_image_commit(h, &r)); close_image(h);
    size_t n; unsigned char *baseline = bytes("image", &n); assert(rename("image", "verification-baseline") == 0);
    for (int i = 0; i < 3; i++) {
        save("image", baseline, n); open_image(&h);
        unsigned char *copy = malloc(n); assert(copy); memcpy(copy, baseline, n);
        unsigned char *commit = record(copy, copy + 4096 + 48, n);
        unsigned char *ns = record(copy, commit + 64, n); uint64_t at;
        if (i < 2) at = get64(manifest_entry(ns, 0) + 40) + 64;
        else { unsigned char *catalog = record(copy, commit + 120, n); at = get64(catalog + 88) + 64; }
        assert(at < n); copy[at] ^= 1;
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, copy + at, 1, (off_t)at); assert(close(fd) == 0);
        if (i == 0) assert(sfs_image_verify(h, &r) == SFS_CORRUPT);
        else if (i == 1) {
            unsigned char output[8]; memset(output, 0xA5, sizeof(output)); size_t got = 99;
            assert(sfs_image_read(h, 0, a, 0, output, sizeof(output), &got, &r) == SFS_CORRUPT && got == 0);
            for (size_t j = 0; j < sizeof(output); j++) assert(output[j] == 0xA5);
        } else { sfs_entry entry; assert(sfs_image_lookup(h, view, SFS_ROOT_INODE, "a", 1, &entry, &r) == SFS_CORRUPT); }
        receipt(i == 0 ? "verify-poison" : i == 1 ? "read-poison" : "snapshot-load-poison", &r);
        assert(sfs_image_begin(h, &r) == SFS_POISONED); close_image(h); unchanged("image", copy, n); free(copy); retain(100 + i);
    }
    save("image", baseline, n); sfs_recovery recovery;
    OK(sfs_image_inspect(root, "image", &h, &recovery, &r)); OK(sfs_image_select(h, 1, &r));
    baseline[4096 + 112] ^= 1;
    int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, baseline + 4096 + 112, 1, 4096 + 112); assert(close(fd) == 0);
    assert(sfs_image_verify(h, &r) == SFS_CORRUPT);
    assert(sfs_image_select(h, 1, &r) != SFS_OK);
    close_image(h); unchanged("image", baseline, n); free(baseline); retain(103);
}
static void review(void) {
    reset("", 0); sfs_image *h; sfs_result r; sfs_inode a, b; create(&h); initial_files(h, &a, &b);
    OK(sfs_image_begin(h, &r)); sfs_view view;
    OK(sfs_image_snapshot(h, "before", 6, &view, &r)); OK(sfs_image_commit(h, &r));
    size_t older_size; unsigned char *older = bytes("image", &older_size);
    change_files(h, a, b); OK(sfs_image_commit(h, &r)); assert(r.generation == 4); close_image(h);
    size_t newer_size; unsigned char *newer = bytes("image", &newer_size); assert(newer_size > older_size);
    unsigned char *tail = malloc(newer_size); assert(tail); memcpy(tail, newer, newer_size); memcpy(tail, older, 8192);
    assert(rename("image", "newer-generation") == 0);
    for (int commit = 0; commit < 2; commit++) {
        /* The newer records already exist in an uncommitted tail when this handle opens. */
        save("image", tail, newer_size); open_image(&h); OK(sfs_image_verify(h, &r));
        assert(r.generation == 3 && r.physical_end == newer_size); change_files(h, a, b);
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
        raw_write(fd, newer, 4096, 0); assert(close(fd) == 0); reset("", 0);
        enum sfs_status status = commit ? sfs_image_commit(h, &r) : sfs_image_verify(h, &r);
        assert(status == SFS_CORRUPT && writes == 0 && fulls == 0);
        receipt(commit ? "newer-anchor-commit-refused" : "newer-anchor-verify-refused", &r);
        assert(sfs_image_begin(h, &r) == SFS_POISONED);
        assert(sfs_image_write(h, a, 0, "x", 1, &r) == SFS_POISONED);
        assert(sfs_image_commit(h, &r) == SFS_POISONED); close_image(h); unchanged("image", newer, newer_size);
        open_image(&h); OK(sfs_image_verify(h, &r)); assert(r.generation == 4);
        expect(h, 0, a, "new-a"); expect(h, 0, b, "new-b"); expect(h, view, a, "old-a"); close_image(h); retain(500 + commit);
    }
    free(tail); free(newer);
    read_at[0] = get64(older + 56); read_at[1] = get64(older + 4096 + 56);
    for (int candidates = 0; candidates < 2; candidates++) for (int mask = 1; mask <= 3; mask++) {
        save("image", older, older_size); reset(candidates ? "candidate_reads" : "slot_reads", mask);
        enum sfs_status status = sfs_image_open(root, "image", &h, &r);
        assert(h == NULL && hit);
        if (!candidates) { assert(status == SFS_RECOVERY_REQUIRED); assert(r.system_errno == (mask & 1 ? EIO : ENXIO)); }
        else assert(status == SFS_IO && r.system_errno == (mask == 1 ? EIO : ENXIO));
        receipt(candidates ? "candidate-errno-open" : "slot-errno-open", &r);
        reset(candidates ? "candidate_reads" : "slot_reads", mask); sfs_recovery recovery;
        status = sfs_image_inspect(root, "image", &h, &recovery, &r);
        assert(hit);
        for (unsigned i = 0; i < 2; i++) {
            assert(recovery.slots[i].status == ((mask & (1 << i)) ? SFS_IO : SFS_OK));
            assert(recovery.slots[i].system_errno == ((mask & (1 << i)) ? (i ? ENXIO : EIO) : 0));
        }
        if (mask == 3) { assert(status == SFS_RECOVERY_REQUIRED && h == NULL && r.system_errno == EIO); }
        else {
            assert(status == SFS_OK && h && r.system_errno == 0); reset("", 0);
            if (!candidates) {
                unsigned bad = mask == 1 ? 0 : 1;
                assert(sfs_image_select(h, bad, &r) == SFS_IO && r.system_errno == (bad ? ENXIO : EIO));
            }
            OK(sfs_image_select(h, mask == 1 ? 1 : 0, &r)); assert(r.system_errno == 0);
            if (!candidates && mask == 1) {
                reset("read_error", 3); assert(sfs_image_verify(h, &r) == SFS_IO && r.system_errno == EIO && hit);
                reset("", 0); OK(sfs_image_verify(h, &r)); OK(sfs_image_select(h, 1, &r));
                assert(sfs_image_begin(h, &r) != SFS_OK && writes == 0 && fulls == 0);
            }
            close_image(h);
        }
        unchanged("image", older, older_size); retain(510 + candidates * 3 + mask);
    }
    for (int operation = 0; operation < 3; operation++) {
        save("image", older, older_size); reset("", 0); open_image(&h); change_files(h, a, b); reset("read_error", operation ? 1 : 3);
        enum sfs_status status;
        if (!operation) status = sfs_image_verify(h, &r);
        else if (operation == 1) {
            unsigned char output[8]; memset(output, 0xA5, sizeof(output)); size_t got = 99;
            status = sfs_image_read(h, 0, a, 0, output, sizeof(output), &got, &r); assert(got == 0);
            for (size_t i = 0; i < sizeof(output); i++) assert(output[i] == 0xA5);
        } else { sfs_entry entry; status = sfs_image_lookup(h, view, SFS_ROOT_INODE, "a", 1, &entry, &r); }
        assert(status == SFS_IO && r.system_errno == EIO && hit && writes == 0 && fulls == 0);
        receipt(operation == 0 ? "verify-io-poison" : operation == 1 ? "read-io-poison" : "snapshot-io-poison", &r);
        assert(sfs_image_begin(h, &r) == SFS_POISONED);
        assert(sfs_image_write(h, a, 0, "x", 1, &r) == SFS_POISONED);
        assert(sfs_image_commit(h, &r) == SFS_POISONED); reset("", 0); close_image(h); unchanged("image", older, older_size); retain(520 + operation);
    }
    free(older);
}
static void watch_payload(unsigned index, const unsigned char *ref) {
    assert(index < 2 && get64(ref + 16) >= 64);
    watch_at[index] = get64(ref + 8) + 64; watch_size[index] = get64(ref + 16) - 64;
    watch_bytes[index] = 0; watch_reads[index] = 0;
}
static void watch_clear(void) { memset(watch_bytes, 0, sizeof(watch_bytes)); memset(watch_reads, 0, sizeof(watch_reads)); }
static void counter_floor(void) {
    sfs_result r; sfs_image *h; sfs_inode a, b;
    for (int snapshots = 0; snapshots < 2; snapshots++) {
        reset("", 0); create(&h); initial_files(h, &a, &b); OK(sfs_image_begin(h, &r));
        if (snapshots) { sfs_view view; OK(sfs_image_snapshot(h, "before", 6, &view, &r)); }
        OK(sfs_image_remove(h, b, &r)); OK(sfs_image_commit(h, &r)); close_image(h);
        size_t n; unsigned char *baseline = bytes("image", &n), *forged = malloc(n); assert(forged); memcpy(forged, baseline, n);
        unsigned char *prior_root = record(baseline, baseline + 48, n), *prior_ns = record(baseline, prior_root + 64, n);
        watch_payload(0, manifest_entry(prior_ns, 1) + 32); watch_at[0] -= 64; watch_size[0] += 64;
        watch_count = snapshots ? 0 : 1;
        open_image(&h); OK(sfs_image_verify(h, &r)); assert(r.generation == 3);
        if (!snapshots) assert(watch_bytes[0] == 0);
        receipt(snapshots ? "valid-snapshot-counter" : "valid-deletion-equal-counter", &r);
        unsigned char *root_ref = forged + 4096 + 48, *commit = record(forged, root_ref, n);
        unsigned char *ns_ref = commit + 64, *ns = record(forged, ns_ref, n);
        assert(get64(ns + 72) == 4 && get64(manifest_entry(ns, 0)) == a && a == 2);
        put64(ns + 72, 3); ref_hash(forged, ns_ref, n); ref_hash(forged, root_ref, n); slot_hash(forged + 4096);
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, forged, n, 0); assert(close(fd) == 0);
        reset("", 0); assert(sfs_image_verify(h, &r) == SFS_CORRUPT && writes == 0 && fulls == 0);
        assert(sfs_image_begin(h, &r) == SFS_POISONED); assert(sfs_image_commit(h, &r) == SFS_POISONED); close_image(h);
        h = NULL; reset("", 0); assert(sfs_image_open(root, "image", &h, &r) == SFS_CORRUPT && h == NULL && writes == 0 && fulls == 0);
        if (!snapshots) assert(watch_bytes[0] == 0);
        receipt(snapshots ? "snapshot-counter-floor-refused" : "predecessor-counter-floor-refused", &r);
        unchanged("image", forged, n); retain(600 + snapshots); watch_count = 0;
        if (!snapshots) {
            /* Prior namespace metadata is a write-admission dependency, though its payload is not. */
            save("image", baseline, n); open_image(&h); memcpy(forged, baseline, n);
            uint64_t at = get64(prior_root + 72) + 64; assert(at < n); forged[at] ^= 1;
            fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, forged + at, 1, (off_t)at); assert(close(fd) == 0);
            reset("", 0); assert(sfs_image_verify(h, &r) == SFS_CORRUPT && writes == 0 && fulls == 0);
            assert(sfs_image_begin(h, &r) == SFS_POISONED); close_image(h); h = NULL;
            assert(sfs_image_open(root, "image", &h, &r) == SFS_CORRUPT && h == NULL);
            sfs_recovery recovery; OK(sfs_image_inspect(root, "image", &h, &recovery, &r));
            assert(recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_OK);
            OK(sfs_image_select(h, 1, &r)); OK(sfs_image_verify(h, &r)); expect(h, 0, a, "old-a");
            assert(sfs_image_begin(h, &r) != SFS_OK); close_image(h); unchanged("image", forged, n); retain(602);
        }
        free(forged); free(baseline);
    }
}
static void payload_memo(void) {
    reset("", 0); sfs_image *h; sfs_result r; create(&h); OK(sfs_image_begin(h, &r));
    sfs_inode a = add(h, SFS_ROOT_INODE, "a", SFS_FILE), b = add(h, SFS_ROOT_INODE, "b", SFS_FILE), c = add(h, SFS_ROOT_INODE, "c", SFS_FILE);
    OK(sfs_image_write(h, a, 0, "shared", 6, &r)); OK(sfs_image_write(h, b, 0, "shared", 6, &r)); OK(sfs_image_write(h, c, 0, "unique", 6, &r));
    OK(sfs_image_commit(h, &r)); close_image(h);
    size_t n; unsigned char *image = bytes("image", &n), *root_ref = image + 48, *commit = record(image, root_ref, n), *ns_ref = commit + 64;
    unsigned char *ns = record(image, ns_ref, n), *first = manifest_entry(ns, 0), *second = manifest_entry(ns, 1);
    memcpy(second + 32, first + 32, 56); watch_payload(0, first + 32); watch_payload(1, manifest_entry(ns, 2) + 32);
    ref_hash(image, ns_ref, n); ref_hash(image, root_ref, n); slot_hash(image);
    int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, image, n, 0); assert(close(fd) == 0); free(image);
    open_image(&h); OK(sfs_image_begin(h, &r)); sfs_view one, two;
    OK(sfs_image_snapshot(h, "one", 3, &one, &r)); OK(sfs_image_snapshot(h, "two", 3, &two, &r)); OK(sfs_image_commit(h, &r)); close_image(h);
    watch_count = 2; watch_clear(); open_image(&h);
    for (unsigned i = 0; i < 2; i++) assert(watch_bytes[i] == 6 && watch_reads[i] == 1);
    for (int pass = 0; pass < 2; pass++) {
        watch_clear(); OK(sfs_image_verify(h, &r));
        for (unsigned i = 0; i < 2; i++) assert(watch_bytes[i] == 6 && watch_reads[i] == 1);
        printf("{\"payload_pass\":%d,\"distinct_records\":2,\"hashed_payload_bytes\":12}\n", pass);
    }
    watch_count = 0; expect(h, one, b, "shared"); expect(h, two, a, "shared");
    image = bytes("image", &n); assert(watch_at[0] < n); image[watch_at[0]] ^= 1;
    fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, image + watch_at[0], 1, (off_t)watch_at[0]); assert(close(fd) == 0);
    watch_count = 2; watch_clear(); reset("", 0);
    assert(sfs_image_verify(h, &r) == SFS_CORRUPT && watch_bytes[0] == 6 && watch_reads[0] == 1 && writes == 0 && fulls == 0);
    assert(sfs_image_begin(h, &r) == SFS_POISONED); close_image(h); watch_count = 0;
    unchanged("image", image, n); free(image); retain(603);
}
static void security(void) { counter_floor(); payload_memo(); }
static void admission_unchanged(sfs_image *h, const unsigned char *before, size_t size) {
    sfs_result r; assert(writes == 0 && fulls == 0);
    assert(sfs_image_commit(h, &r) == SFS_STATE); unchanged("image", before, size);
    enum sfs_status status = sfs_image_begin(h, &r);
    assert(status == SFS_OK || status == SFS_LIMIT);
    if (status == SFS_OK) OK(sfs_image_abort(h, &r));
    OK(sfs_image_verify(h, &r));
}
static void limits(void) {
    reset("", 0); sfs_image *h; sfs_result r; create(&h);
    OK(sfs_image_begin(h, &r)); char longest[SFS_NAME_MAX + 2]; memset(longest, 'x', sizeof(longest));
    sfs_inode id; OK(sfs_image_add(h, SFS_ROOT_INODE, longest, SFS_NAME_MAX, SFS_FILE, &id, &r));
    unsigned char *payload = malloc((size_t)SFS_FILE_MAX); assert(payload); memset(payload, 0x5A, (size_t)SFS_FILE_MAX);
    OK(sfs_image_write(h, id, 0, payload, (size_t)SFS_FILE_MAX, &r)); OK(sfs_image_commit(h, &r));
    size_t n; unsigned char *before = bytes("image", &n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_write(h, id, SFS_FILE_MAX, "x", 1, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_resize(h, id, SFS_FILE_MAX + 1, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_write(h, id, UINT64_MAX, "xx", 2, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_add(h, SFS_ROOT_INODE, longest, SFS_NAME_MAX + 1, SFS_FILE, &id, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); sfs_view invalid_view;
    assert(sfs_image_snapshot(h, longest, SFS_NAME_MAX + 1, &invalid_view, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    free(before); free(payload);
    OK(sfs_image_begin(h, &r));
    for (unsigned i = 1; i < SFS_ENTRY_MAX; i++) { char name[32]; snprintf(name, sizeof(name), "file-%u", i); add(h, SFS_ROOT_INODE, name, SFS_FILE); }
    OK(sfs_image_commit(h, &r)); before = bytes("image", &n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_add(h, SFS_ROOT_INODE, "over", 4, SFS_DIRECTORY, &id, &r) == SFS_LIMIT); admission_unchanged(h, before, n); free(before);
    for (unsigned i = 0; i < SFS_SNAPSHOT_MAX; i++) {
        char name[32]; snprintf(name, sizeof(name), "snapshot-%u", i); sfs_view view;
        OK(sfs_image_begin(h, &r)); OK(sfs_image_snapshot(h, i ? name : longest, i ? strlen(name) : SFS_NAME_MAX, &view, &r)); OK(sfs_image_commit(h, &r));
    }
    before = bytes("image", &n); sfs_view view;
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_snapshot(h, "over", 4, &view, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    OK(sfs_image_verify(h, &r)); close_image(h); unchanged("image", before, n);
    /* A valid adjacent pair at UINT64_MAX must refuse the next generation before I/O. */
    unsigned newest = get64(before + 40) > get64(before + 4096 + 40) ? 0 : 1;
    unsigned char *later = before + newest * 4096, *earlier = before + (1 - newest) * 4096;
    put64(later + 40, UINT64_MAX); put64(earlier + 40, UINT64_MAX - 1);
    if (newest == 0) { unsigned char tmp[4096]; memcpy(tmp, before, 4096); memcpy(before, before + 4096, 4096); memcpy(before + 4096, tmp, 4096); }
    slot_hash(before); slot_hash(before + 4096); assert(rename("image", "limit-baseline") == 0); save("image", before, n);
    open_image(&h); reset("", 0);
    enum sfs_status status = sfs_image_begin(h, &r);
    if (status == SFS_OK) status = sfs_image_commit(h, &r);
    assert(status == SFS_LIMIT && writes == 0 && fulls == 0);
    admission_unchanged(h, before, n); close_image(h); free(before);
}
static void metadata(void) {
    reset("", 0); sfs_image *h; sfs_result r; create(&h); size_t n; unsigned char *before = bytes("image", &n); reset("", 0);
    OK(sfs_image_begin(h, &r)); enum sfs_status status = SFS_OK; unsigned count;
    for (count = 0; count < SFS_ENTRY_MAX && status == SFS_OK; count++) {
        char name[256]; memset(name, 'a' + (int)(count % 26), 255); sfs_inode id;
        status = sfs_image_add(h, SFS_ROOT_INODE, name, 255, SFS_FILE, &id, &r);
    }
    if (status == SFS_OK) status = sfs_image_commit(h, &r);
    assert(status == SFS_LIMIT && count < SFS_ENTRY_MAX); assert(writes == 0 && fulls == 0);
    admission_unchanged(h, before, n); close_image(h); free(before);
}
static void capacity(void) {
    reset("", 0); sfs_image *h; sfs_result r; create(&h); sfs_inode a, b; initial_files(h, &a, &b); close_image(h);
    size_t baseline_size; unsigned char *baseline = bytes("image", &baseline_size);
    /* Five appended records exactly fit after an aligned abandoned tail. */
    int exact = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(exact >= 0);
    raw_write(exact, "T", 1, (off_t)SFS_IMAGE_MAX - 20480 - 1); assert(close(exact) == 0);
    open_image(&h); change_files(h, a, b); OK(sfs_image_commit(h, &r));
    assert(r.physical_end == SFS_IMAGE_MAX && r.committed_end == SFS_IMAGE_MAX);
    expect(h, 0, a, "new-a"); expect(h, 0, b, "new-b"); close_image(h);
    assert(rename("image", "exact-cap") == 0); save("image", baseline, baseline_size); free(baseline);
    /* Abandoned, unreachable tail consumes real capacity; never reclaim it. */
    int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    unsigned char marker[37]; memset(marker, 0xCB, sizeof(marker)); raw_write(fd, marker, sizeof(marker), (off_t)SFS_IMAGE_MAX - 37); assert(close(fd) == 0);
    size_t n; unsigned char *before = bytes("image", &n); assert(n == SFS_IMAGE_MAX);
    open_image(&h); reset("", 0);
    enum sfs_status status = sfs_image_begin(h, &r);
    if (status == SFS_OK) status = sfs_image_write(h, a, 0, "new-a", 5, &r);
    if (status == SFS_OK) status = sfs_image_commit(h, &r);
    assert(status == SFS_LIMIT && writes == 0 && fulls == 0); admission_unchanged(h, before, n);
    expect(h, 0, a, "old-a"); expect(h, 0, b, "old-b"); close_image(h); unchanged("image", before, n); free(before);
}
int main(int argc, char **argv) {
    assert(argc == 2); int before = descriptors(); directory(argv[1]);
    const unsigned char sentinel[] = "owned sentinel must remain unchanged"; save("sentinel", sentinel, sizeof(sentinel));
    /* Names are fixed scenarios, never caller-supplied image or device paths. */
    if (!strcmp(argv[1], "basic")) basic();
    else if (!strcmp(argv[1], "creation")) creation();
    else if (!strcmp(argv[1], "io")) io();
    else if (!strcmp(argv[1], "cuts")) cuts();
    else if (!strcmp(argv[1], "review")) review();
    else if (!strcmp(argv[1], "security")) security();
    else if (!strcmp(argv[1], "parser")) parser();
    else if (!strcmp(argv[1], "limits")) limits();
    else if (!strcmp(argv[1], "metadata")) metadata();
    else if (!strcmp(argv[1], "capacity")) capacity();
    else assert(0);
    unchanged("sentinel", sentinel, sizeof(sentinel));
    free(durable); assert(descriptors() == before); printf("PASS %s\n", argv[1]); return 0;
}
