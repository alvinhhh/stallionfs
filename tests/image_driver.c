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
#define TEST_CAPACITY UINT64_C(67108864)
#define CELL 4096u
static const sfs_verify_budget generous = {
    UINT64_C(131072), UINT64_C(536870912), UINT64_C(536870912),
    UINT64_C(50000000), UINT64_C(33554432), UINT64_C(1073741824), NULL, NULL
};
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
static unsigned char auxiliary[4096];
static uint64_t image_read_bytes, image_read_attempts, image_append_bytes;
static uint64_t aux_read_bytes, aux_write_bytes, aux_attempt_bytes;
static uint64_t aux_write_calls, image_truncates;
static int image_open_fd=-1, image_open_flags;
static uint64_t raw_hash_input, metadata_hash_input, raw_hashes, copies;
static uint64_t overlay_clone_bytes, overlay_clone_calls, observed_clone_size;
static uint64_t allocated, peak_allocated, allocation_calls;
static uint64_t fail_allocation, fail_after_append;
static unsigned aux_created, aux_removed;
static struct { CC_SHA256_CTX *context; int raw; } hash_context[8];
typedef union allocation_header allocation_header;
union allocation_header { max_align_t alignment; struct { size_t bytes; allocation_header *previous, *next; } value; };
static allocation_header *allocations;

void *sfs_test_malloc(size_t n) {
    assert(n <= 5u * 1024u * 1024u);
    allocation_calls++;
    if (allocation_calls == fail_allocation || (fail_after_append && image_append_bytes >= fail_after_append)) {
        fail_after_append = 0; hit++; errno = ENOMEM; return NULL;
    }
    if (n > SIZE_MAX - sizeof(allocation_header)) { errno = ENOMEM; return NULL; }
    allocation_header *p = malloc(sizeof(*p) + n); if (!p) return NULL;
    p->value.bytes = n; p->value.previous = NULL; p->value.next = allocations;
    if (allocations) allocations->value.previous = p; allocations = p;
    allocated += n; if (allocated > peak_allocated) peak_allocated = allocated;
    return p + 1;
}
void *sfs_test_calloc(size_t n, size_t size) {
    if (size && n > SIZE_MAX / size) { errno = ENOMEM; return NULL; }
    void *p = sfs_test_malloc(n * size); if (p) memset(p, 0, n * size); return p;
}
void sfs_test_free(void *p) {
    if (p) { allocation_header *h = (allocation_header *)p - 1; assert(allocated >= h->value.bytes); allocated -= h->value.bytes;
        if (h->value.previous) h->value.previous->value.next = h->value.next; else allocations = h->value.next;
        if (h->value.next) h->value.next->value.previous = h->value.previous; free(h); }
}
void *sfs_test_memcpy(void *dst, const void *src, size_t n) {
    copies += n;
    if (n > CELL) {
        int from = 0, to = 0;
        for (allocation_header *p = allocations; p; p = p->value.next) if (p->value.bytes == n) { from |= src == p + 1; to |= dst == p + 1; }
        if (from && to) { overlay_clone_bytes += n; overlay_clone_calls++; observed_clone_size = n; }
    }
    return memcpy(dst, src, n);
}
int sfs_test_CC_SHA256_Init(CC_SHA256_CTX *c) {
    for (unsigned i = 0; i < 8; i++) if (!hash_context[i].context) {
        hash_context[i].context = c; hash_context[i].raw = 0; return CC_SHA256_Init(c);
    }
    assert(0); return 0;
}
int sfs_test_CC_SHA256_Update(CC_SHA256_CTX *c, const void *p, CC_LONG n) {
    for (unsigned i = 0; i < 8; i++) if (hash_context[i].context == c) {
        if (n == 36 && !memcmp(p, "SFSDAT02", 8)) hash_context[i].raw = 1;
        if (hash_context[i].raw) raw_hash_input += n; else metadata_hash_input += n;
        return CC_SHA256_Update(c, p, n);
    }
    assert(0); return 0;
}
int sfs_test_CC_SHA256_Final(unsigned char *sum, CC_SHA256_CTX *c) {
    for (unsigned i = 0; i < 8; i++) if (hash_context[i].context == c) {
        if (hash_context[i].raw) raw_hashes++;
        hash_context[i].context = NULL; return CC_SHA256_Final(sum, c);
    }
    assert(0); return 0;
}

static void raw_write(int fd, const void *p, size_t n, off_t at) {
    const unsigned char *b = p;
    while (n) { ssize_t w = pwrite(fd, b, n, at); assert(w > 0); b += w; at += w; n -= (size_t)w; }
}
static unsigned char *bytes(const char *name, size_t *size) {
    int fd = openat(AT_FDCWD, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    struct stat st; assert(fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= 0 && (uint64_t)st.st_size <= TEST_CAPACITY);
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
    image_read_bytes = image_read_attempts = image_append_bytes = 0;
    aux_read_bytes = aux_write_bytes = aux_attempt_bytes = 0;
    aux_write_calls = image_truncates = 0; image_open_fd=-1; image_open_flags=0;
    raw_hash_input = metadata_hash_input = raw_hashes = copies = 0;
    overlay_clone_bytes = overlay_clone_calls = observed_clone_size = 0;
    fail_allocation = fail_after_append = 0;
}
static int is(const char *kind) { return !strcmp(fault, kind); }
static void event(char c) { size_t n = strlen(order); if (n + 1 < sizeof(order)) { order[n] = c; order[n + 1] = 0; } }
static void capture(int fd) {
    struct stat st; assert(fstat(fd, &st) == 0 && st.st_size >= 0 && (uint64_t)st.st_size <= TEST_CAPACITY);
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
    assert(fd >= 0 && fd < (int)sizeof(auxiliary));
    if (auxiliary[fd]) {
        aux_attempt_bytes += n;
        if (is("aux_read")) { hit++; errno = ENOSPC; return -1; }
        ssize_t result = pread(fd, p, n, at); if (result > 0) aux_read_bytes += (size_t)result;
        return result;
    }
    reads++;
    image_read_attempts += n;
    if (is("slot_reads") || is("candidate_reads")) {
        for (unsigned i = 0; i < 2; i++) {
            uint64_t offset = is("slot_reads") ? i * UINT64_C(4096) : read_at[i];
            if ((target & (1 << i)) && (uint64_t)at == offset) {
                hit++; errno = i ? ENXIO : EIO; return -1;
            }
        }
    }
    if (is("read_eintr") && !hit++) { errno = EINTR; return -1; }
    if (is("read_zero") && reads == target) { hit++; return 0; }
    if (is("read_error") && reads == target) { hit++; errno = EIO; return -1; }
    if (is("read_short") && n > 17) n = 17;
    ssize_t result = pread(fd, p, n, at);
    if (result > 0) image_read_bytes += (size_t)result;
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
    assert(fd >= 0 && fd < (int)sizeof(auxiliary));
    if (auxiliary[fd]) {
        aux_attempt_bytes += n; aux_write_calls++;
        if (is("aux_enospc") || is("aux_enospc_cleanup")) { hit++; errno = ENOSPC; return -1; }
        ssize_t result = pwrite(fd, p, n, at); if (result > 0) aux_write_bytes += (size_t)result;
        return result;
    }
    assert(fd == locked_fd); tracked_fd = fd; writes++;
    int slot = at < 8192;
    if (!slot) { struct stat st; assert(!fstat(fd, &st) && at >= st.st_size); }
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
    if (result > 0 && !slot) image_append_bytes += (size_t)result;
    if (result > 0 && cut && !slot && records == 1) stop_at(fd, NULL, 0, 0);
    return result;
}
int sfs_test_fcntl(int fd, int command, ...) {
    if (command == F_DUPFD_CLOEXEC) {
        va_list ap; va_start(ap, command); int minimum = va_arg(ap, int); va_end(ap);
        return fcntl(fd, command, minimum);
    }
    assert(command == F_FULLFSYNC);
    tracked_fd = fd; fulls++; event('F');
    if (fulls == 1) {
        struct stat st; unsigned char last[CELL]; assert(!fstat(fd, &st) && st.st_size >= 16384 && !(st.st_size % CELL));
        assert(pread(fd, last, CELL, st.st_size - CELL) == CELL);
        assert(!memcmp(last, "SFSREC02", 8) && last[8] == 4);
        /* The final commit-root exists before the first publication fence. */
        for (unsigned i = 0; i < 2; i++) { const unsigned char *ref = last + 64 + i * 56; if (ref[0]) { uint64_t offset = 0; for (int j = 7; j >= 0; j--) offset = (offset << 8) | ref[8+j]; assert(offset < (uint64_t)st.st_size - CELL); } }
    }
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
    int fail = (is("close") && closes == target) || (is("parent_close") && S_ISDIR(st.st_mode)) || ((is("aux_close") || is("aux_enospc_cleanup")) && auxiliary[fd]);
    int result = close(fd);
    auxiliary[fd] = 0;
    if (fd == locked_fd) locked_fd = -1;
    if (fail) { hit++; errno = EIO; return -1; }
    return result;
}
int sfs_test_openat(int fd, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (is("create") && (flags & O_CREAT)) { hit++; errno = EACCES; return -1; }
    int result = openat(fd, name, flags, mode);
    if (result >= 0) {
        if (!strcmp(name,"image")) { image_open_fd=result; image_open_flags=flags; }
        assert(result < (int)sizeof(auxiliary)); auxiliary[result] = !strcmp(name, "memo");
        if (auxiliary[result]) { struct stat st; assert(!fstat(result, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600 && st.st_uid == geteuid()); aux_created++; }
    }
    return result;
}
int sfs_test_ftruncate(int fd, off_t size) {
    if (!auxiliary[fd]) image_truncates++;
    if (auxiliary[fd] && is("aux_length_enospc")) { hit++; errno = ENOSPC; return -1; }
    return ftruncate(fd, size);
}
int sfs_test_mkdirat(int fd, const char *name, mode_t mode) {
    assert(mode == 0700); return mkdirat(fd, name, mode);
}
int sfs_test_unlinkat(int fd, const char *name, int flags) {
    if (!strcmp(name, "memo")) {
        if (is("aux_unlink")) { hit++; errno = EACCES; return -1; }
        int rc = unlinkat(fd, name, flags); if (!rc) aux_removed++; return rc;
    }
    return unlinkat(fd, name, flags);
}
int sfs_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(sfs_test_fstat);
int sfs_test_fstat(int fd, struct stat *st) {
    int rc=fstat(fd,st);
    if(!rc&&((is("owner")&&S_ISREG(st->st_mode))||(is("parent_owner")&&S_ISDIR(st->st_mode)))) { st->st_uid^=1; hit++; }
    return rc;
}
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
static void create(sfs_image **h) { sfs_result r; OK(sfs_image_create(root, "image", TEST_CAPACITY, h, &r)); assert(r.generation == 1); }
static void close_image(sfs_image *h) { sfs_result r; OK(sfs_image_close(h, &r)); }
static void open_image(sfs_image **h) { sfs_result r; OK(sfs_image_open(root, "image", h, &r)); assert(r.coverage == SFS_COVERAGE_ROOT_ONLY); }
static void directory(const char *name) {
    int n = snprintf(root, sizeof(root), "sfs-image-%s-XXXXXX", name); assert(n > 0 && n < (int)sizeof(root));
    assert(mkdtemp(root)); assert(chmod(root, 0700) == 0);
    char *absolute = realpath(root, NULL); assert(absolute); assert(strlen(absolute) < sizeof(root)); strcpy(root, absolute); free(absolute);
    assert(chdir(root) == 0);
    fprintf(stderr, "Fixture retained until suite success: %s\n", root);
}
static void receipt(const char *name, const sfs_result *r) {
    printf("{\"case\":\"%s\",\"status\":%d,\"phase\":%d,\"system_errno\":%d,\"coverage\":%d,\"incomplete_reason\":%d,\"generation\":%llu,\"committed_end\":%llu,\"physical_end\":%llu,\"root\":\"",
           name, r->status, r->phase, r->system_errno, r->coverage, r->incomplete_reason, (unsigned long long)r->generation, (unsigned long long)r->committed_end, (unsigned long long)r->physical_end);
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
    competing = 0; OK(sfs_image_verify(h, &generous, &r)); receipt("creation-acknowledged", &r);
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
    OK(sfs_image_verify(h, &generous, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); receipt("verify", &r);
    close_image(h); open_image(&h);
    OK(sfs_image_snapshot_view(h, "before", 6, &view, &r)); expect(h, view, a, "old-a"); expect(h, view, b, "old-b");
    OK(sfs_image_lookup(h, 0, dir, "renamed", 7, &entry, &r)); assert(entry.inode == a);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_remove(h, a, &r)); OK(sfs_image_abort(h, &r));
    OK(sfs_image_stat(h, 0, a, &entry, &r)); close_image(h);
}
static void retain(int index) { char name[64]; snprintf(name, sizeof(name), "retained-%d", index); assert(rename("image", name) == 0); }
static void inspect_unchanged(int *candidates) {
    size_t n; unsigned char *before = bytes("image", &n); sfs_image *h = NULL; sfs_result r; sfs_recovery recovery;
    enum sfs_status status = sfs_image_inspect(root, "image", &h, &recovery, &generous, &r);
    *candidates = 0;
    if (h) {
        assert(status == SFS_OK || status == SFS_RECOVERY_REQUIRED || status == SFS_CORRUPT);
        for (unsigned i = 0; i < 2; i++) if (recovery.slots[i].status == SFS_OK) {
            (*candidates)++; OK(sfs_image_select(h, i, &generous, &r));
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
        enum sfs_status status = sfs_image_create(root, "image", TEST_CAPACITY, &h, &r);
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
        assert(sfs_image_create(root, "image", TEST_CAPACITY, &failed, &failure) == SFS_IO && failed == NULL && hit && slots == 0);
        assert(failure.system_errno == (i ? EIO : ENOSPC)); retain(20 + i);
    }
    for (int i = 0; i < 2; i++) {
        reset(i ? "write_short" : "write_eintr", 0); sfs_image *created; create(&created);
        assert(fulls == 3 && syncs == 1); close_image(created); retain(22 + i);
    }
    reset("", 0); sfs_image *h; create(&h); close_image(h);
    size_t n; unsigned char *before = bytes("image", &n); sfs_result r; h = NULL;
    assert(sfs_image_create(root, "image", TEST_CAPACITY, &h, &r) == SFS_EXISTS && h == NULL); unchanged("image", before, n);
    assert(symlink("image", "alias") == 0);
    assert(sfs_image_open(root, "alias", &h, &r) != SFS_OK && h == NULL); unchanged("image", before, n);
    assert(link("image", "hardlink") == 0);
    assert(sfs_image_open(root, "image", &h, &r) != SFS_OK && h == NULL); unchanged("image", before, n); assert(unlink("hardlink") == 0);
    assert(chmod("image", 0644) == 0); assert(sfs_image_open(root, "image", &h, &r) != SFS_OK); unchanged("image", before, n); assert(chmod("image", 0600) == 0);
    assert(mkfifo("fifo", 0600) == 0); assert(sfs_image_open(root, "fifo", &h, &r) != SFS_OK && h == NULL);
    assert(chmod(root, 0755) == 0); assert(sfs_image_create(root, "private-refusal", TEST_CAPACITY, &h, &r) != SFS_OK); assert(access("private-refusal", F_OK) == -1); assert(chmod(root, 0700) == 0);
    open_image(&h); sfs_image *other = NULL; assert(sfs_image_open(root, "image", &other, &r) == SFS_BUSY && other == NULL); close_image(h);
    unchanged("image", before, n); free(before);
    assert(rename("image", "creation-complete") == 0);
    pid_t child = fork(); assert(child >= 0);
    if (!child) { reset("", 0); sfs_image *created; create(&created); _exit(91); }
    int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 91);
    open_image(&h); OK(sfs_image_verify(h, &generous, &r)); assert(r.generation == 1); receipt("creation-success-reply-lost", &r); close_image(h);
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
            reset("", 0); open_image(&h);
            int fd = open("image", O_RDWR | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); capture(fd); assert(close(fd) == 0);
            cut = 1; model = modeled; cut_at = point;
            change_files(h, a, b);
            sfs_image_commit(h, &r); _exit(92);
        }
        int status; assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 91);
        reset("", 0); h = NULL; enum sfs_status s = sfs_image_open(root, "image", &h, &r);
        if (point == 1) {
            struct stat st; assert(stat("image", &st) == 0);
            assert((size_t)st.st_size == n + (modeled ? 0 : CELL));
        }
        printf("{\"cut\":%d,\"model\":%s,\"child_exit\":91,\"acknowledged\":false,\"open_status\":%d}\n", point, modeled ? "true" : "false", s);
        if (point == 3) {
            assert(s == SFS_RECOVERY_REQUIRED && h == NULL);
            size_t z; unsigned char *prior = bytes("image", &z); sfs_recovery recovery;
            OK(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r));
            assert(recovery.latest_may_be_unknown);
            int selected = 0;
            for (unsigned slot = 0; slot < 2; slot++) if (recovery.slots[slot].status == SFS_OK) {
                OK(sfs_image_select(h, slot, &generous, &r)); check_candidate(h, r.generation, a, b); selected++;
            }
            assert(selected == 1); close_image(h); unchanged("image", prior, z); free(prior);
        } else { OK(s); assert(r.generation == (point == 4 ? 4 : 3)); check_candidate(h, r.generation, a, b); close_image(h); }
        retain(modeled * 4 + point);
    }
    free(baseline);
}

/* Independent byte codec: fixtures are built from the documented format, not core helpers. */
static uint16_t get16(const unsigned char *p) { return (uint16_t)(p[0] | (unsigned)p[1] << 8); }
static uint32_t get32(const unsigned char *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static uint64_t get64(const unsigned char *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return v; }
static void put16(unsigned char *p, uint16_t v) { p[0] = (unsigned char)v; p[1] = (unsigned char)(v >> 8); }
static void put32(unsigned char *p, uint32_t v) { for (int i = 0; i < 4; i++, v >>= 8) p[i] = (unsigned char)v; }
static void put64(unsigned char *p, uint64_t v) { for (int i = 0; i < 8; i++, v >>= 8) p[i] = (unsigned char)v; }
static void big64(unsigned char *p, uint64_t v) { for (int i = 7; i >= 0; i--, v >>= 8) p[i] = (unsigned char)v; }
static void slot_hash(unsigned char *p) { unsigned char sum[32]; memset(p + 112, 0, 32); CC_SHA256(p, CELL, sum); memcpy(p + 112, sum, 32); }
static unsigned char *record(unsigned char *image, const unsigned char *ref, size_t size) {
    uint64_t at = get64(ref + 8), n = get64(ref + 16);
    assert(at >= 8192 && !(at % CELL) && n == CELL && at <= size && n <= size - at); return image + at;
}
static void ref_hash(unsigned char *image, unsigned char *ref, size_t size) {
    unsigned char *p = record(image, ref, size);
    if (get32(ref) == 6) {
        unsigned char domain[36]; memcpy(domain, "SFSDAT02", 8); memcpy(domain + 8, image + 24, 16);
        put32(domain + 24, 6); put64(domain + 28, CELL); CC_SHA256_CTX c;
        CC_SHA256_Init(&c); CC_SHA256_Update(&c, domain, sizeof(domain)); CC_SHA256_Update(&c, p, CELL); CC_SHA256_Final(ref + 24, &c);
    } else CC_SHA256(p, CELL, ref + 24);
}
static unsigned char *selected_slot(unsigned char *p) { return p + (get64(p + 40) > get64(p + CELL + 40) ? 0 : CELL); }
static unsigned char *namespace_at(unsigned char *image, unsigned char *slot, size_t n) { return record(image, record(image, slot + 48, n) + 64, n); }
static unsigned char *leaf_row(unsigned char *image, const unsigned char *ref, uint64_t key, size_t n, unsigned stride) {
    unsigned char *p = record(image, ref, n); unsigned count = get16(p + 70); assert(count && count <= 48);
    if (get16(p + 68)) {
        unsigned i = 0;
        for (unsigned j = 1; j < count; j++) { uint64_t k = 0; for (unsigned b = 0; b < 8; b++) k = (k << 8) | p[640 + j * 72 + 8 + b]; if (k > key) break; i = j; }
        return leaf_row(image, p + 640 + i * 72 + 16, key, n, stride);
    }
    for (unsigned i = 0; i < count; i++) if (get64(p + 640 + i * stride) == key) return p + 640 + i * stride;
    assert(0); return NULL;
}
static unsigned char *inode_row(unsigned char *image, unsigned char *ns, uint64_t inode, size_t n) { return leaf_row(image, ns + 64, inode, n, 352); }
static unsigned char *raw_ref(unsigned char *image, unsigned char *row, uint64_t block, size_t n) { return leaf_row(image, row + 32, block, n, 72) + 8; }
static void rehash_integer_tree(unsigned char *image, unsigned char *ref, size_t n) {
    unsigned char *p = record(image, ref, n); unsigned count = get16(p + 70);
    if (get16(p + 68)) for (unsigned i = 0; i < count; i++) rehash_integer_tree(image, p + 640 + i * 72 + 16, n);
    ref_hash(image, ref, n);
}
static void seal_namespace(unsigned char *image, unsigned char *slot, size_t n, int inode_changed) {
    unsigned char *commit = record(image, slot + 48, n), *ns = record(image, commit + 64, n);
    if (inode_changed) rehash_integer_tree(image, ns + 64, n);
    ref_hash(image, commit + 64, n); ref_hash(image, slot + 48, n); slot_hash(slot);
}
static void replace_image(const unsigned char *p, size_t n) {
    int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0);
    assert(ftruncate(fd, (off_t)n) == 0); raw_write(fd, p, n, 0); assert(close(fd) == 0);
}
static void watch_payload(unsigned index, const unsigned char *ref) {
    assert(index < 2); watch_at[index] = get64(ref + 8); watch_size[index] = get64(ref + 16);
    watch_bytes[index] = 0; watch_reads[index] = 0;
}
static void watch_clear(void) { memset(watch_bytes, 0, sizeof(watch_bytes)); memset(watch_reads, 0, sizeof(watch_reads)); }
static void counters(const char *name) {
    printf("{\"case\":\"%s\",\"image_read_bytes\":%llu,\"image_read_attempt_bytes\":%llu,\"image_append_bytes\":%llu,\"aux_read_bytes\":%llu,\"aux_write_bytes\":%llu,\"aux_attempt_bytes\":%llu,\"raw_sha_input\":%llu,\"metadata_sha_input\":%llu,\"raw_sha_finalizations\":%llu,\"all_memcpy_bytes\":%llu,\"overlay_clone_bytes\":%llu,\"overlay_clone_calls\":%llu,\"observed_clone_size\":%llu,\"heap_current\":%llu,\"heap_peak\":%llu}\n", name,
      (unsigned long long)image_read_bytes, (unsigned long long)image_read_attempts, (unsigned long long)image_append_bytes,
      (unsigned long long)aux_read_bytes, (unsigned long long)aux_write_bytes, (unsigned long long)aux_attempt_bytes,
      (unsigned long long)raw_hash_input, (unsigned long long)metadata_hash_input, (unsigned long long)raw_hashes,
      (unsigned long long)copies, (unsigned long long)overlay_clone_bytes, (unsigned long long)overlay_clone_calls, (unsigned long long)observed_clone_size, (unsigned long long)allocated, (unsigned long long)peak_allocated); fflush(stdout);
}
typedef struct { unsigned char ref[56], min[263], max[263]; uint16_t min_n, max_n, level; } fixture_node;
typedef struct { unsigned char *p; size_t n; uint64_t capacity; } fixture;
static fixture fixture_start(void) {
    fixture f = { calloc(1, 16 * 1024 * 1024), 8192, TEST_CAPACITY }; assert(f.p);
    for (unsigned i = 0; i < 16; i++) f.p[24 + i] = (unsigned char)(i + 1); return f;
}
static fixture_node append_cell(fixture *f, unsigned type, const unsigned char *cell) {
    assert(f->n + CELL <= 16 * 1024 * 1024); fixture_node node = {0};
    memcpy(f->p + f->n, cell, CELL); put32(node.ref, type); put64(node.ref + 8, f->n); put64(node.ref + 16, CELL);
    f->n += CELL; ref_hash(f->p, node.ref, f->n); return node;
}
static void envelope(fixture *f, unsigned char *p, unsigned type) {
    memset(p, 0, CELL); memcpy(p, "SFSREC02", 8); put32(p + 8, type); put64(p + 16, 4032); memcpy(p + 24, f->p + 24, 16);
}
static void row_key(unsigned map, const unsigned char *row, unsigned char *key, uint16_t *n) {
    if (map == 2) { *n = (uint16_t)(8 + get32(row + 8)); big64(key, get64(row)); memcpy(key + 8, row + 12, *n - 8); }
    else { *n = 8; big64(key, map == 4 ? get32(row) : get64(row)); }
}
static fixture_node page(fixture *f, unsigned map, unsigned level, const unsigned char *rows, unsigned count, unsigned stride, const fixture_node *children) {
    unsigned char p[CELL]; envelope(f, p, 5); put32(p + 64, map); put16(p + 68, (uint16_t)level); put16(p + 70, (uint16_t)count); put64(p + 72, 1);
    fixture_node node = {0}; node.level = (uint16_t)level;
    if (level) {
        node.min_n = children[0].min_n; memcpy(node.min, children[0].min, node.min_n);
        node.max_n = children[count - 1].max_n; memcpy(node.max, children[count - 1].max, node.max_n);
        for (unsigned i = 0; i < count; i++) { unsigned char *r = p + 640 + i * stride; put32(r, children[i].min_n); memcpy(r + 8, children[i].min, children[i].min_n); memcpy(r + (map == 2 ? 271 : 16), children[i].ref, 56); }
    } else { memcpy(p + 640, rows, count * stride); row_key(map, rows, node.min, &node.min_n); row_key(map, rows + (count - 1) * stride, node.max, &node.max_n); }
    put16(p + 88, node.min_n); put16(p + 90, node.max_n); memcpy(p + 112, node.min, node.min_n); memcpy(p + 375, node.max, node.max_n);
    fixture_node cell = append_cell(f, 5, p); memcpy(node.ref, cell.ref, 56); return node;
}
static fixture_node tree(fixture *f, unsigned map, const unsigned char *rows, unsigned count) {
    const unsigned leaf_stride[] = {0,352,280,72,328}, leaf_max[] = {0,9,12,48,9};
    assert(count); unsigned groups = (count + leaf_max[map] - 1) / leaf_max[map];
    fixture_node *nodes = calloc(groups, sizeof(*nodes)); assert(nodes); unsigned at = 0;
    for (unsigned i = 0; i < groups; i++) { unsigned size = count / groups + (i < count % groups); nodes[i] = page(f, map, 0, rows + at * leaf_stride[map], size, leaf_stride[map], NULL); at += size; }
    unsigned level = 0, max = map == 2 ? 9 : 48, stride = map == 2 ? 328 : 72;
    while (groups > 1) { unsigned parents = (groups + max - 1) / max, used = 0; level++;
        for (unsigned i = 0; i < parents; i++) { unsigned size = groups / parents + (i < groups % parents); nodes[i] = page(f, map, level, NULL, size, stride, nodes + used); used += size; }
        groups = parents;
    }
    fixture_node result = nodes[0]; free(nodes); return result;
}
static fixture_node namespace_cell(fixture *f, fixture_node inodes, fixture_node names, uint64_t next, uint64_t count) {
    unsigned char p[CELL]; envelope(f, p, 2); memcpy(p + 64, inodes.ref, 56); memcpy(p + 120, names.ref, 56); put64(p + 176, next); put64(p + 184, count); return append_cell(f, 2, p);
}
static void finish_fixture(fixture *f, fixture_node ns, fixture_node catalog) {
    unsigned char p[CELL]; envelope(f, p, 4); memcpy(p + 64, ns.ref, 56); memcpy(p + 120, catalog.ref, 56); fixture_node root_node = append_cell(f, 4, p);
    for (unsigned i = 0; i < 2; i++) { unsigned char *s = f->p + i * CELL; unsigned char uuid[16]; memcpy(uuid, f->p + 24, 16); memset(s, 0, CELL); memcpy(s, "SFSIMG01", 8); put32(s + 12, 2); memcpy(s + 24, uuid, 16); put64(s + 40, 1); memcpy(s + 48, root_node.ref, 56); put64(s + 104, f->n); put64(s + 144, f->capacity); slot_hash(s); }
}
/* Shared raw and extent graphs are deliberate; namespace rows remain independently encoded. */
static fixture indexed_fixture(unsigned inode_count, unsigned extent_rows, unsigned snapshots) {
    fixture f = fixture_start(); unsigned char raw[CELL] = {0}; memcpy(raw, "shared", 6); fixture_node data = append_cell(&f, 6, raw), extent = {0};
    if (extent_rows) { unsigned char *rows = calloc(extent_rows, 72); assert(rows); for (unsigned i = 0; i < extent_rows; i++) { put64(rows + i * 72, i); memcpy(rows + i * 72 + 8, data.ref, 56); put16(rows + i * 72 + 64, 6); } extent = tree(&f, 3, rows, extent_rows); free(rows); }
    unsigned char *ir = calloc(inode_count, 352), *nr = calloc(inode_count, 280); assert(ir && nr);
    for (unsigned i = 0; i < inode_count; i++) { char name[32]; int length = snprintf(name, sizeof(name), "f%08u", i); assert(length == 9);
        unsigned char *a = ir + i * 352, *b = nr + i * 280; put64(a, i + 2); put64(a + 8, 1); put32(a + 16, SFS_FILE); put32(a + 20, 9); memcpy(a + 88, name, 9);
        if (extent_rows) { put64(a + 24, (extent_rows - 1) * (uint64_t)CELL + 6); memcpy(a + 32, extent.ref, 56); }
        put64(b, 1); put32(b + 8, 9); memcpy(b + 12, name, 9); put64(b + 267, i + 2);
    }
    fixture_node inodes = tree(&f, 1, ir, inode_count), names = tree(&f, 2, nr, inode_count); free(ir); free(nr);
    fixture_node historical = namespace_cell(&f, inodes, names, inode_count + 2, inode_count), catalog = {0};
    if (snapshots) { unsigned char rows[32 * 328] = {0}; assert(snapshots <= 32); for (unsigned i = 0; i < snapshots; i++) { char name[32]; int length = snprintf(name, sizeof(name), "snapshot-%u", i); put32(rows + i * 328, i + 1); memcpy(rows + i * 328 + 8, historical.ref, 56); put32(rows + i * 328 + 64, (uint32_t)length); memcpy(rows + i * 328 + 68, name, (size_t)length); } catalog = tree(&f, 4, rows, snapshots); }
    fixture_node current = namespace_cell(&f, inodes, names, inode_count + 3, inode_count); finish_fixture(&f, current, catalog); return f;
}
static void fixture_save(fixture *f) { save("image", f->p, f->n); free(f->p); f->p = NULL; }
/* This small parser fixture has fixed 4/3/2 row counts, even when a count is forged. */
static void refresh_parser_ref(unsigned char *image, unsigned char *ref, const unsigned char *original, size_t n, const unsigned char *keep_bad_digest) {
    if (ref != keep_bad_digest && !memcmp(ref, original, 24) && get32(ref)) ref_hash(image, ref, n);
}
static void repair_parser_aliases(unsigned char *image, unsigned char *original, size_t n, const unsigned char *keep_bad_digest) {
    unsigned char *old_commit = record(original, original + 48, n), *old_ns = record(original, old_commit + 64, n);
    unsigned char *old_catalog = record(original, old_commit + 120, n), *old_history = record(original, old_catalog + 648, n);
    unsigned char *old_inodes = record(original, old_ns + 64, n), *old_extents = record(original, old_inodes + 640 + 32, n);
    size_t extent_at = (size_t)(old_extents - original), inode_at = (size_t)(old_inodes - original);
    for (unsigned i = 0; i < 3; i++) refresh_parser_ref(image, image + extent_at + 648 + i * 72, old_extents + 648 + i * 72, n, keep_bad_digest);
    for (unsigned i = 0; i < 4; i++) refresh_parser_ref(image, image + inode_at + 672 + i * 352, old_inodes + 672 + i * 352, n, keep_bad_digest);
    const unsigned char *spaces[] = {old_history, old_ns};
    for (unsigned i = 0; i < 2; i++) for (unsigned j = 0; j < 2; j++) { size_t at = (size_t)(spaces[i] - original) + 64 + j * 56; refresh_parser_ref(image, image + at, original + at, n, keep_bad_digest); }
    for (unsigned i = 0; i < 2; i++) { size_t at = (size_t)(old_catalog - original) + 648 + i * 328; refresh_parser_ref(image, image + at, original + at, n, keep_bad_digest); }
    for (unsigned i = 0; i < 2; i++) { size_t at = (size_t)(old_commit - original) + 64 + i * 56; refresh_parser_ref(image, image + at, original + at, n, keep_bad_digest); }
    for (unsigned i = 0; i < 2; i++) { refresh_parser_ref(image, image + i * CELL + 48, original + i * CELL + 48, n, keep_bad_digest); slot_hash(image + i * CELL); }
}
static int parser_ref_framing(unsigned char *image, const unsigned char *ref, size_t n, uint64_t parent, uint64_t end, unsigned expected) {
    const unsigned char zeroes[24] = {0}; uint64_t at = get64(ref + 8), length = get64(ref + 16);
    if (get32(ref) != expected || memcmp(ref + 4, zeroes, 4) || length != CELL || at < 8192 || at % CELL || at >= parent || at > end || length > end - at || at > n || length > n - at) return 0;
    const unsigned char *p = image + at;
    if (expected != 6 && (memcmp(p, "SFSREC02", 8) || get32(p + 8) != expected || get32(p + 12) || get64(p + 16) != 4032 || memcmp(p + 24, image + 24, 16) || memcmp(p + 40, zeroes, 24))) return 0;
    unsigned char checked[56]; memcpy(checked, ref, 56); ref_hash(image, checked, n); return !memcmp(checked + 24, ref + 24, 32);
}
/* Envelope/hash checks only: no row ordering, counters, parents, kinds, EOF or zero-tail proof. */
static int parser_namespace_framing(unsigned char *image, const unsigned char *ref, size_t n, uint64_t parent, uint64_t end, unsigned inode_count, unsigned extent_count) {
    if (!parser_ref_framing(image, ref, n, parent, end, 2)) return 0;
    unsigned char *ns = image + get64(ref + 8); uint64_t ns_at = (uint64_t)(ns - image);
    if (!parser_ref_framing(image, ns + 64, n, ns_at, end, 5) || !parser_ref_framing(image, ns + 120, n, ns_at, end, 5)) return 0;
    unsigned char *inodes = image + get64(ns + 72);
    for (unsigned i = 0; i < inode_count; i++) {
        const unsigned char *extent_ref = inodes + 672 + i * 352;
        if (!parser_ref_framing(image, extent_ref, n, (uint64_t)(inodes - image), end, 5)) return 0;
        unsigned char *extents = image + get64(extent_ref + 8);
        for (unsigned j = 0; j < extent_count; j++) if (!parser_ref_framing(image, extents + 648 + j * 72, n, (uint64_t)(extents - image), end, 6)) return 0;
    }
    return 1;
}
static int parser_framing_counts(unsigned char *image, size_t n, unsigned inode_count, unsigned extent_count, unsigned snapshots) {
    if (n < 8192) return 0;
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *slot = image + i * CELL, checked[CELL]; memcpy(checked, slot, CELL); slot_hash(checked);
        if (memcmp(slot, "SFSIMG01", 8) || get32(slot + 8) || get32(slot + 12) != 2 || get64(slot + 16)) return 0;
        for (unsigned j = 152; j < CELL; j++) if (slot[j]) return 0;
        if (memcmp(slot + 112, checked + 112, 32)) return 0;
        uint64_t end = get64(slot + 104);
        if (end > n || !parser_ref_framing(image, slot + 48, n, end, end, 4)) return 0;
        unsigned char *commit = image + get64(slot + 56); uint64_t commit_at = (uint64_t)(commit - image);
        if (!parser_namespace_framing(image, commit + 64, n, commit_at, end, inode_count, extent_count)) return 0;
        if (get32(commit + 120)) {
            if (!parser_ref_framing(image, commit + 120, n, commit_at, end, 5)) return 0;
            unsigned char *catalog = image + get64(commit + 128);
            for (unsigned j = 0; j < snapshots; j++) if (!parser_namespace_framing(image, catalog + 648 + j * 328, n, (uint64_t)(catalog - image), end, inode_count, extent_count)) return 0;
        }
    }
    return 1;
}
static int parser_framing_valid(unsigned char *image, size_t n) { return parser_framing_counts(image,n,4,3,2); }
static int parser_semantic_case(const char *kind) {
    const char *cases[] = {"namespace-count", "namespace-next-inode", "leaf-counter-floor", "duplicate-id", "duplicate-name", "bad-parent", "name-length", "nul-name", "slash-name", "bad-kind", "bad-file-size", "catalog-count", "catalog-name-length", "page-padding", "page-kind", "page-level", "page-minimum", "page-maximum", "page-birth", "raw-zero-tail", "smaller-eof-boundary", "smaller-eof-interior"};
    for (unsigned i = 0; i < sizeof(cases) / sizeof(*cases); i++) if (!strcmp(kind, cases[i])) return 1;
    return 0;
}
static void parser(void) {
    fixture f = indexed_fixture(4, 3, 2); size_t n = f.n; unsigned char *baseline = f.p;
    save("image", baseline, n); reset("", 0); sfs_image *valid; sfs_result valid_result;
    open_image(&valid);
    enum sfs_status valid_status = sfs_image_verify(valid, &generous, &valid_result);
    assert(valid_status == SFS_OK && valid_result.status == SFS_OK && valid_result.coverage == SFS_COVERAGE_FULL_REACHABLE);
    receipt("parser-unmodified-baseline-full", &valid_result); close_image(valid);
    unchanged("image", baseline, n); assert(parser_framing_valid(baseline, n)); assert(rename("image", "parser-valid-baseline") == 0);
    const char *cases[] = {
        "one-slot-checksum", "both-slot-checksum", "root-checksum", "current-data", "truncate",
        "uuid-pair", "version-pair", "features-pair", "capacity-pair", "equal-generation", "gap", "zero-generation", "wrap-generation", "parity", "decreasing-end",
        "slot-reserved", "old-minor", "unknown-major", "unknown-minor", "unknown-flags", "root-offset-overflow", "root-offset-slot", "root-length-overflow", "root-type", "root-reserved",
        "record-reserved", "record-uuid", "record-type", "namespace-count", "namespace-next-inode", "leaf-counter-floor", "duplicate-id", "duplicate-name", "bad-parent", "name-length", "nul-name", "slash-name", "bad-kind", "bad-file-size", "extent-offset-overflow", "extent-after-end", "extent-type", "extent-length",
        "catalog-count", "catalog-name-length", "snapshot-root-type", "snapshot-root-cycle", "page-padding", "page-kind", "page-level", "page-minimum", "page-maximum", "page-birth", "raw-zero-tail", "raw-type-conflict", "raw-digest-conflict", "smaller-eof-boundary", "smaller-eof-interior"
    };
    for (unsigned c = 0; c < sizeof(cases)/sizeof(*cases); c++) {
        const char *kind = cases[c]; unsigned char *p = malloc(n); assert(p); memcpy(p, baseline, n); size_t physical = n;
        unsigned char *slot = p, *commit = record(p, slot + 48, n), *ns = record(p, commit + 64, n);
        unsigned char *inodes = record(p, ns + 64, n), *first = inodes + 640, *second = first + 352;
        unsigned char *catalog = record(p, commit + 120, n), *extent = record(p, first + 32, n), *raw = record(p, extent + 648, n);
        int seal_inode = 0, seal_ns = 0, seal_catalog = 0, seal_extent = 0, seal_slot = 0;
        if (!strcmp(kind, "one-slot-checksum")) p[112] ^= 1;
        else if (!strcmp(kind, "both-slot-checksum")) { p[112] ^= 1; p[CELL + 112] ^= 1; }
        else if (!strcmp(kind, "root-checksum")) commit[64] ^= 1;
        else if (!strcmp(kind, "current-data")) raw[0] ^= 1;
        else if (!strcmp(kind, "truncate")) physical = CELL + 17;
        else if (!strcmp(kind, "uuid-pair")) { p[CELL + 24] ^= 1; slot_hash(p + CELL); }
        else if (!strcmp(kind, "version-pair")) { put32(p + CELL + 12, 1); slot_hash(p + CELL); }
        else if (!strcmp(kind, "features-pair")) { put64(p + CELL + 16, 1); slot_hash(p + CELL); }
        else if (!strcmp(kind, "capacity-pair")) { put64(p + CELL + 144, TEST_CAPACITY - CELL); slot_hash(p + CELL); }
        else if (!strcmp(kind, "equal-generation")) { p[CELL + 80] ^= 1; slot_hash(p + CELL); }
        else if (!strcmp(kind, "gap")) { put64(p + 40, 4); seal_slot = 1; }
        else if (!strcmp(kind, "zero-generation")) { put64(p + 40, 0); seal_slot = 1; }
        else if (!strcmp(kind, "wrap-generation")) { put64(p + 40, UINT64_MAX); seal_slot = 1; }
        else if (!strcmp(kind, "parity")) { put64(p + 40, 3); put64(p + CELL + 40, 2); slot_hash(p); slot_hash(p + CELL); }
        else if (!strcmp(kind, "decreasing-end")) { put64(p + 40, 2); put64(p + 104, n - CELL); seal_slot = 1; }
        else if (!strcmp(kind, "slot-reserved")) { p[152] = 1; seal_slot = 1; }
        else if (!strcmp(kind, "old-minor")) { put32(p + 12, 1); seal_slot = 1; }
        else if (!strcmp(kind, "unknown-major")) { put32(p + 8, 99); seal_slot = 1; }
        else if (!strcmp(kind, "unknown-minor")) { put32(p + 12, 99); seal_slot = 1; }
        else if (!strcmp(kind, "unknown-flags")) { put64(p + 16, 1); seal_slot = 1; }
        else if (!strcmp(kind, "root-offset-overflow")) { put64(slot + 56, UINT64_MAX - 4095); seal_slot = 1; }
        else if (!strcmp(kind, "root-offset-slot")) { put64(slot + 56, CELL); seal_slot = 1; }
        else if (!strcmp(kind, "root-length-overflow")) { put64(slot + 64, UINT64_MAX); seal_slot = 1; }
        else if (!strcmp(kind, "root-type")) { put32(slot + 48, 2); seal_slot = 1; }
        else if (!strcmp(kind, "root-reserved")) { put32(slot + 52, 1); seal_slot = 1; }
        else if (!strcmp(kind, "record-reserved")) { ns[40] = 1; seal_ns = 1; }
        else if (!strcmp(kind, "record-uuid")) { ns[24] ^= 1; seal_ns = 1; }
        else if (!strcmp(kind, "record-type")) { put32(ns + 8, 3); seal_ns = 1; }
        else if (!strcmp(kind, "namespace-count")) { put64(ns + 184, UINT64_MAX); seal_ns = 1; }
        else if (!strcmp(kind, "namespace-next-inode")) { put64(ns + 176, 1); seal_ns = 1; }
        else if (!strcmp(kind, "leaf-counter-floor")) { put64(ns + 176, 5); memset(commit + 120, 0, 56); seal_ns = 1; }
        else if (!strcmp(kind, "duplicate-id")) { put64(second, get64(first)); seal_inode = 1; }
        else if (!strcmp(kind, "duplicate-name")) { memcpy(second + 88, first + 88, 9); seal_inode = 1; }
        else if (!strcmp(kind, "bad-parent")) { put64(first + 8, UINT64_MAX); seal_inode = 1; }
        else if (!strcmp(kind, "name-length")) { put32(first + 20, UINT32_MAX); seal_inode = 1; }
        else if (!strcmp(kind, "nul-name")) { first[88] = 0; seal_inode = 1; }
        else if (!strcmp(kind, "slash-name")) { first[88] = '/'; seal_inode = 1; }
        else if (!strcmp(kind, "bad-kind")) { put32(first + 16, 99); seal_inode = 1; }
        else if (!strcmp(kind, "bad-file-size")) { put64(first + 24, UINT64_MAX); seal_inode = 1; }
        else if (!strcmp(kind, "extent-offset-overflow")) { put64(first + 40, UINT64_MAX - 4095); seal_inode = 1; }
        else if (!strcmp(kind, "extent-after-end")) { put64(first + 40, n); seal_inode = 1; }
        else if (!strcmp(kind, "extent-type")) { put32(first + 32, 2); seal_inode = 1; }
        else if (!strcmp(kind, "extent-length")) { put64(first + 48, UINT64_MAX); seal_inode = 1; }
        else if (!strcmp(kind, "catalog-count")) { put16(catalog + 70, 10); seal_catalog = 1; }
        else if (!strcmp(kind, "catalog-name-length")) { put32(catalog + 640 + 64, UINT32_MAX); seal_catalog = 1; }
        else if (!strcmp(kind, "snapshot-root-type")) { put32(catalog + 648, 4); seal_catalog = 1; }
        else if (!strcmp(kind, "snapshot-root-cycle")) { memcpy(catalog + 648, slot + 48, 56); seal_catalog = 1; }
        else if (!strcmp(kind, "page-padding")) { inodes[4095] = 1; seal_inode = 1; }
        else if (!strcmp(kind, "page-kind")) { put32(inodes + 64, 2); seal_inode = 1; }
        else if (!strcmp(kind, "page-level")) { put16(inodes + 68, 16); seal_inode = 1; }
        else if (!strcmp(kind, "page-minimum")) { inodes[119] ^= 1; seal_inode = 1; }
        else if (!strcmp(kind, "page-maximum")) { inodes[382] ^= 1; seal_inode = 1; }
        else if (!strcmp(kind, "page-birth")) { put64(inodes + 72, 2); seal_inode = 1; }
        else if (!strcmp(kind, "raw-zero-tail")) { raw[6] = 'X'; ref_hash(p, extent + 648, n); seal_extent = 1; }
        else if (!strcmp(kind, "raw-type-conflict")) { memcpy(second + 32, extent + 648, 56); put32(second + 32, 5); seal_inode = 1; }
        else if (!strcmp(kind, "raw-digest-conflict")) { extent[640 + 72 + 8 + 24] ^= 1; seal_extent = 1; }
        else if (!strcmp(kind, "smaller-eof-boundary")) { put64(first + 24, 5); seal_inode = 1; }
        else if (!strcmp(kind, "smaller-eof-interior")) { put64(first + 24, CELL); seal_inode = 1; }
        else assert(0);
        if (seal_extent || seal_inode || seal_ns || seal_catalog)
            repair_parser_aliases(p, baseline, n, !strcmp(kind, "raw-digest-conflict") ? extent + 640 + 72 + 8 : NULL);
        else if (seal_slot) slot_hash(slot);
        int semantic = parser_semantic_case(kind), framing = parser_framing_valid(p, physical);
        if (semantic) assert(framing);
        if (!strcmp(kind, "one-slot-checksum") || !strcmp(kind, "both-slot-checksum") || !strcmp(kind, "root-checksum") || !strcmp(kind, "current-data") || !strcmp(kind, "raw-type-conflict") || !strcmp(kind, "raw-digest-conflict")) assert(!framing);
        printf("{\"parser_guard\":\"%s\",\"semantic_only\":%s,\"framing_and_digests_valid\":%s}\n", kind, semantic ? "true" : "false", framing ? "true" : "false"); fflush(stdout);
        save("image", p, physical); reset("", 0); sfs_image *h = NULL; sfs_result r;
        enum sfs_status status = sfs_image_open(root, "image", &h, &r);
        if (status == SFS_OK) {
            assert(r.coverage == SFS_COVERAGE_ROOT_ONLY);
            assert(sfs_image_verify(h, &generous, &r) == SFS_CORRUPT); assert(r.coverage != SFS_COVERAGE_FULL_REACHABLE);
            assert(sfs_image_begin(h, &r) == SFS_POISONED); close_image(h);
        } else assert(h == NULL && (status == SFS_CORRUPT || status == SFS_RECOVERY_REQUIRED || status == SFS_UNSUPPORTED));
        receipt(kind, &r); unchanged("image", p, physical); int candidates; inspect_unchanged(&candidates);
        if (c == 0) assert(candidates == 1); if (c == 1) assert(candidates == 0);
        retain((int)c); free(p);
    }
    free(baseline);
}
static void contexts(void) {
    sfs_image *h; sfs_result r;
    for(unsigned boundary=0;boundary<2;boundary++) for(unsigned mutation=0;mutation<2;mutation++) {
        fixture f=indexed_fixture(2,3,0); unsigned char *slot=f.p, *ns=namespace_at(f.p,slot,f.n), *ir=inode_row(f.p,ns,2,f.n);
        put64(ir+24,boundary?CELL:5); seal_namespace(f.p,slot,f.n,1); memcpy(f.p+CELL,slot,CELL);
        assert(parser_framing_counts(f.p,f.n,2,3,0));
        printf("{\"growth_guard\":true,\"boundary\":%u,\"mutation\":%u}\n",boundary,mutation); fflush(stdout);
        size_t n=f.n; unsigned char *before=malloc(n); assert(before); memcpy(before,f.p,n); fixture_save(&f);
        reset("",0); open_image(&h); OK(sfs_image_begin(h,&r)); reset("",0);
        enum sfs_status status=mutation?sfs_image_resize(h,2,4*UINT64_C(4096),&r):sfs_image_write(h,2,3*UINT64_C(4096),"grow",4,&r);
        assert(status==SFS_CORRUPT&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); unchanged("image",before,n); free(before); retain(750+(int)(boundary*2+mutation));
    }
    /* A page accepted as a current root is invalid as a nonroot child of a snapshot. */
    fixture f=indexed_fixture(5,0,0); unsigned char *old_ns=namespace_at(f.p,f.p,f.n), *ir=record(f.p,old_ns+64,f.n)+640, *nr=record(f.p,old_ns+120,f.n)+640;
    unsigned char inode_rows[5*352], name_rows[5*280]; memcpy(inode_rows,ir,sizeof(inode_rows)); memcpy(name_rows,nr,sizeof(name_rows));
    fixture_node small_i=tree(&f,1,inode_rows,2), small_n=tree(&f,2,name_rows,2), rest=tree(&f,1,inode_rows+2*352,3);
    fixture_node children[2]={small_i,rest}; fixture_node bad_inode=page(&f,1,1,NULL,2,72,children), all_names=tree(&f,2,name_rows,5);
    fixture_node historical=namespace_cell(&f,bad_inode,all_names,7,5); unsigned char snapshot[328]={0}; put32(snapshot,1); memcpy(snapshot+8,historical.ref,56); put32(snapshot+64,3); memcpy(snapshot+68,"bad",3);
    fixture_node catalog=tree(&f,4,snapshot,1), current=namespace_cell(&f,small_i,small_n,8,2); finish_fixture(&f,current,catalog); fixture_save(&f);
    reset("",0); open_image(&h); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); retain(754);
    /* Canonical cross-index rows with an actual directory parent cycle. */
    f=fixture_start(); unsigned char a[2*352]={0}, b[2*280]={0};
    for(unsigned i=0;i<2;i++) { unsigned char *row=a+i*352; put64(row,i+2); put64(row+8,3-i); put32(row+16,SFS_DIRECTORY); put32(row+20,1); row[88]=(unsigned char)('a'+i);
        row=b+(1-i)*280; put64(row,3-i); put32(row+8,1); row[12]=(unsigned char)('a'+i); put64(row+267,i+2); }
    fixture_node inodes=tree(&f,1,a,2), names=tree(&f,2,b,2), ns=namespace_cell(&f,inodes,names,4,2), empty={0}; finish_fixture(&f,ns,empty); fixture_save(&f);
    open_image(&h); OK(sfs_image_begin(h,&r)); sfs_inode id; reset("",0); assert(sfs_image_add(h,2,"child",5,SFS_FILE,&id,&r)==SFS_CORRUPT&&!writes); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); retain(755);
    /* Every changed parent is rehashed, so child-edge failures are beyond checksum framing. */
    for(unsigned kind=0;kind<4;kind++) {
        f=indexed_fixture(432,0,0); unsigned char *slot=f.p, *space=namespace_at(f.p,slot,f.n), *parent=record(f.p,space+64,f.n), *ref=parent+656, *child=record(f.p,ref,f.n);
        if(kind==0) put32(child+64,2); if(kind==1) put16(child+68,1); if(kind==2) child[119]^=1; if(kind==3) memcpy(parent+640+72+16,parent+656,56);
        if(kind<3) ref_hash(f.p,ref,f.n); ref_hash(f.p,space+64,f.n); seal_namespace(f.p,slot,f.n,0); memcpy(f.p+CELL,f.p,CELL);
        fixture_save(&f); open_image(&h); reset("",0); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&!writes&&!fulls); close_image(h); retain(756+(int)kind);
    }
}
static void type_alias_context(void) {
    fixture f=fixture_start(); unsigned char data[CELL]={0}; memcpy(data,"inner",5); fixture_node inner=append_cell(&f,6,data);
    unsigned char extent_row[72]={0}; memcpy(extent_row+8,inner.ref,56); put16(extent_row+64,5); fixture_node as_index=tree(&f,3,extent_row,1);
    unsigned char as_raw[56]; memcpy(as_raw,as_index.ref,56); put32(as_raw,6); ref_hash(f.p,as_raw,f.n);
    memcpy(extent_row+8,as_raw,56); put16(extent_row+64,CELL); fixture_node outer=tree(&f,3,extent_row,1);
    unsigned char ir[2*352]={0}, nr[2*280]={0};
    for(unsigned i=0;i<2;i++) { unsigned char *row=ir+i*352; put64(row,i+2); put64(row+8,1); put32(row+16,SFS_FILE); put32(row+20,1); put64(row+24,i?5:CELL); memcpy(row+32,i?as_index.ref:outer.ref,56); row[88]=(unsigned char)('a'+i);
        row=nr+i*280; put64(row,1); put32(row+8,1); row[12]=(unsigned char)('a'+i); put64(row+267,i+2); }
    fixture_node inodes=tree(&f,1,ir,2), names=tree(&f,2,nr,2), ns=namespace_cell(&f,inodes,names,4,2), empty={0}; finish_fixture(&f,ns,empty); fixture_save(&f);
    sfs_image *h; sfs_result r; reset("",0); open_image(&h); expect(h,0,3,"inner"); reset("",0);
    assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); retain(760);
}
static void verification(void) {
    assert(rename("image", "io-original") == 0); reset("", 0); sfs_image *h; sfs_result r; sfs_inode a,b;
    create(&h); initial_files(h,&a,&b); OK(sfs_image_begin(h,&r)); sfs_view view; OK(sfs_image_snapshot(h,"before",6,&view,&r)); OK(sfs_image_commit(h,&r)); close_image(h);
    size_t n; unsigned char *baseline=bytes("image",&n); assert(rename("image","verification-baseline")==0);
    for (int operation=0;operation<2;operation++) {
        save("image",baseline,n); open_image(&h); unsigned char *copy=malloc(n); assert(copy); memcpy(copy,baseline,n);
        unsigned char *commit=record(copy,selected_slot(copy)+48,n), *ns=record(copy,commit+64,n), *ir=inode_row(copy,ns,a,n);
        uint64_t at= get64(raw_ref(copy,ir,0,n)+8);
        copy[at]^=1; replace_image(copy,n); reset("",0);
        if (!operation) assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT);
        else if (operation==1) { unsigned char out[8]; memset(out,0xA5,sizeof(out)); size_t got=99; assert(sfs_image_read(h,0,a,0,out,sizeof(out),&got,&r)==SFS_CORRUPT && !got); for(unsigned i=0;i<sizeof(out);i++) assert(out[i]==0xA5); }
        assert(!writes&&!fulls&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE); receipt("standalone-corruption-poison",&r);
        assert(sfs_image_begin(h,&r)==SFS_POISONED); close_image(h); unchanged("image",copy,n); free(copy); retain(100+operation);
    }
    for (unsigned io_error=0;io_error<2;io_error++) {
        fixture f=indexed_fixture(10,0,1); size_t size=f.n;
        unsigned char *snapshot_ns=record(f.p,record(f.p,record(f.p,f.p+48,size)+120,size)+648,size);
        unsigned char *inode_root=record(f.p,snapshot_ns+64,size); uint64_t child_at=get64(inode_root+656+8);
        fixture_save(&f); open_image(&h); OK(sfs_image_begin(h,&r));
        if(io_error) reset("read_error",1);
        else { int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); unsigned char bad='X'; raw_write(fd,&bad,1,(off_t)child_at); assert(!close(fd)); reset("",0); }
        sfs_entry entry; assert(sfs_image_lookup(h,1,1,"f00000000",9,&entry,&r)==(io_error?SFS_IO:SFS_CORRUPT));
        assert(!writes&&!fulls); if(io_error) assert(hit&&r.system_errno==EIO);
        receipt("cold-snapshot-child-poison",&r); reset("",0); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); retain(110+(int)io_error);
    }
    save("image",baseline,n); sfs_recovery recovery; OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r));
    OK(sfs_image_select(h,1,&generous,&r)); baseline[CELL+112]^=1; replace_image(baseline,n);
    assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT); assert(sfs_image_select(h,1,&generous,&r)==SFS_CORRUPT);
    close_image(h); unchanged("image",baseline,n); free(baseline); retain(103);
    /* Untouched snapshot damage is not an ordinary-open or commit FULL claim. */
    reset("",0); create(&h); initial_files(h,&a,&b); OK(sfs_image_begin(h,&r)); OK(sfs_image_snapshot(h,"before",6,&view,&r)); OK(sfs_image_commit(h,&r));
    change_files(h,a,b); OK(sfs_image_commit(h,&r)); close_image(h);
    unsigned char *p=bytes("image",&n), *current=record(p,selected_slot(p)+48,n), *catalog=record(p,current+120,n), *old_ns=record(p,catalog+648,n);
    uint64_t old_at=get64(raw_ref(p,inode_row(p,old_ns,a,n),0,n)+8); p[old_at]^=1; replace_image(p,n); free(p);
    open_image(&h); expect(h,0,a,"new-a"); OK(sfs_image_begin(h,&r)); add(h,1,"unrelated",SFS_FILE); OK(sfs_image_commit(h,&r)); assert(r.coverage==SFS_COVERAGE_ROOT_ONLY); close_image(h);
    p=bytes("image",&n); open_image(&h); unsigned char output[8]; size_t got=99; memset(output,0xA5,sizeof(output)); reset("",0);
    assert(sfs_image_read(h,view,a,0,output,sizeof(output),&got,&r)==SFS_CORRUPT&&!got&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h);
    open_image(&h); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE); close_image(h); unchanged("image",p,n); free(p); retain(104);
}
static void review(void) {
    reset("",0); sfs_image *h; sfs_result r; sfs_inode a,b; create(&h); initial_files(h,&a,&b);
    OK(sfs_image_begin(h,&r)); sfs_view view; OK(sfs_image_snapshot(h,"before",6,&view,&r)); OK(sfs_image_commit(h,&r));
    size_t old_n; unsigned char *older=bytes("image",&old_n); change_files(h,a,b); OK(sfs_image_commit(h,&r)); close_image(h);
    size_t new_n; unsigned char *newer=bytes("image",&new_n), *tail=malloc(new_n); assert(tail && new_n>old_n); memcpy(tail,newer,new_n); memcpy(tail,older,8192); retain(499);
    for(int commit=0;commit<2;commit++) {
        save("image",tail,new_n); open_image(&h); OK(sfs_image_begin(h,&r));
        int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); raw_write(fd,newer,CELL,0); assert(!close(fd)); reset("",0);
        assert((commit?sfs_image_commit(h,&r):sfs_image_verify(h,&generous,&r))==SFS_CORRUPT && !writes&&!fulls);
        receipt(commit?"newer-anchor-commit-refused":"newer-anchor-verify-refused",&r);
        assert(sfs_image_begin(h,&r)==SFS_POISONED && sfs_image_write(h,a,0,"x",1,&r)==SFS_POISONED && sfs_image_commit(h,&r)==SFS_POISONED);
        close_image(h); unchanged("image",newer,new_n); open_image(&h); OK(sfs_image_verify(h,&generous,&r)); assert(r.generation==4);
        expect(h,0,a,"new-a"); expect(h,0,b,"new-b"); expect(h,view,a,"old-a"); close_image(h); retain(500+commit);
    }
    free(tail); free(newer); read_at[0]=get64(older+56); read_at[1]=get64(older+CELL+56);
    for(int candidate=0;candidate<2;candidate++) for(int mask=1;mask<=3;mask++) {
        save("image",older,old_n); reset(candidate?"candidate_reads":"slot_reads",mask); h=NULL;
        enum sfs_status status=sfs_image_open(root,"image",&h,&r); assert(!h&&hit);
        assert(status==(candidate?SFS_IO:SFS_RECOVERY_REQUIRED)); assert(r.system_errno==(candidate?(mask==1?EIO:ENXIO):(mask&1?EIO:ENXIO)));
        receipt(candidate?"candidate-errno-open":"slot-errno-open",&r);
        reset(candidate?"candidate_reads":"slot_reads",mask); sfs_recovery recovery;
        status=sfs_image_inspect(root,"image",&h,&recovery,&generous,&r); assert(hit);
        for(unsigned i=0;i<2;i++) { assert(recovery.slots[i].status==((mask&(1<<i))?SFS_IO:SFS_OK)); assert(recovery.slots[i].system_errno==((mask&(1<<i))?(i?ENXIO:EIO):0)); }
        if(mask==3) assert(status==SFS_RECOVERY_REQUIRED&&!h&&r.system_errno==EIO);
        else {
            assert(status==SFS_OK&&h&&!r.system_errno); reset("",0);
            if(!candidate) { unsigned bad=mask==1?0:1; assert(sfs_image_select(h,bad,&generous,&r)==SFS_IO&&r.system_errno==(bad?ENXIO:EIO)); }
            OK(sfs_image_select(h,mask==1?1:0,&generous,&r));
            if(!candidate&&mask==1) { reset("read_error",3); assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&r.system_errno==EIO&&hit); reset("",0); OK(sfs_image_verify(h,&generous,&r)); assert(sfs_image_begin(h,&r)!=SFS_OK); }
            close_image(h);
        }
        unchanged("image",older,old_n); retain(510+candidate*3+mask);
    }
    for(int operation=0;operation<3;operation++) {
        save("image",older,old_n); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r));
        reset("read_error",1);
        if(!operation) {
            enum sfs_status status=sfs_image_verify(h,&generous,&r);
            printf("{\"verify_io_observation\":true,\"returned_status\":%d,\"result_status\":%d,\"phase\":%d,\"system_errno\":%d,\"fault_hits\":%d}\n",status,r.status,r.phase,r.system_errno,hit); fflush(stdout);
            assert(status==SFS_IO&&r.status==SFS_IO&&r.phase==SFS_PHASE_READ);
        }
        else if(operation==1) { unsigned char out[8]; memset(out,0xA5,sizeof(out)); size_t got=99; assert(sfs_image_read(h,0,a,0,out,sizeof(out),&got,&r)==SFS_IO&&!got); for(unsigned i=0;i<sizeof(out);i++) assert(out[i]==0xA5); }
        else { unsigned char out[8]; size_t got; assert(sfs_image_read(h,view,a,0,out,sizeof(out),&got,&r)==SFS_IO&&!got); }
        assert(hit&&r.system_errno==EIO&&!writes&&!fulls&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        receipt("standalone-io-poison",&r); reset("",0);
        assert(sfs_image_write(h,a,0,"x",1,&r)==SFS_POISONED&&sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); unchanged("image",older,old_n); retain(520+operation);
    }
    /* An observed slot I/O error takes precedence over a later read-budget stop. */
    for(unsigned io_error=0;io_error<2;io_error++) {
        save("image",older,old_n); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r));
        OK(sfs_image_write(h,a,0,"pending",7,&r));
        size_t staged_n; unsigned char *staged=bytes("image",&staged_n); struct stat identity,after;
        assert(!lstat("image",&identity)); sfs_verify_budget budget=generous; budget.metadata_read_bytes=CELL;
        reset(io_error?"slot_reads":"",io_error?1:0);
        enum sfs_status status=sfs_image_verify(h,&budget,&r);
        printf("{\"io_before_budget\":%s,\"returned_status\":%d,\"fault_hits\":%d}\n",io_error?"true":"false",status,hit); fflush(stdout);
        receipt(io_error?"slot-io-before-budget":"clean-budget-retains-staging",&r);
        assert(!writes&&!fulls&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        unchanged("image",staged,staged_n);
        assert(!lstat("image",&after)&&identity.st_dev==after.st_dev&&identity.st_ino==after.st_ino&&identity.st_size==after.st_size&&identity.st_mode==after.st_mode&&identity.st_uid==after.st_uid&&identity.st_gid==after.st_gid&&identity.st_nlink==after.st_nlink);
        if(io_error) {
            assert(hit&&status==SFS_IO&&r.status==SFS_IO&&r.system_errno==EIO&&r.phase==SFS_PHASE_READ);
            reset("",0); assert(sfs_image_write(h,a,0,"x",1,&r)==SFS_POISONED&&sfs_image_commit(h,&r)==SFS_POISONED);
            close_image(h); unchanged("image",staged,staged_n); open_image(&h); expect(h,0,a,"old-a"); expect(h,view,a,"old-a"); close_image(h);
        } else {
            assert(!hit&&status==SFS_INCOMPLETE&&r.status==SFS_INCOMPLETE&&!r.system_errno&&r.incomplete_reason==SFS_INCOMPLETE_METADATA_READ);
            reset("",0); OK(sfs_image_commit(h,&r)); expect(h,0,a,"pending"); expect(h,view,a,"old-a"); close_image(h);
        }
        free(staged); retain(530+(int)io_error);
    }
    free(older);
}
static void counter_floor(void) {
    for(unsigned snapshot=0;snapshot<2;snapshot++) {
        reset("",0); sfs_image *h; sfs_result r; sfs_inode a,b; create(&h); initial_files(h,&a,&b); OK(sfs_image_begin(h,&r));
        if(snapshot) { sfs_view v; OK(sfs_image_snapshot(h,"before",6,&v,&r)); }
        OK(sfs_image_remove(h,b,&r)); OK(sfs_image_commit(h,&r)); close_image(h);
        size_t n; unsigned char *base=bytes("image",&n), *p=malloc(n); assert(p); memcpy(p,base,n);
        unsigned char *prior=namespace_at(base,base,n); watch_payload(0,raw_ref(base,inode_row(base,prior,b,n),0,n)); watch_count=snapshot?0:1;
        open_image(&h); watch_clear(); OK(sfs_image_verify(h,&generous,&r)); if(!snapshot) assert(!watch_bytes[0]); close_image(h);
        unsigned char *slot=selected_slot(p), *ns=namespace_at(p,slot,n); assert(get64(ns+176)==4); put64(ns+176,3); seal_namespace(p,slot,n,0); replace_image(p,n);
        reset("",0); h=NULL; assert(sfs_image_open(root,"image",&h,&r)==SFS_CORRUPT&&!h&&!writes&&!fulls); if(!snapshot) assert(!watch_bytes[0]);
        receipt(snapshot?"snapshot-counter-floor-refused":"predecessor-counter-floor-refused",&r); unchanged("image",p,n); retain(600+snapshot); watch_count=0;
        if(!snapshot) {
            save("image",base,n); open_image(&h); memcpy(p,base,n); unsigned char *prior_ns=namespace_at(p,p,n); prior_ns[176]^=1; replace_image(p,n);
            reset("",0); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h);
            h=NULL; assert(sfs_image_open(root,"image",&h,&r)==SFS_CORRUPT&&!h);
            sfs_recovery recovery; OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); assert(recovery.slots[0].status==SFS_CORRUPT&&recovery.slots[1].status==SFS_OK);
            OK(sfs_image_select(h,1,&generous,&r)); expect(h,0,a,"old-a"); assert(sfs_image_begin(h,&r)!=SFS_OK); close_image(h); unchanged("image",p,n); retain(602);
        }
        free(base); free(p);
    }
}
static void shared_graph(void) {
    /* 1,201 leaves exceed the 4 MiB clean cache; one raw cell is shared by every extent. */
    fixture f=indexed_fixture(2,48*1201,3); fixture_save(&f); reset("",0); sfs_image *h; sfs_result r; open_image(&h);
    size_t n; unsigned char *image=bytes("image",&n), *ns=namespace_at(image,selected_slot(image),n);
    watch_payload(0,ns+64); watch_payload(1,raw_ref(image,inode_row(image,ns,2,n),0,n)); watch_count=2;
    for(unsigned pass=0;pass<2;pass++) {
        reset("",0); watch_clear(); unsigned made=aux_created, removed=aux_removed; OK(sfs_image_verify(h,&generous,&r));
        assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE && aux_created==made+1 && aux_removed==removed+1);
        assert(raw_hashes==1&&raw_hash_input==4132&&watch_bytes[1]==CELL&&watch_reads[1]==1);
        assert(allocated <= ((allocation_header *)h-1)->value.bytes + UINT64_C(4194304));
        assert(peak_allocated <= ((allocation_header *)h-1)->value.bytes + UINT64_C(9437184));
        assert(watch_reads[0]>=2&&metadata_hash_input>UINT64_C(4194304)&&image_read_bytes>UINT64_C(4194304)); counters("eviction-metadata-reloads-unique-raw");
    }
    watch_count=0;
    /* Mutation owns inode 2; inode 3 and every snapshot retain the shared tree. */
    OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); OK(sfs_image_resize(h,2,3,&r)); OK(sfs_image_commit(h,&r));
    unsigned char b[8]; size_t got; OK(sfs_image_read(h,0,2,0,b,sizeof(b),&got,&r)); assert(got==3&&!memcmp(b,"new",3));
    for(unsigned v=0;v<=3;v++) { uint64_t last=(48*UINT64_C(1201)-1)*CELL; sfs_entry entry; OK(sfs_image_stat(h,v,3,&entry,&r)); assert(entry.size==last+6); OK(sfs_image_read(h,v,3,last,b,6,&got,&r)); assert(got==6&&!memcmp(b,"shared",6)); if(v) { OK(sfs_image_stat(h,v,2,&entry,&r)); assert(entry.size==last+6); OK(sfs_image_read(h,v,2,last,b,6,&got,&r)); assert(got==6&&!memcmp(b,"shared",6)); } }
    OK(sfs_image_verify(h,&generous,&r)); close_image(h); open_image(&h); OK(sfs_image_verify(h,&generous,&r));
    image[watch_at[1]]^=1; int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); raw_write(fd,image+watch_at[1],1,(off_t)watch_at[1]); assert(!close(fd));
    reset("",0); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&raw_hash_input>=4132&&!writes&&!fulls); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); free(image); retain(603);
}
static void security(void) { counter_floor(); shared_graph(); }
static unsigned disk_level(unsigned map) {
    size_t n; unsigned char *p=bytes("image",&n), *slot=selected_slot(p), *ns=namespace_at(p,slot,n), *ref=ns+(map==1?64:120);
    unsigned result=get32(ref)?get16(record(p,ref,n)+68):UINT_MAX; free(p); return result;
}
static void check_directory(sfs_image *h, unsigned count, const unsigned char *live) {
    sfs_cookie cookie={0}; sfs_entry entry; sfs_result r; int found; unsigned seen=0; uint64_t previous=0;
    do { OK(sfs_image_next(h,0,1,&cookie,&entry,&found,&r)); if(found) { assert(r.coverage==SFS_COVERAGE_TOUCHED && entry.inode>previous); previous=entry.inode; if(live) assert(live[entry.inode-2]); seen++; } } while(found);
    assert(seen==count);
}
static void indexes(void) {
    /* Full inode root plus full leaves: the next insertion must grow a real third level. */
    fixture f=indexed_fixture(432,0,2); fixture_save(&f); reset("",0); sfs_image *h; sfs_result r; open_image(&h);
    OK(sfs_image_verify(h,&generous,&r)); assert(disk_level(1)==1&&disk_level(2)>=2);
    OK(sfs_image_begin(h,&r)); sfs_inode extra=add(h,1,"z-final",SFS_FILE); OK(sfs_image_commit(h,&r)); assert(disk_level(1)==2); check_directory(h,433,NULL);
    unsigned char live[432]; memset(live,1,sizeof(live)); OK(sfs_image_begin(h,&r)); OK(sfs_image_remove(h,extra,&r));
    for(unsigned i=0;i<432;i++) { unsigned key=(i&1)?431-i/2:i/2; OK(sfs_image_remove(h,key+2,&r)); live[key]=0; }
    OK(sfs_image_commit(h,&r)); assert(disk_level(1)==UINT_MAX&&disk_level(2)==UINT_MAX); check_directory(h,0,live);
    OK(sfs_image_verify(h,&generous,&r)); for(unsigned v=1;v<=2;v++) { sfs_entry e; OK(sfs_image_lookup(h,v,1,"f00000431",9,&e,&r)); assert(e.inode==433); }
    close_image(h); retain(700);
    /* Equal-sized legal children force right then left lending and eventual root collapse. */
    for(unsigned reverse=0;reverse<2;reverse++) {
        f=indexed_fixture(10,0,0); fixture_save(&f); open_image(&h); memset(live,1,10);
        for(unsigned i=0;i<5;i++) { unsigned id=reverse?11-i:2+i; OK(sfs_image_begin(h,&r)); OK(sfs_image_remove(h,id,&r)); OK(sfs_image_commit(h,&r)); live[id-2]=0;
            check_directory(h,9-i,live); OK(sfs_image_verify(h,&generous,&r));
            if(i==2) { size_t n; unsigned char *p=bytes("image",&n), *ns=namespace_at(p,selected_slot(p),n), *root_page=record(p,ns+64,n);
                assert(get16(root_page+68)==1&&get16(root_page+70)==2); unsigned left=get16(record(p,root_page+656,n)+70), right=get16(record(p,root_page+728,n)+70);
                assert(left==(reverse?4:3)&&right==(reverse?3:4)); free(p);
            }
        }
        assert(disk_level(1)==0); close_image(h); retain(701+(int)reverse);
    }
    reset("",0); create(&h); OK(sfs_image_begin(h,&r)); sfs_inode a=add(h,1,"a",SFS_DIRECTORY), b=add(h,a,"b",SFS_DIRECTORY), file=add(h,b,"file",SFS_FILE);
    OK(sfs_image_commit(h,&r)); sfs_cookie cookie={0}; sfs_entry e; int found; OK(sfs_image_next(h,0,b,&cookie,&e,&found,&r)); assert(found&&e.inode==file);
    sfs_cookie wrong=cookie; assert(sfs_image_next(h,0,a,&wrong,&e,&found,&r)==SFS_INVALID);
    wrong=cookie; wrong.bytes[1087]=1; assert(sfs_image_next(h,0,b,&wrong,&e,&found,&r)==SFS_INVALID);
    OK(sfs_image_begin(h,&r)); assert(sfs_image_remove(h,b,&r)!=SFS_OK); assert(sfs_image_rename(h,a,b,"cycle",5,&r)!=SFS_OK); OK(sfs_image_abort(h,&r));
    OK(sfs_image_begin(h,&r)); OK(sfs_image_rename(h,file,1,"moved",5,&r)); OK(sfs_image_commit(h,&r)); assert(sfs_image_next(h,0,b,&cookie,&e,&found,&r)!=SFS_OK);
    OK(sfs_image_lookup(h,0,1,"moved",5,&e,&r)); assert(e.inode==file); OK(sfs_image_verify(h,&generous,&r)); close_image(h); retain(703);
    /* Prefix ordering includes maximum-length names and unsigned bytes. */
    create(&h); OK(sfs_image_begin(h,&r)); unsigned char name[255]; memset(name,'p',sizeof(name));
    sfs_inode id; for(unsigned i=0;i<25;i++) { name[254]=(unsigned char)('a'+i); OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r)); }
    name[254]=0x80; OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r)); name[254]=0xFF; OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r));
    add(h,1,"p",SFS_FILE); OK(sfs_image_commit(h,&r)); cookie=(sfs_cookie){0}; unsigned seen=0;
    do { OK(sfs_image_next(h,0,1,&cookie,&e,&found,&r)); if(found) { if(!seen) assert(e.name_length==1); else { assert(e.name_length==255); assert(e.name[254]==(seen<=25?'a'+seen-1:seen==26?0x80u:0xFFu)); } seen++; } } while(found);
    assert(seen==28); OK(sfs_image_verify(h,&generous,&r)); close_image(h);
}
static void expect_buffer(sfs_image *h, sfs_view view, sfs_inode id, const unsigned char *want, size_t length) {
    unsigned char b[32768]; sfs_result r; size_t got;
    for(size_t at=0;at<length;at+=sizeof(b)) { size_t n=length-at; if(n>sizeof(b)) n=sizeof(b); memset(b,0xA5,sizeof(b)); OK(sfs_image_read(h,view,id,at,b,n,&got,&r)); assert(got==n&&!memcmp(b,want+at,n)&&r.coverage==SFS_COVERAGE_TOUCHED); }
    OK(sfs_image_read(h,view,id,length,b,sizeof(b),&got,&r)); assert(!got);
}
static void ranges(void) {
    fixture f=indexed_fixture(2,1,2); fixture_save(&f); reset("",0); sfs_image *h; sfs_result r; open_image(&h); OK(sfs_image_begin(h,&r));
    unsigned char input[65537], *expected=calloc(257,CELL); assert(expected); memset(input,'A',sizeof(input));
    size_t old_n; unsigned char *before=bytes("image",&old_n); reset("",0);
    assert(sfs_image_write(h,2,0,input,sizeof(input),&r)==SFS_INVALID&&!writes&&!fulls); unchanged("image",before,old_n); free(before);
    fail_allocation=allocation_calls+1; assert(sfs_image_write(h,2,0,input,7,&r)==SFS_NOMEM&&!writes); fail_allocation=0;
    for(unsigned i=0;i<16;i++) { memset(input,'A'+i,65536); OK(sfs_image_write(h,2,(uint64_t)i*65536,input,65536,&r)); memcpy(expected+i*65536,input,65536);
        if(!i) {
            uint64_t at=image_append_bytes; fail_allocation=allocation_calls+1;
            assert(sfs_image_write(h,2,1,"never",5,&r)==SFS_NOMEM&&image_append_bytes==at); fail_allocation=0;
            uint64_t clone_before=overlay_clone_bytes, calls_before=overlay_clone_calls;
            OK(sfs_image_write(h,2,CELL-1,"cross",5,&r)); memcpy(expected+CELL-1,"cross",5);
            counters("early-owned-overlay-clone");
            assert(overlay_clone_bytes>clone_before&&overlay_clone_calls>calls_before&&observed_clone_size>CELL);
            OK(sfs_image_write(h,2,5,"partial",7,&r)); memcpy(expected+5,"partial",7); OK(sfs_image_write(h,2,8,"XYZ",3,&r)); memcpy(expected+8,"XYZ",3);
        }
    }
    counters("stream-overlay-clones-before-assert");
    assert(overlay_clone_bytes&&overlay_clone_calls&&observed_clone_size>CELL);
    assert(peak_allocated <= ((allocation_header *)h-1)->value.bytes + UINT64_C(14680064));
    assert(!fulls); uint64_t zero_before=image_append_bytes; OK(sfs_image_write(h,3,0,NULL,0,&r)); assert(image_append_bytes==zero_before&&!fulls); expect(h,0,2,"shared");
    uint64_t appended=image_append_bytes; OK(sfs_image_write(h,2,256*UINT64_C(4096),"R",1,&r)); expected[256*CELL]='R'; assert(image_append_bytes>appended&&!fulls);
    OK(sfs_image_write(h,3,0,"new-b",5,&r)); sfs_view view; OK(sfs_image_snapshot(h,"during",6,&view,&r)); assert(!fulls); OK(sfs_image_commit(h,&r)); assert(r.coverage==SFS_COVERAGE_ROOT_ONLY&&fulls==2);
    expect_buffer(h,0,2,expected,256*CELL+1); for(unsigned v=1;v<=3;v++) expect(h,v,2,"shared"); expect(h,0,3,"new-bd"); counters("real-stream-forced-seal");
    OK(sfs_image_verify(h,&generous,&r)); close_image(h); open_image(&h);
    OK(sfs_image_begin(h,&r)); OK(sfs_image_resize(h,2,49*UINT64_C(4096)+13,&r)); OK(sfs_image_commit(h,&r)); close_image(h); open_image(&h);
    OK(sfs_image_begin(h,&r)); OK(sfs_image_resize(h,2,64*UINT64_C(4096),&r)); OK(sfs_image_commit(h,&r)); memset(expected+49*CELL+13,0,64*CELL-(49*CELL+13)); expect_buffer(h,0,2,expected,64*CELL);
    OK(sfs_image_begin(h,&r)); OK(sfs_image_resize(h,2,0,&r)); OK(sfs_image_resize(h,2,8192,&r)); OK(sfs_image_commit(h,&r)); memset(expected,0,8192); expect_buffer(h,0,2,expected,8192);
    OK(sfs_image_verify(h,&generous,&r)); close_image(h); free(expected); retain(710);
    /* Verified-prefix output on a second raw-cell read error. */
    create(&h); OK(sfs_image_begin(h,&r)); sfs_inode id=add(h,1,"prefix",SFS_FILE); memset(input,'Q',8192); OK(sfs_image_write(h,id,0,input,8192,&r)); OK(sfs_image_commit(h,&r)); close_image(h);
    size_t n; unsigned char *image=bytes("image",&n), *ns=namespace_at(image,selected_slot(image),n); read_at[0]=get64(raw_ref(image,inode_row(image,ns,id,n),1,n)+8); free(image);
    open_image(&h); reset("candidate_reads",1); unsigned char output[8192]; memset(output,0xA5,sizeof(output)); size_t got=99;
    assert(sfs_image_read(h,0,id,0,output,sizeof(output),&got,&r)==SFS_IO&&got==CELL&&r.system_errno==EIO);
    for(unsigned i=0;i<CELL;i++) assert(output[i]=='Q'&&output[CELL+i]==0xA5); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h);
}
static void file_digest(const char *name, unsigned char digest[32], uint64_t *length) {
    int fd=open(name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); struct stat st; assert(!fstat(fd,&st)&&st.st_size>=0); *length=(uint64_t)st.st_size;
    CC_SHA256_CTX c; CC_SHA256_Init(&c); unsigned char b[65536];
    for(uint64_t at=0;at<*length;) { ssize_t n=pread(fd,b,sizeof(b),(off_t)at); assert(n>0); CC_SHA256_Update(&c,b,(CC_LONG)n); at+=(size_t)n; }
    CC_SHA256_Final(digest,&c); assert(!close(fd));
}
static void mapped_ref(unsigned char *ref, unsigned char *mapping, size_t cells) {
    if(!get32(ref)) return; uint64_t cell=get64(ref+8)/CELL; assert(cell<cells&&get32(mapping+cell*56)==get32(ref)); memcpy(ref,mapping+cell*56,56);
}
static void sparse_aux_fixture(void) {
    fixture f=indexed_fixture(2,48*1050,2); size_t cells=f.n/CELL; unsigned char *mapping=calloc(cells,56); assert(mapping);
    int fd=open("image",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); assert(fd>=0); uint64_t end=0;
    for(size_t i=2;i<cells;i++) {
        unsigned char *p=f.p+i*CELL; unsigned type=!memcmp(p,"SFSREC02",8)?get32(p+8):6;
        if(type==2||type==4) { mapped_ref(p+64,mapping,cells); mapped_ref(p+120,mapping,cells); }
        if(type==5) { unsigned map=get32(p+64), level=get16(p+68), count=get16(p+70), stride=level?(map==2?328:72):(map==1?352:map==2?280:map==3?72:328);
            for(unsigned j=0;j<count;j++) { unsigned char *row=p+640+j*stride; if(level) mapped_ref(row+(map==2?271:16),mapping,cells); else if(map==1) mapped_ref(row+32,mapping,cells); else if(map==3||map==4) mapped_ref(row+8,mapping,cells); }
        }
        unsigned char *ref=mapping+i*56; put32(ref,type); uint64_t at=(2+(i-2)*32)*UINT64_C(4096); put64(ref+8,at); put64(ref+16,CELL);
        if(type==6) { unsigned char domain[36]; memcpy(domain,"SFSDAT02",8); memcpy(domain+8,f.p+24,16); put32(domain+24,6); put64(domain+28,CELL); CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c,domain,36); CC_SHA256_Update(&c,p,CELL); CC_SHA256_Final(ref+24,&c); }
        else CC_SHA256(p,CELL,ref+24); raw_write(fd,p,CELL,(off_t)at); end=at+CELL;
    }
    assert(end<UINT64_C(268435456));
    for(unsigned i=0;i<2;i++) { unsigned char *slot=f.p+i*CELL; mapped_ref(slot+48,mapping,cells); put64(slot+104,end); put64(slot+144,UINT64_C(268435456)); slot_hash(slot); raw_write(fd,slot,CELL,i*CELL); }
    assert(!close(fd)); printf("{\"case\":\"sparse-aux-layout\",\"stored_cell_bytes\":%llu,\"logical_end\":%llu,\"capacity\":268435456,\"filesystem_allocation_claim\":false}\n",(unsigned long long)(cells*CELL),(unsigned long long)end); fflush(stdout); free(mapping); free(f.p);
}
static int cancel_now(void *context) { unsigned *calls=context; (*calls)++; return 1; }
typedef struct {
    uint64_t after_hash, hash_at_cancel;
    unsigned calls, fired;
    int reads_at_cancel;
} recovery_cancellation;
static int cancel_recovery_once(void *context) {
    recovery_cancellation *c = context; c->calls++;
    if (!c->fired && metadata_hash_input >= c->after_hash) {
        c->fired = 1; c->hash_at_cancel = metadata_hash_input; c->reads_at_cancel = reads; return 1;
    }
    return 0;
}
static void recovery_observation(void) {
    reset("", 0); sfs_image *h; sfs_result r; create(&h); close_image(h);
    size_t n; unsigned char *baseline = bytes("image", &n), *changed = malloc(n); assert(changed);
    memcpy(changed, baseline, n); put64(changed + 40, 2); slot_hash(changed);
    assert(get64(baseline + 40) == 1 && get64(changed + 104) == get64(baseline + 104));
    assert(!memcmp(changed + CELL, baseline + CELL, n - CELL));
    /* The replacement is independently FULL-valid as a standalone readonly candidate. */
    save("recovery-valid-alternate", changed, n); sfs_recovery recovery;
    OK(sfs_image_inspect(root, "recovery-valid-alternate", &h, &recovery, &generous, &r));
    assert(recovery.slots[0].status == SFS_OK && recovery.slots[0].coverage == SFS_COVERAGE_FULL_REACHABLE);
    OK(sfs_image_select(h, 0, &generous, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && r.generation == 2 && !r.system_errno);
    close_image(h); unchanged("recovery-valid-alternate", changed, n);
    struct stat identity; assert(!lstat("image", &identity));
    for (unsigned mode = 0; mode < 3; mode++) {
        /* mode1 cancels after both anchors; modes0/2 cancel before slot0 is observed. */
        recovery_cancellation initial = {.after_hash = mode == 1 ? 2 * CELL : 0};
        sfs_verify_budget budget = generous; budget.cancelled = cancel_recovery_once; budget.context = &initial;
        reset("", 0); OK(sfs_image_inspect(root, "image", &h, &recovery, &budget, &r));
        assert(initial.fired == 1 && initial.hash_at_cancel == (mode == 1 ? 2 * CELL : 0) && initial.reads_at_cancel == (mode == 1 ? 2 : 0));
        assert(recovery.slots[0].status == SFS_INCOMPLETE && !recovery.slots[0].system_errno && recovery.slots[0].incomplete_reason == SFS_INCOMPLETE_CANCELLED && recovery.slots[0].coverage != SFS_COVERAGE_FULL_REACHABLE);
        assert(recovery.slots[1].status == SFS_OK && !recovery.slots[1].system_errno && recovery.slots[1].coverage == SFS_COVERAGE_FULL_REACHABLE);
        sfs_entry entry; assert(sfs_image_stat(h, 0, SFS_ROOT_INODE, &entry, &r) == SFS_STATE);
        assert(!writes && !fulls); unchanged("image", baseline, n);
        if (mode == 0) {
            OK(sfs_image_select(h, 0, &generous, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && r.generation == 1 && !r.system_errno);
            receipt("unobserved-anchor-fresh-full-select", &r);
        } else if (mode == 2) {
            recovery_cancellation during = {.after_hash = CELL}; budget.context = &during;
            reset("", 0); assert(sfs_image_select(h, 0, &budget, &r) == SFS_INCOMPLETE);
            assert(during.fired == 1 && during.hash_at_cancel == CELL && during.reads_at_cancel == 1);
            assert(!r.system_errno && r.incomplete_reason == SFS_INCOMPLETE_CANCELLED && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
            receipt("first-select-observation-then-incomplete", &r);
            assert(sfs_image_stat(h, 0, SFS_ROOT_INODE, &entry, &r) == SFS_STATE);
        }
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, changed, CELL, 0); assert(!close(fd)); reset("", 0);
        assert(sfs_image_select(h, 0, &generous, &r) == SFS_CORRUPT && r.status == SFS_CORRUPT && !r.system_errno && r.phase == SFS_PHASE_READ && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
        assert(!writes && !fulls); receipt(mode == 1 ? "observed-inspect-anchor-change-refused" : mode == 2 ? "observed-select-anchor-change-refused" : "verified-anchor-change-refused", &r);
        unchanged("image", changed, n);
        fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, baseline, CELL, 0); assert(!close(fd));
        OK(sfs_image_select(h, 0, &generous, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && r.generation == 1 && !r.system_errno);
        OK(sfs_image_stat(h, 0, SFS_ROOT_INODE, &entry, &r)); assert(entry.kind == SFS_DIRECTORY && r.coverage == SFS_COVERAGE_TOUCHED);
        assert(sfs_image_begin(h, &r) == SFS_STATE && !writes && !fulls); close_image(h); unchanged("image", baseline, n);
        struct stat after; assert(!lstat("image", &after) && identity.st_dev == after.st_dev && identity.st_ino == after.st_ino && identity.st_size == after.st_size && identity.st_mode == after.st_mode && identity.st_uid == after.st_uid && identity.st_gid == after.st_gid && identity.st_nlink == after.st_nlink);
    }
    free(changed); free(baseline); assert(rename("image", "recovery-observation-complete") == 0);
}
static void budgets(void) {
    recovery_observation();
    reset("",0); sfs_image *h; sfs_result r; sfs_inode a,b; create(&h); initial_files(h,&a,&b);
    reset("",0); OK(sfs_image_verify(h,&generous,&r)); assert(raw_hashes==2&&raw_hash_input==2*UINT64_C(4132));
    uint64_t meta_reads=image_read_bytes-2*CELL, meta_hash=metadata_hash_input, aux_io=aux_attempt_bytes;
    size_t n; unsigned char *before=bytes("image",&n); assert(meta_reads&&meta_hash&&aux_io);
    const enum sfs_incomplete_reason reasons[]={SFS_INCOMPLETE_RAW,SFS_INCOMPLETE_METADATA_READ,SFS_INCOMPLETE_METADATA_HASH,SFS_INCOMPLETE_CHECKS,SFS_INCOMPLETE_AUX_LENGTH,SFS_INCOMPLETE_AUX_IO,SFS_INCOMPLETE_CANCELLED};
    for(unsigned i=0;i<7;i++) {
        sfs_verify_budget budget=generous; unsigned polls=0;
        if(i==0) budget.raw_cells=1; if(i==1) budget.metadata_read_bytes=meta_reads-1; if(i==2) budget.metadata_hash_bytes=meta_hash-1;
        if(i==3) budget.checks=1; if(i==4) budget.auxiliary_bytes=128*(n/CELL)-1; if(i==5) budget.auxiliary_io_bytes=aux_io-1;
        if(i==6) { budget.cancelled=cancel_now; budget.context=&polls; }
        reset("",0); assert(sfs_image_verify(h,&budget,&r)==SFS_INCOMPLETE&&r.system_errno==0&&r.incomplete_reason==reasons[i]&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        assert(!writes&&!fulls); if(i==6) assert(polls); receipt("verify-controlled-incomplete",&r); counters("verify-controlled-incomplete"); unchanged("image",before,n);
        OK(sfs_image_begin(h,&r)); OK(sfs_image_abort(h,&r));
    }
    sfs_verify_budget zero=generous; zero.checks=0; assert(sfs_image_verify(h,NULL,&r)==SFS_INVALID); assert(sfs_image_verify(h,&zero,&r)==SFS_INVALID);
    reset("",0); fail_allocation=allocation_calls+1;
    assert(sfs_image_verify(h,&generous,&r)==SFS_NOMEM&&hit&&r.system_errno==ENOMEM&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE); fail_allocation=0;
    OK(sfs_image_begin(h,&r)); OK(sfs_image_abort(h,&r)); unchanged("image",before,n);
    /* A controlled read-only verification stop retains an otherwise valid transaction. */
    OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,a,0,"new-a",5,&r)); sfs_verify_budget tiny=generous; tiny.raw_cells=1;
    assert(sfs_image_verify(h,&tiny,&r)==SFS_INCOMPLETE); OK(sfs_image_commit(h,&r)); expect(h,0,a,"new-a"); close_image(h);
    free(before); before=bytes("image",&n);
    /* Candidate passes share budget; select starts a new pass and remains read-only. */
    sfs_recovery recovery; tiny=generous; tiny.raw_cells=2;
    enum sfs_status s=sfs_image_inspect(root,"image",&h,&recovery,&tiny,&r); assert(h&&(s==SFS_OK||s==SFS_INCOMPLETE));
    assert(recovery.slots[0].status==SFS_OK&&recovery.slots[0].coverage==SFS_COVERAGE_FULL_REACHABLE);
    assert(recovery.slots[1].status==SFS_INCOMPLETE&&recovery.slots[1].incomplete_reason==SFS_INCOMPLETE_RAW&&recovery.slots[1].coverage!=SFS_COVERAGE_FULL_REACHABLE);
    tiny.raw_cells=1; assert(sfs_image_select(h,0,&tiny,&r)==SFS_INCOMPLETE); OK(sfs_image_select(h,0,&generous,&r)); assert(sfs_image_begin(h,&r)!=SFS_OK); close_image(h); unchanged("image",before,n); free(before); retain(720);
    const char *errors[]={"aux_length_enospc","aux_close","aux_unlink"};
    for(unsigned i=0;i<3;i++) {
        create(&h); initial_files(h,&a,&b); before=bytes("image",&n); reset(errors[i],0);
        assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&hit&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE&&r.phase==SFS_PHASE_VERIFY_AUX);
        assert(r.system_errno==(i==0?ENOSPC:i==1?EIO:EACCES)&&!writes&&!fulls); receipt(errors[i],&r); reset("",0); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); unchanged("image",before,n); free(before); retain(721+(int)i);
    }
    /* Same graph, sparse physical offsets: >1000 memo pages force an actual dirty-cache write. */
    sparse_aux_fixture(); struct stat identity, final_identity; assert(!lstat("image",&identity)); open_image(&h); unsigned char digest[32], after[32]; uint64_t size, size_after; file_digest("image",digest,&size);
    reset("",0); OK(sfs_image_verify(h,&generous,&r)); assert(aux_write_calls&&aux_write_bytes); counters("actual-aux-write-baseline");
    reset("aux_enospc_cleanup",0); assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&hit&&r.system_errno==ENOSPC&&r.phase==SFS_PHASE_VERIFY_AUX&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
    assert(aux_write_calls&&!writes&&!fulls); receipt("actual-aux-write-enospc-original-error",&r); counters("actual-aux-write-enospc-original-error"); reset("",0); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h);
    file_digest("image",after,&size_after); assert(size==size_after&&!memcmp(digest,after,32)); assert(!lstat("image",&final_identity)&&identity.st_dev==final_identity.st_dev&&identity.st_ino==final_identity.st_ino&&identity.st_mode==final_identity.st_mode&&identity.st_nlink==final_identity.st_nlink);
}
static void admission_unchanged(sfs_image *h, const unsigned char *before, size_t size) {
    sfs_result r; assert(writes == 0 && fulls == 0);
    assert(sfs_image_commit(h, &r) == SFS_STATE); unchanged("image", before, size);
    enum sfs_status status = sfs_image_begin(h, &r);
    assert(status == SFS_OK || status == SFS_LIMIT);
    if (status == SFS_OK) OK(sfs_image_abort(h, &r));
    OK(sfs_image_verify(h, &generous, &r));
}
static void cap_phase(const char *phase, const char *state) {
    printf("{\"cap_phase\":\"%s\",\"state\":\"%s\"}\n", phase, state); fflush(stdout);
}
static void limits(void) {
    assert(SFS_FILE_MAX == UINT64_C(4194304) && SFS_ENTRY_MAX == 1024);
    cap_phase("file-name", "before");
    reset("", 0); sfs_image *h; sfs_result r; create(&h);
    OK(sfs_image_begin(h, &r)); char longest[SFS_NAME_MAX + 2]; memset(longest, 'x', sizeof(longest));
    sfs_inode id; OK(sfs_image_add(h, SFS_ROOT_INODE, longest, SFS_NAME_MAX, SFS_FILE, &id, &r));
    unsigned char *payload = malloc((size_t)SFS_FILE_MAX); assert(payload); memset(payload, 0x5A, (size_t)SFS_FILE_MAX);
    for (uint64_t at = 0; at < SFS_FILE_MAX; at += 65536) { size_t part = (size_t)(SFS_FILE_MAX - at); if (part > 65536) part = 65536; OK(sfs_image_write(h, id, at, payload + at, part, &r)); } OK(sfs_image_commit(h, &r));
    size_t n; unsigned char *before = bytes("image", &n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_write(h, id, SFS_FILE_MAX, "x", 1, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_resize(h, id, SFS_FILE_MAX + 1, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_write(h, id, UINT64_MAX, "xx", 2, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_add(h, SFS_ROOT_INODE, longest, SFS_NAME_MAX + 1, SFS_FILE, &id, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    reset("", 0); OK(sfs_image_begin(h, &r)); sfs_view invalid_view;
    assert(sfs_image_snapshot(h, longest, SFS_NAME_MAX + 1, &invalid_view, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    free(before); free(payload); cap_phase("file-name", "after");
    cap_phase("entries", "before");
    OK(sfs_image_begin(h, &r));
    for (unsigned i = 1; i < 1024; i++) { char name[32]; snprintf(name, sizeof(name), "file-%u", i); add(h, SFS_ROOT_INODE, name, SFS_FILE); }
    OK(sfs_image_commit(h, &r)); before = bytes("image", &n);
    assert(disk_level(1) >= 2 && disk_level(2) >= 3);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_add(h, SFS_ROOT_INODE, "over", 4, SFS_DIRECTORY, &id, &r) == SFS_LIMIT); admission_unchanged(h, before, n); free(before);
    cap_phase("entries", "after");
    cap_phase("snapshots-31", "before");
    sfs_view view = 0, committed_view;
    OK(sfs_image_begin(h, &r));
    for (unsigned i = 0; i < 31; i++) {
        char name[32]; snprintf(name, sizeof(name), "snapshot-%u", i);
        OK(sfs_image_snapshot(h, i ? name : longest, i ? strlen(name) : SFS_NAME_MAX, &view, &r)); assert(view == i + 1);
    }
    assert(view == 31); OK(sfs_image_commit(h, &r));
    OK(sfs_image_snapshot_view(h, longest, SFS_NAME_MAX, &committed_view, &r)); assert(committed_view == 1);
    OK(sfs_image_snapshot_view(h, "snapshot-30", 11, &committed_view, &r)); assert(committed_view == 31);
    cap_phase("snapshots-31", "after");
    cap_phase("snapshot-32", "before");
    OK(sfs_image_begin(h, &r)); OK(sfs_image_snapshot(h, "snapshot-31", 11, &view, &r)); assert(view == 32);
    OK(sfs_image_commit(h, &r));
    OK(sfs_image_snapshot_view(h, "snapshot-31", 11, &committed_view, &r)); assert(committed_view == 32);
    cap_phase("snapshot-32", "after");
    cap_phase("snapshot-33-refused", "before");
    before = bytes("image", &n);
    reset("", 0); OK(sfs_image_begin(h, &r)); assert(sfs_image_snapshot(h, "over", 4, &view, &r) == SFS_LIMIT); admission_unchanged(h, before, n);
    OK(sfs_image_verify(h, &generous, &r)); close_image(h); unchanged("image", before, n);
    cap_phase("snapshot-33-refused", "after");
    cap_phase("generation-limit", "before");
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
    cap_phase("generation-limit", "after");
}
static void capacity(void) {
    sfs_image *h; sfs_result r;
    const uint64_t invalid[]={0,8192,16385,UINT64_MAX};
    for(unsigned i=0;i<4;i++) { h=NULL; assert(sfs_image_create(root,"image",invalid[i],&h,&r)!=SFS_OK&&!h); assert(access("image",F_OK)==-1&&errno==ENOENT); }
    for(unsigned transition=0;transition<2;transition++) {
        fixture f=indexed_fixture(2,1,2); size_t initial=f.n; for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,initial+5*CELL); slot_hash(f.p+i*CELL); } fixture_save(&f);
        reset("",0); open_image(&h); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r));
        size_t n; unsigned char *before=bytes("image",&n); assert(n==initial+CELL); reset("",0);
        assert(sfs_image_write(h,transition?3:2,transition?0:CELL,"next",4,&r)==SFS_LIMIT&&r.phase==SFS_PHASE_ADMISSION&&!r.system_errno);
        admission_unchanged(h,before,n); expect(h,0,2,"shared"); expect(h,1,2,"shared"); expect(h,0,3,"shared"); close_image(h); unchanged("image",before,n); free(before); retain(730+(int)transition);
    }
    fixture f=indexed_fixture(1,1,0); size_t initial=f.n;
    for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,initial+5*CELL); slot_hash(f.p+i*CELL); } fixture_save(&f);
    open_image(&h); reset("",0); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); OK(sfs_image_commit(h,&r));
    assert(r.physical_end==initial+5*CELL&&r.committed_end==r.physical_end&&image_append_bytes==5*CELL); expect(h,0,2,"new-ad"); close_image(h); retain(732);
    /* An unaligned abandoned tail leaves four cells after its 37-byte alignment gap. */
    f=indexed_fixture(1,1,0); for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,131072); slot_hash(f.p+i*CELL); } fixture_save(&f);
    const uint64_t unaligned_end=UINT64_C(131072)-4*CELL-37;
    int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); unsigned char marker[37]; memset(marker,0xCB,sizeof(marker)); raw_write(fd,marker,sizeof(marker),(off_t)(unaligned_end-sizeof(marker))); assert(!close(fd));
    size_t n; unsigned char *before=bytes("image",&n);
    assert(n==unaligned_end && n%CELL==CELL-37 && UINT64_C(131072)-n==4*CELL+37);
    assert(UINT64_C(131072)-((n+CELL-1)/CELL)*CELL==4*CELL);
    open_image(&h); reset("",0); OK(sfs_image_begin(h,&r)); assert(sfs_image_write(h,2,0,"new-a",5,&r)==SFS_LIMIT&&r.phase==SFS_PHASE_ADMISSION&&!r.system_errno&&r.physical_end==n);
    receipt("unaligned-tail-five-cell-reservation-refused",&r);
    admission_unchanged(h,before,n); expect(h,0,2,"shared"); close_image(h); unchanged("image",before,n); free(before); retain(733);
    /* Two raw calls plus one extent/inode/namespace/root finalization fit exactly six cells. */
    f=indexed_fixture(1,1,0); initial=f.n;
    for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,initial+6*CELL); slot_hash(f.p+i*CELL); } fixture_save(&f);
    open_image(&h); reset("",0); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); OK(sfs_image_write(h,2,CELL,"x",1,&r)); OK(sfs_image_commit(h,&r));
    assert(r.physical_end==initial+6*CELL&&r.committed_end==r.physical_end&&image_append_bytes==6*CELL&&fulls==2);
    unsigned char same_batch[CELL+1]={0}; memcpy(same_batch,"new-ad",6); same_batch[CELL]='x'; expect_buffer(h,0,2,same_batch,sizeof(same_batch)); receipt("same-batch-exact-six-cell-fit",&r);
    before=bytes("image",&n); reset("",0); assert(sfs_image_begin(h,&r)==SFS_LIMIT&&r.phase==SFS_PHASE_ADMISSION&&!r.system_errno&&r.physical_end==n); receipt("full-image-begin-root-reservation-refused",&r); admission_unchanged(h,before,n); expect_buffer(h,0,2,same_batch,sizeof(same_batch)); close_image(h); unchanged("image",before,n); free(before); retain(735);
    /* A's three-cell seal and B's three-cell growth liability must be reserved together. */
    f=indexed_fixture(2,1,2); initial=f.n;
    for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,initial+6*CELL); slot_hash(f.p+i*CELL); } fixture_save(&f);
    open_image(&h); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); before=bytes("image",&n); assert(n==initial+CELL&&initial+6*CELL-n==5*CELL); reset("",0);
    assert(sfs_image_resize(h,3,2*UINT64_C(4096),&r)==SFS_LIMIT&&r.phase==SFS_PHASE_ADMISSION&&!r.system_errno&&r.physical_end==n); receipt("pending-owner-write-resize-preseal-refused",&r);
    admission_unchanged(h,before,n);
    for(unsigned view=0;view<=2;view++) { expect(h,view,2,"shared"); expect(h,view,3,"shared"); }
    close_image(h); unchanged("image",before,n); free(before); retain(736);
    /* Whole-call late image failure retains prior immutable tail and cannot publish a prefix. */
    f=indexed_fixture(2,1,1); fixture_save(&f); open_image(&h); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); before=bytes("image",&n);
    reset("write_error",2); assert(sfs_image_write(h,3,0,"new-b",5,&r)==SFS_IO&&hit&&r.system_errno==EIO); receipt("late-owner-transition-io",&r); assert(sfs_image_commit(h,&r)==SFS_POISONED); reset("",0); close_image(h);
    size_t retained_n; unsigned char *retained=bytes("image",&retained_n); assert(retained_n>=n&&!memcmp(retained+8192,before+8192,n-8192)); free(retained); free(before);
    open_image(&h); expect(h,0,2,"shared"); expect(h,0,3,"shared"); expect(h,1,2,"shared"); OK(sfs_image_verify(h,&generous,&r)); close_image(h);
    retain(734);
    f=indexed_fixture(2,1,1); fixture_save(&f); open_image(&h); OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,2,0,"new-a",5,&r)); before=bytes("image",&n);
    reset("",0); fail_after_append=1;
    assert(sfs_image_write(h,3,0,"new-b",5,&r)==SFS_NOMEM&&hit&&r.system_errno==ENOMEM&&!fulls);
    assert(sfs_image_commit(h,&r)==SFS_STATE); OK(sfs_image_begin(h,&r)); OK(sfs_image_abort(h,&r)); expect(h,0,2,"shared"); expect(h,1,2,"shared"); close_image(h);
    retained=bytes("image",&retained_n); assert(retained_n==n+3*CELL&&!memcmp(retained+8192,before+8192,n-8192)); free(before); free(retained);
    open_image(&h); OK(sfs_image_verify(h,&generous,&r)); close_image(h);
}
/* Ordinary read-only admission is distinct from explicitly selected recovery. */
static void image_unwritten(void) { assert(!writes&&!fulls&&!syncs&&!image_truncates&&!image_append_bytes); }
static void identical_identity(const struct stat *a, const struct stat *b) {
    assert(a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_gid==b->st_gid&&a->st_nlink==b->st_nlink);
}
static void open_readonly(sfs_image **h, sfs_result *r) {
    ok(sfs_image_open_readonly(root,"image",h,r),r);
    assert(*h&&r->coverage==SFS_COVERAGE_ROOT_ONLY&&image_open_fd>=0);
    assert((image_open_flags&O_ACCMODE)==O_RDONLY&&(fcntl(image_open_fd,F_GETFL)&O_ACCMODE)==O_RDONLY);
    assert((image_open_flags&(O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK))==(O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    assert(fcntl(image_open_fd,F_GETFD)&FD_CLOEXEC);
    printf("{\"ordinary_readonly_descriptor\":true,\"open_flags\":%d,\"descriptor_access_mode\":%d,\"image_write_attempts\":%d,\"image_truncate_attempts\":%llu,\"image_barriers\":%d,\"parent_barriers\":%d}\n",image_open_flags,fcntl(image_open_fd,F_GETFL)&O_ACCMODE,writes,(unsigned long long)image_truncates,fulls,syncs); fflush(stdout);
    image_unwritten();
}
static void readonly_refusals(sfs_image *h, enum sfs_status expected, enum sfs_phase phase) {
    sfs_result r; sfs_inode id; sfs_view view;
#define DENIED(call) do { assert((call)==expected&&r.status==expected&&r.phase==phase&&!r.system_errno); } while(0)
    DENIED(sfs_image_begin(h,&r)); DENIED(sfs_image_abort(h,&r)); DENIED(sfs_image_commit(h,&r));
    DENIED(sfs_image_add(h,0,NULL,0,SFS_FILE,&id,&r)); DENIED(sfs_image_remove(h,0,&r));
    DENIED(sfs_image_rename(h,0,0,NULL,0,&r)); DENIED(sfs_image_write(h,0,0,NULL,0,&r));
    DENIED(sfs_image_resize(h,0,0,&r)); DENIED(sfs_image_snapshot(h,NULL,0,&view,&r));
#undef DENIED
    assert(sfs_image_select(h,0,&generous,&r)==SFS_INVALID&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    image_unwritten();
}
static void poisoned_readonly(sfs_image *h, enum sfs_phase phase) {
    sfs_result r; sfs_cookie cookie,canary; memset(&cookie,0xA5,sizeof(cookie)); canary=cookie;
    assert(sfs_image_resume_after(h,0,0,NULL,0,0,&cookie,&r)==SFS_POISONED&&r.phase==phase&&!r.system_errno&&!memcmp(&cookie,&canary,sizeof(cookie)));
    assert(sfs_image_stat(h,0,0,NULL,&r)==SFS_POISONED&&r.phase==phase&&!r.system_errno);
    readonly_refusals(h,SFS_POISONED,phase);
}
static fixture alternate_root(unsigned generation, uint64_t next_inode) {
    fixture f=indexed_fixture(4,3,2); size_t old_end=f.n; unsigned char *old_ns=namespace_at(f.p,f.p,f.n), *commit=record(f.p,f.p+48,f.n);
    fixture_node inodes={0},names={0}; unsigned char catalog[56]; memcpy(inodes.ref,old_ns+64,56); memcpy(names.ref,old_ns+120,56); memcpy(catalog,commit+120,56);
    fixture_node ns=namespace_cell(&f,inodes,names,next_inode,4); unsigned char cell[CELL]; envelope(&f,cell,4); memcpy(cell+64,ns.ref,56); memcpy(cell+120,catalog,56); fixture_node newer=append_cell(&f,4,cell);
    unsigned char *slot=f.p+(generation==1?CELL:0); memcpy(slot,f.p+CELL,CELL); put64(slot+40,generation); memcpy(slot+48,newer.ref,56); put64(slot+104,f.n); slot_hash(slot);
    assert(get64(f.p+(generation==1?0:CELL)+104)==old_end); return f;
}
static void open_failure_parity(const char *name, const char *kind, int nth) {
    sfs_result ordinary,ro; sfs_image *h=(sfs_image *)(uintptr_t)1; int count=descriptors();
    reset(kind,nth); enum sfs_status status=sfs_image_open(root,name,&h,&ordinary); assert(status!=SFS_OK&&!h); image_unwritten(); assert(descriptors()==count);
    h=(sfs_image *)(uintptr_t)1; reset(kind,nth); enum sfs_status other=sfs_image_open_readonly(root,name,&h,&ro);
    assert(other==status&&!h&&ordinary.phase==ro.phase&&ordinary.system_errno==ro.system_errno&&ro.coverage==SFS_COVERAGE_NONE);
    if(*kind) assert(hit); image_unwritten(); assert(descriptors()==count); receipt("readonly-open-refusal-parity",&ro);
}
static int cancel_after_image_read(void *context) { unsigned *calls=context; (*calls)++; return reads!=0; }
static void readonly_budgets(void) {
    reset("",0); sfs_image *h; sfs_result r; sfs_inode a,b; create(&h); initial_files(h,&a,&b); close_image(h);
    size_t n; unsigned char *baseline=bytes("image",&n); reset("",0); open_readonly(&h,&r); reset("",0);
    OK(sfs_image_verify(h,&generous,&r)); uint64_t meta=image_read_bytes-2*CELL,hash=metadata_hash_input,aux=aux_attempt_bytes; assert(meta&&hash&&aux);
    const enum sfs_incomplete_reason reasons[]={SFS_INCOMPLETE_RAW,SFS_INCOMPLETE_METADATA_READ,SFS_INCOMPLETE_METADATA_HASH,SFS_INCOMPLETE_CHECKS,SFS_INCOMPLETE_AUX_LENGTH,SFS_INCOMPLETE_AUX_IO,SFS_INCOMPLETE_CANCELLED};
    for(unsigned i=0;i<7;i++) {
        sfs_verify_budget budget=generous; unsigned calls=0;
        if(i==0) budget.raw_cells=1; if(i==1) budget.metadata_read_bytes=meta-1; if(i==2) budget.metadata_hash_bytes=hash-1;
        if(i==3) budget.checks=1; if(i==4) budget.auxiliary_bytes=128*(n/CELL)-1; if(i==5) budget.auxiliary_io_bytes=aux-1;
        if(i==6) { budget.cancelled=cancel_now; budget.context=&calls; }
        reset("",0); assert(sfs_image_verify(h,&budget,&r)==SFS_INCOMPLETE&&!r.system_errno&&r.incomplete_reason==reasons[i]&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        if(i==6) assert(calls); image_unwritten(); receipt("readonly-controlled-stop",&r); unchanged("image",baseline,n);
        sfs_entry entry; OK(sfs_image_stat(h,0,a,&entry,&r)); readonly_refusals(h,SFS_STATE,SFS_PHASE_NONE);
    }
    close_image(h); unchanged("image",baseline,n); retain(1000);
    for(unsigned unsupported=0;unsupported<2;unsupported++) for(unsigned cancellation=0;cancellation<2;cancellation++) {
        save("image",baseline,n); reset("",0); open_readonly(&h,&r); unsigned char *changed=malloc(n); assert(changed); memcpy(changed,baseline,n);
        if(unsupported) { put32(changed+8,99); slot_hash(changed); replace_image(changed,n); }
        sfs_verify_budget budget=generous; unsigned calls=0;
        if(cancellation) { budget.cancelled=cancel_after_image_read; budget.context=&calls; } else budget.metadata_read_bytes=CELL;
        reset(unsupported?"":"slot_reads",unsupported?0:1);
        enum sfs_status status=sfs_image_verify(h,&budget,&r); receipt("readonly-fatal-before-control-stop",&r);
        assert(status==(unsupported?SFS_UNSUPPORTED:SFS_IO)&&r.system_errno==(unsupported?0:EIO)&&r.phase==SFS_PHASE_READ&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        if(!unsupported) assert(hit); image_unwritten(); poisoned_readonly(h,r.phase); close_image(h); unchanged("image",changed,n); free(changed); retain(1001+(int)(unsupported*2+cancellation));
    }
    free(baseline);
    const char *errors[]={"aux_length_enospc","aux_close","aux_unlink"};
    for(unsigned i=0;i<3;i++) {
        reset("",0); create(&h); initial_files(h,&a,&b); close_image(h); baseline=bytes("image",&n); reset("",0); open_readonly(&h,&r);
        reset(errors[i],0); assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&hit&&r.phase==SFS_PHASE_VERIFY_AUX&&r.system_errno==(i==0?ENOSPC:i==1?EIO:EACCES));
        image_unwritten(); poisoned_readonly(h,r.phase); reset("",0); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1010+(int)i);
    }
    sparse_aux_fixture(); unsigned char before[32],after[32]; uint64_t length,after_length; file_digest("image",before,&length);
    struct stat identity,final; assert(!lstat("image",&identity)); reset("",0); open_readonly(&h,&r);
    OK(sfs_image_verify(h,&generous,&r)); assert(aux_write_calls&&aux_write_bytes); image_unwritten(); counters("readonly-actual-aux-write-baseline");
    reset("aux_enospc_cleanup",0); assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&hit&&aux_write_calls&&r.system_errno==ENOSPC&&r.phase==SFS_PHASE_VERIFY_AUX);
    image_unwritten(); receipt("readonly-actual-aux-enospc",&r); poisoned_readonly(h,r.phase); reset("",0); close_image(h);
    file_digest("image",after,&after_length); assert(length==after_length&&!memcmp(before,after,32)); assert(!lstat("image",&final)); identical_identity(&identity,&final); retain(1014);
}
static void readonly(void) {
    sfs_image *h; sfs_result r; reset("",0); fixture f=indexed_fixture(2,1,1); fixture_save(&f);
    size_t n; unsigned char *baseline=bytes("image",&n); struct stat identity,after; assert(!lstat("image",&identity));
    reset("",0); unsigned made=aux_created; open_readonly(&h,&r); assert(r.generation==1&&aux_created==made); receipt("ordinary-readonly-equal-slots",&r);
    readonly_refusals(h,SFS_STATE,SFS_PHASE_NONE); sfs_entry e; OK(sfs_image_stat(h,0,2,&e,&r)); assert(e.size==6); OK(sfs_image_lookup(h,0,1,"f00000000",9,&e,&r)); assert(e.inode==2); expect(h,0,2,"shared");
    sfs_image *other=(sfs_image *)(uintptr_t)1; assert(sfs_image_open(root,"image",&other,&r)==SFS_BUSY&&!other);
    other=(sfs_image *)(uintptr_t)1; assert(sfs_image_open_readonly(root,"image",&other,&r)==SFS_BUSY&&!other);
    sfs_recovery recovery; other=(sfs_image *)(uintptr_t)1; assert(sfs_image_inspect(root,"image",&other,&recovery,&generous,&r)==SFS_BUSY&&!other);
    image_unwritten(); close_image(h); unchanged("image",baseline,n); assert(!lstat("image",&after)); identical_identity(&identity,&after);
    assert(sfs_image_open_readonly(root,"image",NULL,&r)==SFS_INVALID); reset("",0); assert(sfs_image_open_readonly(root,"image",&h,NULL)==SFS_OK&&h); close_image(h);
    const char *faults[]={"owner","parent_owner","unsupported","readonly","lock","slot_reads","slot_reads","slot_reads","parent_close"};
    const int nth[]={0,0,0,0,0,1,2,3,0};
    for(unsigned i=0;i<sizeof(nth)/sizeof(*nth);i++) { open_failure_parity("image",faults[i],nth[i]); unchanged("image",baseline,n); }
    assert(symlink("image","ro-alias")==0); open_failure_parity("ro-alias","",0);
    assert(link("image","ro-link")==0); open_failure_parity("image","",0); assert(!unlink("ro-link"));
    assert(!chmod("image",0644)); open_failure_parity("image","",0); assert(!chmod("image",0600));
    assert(!chmod(root,0755)); open_failure_parity("image","",0); assert(!chmod(root,0700));
    assert(!mkfifo("ro-fifo",0600)); open_failure_parity("ro-fifo","",0); retain(1020);
    for(unsigned kind=0;kind<3;kind++) {
        unsigned char *changed=malloc(n); assert(changed); memcpy(changed,baseline,n);
        if(kind==0) { put32(changed+8,99); slot_hash(changed); }
        if(kind==1) { put64(changed+40,9); slot_hash(changed); }
        save("image",changed,kind==2?CELL:n); open_failure_parity("image","",0); unchanged("image",changed,kind==2?CELL:n); free(changed); retain(1021+(int)kind);
    }
    save("image",baseline,n); reset("",0); open_readonly(&h,&r); unsigned char *incoherent=malloc(n); assert(incoherent); memcpy(incoherent,baseline,n); put64(incoherent+40,9); slot_hash(incoherent); replace_image(incoherent,n); reset("",0);
    assert(sfs_image_verify(h,&generous,&r)==SFS_RECOVERY_REQUIRED&&!r.system_errno); poisoned_readonly(h,r.phase); close_image(h); unchanged("image",incoherent,n); free(incoherent); retain(1040);
    free(baseline); f=alternate_root(2,6); fixture_save(&f); open_failure_parity("image","",0);
    reset("",0); OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); assert(recovery.slots[0].status==SFS_OK&&recovery.slots[1].status==SFS_OK); OK(sfs_image_select(h,0,&generous,&r)); close_image(h); retain(1024);
    f=alternate_root(2,8); n=f.n; baseline=malloc(n); assert(baseline); memcpy(baseline,f.p,n); fixture_save(&f); reset("",0); open_readonly(&h,&r); OK(sfs_image_verify(h,&generous,&r));
    unsigned char *prior_ns=namespace_at(baseline,baseline+CELL,n); put64(prior_ns+176,9); seal_namespace(baseline,baseline+CELL,n,0); assert(parser_framing_valid(baseline,n)); replace_image(baseline,n); reset("",0);
    assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&!r.system_errno); poisoned_readonly(h,r.phase); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1041);
    /* Only explicit recovery can use an independently verified candidate of a broken pair. */
    f=indexed_fixture(2,1,1); f.p[112]^=1; fixture_save(&f); open_failure_parity("image","",0); reset("",0);
    OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); sfs_cookie canary; memset(&canary,0xA5,sizeof(canary)); sfs_cookie cookie=canary;
    assert(sfs_image_resume_after(h,0,1,r.root_digest,1,2,&cookie,&r)==SFS_STATE&&!memcmp(&cookie,&canary,sizeof(cookie)));
    OK(sfs_image_select(h,1,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); expect(h,0,2,"shared"); image_unwritten(); close_image(h); retain(1025);
    /* Fresh ordinary verification refuses a new latest anchor; recovery keeps its selected old candidate. */
    reset("",0); create(&h); sfs_inode a,b; initial_files(h,&a,&b); OK(sfs_image_begin(h,&r)); sfs_view view; OK(sfs_image_snapshot(h,"before",6,&view,&r)); OK(sfs_image_commit(h,&r));
    size_t old_n; unsigned char *older=bytes("image",&old_n); change_files(h,a,b); OK(sfs_image_commit(h,&r)); close_image(h); size_t new_n; unsigned char *newer=bytes("image",&new_n),*tail=malloc(new_n); assert(tail); memcpy(tail,newer,new_n); memcpy(tail,older,8192); retain(1026);
    for(unsigned recovery_mode=0;recovery_mode<2;recovery_mode++) {
        save("image",tail,new_n); reset("",0);
        if(recovery_mode) { OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); OK(sfs_image_select(h,1,&generous,&r)); }
        else open_readonly(&h,&r);
        assert(r.generation==3); replace_image(newer,new_n); reset("",0);
        if(recovery_mode) { OK(sfs_image_verify(h,&generous,&r)); assert(r.generation==3&&r.coverage==SFS_COVERAGE_FULL_REACHABLE); expect(h,0,a,"old-a"); }
        else { assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT); poisoned_readonly(h,r.phase); }
        image_unwritten(); close_image(h); unchanged("image",newer,new_n); retain(1027+(int)recovery_mode);
    }
    free(tail); free(newer); free(older);
    /* Cold touched damage, short input and stable descriptor EOF errors latch ordinary poison. */
    for(unsigned damage=0;damage<3;damage++) {
        f=indexed_fixture(2,1,1); size_t size=f.n; unsigned char *copy=malloc(size); assert(copy); memcpy(copy,f.p,size);
        unsigned char *ns=namespace_at(f.p,f.p,size); uint64_t raw=get64(raw_ref(f.p,inode_row(f.p,ns,2,size),0,size)+8); fixture_save(&f); reset("",0); open_readonly(&h,&r);
        if(damage==0) { copy[raw]^=1; replace_image(copy,size); reset("",0); }
        if(damage==1) reset("read_zero",1);
        if(damage==2) { int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0&&!ftruncate(fd,(off_t)(size+1))&&!close(fd)); reset("",0); }
        unsigned char out[8]; memset(out,0xA5,sizeof(out)); size_t got=99; enum sfs_status status=sfs_image_read(h,0,2,0,out,sizeof(out),&got,&r);
        assert(status==(damage==0?SFS_CORRUPT:SFS_IO)&&!got); for(unsigned i=0;i<sizeof(out);i++) assert(out[i]==0xA5);
        if(damage==1) assert(hit&&r.system_errno==EIO); if(damage==2) assert(r.phase==SFS_PHASE_IDENTITY&&r.system_errno==ESTALE);
        image_unwritten(); receipt("readonly-fatal-touched-read",&r); poisoned_readonly(h,r.phase); reset("",0); close_image(h); free(copy); retain(1030+(int)damage);
    }
    reset("",0); create(&h); OK(sfs_image_begin(h,&r)); a=add(h,1,"prefix",SFS_FILE); unsigned char data[8192]; memset(data,'Q',sizeof(data)); OK(sfs_image_write(h,a,0,data,sizeof(data),&r)); OK(sfs_image_commit(h,&r)); close_image(h);
    baseline=bytes("image",&n); unsigned char *ns=namespace_at(baseline,selected_slot(baseline),n); read_at[0]=get64(raw_ref(baseline,inode_row(baseline,ns,a,n),1,n)+8); reset("",0); open_readonly(&h,&r); reset("candidate_reads",1);
    unsigned char out[8192]; memset(out,0xA5,sizeof(out)); size_t got=99; assert(sfs_image_read(h,0,a,0,out,sizeof(out),&got,&r)==SFS_IO&&got==CELL&&hit&&r.system_errno==EIO);
    for(unsigned i=0;i<CELL;i++) assert(out[i]=='Q'&&out[CELL+i]==0xA5); image_unwritten(); poisoned_readonly(h,r.phase); reset("",0); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1033);
    /* Checked close consumes its handle once and releases the lock, even on error. */
    f=indexed_fixture(2,0,0); fixture_save(&f); reset("",0); int count=descriptors(); open_readonly(&h,&r); int owned=image_open_fd; reset("close",1); assert(sfs_image_close(h,&r)==SFS_IO&&hit&&closes==2); h=NULL; assert(fcntl(owned,F_GETFD)==-1&&errno==EBADF&&descriptors()==count); reset("",0); open_readonly(&h,&r); close_image(h); retain(1034);
    readonly_budgets();
}
static void resume_failure(sfs_image *h,sfs_view view,const sfs_result *anchor,sfs_inode parent,sfs_inode previous,enum sfs_status expected) {
    sfs_cookie out,before; memset(&out,0xA5,sizeof(out)); before=out; sfs_result r;
    enum sfs_status status=sfs_image_resume_after(h,view,anchor->generation,anchor->root_digest,parent,previous,&out,&r);
    assert(status==expected&&r.status==expected&&!memcmp(&out,&before,sizeof(out))&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE); image_unwritten();
    if(expected==SFS_INVALID||expected==SFS_NOT_FOUND||expected==SFS_STATE) assert(!r.system_errno);
    if(!h||previous<=SFS_ROOT_INODE||expected==SFS_STATE) assert(r.phase==SFS_PHASE_NONE);
    else if(expected==SFS_INVALID||expected==SFS_NOT_FOUND) assert(r.phase==SFS_PHASE_READ);
}
static void equal_entry(const sfs_entry *a,const sfs_entry *b) {
    assert(a->inode==b->inode&&a->parent==b->parent&&a->kind==b->kind&&a->size==b->size&&a->name_length==b->name_length&&!memcmp(a->name,b->name,a->name_length));
}
static unsigned resume_equivalence(sfs_image *h,sfs_view view,sfs_inode parent,const sfs_result *anchor) {
    sfs_cookie sequential={0}; sfs_result r; sfs_entry entry; int found; unsigned count=0;
    for(;;) {
        OK(sfs_image_next(h,view,parent,&sequential,&entry,&found,&r)); if(!found) break; count++;
        sfs_cookie resumed; memset(&resumed,0xA5,sizeof(resumed));
        OK(sfs_image_resume_after(h,view,anchor->generation,anchor->root_digest,parent,entry.inode,&resumed,&r));
        assert(r.coverage==SFS_COVERAGE_TOUCHED&&!r.system_errno&&!memcmp(&sequential,&resumed,sizeof(resumed)));
        unsigned depth=get32(resumed.bytes+40); assert(depth<=16); for(unsigned i=48+depth*64;i<sizeof(resumed.bytes);i++) assert(!resumed.bytes[i]);
        sfs_cookie left=sequential,right=resumed; sfs_entry a,b; int has_a,has_b;
        OK(sfs_image_next(h,view,parent,&left,&a,&has_a,&r)); OK(sfs_image_next(h,view,parent,&right,&b,&has_b,&r)); assert(has_a==has_b); if(has_a) equal_entry(&a,&b);
    }
    image_unwritten(); return count;
}
/* Fixed existing 432-row topology; never traverse using a deliberately damaged header. */
static int child_ref_framing(unsigned char *image,const unsigned char *ref,const unsigned char *original_ref,size_t n,uint64_t parent,uint64_t end,unsigned type) {
    return !memcmp(ref,original_ref,24)&&parser_ref_framing(image,ref,n,parent,end,type);
}
static int child_namespace_framing(unsigned char *image,unsigned char *original,const unsigned char *ref,const unsigned char *original_ref,size_t n,uint64_t parent,uint64_t end) {
    if(!child_ref_framing(image,ref,original_ref,n,parent,end,2)) return 0;
    unsigned char *old_ns=record(original,original_ref,n),*ns=image+(old_ns-original); uint64_t ns_at=(uint64_t)(ns-image);
    if(memcmp(ns+176,old_ns+176,CELL-176)) return 0;
    for(unsigned map=1;map<=2;map++) {
        unsigned at=map==1?64:120;
        if(!child_ref_framing(image,ns+at,old_ns+at,n,ns_at,end,5)) return 0;
        unsigned char *old_root=record(original,old_ns+at,n),*tree_root=image+(old_root-original); uint64_t root_at=(uint64_t)(tree_root-image);
        assert(get16(old_root+68)==(map==1?1:2)&&get16(old_root+70)==(map==1?48:4));
        if(memcmp(tree_root,old_root,640)) return 0;
        unsigned root_count=map==1?48:4,step=map==1?72:328,child_at=map==1?16:271;
        if(memcmp(tree_root+640+root_count*step,old_root+640+root_count*step,CELL-640-root_count*step)) return 0;
        for(unsigned i=0;i<root_count;i++) {
            const unsigned char *old_ref=old_root+640+i*step+child_at,*new_ref=tree_root+640+i*step+child_at;
            if(memcmp(new_ref-child_at,old_ref-child_at,child_at)||memcmp(new_ref+56,old_ref+56,step-child_at-56)) return 0;
            if(!child_ref_framing(image,new_ref,old_ref,n,root_at,end,5)) return 0;
            unsigned char *old_page=record(original,old_ref,n),*page=image+(old_page-original);
            if(map==1) {
                assert(!get16(old_page+68)&&get16(old_page+70)==9);
                if(memcmp(page+640,old_page+640,CELL-640)) return 0;
            } else {
                assert(get16(old_page+68)==1&&get16(old_page+70)==9);
                if(memcmp(page,old_page,640)||memcmp(page+640+9*328,old_page+640+9*328,CELL-640-9*328)) return 0;
                for(unsigned j=0;j<9;j++) {
                    const unsigned char *old_leaf_ref=old_page+640+j*328+271,*new_leaf_ref=page+640+j*328+271;
                    if(memcmp(new_leaf_ref-271,old_leaf_ref-271,271)||memcmp(new_leaf_ref+56,old_leaf_ref+56,1)) return 0;
                    if(!child_ref_framing(image,new_leaf_ref,old_leaf_ref,n,(uint64_t)(page-image),end,5)) return 0;
                    unsigned char *old_leaf=record(original,old_leaf_ref,n),*leaf=image+(old_leaf-original);
                    assert(!get16(old_leaf+68)&&get16(old_leaf+70)==12);
                    if(memcmp(leaf+640,old_leaf+640,CELL-640)) return 0;
                }
            }
        }
    }
    return 1;
}
/* Framing, SHA and unchanged rows only; damaged child map/level/fences are semantic. */
static int child_fixture_framing(unsigned char *image,unsigned char *original,size_t n) {
    for(unsigned i=0;i<2;i++) {
        unsigned char *slot=image+i*CELL,*old_slot=original+i*CELL,checked[CELL]; memcpy(checked,slot,CELL); slot_hash(checked);
        if(memcmp(slot,old_slot,72)||memcmp(slot+104,old_slot+104,8)||memcmp(slot+144,old_slot+144,CELL-144)||memcmp(slot+112,checked+112,32)) return 0;
        uint64_t end=get64(slot+104);
        if(!child_ref_framing(image,slot+48,old_slot+48,n,end,end,4)) return 0;
        unsigned char *old_commit=record(original,old_slot+48,n),*commit=image+(old_commit-original); uint64_t commit_at=(uint64_t)(commit-image);
        if(memcmp(commit+176,old_commit+176,CELL-176)||!child_namespace_framing(image,original,commit+64,old_commit+64,n,commit_at,end)) return 0;
        if(!child_ref_framing(image,commit+120,old_commit+120,n,commit_at,end,5)) return 0;
        unsigned char *old_catalog=record(original,old_commit+120,n),*catalog=image+(old_catalog-original); assert(!get16(old_catalog+68)&&get16(old_catalog+70)==2);
        if(memcmp(catalog,old_catalog,640)||memcmp(catalog+640+2*328,old_catalog+640+2*328,CELL-640-2*328)) return 0;
        for(unsigned j=0;j<2;j++) {
            if(memcmp(catalog+640+j*328,old_catalog+640+j*328,8)||memcmp(catalog+704+j*328,old_catalog+704+j*328,264)) return 0;
            if(!child_namespace_framing(image,original,catalog+648+j*328,old_catalog+648+j*328,n,(uint64_t)(catalog-image),end)) return 0;
        }
    }
    return 1;
}
static void repair_child_fixture(unsigned char *image,unsigned char *original,size_t n) {
    unsigned char *old_commit=record(original,original+48,n),*old_ns=record(original,old_commit+64,n);
    for(unsigned map=1;map<=2;map++) {
        unsigned char *old_root=record(original,old_ns+(map==1?64:120),n); unsigned count=map==1?48:4,step=map==1?72:328,ref_at=map==1?16:271;
        for(unsigned i=0;i<count;i++) {
            unsigned char *old_ref=old_root+640+i*step+ref_at;
            if(map==2) {
                unsigned char *old_middle=record(original,old_ref,n);
                for(unsigned j=0;j<9;j++) ref_hash(image,image+(old_middle-original)+640+j*328+271,n);
            }
            ref_hash(image,image+(old_ref-original),n);
        }
    }
    unsigned char *old_catalog=record(original,old_commit+120,n),*old_history=record(original,old_catalog+648,n);
    unsigned char *spaces[]={old_ns,old_history};
    for(unsigned i=0;i<2;i++) for(unsigned j=0;j<2;j++) ref_hash(image,image+(spaces[i]-original)+64+j*56,n);
    for(unsigned i=0;i<2;i++) ref_hash(image,image+(old_catalog-original)+648+i*328,n);
    for(unsigned i=0;i<2;i++) ref_hash(image,image+(old_commit-original)+64+i*56,n);
    for(unsigned i=0;i<2;i++) { ref_hash(image,image+i*CELL+48,n); slot_hash(image+i*CELL); }
}
static void resume_child_contexts(const sfs_cookie *canary) {
    fixture f=indexed_fixture(432,0,2); size_t n=f.n; unsigned char *original=malloc(n); assert(original); memcpy(original,f.p,n); fixture_save(&f);
    assert(child_fixture_framing(original,original,n)); reset("",0); sfs_image *h; sfs_result r,anchor; open_readonly(&h,&anchor);
    OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); receipt("resume-child-unmodified-baseline-full",&r); image_unwritten(); close_image(h); unchanged("image",original,n); retain(1125);
    unsigned char *old_commit=record(original,original+48,n),*old_ns=record(original,old_commit+64,n);
    unsigned char *inode_root=record(original,old_ns+64,n),*name_root=record(original,old_ns+120,n);
    unsigned char *inode_leaf=record(original,inode_root+656,n),*name_middle=record(original,name_root+911,n),*name_leaf=record(original,name_middle+911,n);
    assert(get64(inode_leaf+640)==2&&get64(name_leaf+640+267)==2);
    for(unsigned kind=1;kind<=4;kind++) {
        unsigned char *image=malloc(n); assert(image); memcpy(image,original,n); size_t target_at=(size_t)((kind==4?name_leaf:inode_leaf)-original); unsigned char *target_page=image+target_at;
        if(kind==1) put32(target_page+64,2); if(kind==2) put16(target_page+68,16); if(kind==3||kind==4) target_page[119]^=1;
        repair_child_fixture(image,original,n); assert(child_fixture_framing(image,original,n));
        printf("{\"resume_child_case\":%u,\"target_offset\":%llu,\"framing_and_hashes_valid\":true}\n",kind,(unsigned long long)target_at); fflush(stdout);
        save("image",image,n); struct stat identity,after; assert(!lstat("image",&identity)); reset("",0); open_readonly(&h,&anchor); assert(anchor.coverage==SFS_COVERAGE_ROOT_ONLY);
        sfs_entry root_entry; OK(sfs_image_stat(h,0,SFS_ROOT_INODE,&root_entry,&r)); assert(root_entry.inode==SFS_ROOT_INODE&&root_entry.kind==SFS_DIRECTORY&&r.coverage==SFS_COVERAGE_TOUCHED); image_unwritten(); receipt("resume-child-ro-admitted",&anchor);
        sfs_cookie cookie=*canary; enum sfs_status status=sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,2,&cookie,&r); receipt("resume-rehashed-child-semantic-failure",&r);
        assert(status==SFS_CORRUPT&&r.status==SFS_CORRUPT&&r.phase==SFS_PHASE_READ&&!r.system_errno&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE&&!memcmp(&cookie,canary,sizeof(cookie)));
        image_unwritten(); poisoned_readonly(h,r.phase); close_image(h); unchanged("image",image,n); assert(!lstat("image",&after)); identical_identity(&identity,&after); free(image); retain(1120+(int)kind);
    }
    free(original);
}

static void resume(void) {
    sfs_image *h; sfs_result r,anchor; fixture f=indexed_fixture(1024,0,2); fixture_save(&f);
    size_t n; unsigned char *baseline=bytes("image",&n); unsigned char *ns=namespace_at(baseline,baseline,n);
    unsigned inode_height=get16(record(baseline,ns+64,n)+68)+1, name_height=get16(record(baseline,ns+120,n)+68)+1;
    assert(inode_height>=3&&name_height>=4); reset("",0); open_readonly(&h,&anchor);
    reset("",0); sfs_cookie cookie; memset(&cookie,0xA5,sizeof(cookie));
    OK(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,1025,&cookie,&r));
    /* Cold root-parent resume has three seeks, not one walk per earlier entry. */
    uint64_t bound=2*inode_height+3*name_height+6;
    assert(image_read_attempts>0&&image_read_attempts<=bound*CELL&&metadata_hash_input<=bound*CELL&&!raw_hash_input&&!raw_hashes);
    printf("{\"resume_cold_last\":true,\"inode_height\":%u,\"name_height\":%u,\"checked_metadata_read_bytes\":%llu,\"metadata_sha_input\":%llu,\"cell_bound\":%llu}\n",inode_height,name_height,(unsigned long long)image_read_attempts,(unsigned long long)metadata_hash_input,(unsigned long long)bound); fflush(stdout);
    sfs_entry entry; int found; OK(sfs_image_next(h,0,1,&cookie,&entry,&found,&r)); assert(!found);
    assert(resume_equivalence(h,0,1,&anchor)==1024); assert(resume_equivalence(h,1,1,&anchor)==1024);
    close_image(h); unchanged("image",baseline,n); reset("",0); open_readonly(&h,&anchor);
    assert(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,1025,&cookie,NULL)==SFS_OK); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1100);
    /* Mixed kinds, raw ordering, prefix/case distinctions, and maximal names. */
    reset("",0); create(&h); OK(sfs_image_begin(h,&r)); sfs_inode dir_a=add(h,1,"A",SFS_DIRECTORY),dir_b=add(h,1,"b",SFS_DIRECTORY),empty=add(h,1,"empty",SFS_DIRECTORY);
    sfs_inode child=add(h,dir_a,"child",SFS_FILE),other=add(h,dir_b,"other",SFS_FILE); add(h,1,"a",SFS_FILE); add(h,1,"p",SFS_FILE);
    unsigned char name[255]; memset(name,'p',sizeof(name)); sfs_inode id;
    for(unsigned i=0;i<25;i++) { name[254]=(unsigned char)('a'+i); OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r)); }
    name[254]=0x80; OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r)); name[254]=0xFF; OK(sfs_image_add(h,1,name,sizeof(name),SFS_FILE,&id,&r));
    OK(sfs_image_commit(h,&r)); OK(sfs_image_begin(h,&r)); sfs_view view; OK(sfs_image_snapshot(h,"before",6,&view,&r)); OK(sfs_image_commit(h,&r)); anchor=r;
    reset("",0); assert(resume_equivalence(h,0,1,&anchor)==32); assert(resume_equivalence(h,0,dir_a,&anchor)==1); assert(resume_equivalence(h,0,dir_b,&anchor)==1); assert(!resume_equivalence(h,0,empty,&anchor));
    resume_failure(NULL,0,&anchor,1,child,SFS_INVALID); resume_failure(h,0,&anchor,1,0,SFS_INVALID); resume_failure(h,0,&anchor,1,1,SFS_INVALID);
    resume_failure(h,0,&anchor,0,child,SFS_INVALID); resume_failure(h,0,&anchor,99999,child,SFS_INVALID); resume_failure(h,0,&anchor,child,other,SFS_INVALID);
    resume_failure(h,0,&anchor,empty,child,SFS_INVALID); resume_failure(h,0,&anchor,dir_a,other,SFS_INVALID); resume_failure(h,0,&anchor,1,99999,SFS_NOT_FOUND); resume_failure(h,99,&anchor,dir_a,child,SFS_NOT_FOUND);
    sfs_cookie canary; memset(&canary,0xA5,sizeof(canary)); cookie=canary;
    assert(sfs_image_resume_after(h,0,0,anchor.root_digest,dir_a,child,&cookie,&r)==SFS_INVALID&&r.phase==SFS_PHASE_NONE&&!r.system_errno&&!memcmp(&cookie,&canary,sizeof(cookie)));
    assert(sfs_image_resume_after(h,0,anchor.generation,NULL,dir_a,child,&cookie,&r)==SFS_INVALID&&r.phase==SFS_PHASE_NONE&&!r.system_errno&&!memcmp(&cookie,&canary,sizeof(cookie)));
    assert(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,dir_a,child,NULL,&r)==SFS_INVALID&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    sfs_result stale=anchor; stale.generation++; reset("",0); resume_failure(h,0,&stale,dir_a,child,SFS_STATE); assert(!reads);
    stale=anchor; stale.root_digest[0]^=1; resume_failure(h,0,&stale,dir_a,child,SFS_STATE); assert(!reads);
    /* Explicit parent and namespace, including a neighboring directory after its last row. */
    cookie=canary; OK(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,dir_a,child,&cookie,&r)); sfs_cookie old_cookie=cookie;
    OK(sfs_image_next(h,0,dir_a,&cookie,&entry,&found,&r)); assert(!found);
    cookie=old_cookie; assert(sfs_image_next(h,0,dir_b,&cookie,&entry,&found,&r)==SFS_INVALID);
    reset("",0); OK(sfs_image_begin(h,&r)); OK(sfs_image_rename(h,child,dir_b,"moved",5,&r));
    cookie=canary; OK(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,dir_a,child,&cookie,&r));
    OK(sfs_image_commit(h,&r)); sfs_result fresh=r; reset("",0);
    resume_failure(h,0,&anchor,dir_a,child,SFS_STATE); resume_failure(h,view,&anchor,dir_a,child,SFS_STATE); assert(!reads);
    resume_failure(h,0,&fresh,dir_a,child,SFS_INVALID); cookie=canary; OK(sfs_image_resume_after(h,0,fresh.generation,fresh.root_digest,dir_b,child,&cookie,&r));
    OK(sfs_image_resume_after(h,view,fresh.generation,fresh.root_digest,dir_a,child,&cookie,&r));
    sfs_cookie stale_cookie=old_cookie; memset(&entry,0xA5,sizeof(entry)); sfs_entry entry_canary=entry; found=99;
    assert(sfs_image_next(h,0,dir_a,&old_cookie,&entry,&found,&r)==SFS_STATE&&!found&&!memcmp(&old_cookie,&stale_cookie,sizeof(old_cookie))&&!memcmp(&entry,&entry_canary,sizeof(entry))); close_image(h);
    baseline=bytes("image",&n); reset("",0); open_readonly(&h,&anchor); OK(sfs_image_resume_after(h,view,anchor.generation,anchor.root_digest,dir_a,child,&cookie,&r)); close_image(h); unchanged("image",baseline,n);
    sfs_recovery generations; reset("",0); OK(sfs_image_inspect(root,"image",&h,&generations,&generous,&r));
    unsigned latest=generations.slots[0].generation>generations.slots[1].generation?0:1;
    ok(sfs_image_select(h,1-latest,&generous,&anchor), &anchor); ok(sfs_image_select(h,latest,&generous,&fresh), &fresh); assert(anchor.generation!=fresh.generation); reset("",0);
    resume_failure(h,view,&anchor,dir_a,child,SFS_STATE); assert(!reads); OK(sfs_image_resume_after(h,view,fresh.generation,fresh.root_digest,dir_a,child,&cookie,&r));
    close_image(h); unchanged("image",baseline,n); free(baseline); retain(1101);
    /* Independently FULL-valid conflicting roots at the same generation need digest binding. */
    f=alternate_root(1,8); fixture_save(&f); baseline=bytes("image",&n); reset("",0); sfs_recovery recovery;
    OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); assert(!recovery.pair_valid&&recovery.slots[0].status==SFS_OK&&recovery.slots[1].status==SFS_OK&&recovery.slots[0].coverage==SFS_COVERAGE_FULL_REACHABLE&&recovery.slots[1].coverage==SFS_COVERAGE_FULL_REACHABLE);
    ok(sfs_image_select(h,0,&generous,&anchor), &anchor); cookie=canary; OK(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,2,&cookie,&r));
    ok(sfs_image_select(h,1,&generous,&fresh), &fresh); assert(anchor.generation==fresh.generation&&memcmp(anchor.root_digest,fresh.root_digest,32)); reset("",0);
    resume_failure(h,0,&anchor,1,2,SFS_STATE); assert(!reads); cookie=canary; OK(sfs_image_resume_after(h,0,fresh.generation,fresh.root_digest,1,2,&cookie,&r));
    OK(sfs_image_resume_after(h,1,fresh.generation,fresh.root_digest,1,2,&cookie,&r)); image_unwritten(); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1102);
    /* Cold metadata failure cannot publish even a partial reconstructed cursor. */
    for(unsigned policy=0;policy<3;policy++) for(unsigned failure=0;failure<3;failure++) {
        f=indexed_fixture(4,3,2); fixture_save(&f); reset("",0);
        if(policy==0) open_image(&h); else if(policy==1) open_readonly(&h,&r); else { OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); OK(sfs_image_select(h,1,&generous,&r)); }
        ok(sfs_image_stat(h,0,SFS_ROOT_INODE,&entry,&anchor), &anchor);
        sfs_verify_budget cold=generous; unsigned polls=0; cold.cancelled=cancel_now; cold.context=&polls; reset("",0);
        assert(sfs_image_verify(h,&cold,&r)==SFS_INCOMPLETE&&!r.system_errno&&polls);
        reset(failure==0?"read_error":failure==1?"read_zero":"",1);
        if(failure==2) fail_allocation=allocation_calls+1;
        cookie=canary; enum sfs_status status=sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,2,&cookie,&r);
        assert(status==(failure==2?SFS_NOMEM:SFS_IO)&&r.status==status&&hit&&r.phase==SFS_PHASE_READ&&r.system_errno==(failure==2?ENOMEM:EIO)&&!memcmp(&cookie,&canary,sizeof(cookie))&&r.coverage!=SFS_COVERAGE_FULL_REACHABLE);
        image_unwritten(); receipt("resume-cold-failure-output-atomic",&r); reset("",0);
        if(failure==2||policy==2) { OK(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,2,&cookie,&r)); }
        else { cookie=canary; assert(sfs_image_resume_after(h,0,0,NULL,0,0,&cookie,&r)==SFS_POISONED&&r.phase==SFS_PHASE_READ&&!r.system_errno&&!memcmp(&cookie,&canary,sizeof(cookie))); }
        close_image(h); retain(1110+(int)(policy*3+failure));
    }
    /* Rehash every incoming alias: semantic mapping/context errors cannot hide behind bad digests. */
    {
        f=indexed_fixture(4,3,2); n=f.n; baseline=malloc(n); assert(baseline); memcpy(baseline,f.p,n);
        ns=namespace_at(f.p,f.p,n); unsigned char *names=record(f.p,ns+120,n); put64(names+640+267,3);
        repair_parser_aliases(f.p,baseline,n,NULL); assert(parser_framing_valid(f.p,n)); free(baseline);
        baseline=malloc(n); assert(baseline); memcpy(baseline,f.p,n); fixture_save(&f); reset("",0); open_readonly(&h,&anchor); cookie=canary;
        assert(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,1,2,&cookie,&r)==SFS_CORRUPT&&!memcmp(&cookie,&canary,sizeof(cookie)));
        image_unwritten(); receipt("resume-rehashed-semantic-failure",&r); poisoned_readonly(h,r.phase); close_image(h); unchanged("image",baseline,n); free(baseline); retain(1120);
    }
    resume_child_contexts(&canary);
}

int main(int argc, char **argv) {
    assert(argc==2); int before=descriptors(); directory(argv[1]);
    const unsigned char sentinel[]="owned sentinel must remain unchanged"; save("sentinel",sentinel,sizeof(sentinel));
    if(!strcmp(argv[1],"basic")) basic(); else if(!strcmp(argv[1],"creation")) creation();
    else if(!strcmp(argv[1],"io")) io(); else if(!strcmp(argv[1],"cuts")) cuts();
    else if(!strcmp(argv[1],"review")) review(); else if(!strcmp(argv[1],"security")) security();
    else if(!strcmp(argv[1],"parser")) { parser(); contexts(); type_alias_context(); } else if(!strcmp(argv[1],"limits")) limits();
    else if(!strcmp(argv[1],"indexes")) indexes(); else if(!strcmp(argv[1],"ranges")) ranges();
    else if(!strcmp(argv[1],"budgets")) budgets(); else if(!strcmp(argv[1],"capacity")) capacity();
    else if(!strcmp(argv[1],"readonly")) readonly(); else if(!strcmp(argv[1],"resume")) resume(); else assert(0);
    unchanged("sentinel",sentinel,sizeof(sentinel)); free(durable); assert(!allocated); assert(descriptors()==before);
    printf("PASS %s\n",argv[1]); return 0;
}
