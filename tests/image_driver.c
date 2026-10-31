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
#include <time.h>
#include <unistd.h>

static int clearing_cache;
static unsigned cache_frees;
static void verification(void);
static unsigned clock_calls;
static int clock_failure;
static struct timespec clock_value;
int sfs_test_clock_gettime(clockid_t clock, struct timespec *out) {
    assert(!clearing_cache);
    assert(clock == CLOCK_REALTIME); clock_calls++;
    if (clock_failure) { errno = ENXIO; return -1; }
    *out = clock_value; return 0;
}
static void clock_at(int64_t seconds, long nanos) {
    clock_value.tv_sec = (time_t)seconds; clock_value.tv_nsec = nanos; clock_failure = 0; clock_calls = 0;
}
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
static void memo_target_open(int fd);
static void memo_target_io(int fd, const void *bytes, size_t n, off_t at, int writing);
static int memo_target_enabled, memo_target_fd[4096];
static unsigned memo_target_passes;
static uint64_t memo_target_sequence, memo_target_first_zero;
static unsigned char memo_target_reference[56];
static struct {
    int fd;
    unsigned zero_loads, writes, reloads;
    uint64_t first_write, first_reload;
    unsigned char entry[128];
} memo_target_pass[2];
static uint64_t image_read_bytes, image_read_attempts, image_append_bytes;
static uint64_t aux_read_bytes, aux_write_bytes, aux_attempt_bytes;
static uint64_t aux_write_calls, image_truncates;
static int image_open_fd=-1, image_open_flags;
static uint64_t raw_hash_input, metadata_hash_input, raw_hashes, copies;
static uint64_t overlay_clone_bytes, overlay_clone_calls, observed_clone_size;
static uint64_t allocated, peak_allocated, allocation_calls, free_calls;
static uint64_t fail_allocation, fail_after_append;
static unsigned arena_allocations, fail_arena_allocation;
static unsigned aux_created, aux_removed;
static struct { CC_SHA256_CTX *context; int raw; } hash_context[8];
typedef union allocation_header allocation_header;
union allocation_header { max_align_t alignment; struct { size_t bytes; allocation_header *previous, *next; } value; };
static allocation_header *allocations;

void *sfs_test_malloc(size_t n) {
    assert(!clearing_cache);
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
    assert(!clearing_cache);
    /* Match only arena headers; payload, prefix and cache buffers have other sizes. */
    if (n == 1 && size == 8272 && ++arena_allocations == fail_arena_allocation) { hit++; errno = ENOMEM; return NULL; }
    if (size && n > SIZE_MAX / size) { errno = ENOMEM; return NULL; }
    void *p = sfs_test_malloc(n * size); if (p) memset(p, 0, n * size); return p;
}
void sfs_test_free(void *p) {
    if (p) free_calls++;
    if (clearing_cache && p) cache_frees++;
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
    assert(!clearing_cache);
    for (unsigned i = 0; i < 8; i++) if (!hash_context[i].context) {
        hash_context[i].context = c; hash_context[i].raw = 0; return CC_SHA256_Init(c);
    }
    assert(0); return 0;
}
int sfs_test_CC_SHA256_Update(CC_SHA256_CTX *c, const void *p, CC_LONG n) {
    assert(!clearing_cache);
    for (unsigned i = 0; i < 8; i++) if (hash_context[i].context == c) {
        if (n == 36 && (!memcmp(p, "SFSDAT02", 8) || !memcmp(p, "SFSDAT03", 8) || !memcmp(p, "SFSDAT04", 8) || !memcmp(p, "SFSDAT05", 8) || !memcmp(p, "SFSDAT06", 8))) hash_context[i].raw = 1;
        if (hash_context[i].raw) raw_hash_input += n; else metadata_hash_input += n;
        return CC_SHA256_Update(c, p, n);
    }
    assert(0); return 0;
}
int sfs_test_CC_SHA256_Final(unsigned char *sum, CC_SHA256_CTX *c) {
    assert(!clearing_cache);
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
    fail_allocation = fail_after_append = 0; arena_allocations = fail_arena_allocation = 0;
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
    assert(!clearing_cache);
    assert(fd >= 0 && fd < (int)sizeof(auxiliary));
    if (auxiliary[fd]) {
        aux_attempt_bytes += n;
        if (is("aux_read")) { hit++; errno = ENOSPC; return -1; }
        ssize_t result = pread(fd, p, n, at); if (result > 0) { aux_read_bytes += (size_t)result; memo_target_io(fd, p, (size_t)result, at, 0); }
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
    assert(!clearing_cache);
    assert(fd >= 0 && fd < (int)sizeof(auxiliary));
    if (auxiliary[fd]) {
        aux_attempt_bytes += n; aux_write_calls++;
        if (is("aux_enospc") || is("aux_enospc_cleanup")) { hit++; errno = ENOSPC; return -1; }
        ssize_t result = pwrite(fd, p, n, at); if (result > 0) { aux_write_bytes += (size_t)result; memo_target_io(fd, p, (size_t)result, at, 1); }
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
    assert(!clearing_cache);
    if (command == F_DUPFD_CLOEXEC) {
        va_list ap; va_start(ap, command); int minimum = va_arg(ap, int); va_end(ap);
        return fcntl(fd, command, minimum);
    }
    assert(command == F_FULLFSYNC);
    tracked_fd = fd; fulls++; event('F');
    if (fulls == 1) {
        struct stat st; unsigned char last[CELL]; assert(!fstat(fd, &st) && st.st_size >= 16384 && !(st.st_size % CELL));
        assert(pread(fd, last, CELL, st.st_size - CELL) == CELL);
        assert((!memcmp(last, "SFSREC02", 8) || !memcmp(last, "SFSREC03", 8) || !memcmp(last, "SFSREC04", 8) || !memcmp(last, "SFSREC05", 8) || !memcmp(last, "SFSREC06", 8)) && last[8] == 4);
        /* The final commit-root exists before the first publication fence. */
        for (unsigned i = 0; i < 2; i++) { const unsigned char *ref = last + 64 + i * 56; if (ref[0]) { uint64_t offset = 0; for (int j = 7; j >= 0; j--) offset = (offset << 8) | ref[8+j]; assert(offset < (uint64_t)st.st_size - CELL); } }
    }
    if (competing) competitor();
    if ((is("full") || is("full_enospc")) && fulls == target) { hit++; errno = is("full_enospc") ? ENOSPC : EIO; return -1; }
    int result = fcntl(fd, command);
    if (!result && model) capture(fd);
    if (!result && cut) stop_at(fd, NULL, 0, 0);
    return result;
}
int sfs_test_fsync(int fd) {
    assert(!clearing_cache);
    syncs++; event('D');
    if (is("parent_sync")) { hit++; errno = EIO; return -1; }
    return fsync(fd);
}
int sfs_test_flock(int fd, int operation) {
    assert(!clearing_cache);
    locks++; tracked_fd = fd;
    if (is("lock")) { hit++; errno = EWOULDBLOCK; return -1; }
    if (competing && locks == 1 && writes == 0) competitor();
    int rc = flock(fd, operation);
    if (!rc && (operation & LOCK_EX)) locked_fd = fd;
    return rc;
}
int sfs_test_close(int fd) {
    assert(!clearing_cache);
    closes++; struct stat st; assert(fstat(fd, &st) == 0);
    int fail = (is("close") && closes == target) || (is("parent_close") && S_ISDIR(st.st_mode)) || ((is("aux_close") || is("aux_enospc_cleanup")) && auxiliary[fd]);
    int result = close(fd);
    auxiliary[fd] = 0; memo_target_fd[fd] = 0;
    if (fd == locked_fd) locked_fd = -1;
    if (fail) { hit++; errno = EIO; return -1; }
    return result;
}
int sfs_test_openat(int fd, const char *name, int flags, ...) {
    assert(!clearing_cache);
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (is("create") && (flags & O_CREAT)) { hit++; errno = EACCES; return -1; }
    int result = openat(fd, name, flags, mode);
    if (result >= 0) {
        if (!strcmp(name,"image")) { image_open_fd=result; image_open_flags=flags; }
        assert(result < (int)sizeof(auxiliary)); auxiliary[result] = !strcmp(name, "memo");
        if (auxiliary[result]) { struct stat st; assert(!fstat(result, &st) && S_ISREG(st.st_mode) && (st.st_mode & 0777) == 0600 && st.st_uid == geteuid()); aux_created++; memo_target_open(result); }
    }
    return result;
}
int sfs_test_ftruncate(int fd, off_t size) {
    assert(!clearing_cache);
    if (!auxiliary[fd]) image_truncates++;
    if (auxiliary[fd] && is("aux_length_enospc")) { hit++; errno = ENOSPC; return -1; }
    return ftruncate(fd, size);
}
int sfs_test_mkdirat(int fd, const char *name, mode_t mode) {
    assert(!clearing_cache);
    assert(mode == 0700); return mkdirat(fd, name, mode);
}
int sfs_test_unlinkat(int fd, const char *name, int flags) {
    assert(!clearing_cache);
    if (!strcmp(name, "memo")) {
        if (is("aux_unlink")) { hit++; errno = EACCES; return -1; }
        int rc = unlinkat(fd, name, flags); if (!rc) aux_removed++; return rc;
    }
    return unlinkat(fd, name, flags);
}
int sfs_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(sfs_test_fstat);
int sfs_test_fstat(int fd, struct stat *st) {
    assert(!clearing_cache);
    int rc=fstat(fd,st);
    if(!rc&&((is("owner")&&S_ISREG(st->st_mode))||(is("parent_owner")&&S_ISDIR(st->st_mode)))) { st->st_uid^=1; hit++; }
    return rc;
}
int sfs_test_fstatat(int fd, const char *name, struct stat *st, int flags) __DARWIN_INODE64(sfs_test_fstatat);
int sfs_test_fstatat(int fd, const char *name, struct stat *st, int flags) {
    assert(!clearing_cache);
    int rc = fstatat(fd, name, st, flags);
    if (!rc && is("identity") && fulls >= 3) { st->st_ino++; hit++; }
    return rc;
}
int sfs_test_fstatfs(int fd, struct statfs *st) __DARWIN_INODE64(sfs_test_fstatfs);
int sfs_test_fstatfs(int fd, struct statfs *st) {
    assert(!clearing_cache);
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
/* Observe the actual auxiliary page, never cache pointers or a synthetic eviction event. */
static void memo_target_open(int fd) {
    memo_target_fd[fd] = 0;
    if (!memo_target_enabled) return;
    assert(memo_target_passes < 2);
    memo_target_fd[fd] = (int)++memo_target_passes;
    memo_target_pass[memo_target_passes - 1].fd = fd;
}
static void memo_target_io(int fd, const void *bytes, size_t n, off_t at, int writing) {
    if (!memo_target_enabled || !memo_target_fd[fd]) return;
    uint64_t entry_at = get64(memo_target_reference + 8) / CELL * 128;
    uint64_t page_at = entry_at / CELL * CELL;
    if ((uint64_t)at != page_at) return;
    assert(n >= entry_at % CELL + 128);
    unsigned i = (unsigned)memo_target_fd[fd] - 1;
    const unsigned char *entry = (const unsigned char *)bytes + entry_at % CELL;
    if (!get32(entry)) { assert(!writing); memo_target_pass[i].zero_loads++; return; }
    assert(get32(entry) == 2 && get32(entry + 4) == 6 && !memcmp(entry + 8, memo_target_reference + 24, 32));
    assert(get64(entry + 40) == memo_target_first_zero && !get64(entry + 48) && get64(entry + 56) == 6);
    assert(!memcmp(entry + 64, (unsigned char[64]){0}, 64));
    uint64_t sequence = ++memo_target_sequence;
    if (writing) {
        if (!memo_target_pass[i].writes++) { memo_target_pass[i].first_write = sequence; memcpy(memo_target_pass[i].entry, entry, 128); }
        else assert(!memcmp(memo_target_pass[i].entry, entry, 128));
    } else {
        assert(memo_target_pass[i].writes && !memcmp(memo_target_pass[i].entry, entry, 128));
        if (!memo_target_pass[i].reloads++) memo_target_pass[i].first_reload = sequence;
    }
}
static void big64(unsigned char *p, uint64_t v) { for (int i = 7; i >= 0; i--, v >>= 8) p[i] = (unsigned char)v; }
static void slot_hash(unsigned char *p) { unsigned char sum[32]; memset(p + 112, 0, 32); CC_SHA256(p, CELL, sum); memcpy(p + 112, sum, 32); }
static unsigned char *record(unsigned char *image, const unsigned char *ref, size_t size) {
    uint64_t at = get64(ref + 8), n = get64(ref + 16);
    assert(at >= 8192 && !(at % CELL) && n == CELL && at <= size && n <= size - at); return image + at;
}
static void ref_hash(unsigned char *image, unsigned char *ref, size_t size) {
    unsigned char *p = record(image, ref, size);
    if (get32(ref) == 6) {
        unsigned char domain[36]; memcpy(domain, get32(image + 12) == 6 ? "SFSDAT06" : get32(image + 12) == 5 ? "SFSDAT05" : get32(image + 12) == 4 ? "SFSDAT04" : get32(image + 12) == 3 ? "SFSDAT03" : "SFSDAT02", 8); memcpy(domain + 8, image + 24, 16);
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
typedef struct { unsigned char *p; size_t n; uint64_t capacity; unsigned minor; } fixture;
static fixture fixture_start(void) {
    fixture f = { calloc(1, 16 * 1024 * 1024), 8192, TEST_CAPACITY, 2 }; assert(f.p);
    for (unsigned i = 0; i < 16; i++) f.p[24 + i] = (unsigned char)(i + 1); return f;
}
static fixture_node append_cell(fixture *f, unsigned type, const unsigned char *cell) {
    assert(f->n + CELL <= 16 * 1024 * 1024); fixture_node node = {0};
    memcpy(f->p + f->n, cell, CELL); put32(node.ref, type); put64(node.ref + 8, f->n); put64(node.ref + 16, CELL);
    f->n += CELL; ref_hash(f->p, node.ref, f->n); return node;
}
static void envelope(fixture *f, unsigned char *p, unsigned type) {
    memset(p, 0, CELL); memcpy(p, f->minor == 6 ? "SFSREC06" : f->minor == 5 ? "SFSREC05" : f->minor == 4 ? "SFSREC04" : f->minor == 3 ? "SFSREC03" : "SFSREC02", 8); put32(p + 8, type); put64(p + 16, 4032); memcpy(p + 24, f->p + 24, 16);
}
static void row_key(unsigned map, const unsigned char *row, unsigned char *key, uint16_t *n) {
    if ((map == 2 || map == 5 || map == 6)) { *n = (uint16_t)(8 + get32(row + 8)); big64(key, get64(row)); memcpy(key + 8, row + 12, *n - 8); }
    else { *n = 8; big64(key, map == 4 ? get32(row) : get64(row)); }
}
static fixture_node page(fixture *f, unsigned map, unsigned level, const unsigned char *rows, unsigned count, unsigned stride, const fixture_node *children) {
    unsigned char p[CELL]; envelope(f, p, 5); put32(p + 64, map); put16(p + 68, (uint16_t)level); put16(p + 70, (uint16_t)count); put64(p + 72, 1);
    fixture_node node = {0}; node.level = (uint16_t)level;
    if (level) {
        node.min_n = children[0].min_n; memcpy(node.min, children[0].min, node.min_n);
        node.max_n = children[count - 1].max_n; memcpy(node.max, children[count - 1].max, node.max_n);
        for (unsigned i = 0; i < count; i++) { unsigned char *r = p + 640 + i * stride; put32(r, children[i].min_n); memcpy(r + 8, children[i].min, children[i].min_n); memcpy(r + ((map == 2 || map == 5 || map == 6) ? 271 : 16), children[i].ref, 56); }
    } else { memcpy(p + 640, rows, count * stride); row_key(map, rows, node.min, &node.min_n); row_key(map, rows + (count - 1) * stride, node.max, &node.max_n); }
    put16(p + 88, node.min_n); put16(p + 90, node.max_n); memcpy(p + 112, node.min, node.min_n); memcpy(p + 375, node.max, node.max_n);
    fixture_node cell = append_cell(f, 5, p); memcpy(node.ref, cell.ref, 56); return node;
}
static fixture_node tree(fixture *f, unsigned map, const unsigned char *rows, unsigned count) {
    const unsigned leaf_stride[] = {0,f->minor == 6 ? 496u : (f->minor == 3 || f->minor == 4 || f->minor == 5) ? 440u : 352u,280,72,328,352,280}, leaf_max[] = {0,f->minor >= 3 ? 6u : 9u,12,48,9,9,12};
    assert(count); unsigned groups = (count + leaf_max[map] - 1) / leaf_max[map];
    fixture_node *nodes = calloc(groups, sizeof(*nodes)); assert(nodes); unsigned at = 0;
    for (unsigned i = 0; i < groups; i++) { unsigned size = count / groups + (i < count % groups); nodes[i] = page(f, map, 0, rows + at * leaf_stride[map], size, leaf_stride[map], NULL); at += size; }
    unsigned level = 0, max = (map == 2 || map == 5 || map == 6) ? 9 : 48, stride = (map == 2 || map == 5 || map == 6) ? 328 : 72;
    while (groups > 1) { unsigned parents = (groups + max - 1) / max, used = 0; level++;
        for (unsigned i = 0; i < parents; i++) { unsigned size = groups / parents + (i < groups % parents); nodes[i] = page(f, map, level, NULL, size, stride, nodes + used); used += size; }
        groups = parents;
    }
    fixture_node result = nodes[0]; free(nodes); return result;
}
static void fixture_tuple(unsigned char *p, unsigned kind, uint64_t mappings) {
    memset(p,0,88);
    for (unsigned i=0;i<4;i++) { put64(p+i*16,UINT64_C(1700000000)+i); put32(p+i*16+8,123+i); }
    put32(p+64,kind==SFS_FILE?0100600:0040700); put32(p+68,1234); put32(p+72,5678); put64(p+80,mappings);
}
static fixture_node namespace_cell(fixture *f, fixture_node inodes, fixture_node names, uint64_t next, uint64_t count) {
    unsigned char p[CELL]; envelope(f, p, 2); memcpy(p + 64, inodes.ref, 56); memcpy(p + 120, names.ref, 56); put64(p + 176, next); put64(p + 184, count); if(f->minor==3||f->minor==4||f->minor==5||f->minor==6) fixture_tuple(p+192,SFS_DIRECTORY,0); if(f->minor==6) put64(p+336,count); return append_cell(f, 2, p);
}
static void finish_fixture(fixture *f, fixture_node ns, fixture_node catalog) {
    unsigned char p[CELL]; envelope(f, p, 4); memcpy(p + 64, ns.ref, 56); memcpy(p + 120, catalog.ref, 56); fixture_node root_node = append_cell(f, 4, p);
    for (unsigned i = 0; i < 2; i++) { unsigned char *s = f->p + i * CELL; unsigned char uuid[16]; memcpy(uuid, f->p + 24, 16); memset(s, 0, CELL); memcpy(s, "SFSIMG01", 8); put32(s + 12, f->minor); memcpy(s + 24, uuid, 16); put64(s + 40, 1); memcpy(s + 48, root_node.ref, 56); put64(s + 104, f->n); put64(s + 144, f->capacity); slot_hash(s); }
}
/* Shared raw and extent graphs are deliberate; namespace rows remain independently encoded. */
static fixture indexed_fixture_version(unsigned inode_count, unsigned extent_rows, unsigned snapshots, unsigned minor) {
    fixture f = fixture_start(); f.minor=minor; put32(f.p+12,minor); unsigned stride=(minor==3||minor==4||minor==5)?440:352; unsigned char raw[CELL] = {0}; memcpy(raw, "shared", 6); fixture_node data = append_cell(&f, 6, raw), extent = {0};
    if (extent_rows) { unsigned char *rows = calloc(extent_rows, 72); assert(rows); for (unsigned i = 0; i < extent_rows; i++) { put64(rows + i * 72, i); memcpy(rows + i * 72 + 8, data.ref, 56); put16(rows + i * 72 + 64, 6); } extent = tree(&f, 3, rows, extent_rows); free(rows); }
    unsigned char *ir = calloc(inode_count, stride), *nr = calloc(inode_count, 280); assert(ir && nr);
    for (unsigned i = 0; i < inode_count; i++) { char name[32]; int length = snprintf(name, sizeof(name), "f%08u", i); assert(length == 9);
        unsigned char *a = ir + i * stride, *b = nr + i * 280; put64(a, i + 2); put64(a + 8, 1); put32(a + 16, SFS_FILE); put32(a + 20, 9); memcpy(a + 88, name, 9);
        if (extent_rows) { put64(a + 24, (extent_rows - 1) * (uint64_t)CELL + 6); memcpy(a + 32, extent.ref, 56); }
        if(minor==3||minor==4||minor==5) fixture_tuple(a+352,SFS_FILE,extent_rows);
        put64(b, 1); put32(b + 8, 9); memcpy(b + 12, name, 9); put64(b + 267, i + 2);
    }
    fixture_node inodes = tree(&f, 1, ir, inode_count), names = tree(&f, 2, nr, inode_count); free(ir); free(nr);
    fixture_node historical = namespace_cell(&f, inodes, names, inode_count + 2, inode_count), catalog = {0};
    if (snapshots) { unsigned char rows[32 * 328] = {0}; assert(snapshots <= 32); for (unsigned i = 0; i < snapshots; i++) { char name[32]; int length = snprintf(name, sizeof(name), "snapshot-%u", i); put32(rows + i * 328, i + 1); memcpy(rows + i * 328 + 8, historical.ref, 56); put32(rows + i * 328 + 64, (uint32_t)length); memcpy(rows + i * 328 + 68, name, (size_t)length); } catalog = tree(&f, 4, rows, snapshots); }
    fixture_node current = namespace_cell(&f, inodes, names, inode_count + 3, inode_count); finish_fixture(&f, current, catalog); return f;
}
static fixture indexed_fixture(unsigned inodes, unsigned extents, unsigned snapshots) { return indexed_fixture_version(inodes,extents,snapshots,2); }
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
static void sparse_aux_fixture_version(unsigned minor) {
    fixture f=indexed_fixture_version(2,48*1050,2,minor); size_t cells=f.n/CELL; unsigned char *mapping=calloc(cells,56); assert(mapping);
    int fd=open("image",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600); assert(fd>=0); uint64_t end=0;
    for(size_t i=2;i<cells;i++) {
        unsigned char *p=f.p+i*CELL; unsigned type=!memcmp(p,minor==3?"SFSREC03":"SFSREC02",8)?get32(p+8):6;
        if(type==2||type==4) { mapped_ref(p+64,mapping,cells); mapped_ref(p+120,mapping,cells); }
        if(type==5) { unsigned map=get32(p+64), level=get16(p+68), count=get16(p+70), stride=level?(map==2?328:72):(map==1?(minor==3?440:352):map==2?280:map==3?72:328);
            for(unsigned j=0;j<count;j++) { unsigned char *row=p+640+j*stride; if(level) mapped_ref(row+(map==2?271:16),mapping,cells); else if(map==1) mapped_ref(row+32,mapping,cells); else if(map==3||map==4) mapped_ref(row+8,mapping,cells); }
        }
        unsigned char *ref=mapping+i*56; put32(ref,type); uint64_t at=(2+(i-2)*32)*UINT64_C(4096); put64(ref+8,at); put64(ref+16,CELL);
        if(type==6) { unsigned char domain[36]; memcpy(domain,minor==3?"SFSDAT03":"SFSDAT02",8); memcpy(domain+8,f.p+24,16); put32(domain+24,6); put64(domain+28,CELL); CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c,domain,36); CC_SHA256_Update(&c,p,CELL); CC_SHA256_Final(ref+24,&c); }
        else CC_SHA256(p,CELL,ref+24); raw_write(fd,p,CELL,(off_t)at); end=at+CELL;
    }
    assert(end<UINT64_C(268435456));
    for(unsigned i=0;i<2;i++) { unsigned char *slot=f.p+i*CELL; mapped_ref(slot+48,mapping,cells); put64(slot+104,end); put64(slot+144,UINT64_C(268435456)); slot_hash(slot); raw_write(fd,slot,CELL,i*CELL); }
    assert(!close(fd)); printf("{\"case\":\"sparse-aux-layout\",\"stored_cell_bytes\":%llu,\"logical_end\":%llu,\"capacity\":268435456,\"filesystem_allocation_claim\":false}\n",(unsigned long long)(cells*CELL),(unsigned long long)end); fflush(stdout); free(mapping); free(f.p);
}
static void sparse_aux_fixture(void) { sparse_aux_fixture_version(2); }
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
    assert(status == SFS_LIMIT && r.limit_reason == SFS_LIMIT_STRUCTURE && writes == 0 && fulls == 0);
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

/* Stored metadata uses independent field expectations, never host-struct serialization. */
static int timestamp_is(sfs_timestamp t,int64_t s,uint32_t n) { return t.seconds==s&&t.nanoseconds==n; }
static int timestamp_equal(sfs_timestamp a,sfs_timestamp b) { return timestamp_is(a,b.seconds,b.nanoseconds); }
static void metadata_equal(const sfs_metadata_entry *a,const sfs_metadata_entry *b) {
    assert(a->entry.inode==b->entry.inode&&a->entry.parent==b->entry.parent&&a->entry.kind==b->entry.kind&&a->entry.size==b->entry.size&&a->entry.name_length==b->entry.name_length&&!memcmp(a->entry.name,b->entry.name,a->entry.name_length));
    assert(timestamp_equal(a->birth,b->birth)&&timestamp_equal(a->access,b->access)&&timestamp_equal(a->modification,b->modification)&&timestamp_equal(a->change,b->change));
    assert(a->mode==b->mode&&a->uid==b->uid&&a->gid==b->gid&&a->flags==b->flags&&a->referenced_data_bytes==b->referenced_data_bytes&&a->link_count==b->link_count);
}
static sfs_metadata_entry metadata_get(sfs_image *h,sfs_view view,sfs_inode id) {
    sfs_metadata_entry m; sfs_result r; unsigned calls=clock_calls;
    OK(sfs_image_stat_metadata(h,view,id,&m,&r)); assert(r.coverage==SFS_COVERAGE_TOUCHED&&clock_calls==calls&&m.entry.inode==id&&m.link_count==1);
    return m;
}
static sfs_metadata_initial metadata_input(unsigned kind) {
    sfs_metadata_initial in={0}; in.mode=kind==SFS_FILE?0100641:0040751; in.uid=UINT32_MAX; in.gid=UINT32_MAX-1; in.flags=SFS_FLAGS_SUPPORTED;
    in.restore=SFS_RESTORE_BIRTH|SFS_RESTORE_ACCESS|SFS_RESTORE_MODIFICATION;
    in.birth=(sfs_timestamp){10,11}; in.access=(sfs_timestamp){20,21}; in.modification=(sfs_timestamp){30,31}; return in;
}
static void metadata_commit(sfs_image *h) { sfs_result r; unsigned calls=clock_calls; OK(sfs_image_commit(h,&r)); assert(clock_calls==calls); }
static void metadata_create(sfs_image **h,uint64_t capacity) {
    sfs_metadata_initial in=metadata_input(SFS_DIRECTORY); sfs_result r;
    in.birth=(sfs_timestamp){INT64_MIN,0}; in.access=(sfs_timestamp){INT64_MAX,999999999}; in.modification=(sfs_timestamp){-2,3};
    clock_at(100,101); OK(sfs_image_create_metadata(root,"image",capacity,&in,h,&r)); assert(clock_calls==1&&r.generation==1);
    sfs_metadata_entry m=metadata_get(*h,0,1); assert(timestamp_equal(m.birth,in.birth)&&timestamp_equal(m.access,in.access)&&timestamp_equal(m.modification,in.modification)&&timestamp_is(m.change,100,101));
    assert(m.mode==in.mode&&m.uid==in.uid&&m.gid==in.gid&&m.flags==in.flags&&!m.referenced_data_bytes&&m.entry.kind==SFS_DIRECTORY);
}
static void metadata_changed(const sfs_metadata_entry *m,int64_t seconds,int content) {
    assert(timestamp_is(m->change,seconds,(uint32_t)(seconds+1)));
    if(content) assert(timestamp_is(m->modification,seconds,(uint32_t)(seconds+1)));
}
static void metadata_clock(int64_t seconds) { clock_at(seconds,(long)(seconds+1)); }
static void metadata_compatibility(void) {
    sfs_image *h; sfs_result r; clock_at(500,501); reset("",0); create(&h); OK(sfs_image_begin(h,&r)); sfs_inode id=add(h,1,"old",SFS_FILE);
    OK(sfs_image_write(h,id,0,"legacy",6,&r)); metadata_commit(h); expect(h,0,id,"legacy"); assert(!clock_calls);
    OK(sfs_image_begin(h,&r)); OK(sfs_image_write(h,id,0,"staged",6,&r)); size_t n; unsigned char *before=bytes("image",&n); reset("",0);
    sfs_metadata_entry m,canary; memset(&canary,0xA5,sizeof(canary)); m=canary; sfs_metadata_initial in=metadata_input(SFS_FILE); sfs_metadata_update update={0}; update.fields=SFS_META_UID; update.uid=123;
    sfs_inode output=UINT64_MAX;
    assert(sfs_image_stat_metadata(h,0,id,&m,&r)==SFS_UNSUPPORTED&&!memcmp(&m,&canary,sizeof(m))&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    assert(sfs_image_set_metadata(h,id,&update,&r)==SFS_UNSUPPORTED&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    assert(sfs_image_add_metadata(h,1,"new",3,SFS_FILE,&in,&output,&r)==SFS_UNSUPPORTED&&output==UINT64_MAX&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    assert(sfs_image_stat_metadata(h,0,id,NULL,&r)==SFS_INVALID); update.now=SFS_META_ACCESS; assert(sfs_image_set_metadata(h,id,&update,&r)==SFS_INVALID); update.now=0;
    assert(!clock_calls); image_unwritten(); unchanged("image",before,n); free(before); metadata_commit(h); expect(h,0,id,"staged"); close_image(h); retain(1200);
}
static void metadata(void) {
    metadata_compatibility(); sfs_image *h; sfs_result r; reset("",0); metadata_create(&h,TEST_CAPACITY);
    OK(sfs_image_begin(h,&r)); metadata_clock(110); sfs_inode p=add(h,1,"p",SFS_DIRECTORY); assert(clock_calls==1); metadata_commit(h);
    sfs_metadata_entry m=metadata_get(h,0,p); assert(m.mode==0040700&&m.uid==(uint32_t)geteuid()&&m.gid==(uint32_t)getegid()&&!m.flags&&!m.referenced_data_bytes);
    assert(timestamp_is(m.birth,110,111)&&timestamp_equal(m.birth,m.access)&&timestamp_equal(m.birth,m.modification)&&timestamp_equal(m.birth,m.change));
    OK(sfs_image_begin(h,&r)); metadata_clock(120); sfs_inode q=add(h,1,"q",SFS_DIRECTORY); assert(clock_calls==1); metadata_commit(h);
    OK(sfs_image_begin(h,&r)); metadata_clock(130); sfs_metadata_initial in=metadata_input(SFS_FILE); sfs_inode a;
    OK(sfs_image_add_metadata(h,p,"a",1,SFS_FILE,&in,&a,&r)); assert(clock_calls==1); metadata_commit(h);
    m=metadata_get(h,0,a); assert(m.mode==in.mode&&m.uid==in.uid&&m.gid==in.gid&&m.flags==in.flags&&timestamp_equal(m.birth,in.birth)&&timestamp_equal(m.access,in.access)&&timestamp_equal(m.modification,in.modification)); metadata_changed(&m,130,0);
    m=metadata_get(h,0,p); metadata_changed(&m,130,1); m=metadata_get(h,0,q); metadata_changed(&m,120,1); m=metadata_get(h,0,1); metadata_changed(&m,120,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(140); sfs_inode b=add(h,q,"b",SFS_FILE); assert(clock_calls==1); metadata_commit(h);
    OK(sfs_image_begin(h,&r)); metadata_clock(150); OK(sfs_image_write(h,a,0,"abcde",5,&r)); assert(clock_calls==1); metadata_commit(h);
    m=metadata_get(h,0,a); assert(m.entry.size==5&&m.referenced_data_bytes==CELL&&timestamp_equal(m.birth,in.birth)&&timestamp_equal(m.access,in.access)); metadata_changed(&m,150,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(151); OK(sfs_image_write(h,a,0,"abcde",5,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); metadata_changed(&m,151,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(152); OK(sfs_image_write(h,a,1,"Z",1,&r)); assert(clock_calls==1); reset("",0); clock_calls=0;
    OK(sfs_image_write(h,a,0,NULL,0,&r)); OK(sfs_image_rename(h,a,p,"a",1,&r)); sfs_metadata_update update; memset(&update,0xA5,sizeof(update)); update.fields=update.now=0; OK(sfs_image_set_metadata(h,b,&update,&r)); assert(!clock_calls); image_unwritten();
    /* Equal-size resize may seal the pending batch; its metadata remains a no-op. */
    OK(sfs_image_resize(h,a,5,&r)); assert(!clock_calls); metadata_commit(h); m=metadata_get(h,0,a); metadata_changed(&m,152,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(160); memset(&update,0,sizeof(update)); update.fields=SFS_META_MODIFICATION|SFS_META_ACCESS; update.now=SFS_META_ACCESS; update.modification=(sfs_timestamp){-99,7};
    OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(timestamp_is(m.modification,-99,7)&&timestamp_is(m.access,160,161)&&timestamp_equal(m.birth,in.birth)); metadata_changed(&m,160,0);
    OK(sfs_image_begin(h,&r)); metadata_clock(161); update.fields=SFS_META_UID; update.now=0; update.uid=m.uid; OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); metadata_changed(&m,161,0);
    OK(sfs_image_begin(h,&r)); clock_at(INT64_MIN,0); OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(timestamp_is(m.change,INT64_MIN,0)&&timestamp_is(m.modification,-99,7));
    OK(sfs_image_begin(h,&r)); metadata_clock(170); OK(sfs_image_rename(h,a,q,"moved",5,&r)); assert(clock_calls==1); metadata_commit(h);
    m=metadata_get(h,0,a); metadata_changed(&m,170,0); assert(timestamp_is(m.modification,-99,7)); m=metadata_get(h,0,p); metadata_changed(&m,170,1); m=metadata_get(h,0,q); metadata_changed(&m,170,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(171); OK(sfs_image_rename(h,a,q,"same-parent",11,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,q); metadata_changed(&m,171,1); m=metadata_get(h,0,p); metadata_changed(&m,170,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(172); OK(sfs_image_rename(h,a,1,"at-root",7,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,1); metadata_changed(&m,172,1); m=metadata_get(h,0,q); metadata_changed(&m,172,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(173); OK(sfs_image_rename(h,a,p,"back",4,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,1); metadata_changed(&m,173,1); m=metadata_get(h,0,p); metadata_changed(&m,173,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(174); OK(sfs_image_write(h,a,0,"pending",7,&r)); assert(clock_calls==1); metadata_clock(175); update.uid=77; OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); metadata_commit(h);
    expect(h,0,a,"pending"); m=metadata_get(h,0,a); assert(m.entry.size==7&&m.referenced_data_bytes==CELL&&m.uid==77); metadata_changed(&m,175,0); assert(timestamp_is(m.modification,174,175));
    OK(sfs_image_begin(h,&r)); metadata_clock(176); OK(sfs_image_write(h,a,0,"latest!",7,&r)); assert(clock_calls==1); metadata_clock(177); OK(sfs_image_rename(h,a,q,"latest",6,&r)); assert(clock_calls==1); metadata_commit(h); expect(h,0,a,"latest!"); m=metadata_get(h,0,a); metadata_changed(&m,177,0); assert(timestamp_is(m.modification,176,177)&&m.entry.parent==q&&m.entry.size==7&&m.referenced_data_bytes==CELL);
    /* Move sibling p under q; the parent edits share root/index paths. */
    OK(sfs_image_begin(h,&r)); metadata_clock(178); OK(sfs_image_rename(h,p,q,"nested-p",8,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,p); metadata_changed(&m,178,0); m=metadata_get(h,0,q); metadata_changed(&m,178,1); m=metadata_get(h,0,1); metadata_changed(&m,178,1);
    sfs_metadata_entry saved=metadata_get(h,0,a), historical=saved, saved_root=metadata_get(h,0,1); sfs_view view;
    OK(sfs_image_begin(h,&r)); metadata_clock(180); OK(sfs_image_write(h,a,2*CELL+1,"\0",1,&r)); assert(clock_calls==1); clock_calls=0; OK(sfs_image_snapshot(h,"before-metadata",15,&view,&r)); assert(!clock_calls); metadata_commit(h);
    m=metadata_get(h,view,a); metadata_equal(&m,&saved); m=metadata_get(h,view,1); metadata_equal(&m,&saved_root); expect(h,view,a,"latest!");
    m=metadata_get(h,0,a); assert(m.entry.size==2*CELL+2&&m.referenced_data_bytes==2*CELL); metadata_changed(&m,180,1);
    OK(sfs_image_begin(h,&r)); metadata_clock(181); OK(sfs_image_write(h,a,2*CELL,"\0\0",2,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(m.referenced_data_bytes==2*CELL);
    OK(sfs_image_begin(h,&r)); metadata_clock(182); OK(sfs_image_write(h,a,CELL,"x",1,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(m.referenced_data_bytes==3*CELL);
    OK(sfs_image_begin(h,&r)); metadata_clock(183); OK(sfs_image_resize(h,a,5*CELL,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(m.referenced_data_bytes==3*CELL);
    OK(sfs_image_begin(h,&r)); metadata_clock(184); OK(sfs_image_resize(h,a,CELL+1,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(m.referenced_data_bytes==2*CELL);
    OK(sfs_image_begin(h,&r)); metadata_clock(185); OK(sfs_image_resize(h,a,0,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(!m.referenced_data_bytes);
    OK(sfs_image_begin(h,&r)); metadata_clock(186); OK(sfs_image_resize(h,a,CELL,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(!m.referenced_data_bytes);
    OK(sfs_image_begin(h,&r)); metadata_clock(187); OK(sfs_image_write(h,a,0,"\0",1,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,a); assert(m.referenced_data_bytes==CELL);
    /* Metadata-only publication binds cookies/results to a different root. */
    sfs_cookie cookie={0}, resume_cookie={0}; sfs_entry entry; int found; sfs_result anchor;
    ok(sfs_image_stat(h,0,1,&entry,&anchor),&anchor); OK(sfs_image_next(h,0,q,&cookie,&entry,&found,&r)); assert(found);
    OK(sfs_image_begin(h,&r)); metadata_clock(188); update.uid=78; OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); metadata_commit(h);
    assert(sfs_image_next(h,0,q,&cookie,&entry,&found,&r)==SFS_STATE); memset(&resume_cookie,0xA5,sizeof(resume_cookie)); sfs_cookie canary=resume_cookie;
    assert(sfs_image_resume_after(h,0,anchor.generation,anchor.root_digest,q,a,&resume_cookie,&r)==SFS_STATE&&!memcmp(&resume_cookie,&canary,sizeof(canary)));
    saved=metadata_get(h,0,a); OK(sfs_image_begin(h,&r)); metadata_clock(189); update.uid=79; OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1); clock_calls=0; OK(sfs_image_abort(h,&r)); assert(!clock_calls); m=metadata_get(h,0,a); metadata_equal(&m,&saved);
    OK(sfs_image_begin(h,&r)); metadata_clock(190); OK(sfs_image_remove(h,b,&r)); assert(clock_calls==1); metadata_commit(h); m=metadata_get(h,0,q); metadata_changed(&m,190,1);
    /* Each successful setter selects one previously untested field; all other fields/data stay exact. */
    const uint32_t setter_fields[]={SFS_META_MODE,SFS_META_GID,SFS_META_FLAGS,SFS_META_BIRTH};
    unsigned char zero_data[CELL]={0};
    for(unsigned i=0;i<4;i++) {
        sfs_metadata_entry expected=metadata_get(h,0,a), parent_before=metadata_get(h,0,q);
        memset(&update,0,sizeof(update)); update.fields=setter_fields[i];
        if(i==0) { update.mode=0106754; expected.mode=update.mode; }
        else if(i==1) { update.gid=UINT32_MAX; expected.gid=update.gid; }
        else if(i==2) { update.flags=1; expected.flags=update.flags; }
        else { update.birth=(sfs_timestamp){INT64_MAX,999999999}; expected.birth=update.birth; }
        OK(sfs_image_begin(h,&r)); metadata_clock(191+i); OK(sfs_image_set_metadata(h,a,&update,&r)); assert(clock_calls==1);
        expected.change=(sfs_timestamp){191+i,192+i}; metadata_commit(h); assert(clock_calls==1);
        m=metadata_get(h,0,a); metadata_equal(&m,&expected); expect_buffer(h,0,a,zero_data,sizeof(zero_data));
        m=metadata_get(h,0,q); metadata_equal(&m,&parent_before); m=metadata_get(h,view,a); metadata_equal(&m,&historical); expect(h,view,a,"latest!"); assert(clock_calls==1);
        printf("{\"metadata_setter_field\":%u,\"operation_clock_calls\":%u,\"change_seconds\":%lld}\n",setter_fields[i],clock_calls,(long long)expected.change.seconds); fflush(stdout);
        saved=expected;
    }
    close_image(h); open_image(&h); m=metadata_get(h,0,a); metadata_equal(&m,&saved); expect_buffer(h,0,a,zero_data,sizeof(zero_data));
    m=metadata_get(h,view,a); metadata_equal(&m,&historical); expect(h,view,a,"latest!");
    OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); receipt("metadata-times-parents-allocation-full",&r); close_image(h);
    size_t n; unsigned char *before=bytes("image",&n); assert(get32(selected_slot(before)+12)==3); reset("",0); clock_calls=0; open_readonly(&h,&r); m=metadata_get(h,view,a); metadata_equal(&m,&historical); m=metadata_get(h,0,a); metadata_equal(&m,&saved);
    reset("",0); clock_calls=0; assert(sfs_image_set_metadata(h,a,&update,&r)==SFS_STATE&&!clock_calls); assert(sfs_image_set_metadata(h,a,NULL,&r)==SFS_STATE&&!clock_calls); sfs_inode output=UINT64_MAX; assert(sfs_image_add_metadata(h,1,"refused",7,SFS_FILE,&in,&output,&r)==SFS_STATE&&output==UINT64_MAX&&!clock_calls);
    sfs_metadata_entry canary_m; memset(&canary_m,0xA5,sizeof(canary_m)); m=canary_m; assert(sfs_image_stat_metadata(h,0,UINT64_MAX,&m,&r)==SFS_NOT_FOUND&&!memcmp(&m,&canary_m,sizeof(m))); image_unwritten(); assert(!clock_calls); close_image(h); unchanged("image",before,n); free(before);
    sfs_recovery recovery; reset("",0); OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); assert(recovery.pair_valid); unsigned slot=recovery.slots[0].generation>recovery.slots[1].generation?0:1; OK(sfs_image_select(h,slot,&generous,&r)); m=metadata_get(h,view,a); metadata_equal(&m,&historical); reset("",0); clock_calls=0; assert(sfs_image_set_metadata(h,a,&update,&r)==SFS_STATE&&!clock_calls); image_unwritten(); close_image(h);
    /* Recheck the held descriptor's expected EOF even when metadata is already cached. */
    for(unsigned cached_file=0;cached_file<2;cached_file++) {
        reset("",0); open_image(&h); m=metadata_get(h,0,1); m=metadata_get(h,0,a); metadata_equal(&m,&saved);
        OK(sfs_image_begin(h,&r)); metadata_clock(260+cached_file); OK(sfs_image_write(h,a,0,"discarded",9,&r)); assert(clock_calls==1);
        m=metadata_get(h,0,a); metadata_equal(&m,&saved); /* Warm the committed file path after staging. */
        size_t staged_n; unsigned char *staged=bytes("image",&staged_n); struct stat identity,after; assert(!lstat("image",&identity));
        int fd=open("image",O_WRONLY|O_NOFOLLOW|O_CLOEXEC); assert(fd>=0); unsigned char marker[37]; memset(marker,0xD7,sizeof(marker)); raw_write(fd,marker,sizeof(marker),(off_t)staged_n); assert(!close(fd));
        size_t changed_n; unsigned char *changed=bytes("image",&changed_n); assert(changed_n==staged_n+sizeof(marker)&&!memcmp(changed,staged,staged_n)&&!memcmp(changed+staged_n,marker,sizeof(marker))); free(staged);
        assert(!lstat("image",&after)&&after.st_dev==identity.st_dev&&after.st_ino==identity.st_ino&&after.st_size==identity.st_size+(off_t)sizeof(marker));
        sfs_metadata_entry output,canary; memset(&canary,0xA5,sizeof(canary)); output=canary; reset("",0); clock_calls=0;
        enum sfs_status status=sfs_image_stat_metadata(h,0,cached_file?a:SFS_ROOT_INODE,&output,&r);
        assert(status==SFS_IO&&r.status==SFS_IO&&r.phase==SFS_PHASE_IDENTITY&&r.system_errno==ESTALE&&r.coverage==SFS_COVERAGE_NONE&&!memcmp(&output,&canary,sizeof(output))&&!clock_calls&&!reads); image_unwritten(); receipt(cached_file?"metadata-cached-file-eof-identity":"metadata-root-eof-identity",&r);
        assert(sfs_image_stat_metadata(h,0,a,&output,&r)==SFS_POISONED&&!memcmp(&output,&canary,sizeof(output)));
        assert(sfs_image_write(h,a,0,"not-published",13,&r)==SFS_POISONED&&sfs_image_commit(h,&r)==SFS_POISONED&&!clock_calls); image_unwritten(); close_image(h); unchanged("image",changed,changed_n);
        reset("",0); open_image(&h); m=metadata_get(h,0,a); metadata_equal(&m,&saved); expect_buffer(h,0,a,zero_data,sizeof(zero_data)); m=metadata_get(h,view,a); metadata_equal(&m,&historical); expect(h,view,a,"latest!"); image_unwritten(); close_image(h); unchanged("image",changed,changed_n); free(changed);
    }
}
/* Traverse only the untouched fixture topology; semantic mutations never choose repair edges. */
static void metadata_repair_ref(unsigned char *p,const unsigned char *original,unsigned char *ref,const unsigned char *old_ref,size_t n,unsigned depth) {
    assert(depth<32&&!memcmp(ref,old_ref,24)); if(!get32(old_ref)) return;
    const unsigned char *old=record((unsigned char *)original,old_ref,n); unsigned char *cell=record(p,old_ref,n); unsigned type=get32(old_ref);
    if(type==4||type==2) for(unsigned i=0;i<2;i++) metadata_repair_ref(p,original,cell+64+i*56,old+64+i*56,n,depth+1);
    if(type==5) {
        unsigned map=get32(old+64), level=get16(old+68), count=get16(old+70), stride=level?(map==2?328:72):(map==1?440:map==2?280:map==3?72:328);
        for(unsigned i=0;i<count;i++) {
            unsigned offset=level?(map==2?271:16):map==1?32:8;
            if(level||map!=2) metadata_repair_ref(p,original,cell+640+i*stride+offset,old+640+i*stride+offset,n,depth+1);
        }
    }
    ref_hash(p,ref,n);
}
static void metadata_repair(unsigned char *p,unsigned char *original,size_t n) {
    for(unsigned i=0;i<2;i++) { metadata_repair_ref(p,original,p+i*CELL+48,original+i*CELL+48,n,0); slot_hash(p+i*CELL); }
}
/* Framing/digest guard deliberately does not validate time, flags, kinds, counters or fences. */
static int metadata_ref_guard(unsigned char *p,unsigned char *original,const unsigned char *ref,const unsigned char *old_ref,size_t n,uint64_t parent,uint64_t end,unsigned depth) {
    static const unsigned char zeros[56]={0};
    if(depth>=32||memcmp(ref,old_ref,24)) return 0;
    if(!get32(old_ref)) return !memcmp(ref,zeros,56);
    uint64_t at=get64(ref+8); unsigned type=get32(old_ref);
    if(at<8192||at%CELL||at>=parent||at>end||end>n||CELL>end-at||get64(ref+16)!=CELL||get32(ref+4)) return 0;
    unsigned char *cell=p+at,*old=original+at, checked[56]; memcpy(checked,ref,56); ref_hash(p,checked,n); if(memcmp(checked+24,ref+24,32)) return 0;
    if(type!=6&&(memcmp(cell,get32(p+12)==4?"SFSREC04":"SFSREC03",8)||get32(cell+8)!=type||get32(cell+12)||get64(cell+16)!=4032||memcmp(cell+24,p+24,16)||memcmp(cell+40,zeros,24))) return 0;
    if(type==4||type==2) for(unsigned i=0;i<2;i++) if(!metadata_ref_guard(p,original,cell+64+i*56,old+64+i*56,n,at,end,depth+1)) return 0;
    if(type==5) {
        unsigned map=get32(old+64), level=get16(old+68), count=get16(old+70), stride=level?(map==2?328:72):(map==1?440:map==2?280:map==3?72:328);
        for(unsigned i=0;i<count;i++) { unsigned offset=level?(map==2?271:16):map==1?32:8;
            if((level||map!=2)&&!metadata_ref_guard(p,original,cell+640+i*stride+offset,old+640+i*stride+offset,n,at,end,depth+1)) return 0;
        }
    }
    return 1;
}
static int metadata_guard(unsigned char *p,unsigned char *original,size_t n) {
    for(unsigned i=0;i<2;i++) {
        unsigned char *slot=p+i*CELL,checked[CELL]; memcpy(checked,slot,CELL); slot_hash(checked);
        if(memcmp(slot,"SFSIMG01",8)||get32(slot+8)||(get32(slot+12)!=3&&get32(slot+12)!=4)||get64(slot+16)||memcmp(slot+112,checked+112,32)) return 0;
        if(!metadata_ref_guard(p,original,slot+48,original+i*CELL+48,n,get64(slot+104),get64(slot+104),0)) return 0;
    }
    return 1;
}
static void metadata_codec(void) {
    fixture f=indexed_fixture_version(4,3,2,3); size_t n=f.n; unsigned char *baseline=malloc(n); assert(baseline); memcpy(baseline,f.p,n); assert(metadata_guard(f.p,baseline,n)); fixture_save(&f);
    sfs_image *h; sfs_result r; reset("",0); clock_calls=0; open_image(&h); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); receipt("metadata-codec-full-baseline",&r);
    reset("",0); OK(sfs_image_verify(h,&generous,&r)); assert(raw_hashes==1&&raw_hash_input==4132); counters("metadata-per-mapping-versus-unique-raw");
    for(unsigned view=0;view<=2;view++) for(unsigned id=2;id<=5;id++) { sfs_metadata_entry m=metadata_get(h,view,id); assert(m.referenced_data_bytes==3*CELL&&m.link_count==1&&m.entry.size==2*CELL+6); }
    assert(!clock_calls); close_image(h); unchanged("image",baseline,n); retain(1210);
    const char *cases[]={"root-nanoseconds","timestamp-padding","file-nanoseconds","mode-kind","unsupported-flags","count-over-size","count-full-mismatch","zero-count-nonempty-root","root-count","directory-mode","root-padding","negative-seconds-valid"};
    for(unsigned kind=0;kind<sizeof(cases)/sizeof(*cases);kind++) {
        unsigned char *p=malloc(n); assert(p); memcpy(p,baseline,n); unsigned char *ns=namespace_at(p,p,n), *row=leaf_row(p,ns+64,2,n,440), *tuple=row+352;
        if(kind==0) put32(ns+192+8,1000000000); else if(kind==1) tuple[12]=1; else if(kind==2) put32(tuple+8,1000000000);
        else if(kind==3) put32(tuple+64,0040600); else if(kind==4) put32(tuple+76,2); else if(kind==5) put64(tuple+80,4); else if(kind==6) { row=leaf_row(p,ns+64,5,n,440); put64(row+352+80,2); }
        else if(kind==7) put64(tuple+80,0);
        else if(kind==8) put64(ns+192+80,1); else if(kind==9) put32(ns+192+64,0100700); else if(kind==10) ns[280]=1;
        else { put64(tuple,UINT64_C(0x8000000000000000)); put64(tuple+16,UINT64_C(0x7fffffffffffffff)); put32(tuple+24,999999999); }
        metadata_repair(p,baseline,n); assert(metadata_guard(p,baseline,n)); save("image",p,n); reset("",0); h=NULL;
        if(kind==11) { open_image(&h); sfs_metadata_entry m=metadata_get(h,0,2); assert(timestamp_is(m.birth,INT64_MIN,123)&&timestamp_is(m.access,INT64_MAX,999999999)); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); close_image(h); }
        else {
            /* FULL inspection reaches all shared historical aliases; it is not masked by admission roots. */
            sfs_recovery recovery; enum sfs_status status=sfs_image_inspect(root,"image",&h,&recovery,&generous,&r);
            printf("{\"metadata_semantic_case\":\"%s\",\"digest_framing_valid\":true,\"status\":%d,\"slot0\":%d,\"slot1\":%d}\n",cases[kind],status,recovery.slots[0].status,recovery.slots[1].status); fflush(stdout);
            assert(status==SFS_RECOVERY_REQUIRED&&r.status==SFS_RECOVERY_REQUIRED&&r.phase==SFS_PHASE_READ&&!r.system_errno&&!h&&recovery.slots[0].status==SFS_CORRUPT&&recovery.slots[1].status==SFS_CORRUPT); image_unwritten();
        }
        unchanged("image",p,n); free(p); retain(1211+(int)kind);
    }
    free(baseline);
    /* Two separately FULL-valid versions are recoverable, but not an ordinary version-mixed pair. */
    f=indexed_fixture_version(2,1,0,3); unsigned char metadata_slot[CELL]; memcpy(metadata_slot,f.p,CELL);
    f.minor=2; fixture_node empty={0}, legacy=namespace_cell(&f,empty,empty,2,0); finish_fixture(&f,legacy,empty); memcpy(f.p,metadata_slot,CELL); fixture_save(&f);
    reset("",0); h=NULL; assert(sfs_image_open(root,"image",&h,&r)==SFS_RECOVERY_REQUIRED&&!h); image_unwritten();
    sfs_recovery recovery; OK(sfs_image_inspect(root,"image",&h,&recovery,&generous,&r)); assert(!recovery.pair_valid&&recovery.slots[0].status==SFS_OK&&recovery.slots[1].status==SFS_OK);
    OK(sfs_image_select(h,0,&generous,&r)); sfs_metadata_entry m=metadata_get(h,0,2); assert(m.referenced_data_bytes==CELL);
    size_t mixed_n; unsigned char *mixed=bytes("image",&mixed_n); memcpy(mixed,mixed+CELL,CELL); replace_image(mixed,mixed_n); reset("",0);
    assert(sfs_image_select(h,0,&generous,&r)==SFS_CORRUPT); image_unwritten(); close_image(h); unchanged("image",mixed,mixed_n); free(mixed); retain(1223);
    /* The established eviction graph now exercises codec3 metadata count contexts and DAT03 hashing. */
    f=indexed_fixture_version(2,48*1201,3,3); fixture_save(&f); reset("",0); open_image(&h);
    size_t large_n; unsigned char *large=bytes("image",&large_n), *space=namespace_at(large,selected_slot(large),large_n); watch_payload(0,space+64); watch_payload(1,raw_ref(large,leaf_row(large,space+64,2,large_n,440),0,large_n)); watch_count=2;
    for(unsigned pass=0;pass<2;pass++) { reset("",0); watch_clear(); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE&&raw_hash_input==4132&&raw_hashes==1&&watch_bytes[1]==CELL&&watch_reads[0]>=2&&metadata_hash_input>4194304); counters("metadata-shared-evicted-full"); sfs_metadata_entry mm=metadata_get(h,3,2); assert(mm.referenced_data_bytes==48*UINT64_C(1201)*CELL); }
    watch_count=0; large[watch_at[1]]^=1; replace_image(large,large_n); reset("",0); assert(sfs_image_verify(h,&generous,&r)==SFS_CORRUPT&&raw_hash_input>=4132); assert(sfs_image_commit(h,&r)==SFS_POISONED); image_unwritten(); close_image(h); unchanged("image",large,large_n); free(large); retain(1224);
    sparse_aux_fixture_version(3); unsigned char digest[32],after_digest[32]; uint64_t length,after_length; file_digest("image",digest,&length); assert(length<=UINT64_C(268435456)); struct stat identity,after; assert(!lstat("image",&identity));
    reset("",0); open_readonly(&h,&r); reset("",0); clock_calls=0; OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE&&aux_write_calls&&aux_write_bytes&&raw_hash_input==4132&&raw_hashes==1); image_unwritten(); counters("metadata-actual-aux-write-baseline");
    reset("aux_enospc_cleanup",0); assert(sfs_image_verify(h,&generous,&r)==SFS_IO&&hit&&aux_write_calls&&r.phase==SFS_PHASE_VERIFY_AUX&&r.system_errno==ENOSPC&&!clock_calls); receipt("metadata-aux-first-error-enospc",&r); image_unwritten(); sfs_metadata_entry output; memset(&output,0xA5,sizeof(output)); sfs_metadata_entry canary=output;
    assert(sfs_image_stat_metadata(h,0,2,&output,&r)==SFS_POISONED&&!memcmp(&output,&canary,sizeof(output))); reset("",0); close_image(h); file_digest("image",after_digest,&after_length); assert(length==after_length&&!memcmp(digest,after_digest,32)); assert(!lstat("image",&after)); identical_identity(&identity,&after);
}
static void metadata_indexes(void) {
    sfs_image *h; sfs_result r; reset("",0); metadata_create(&h,TEST_CAPACITY); OK(sfs_image_begin(h,&r)); sfs_inode ids[300];
    for(unsigned i=0;i<300;i++) { char name[24]; snprintf(name,sizeof(name),"metadata-%03u",i); metadata_clock(1000+i); ids[i]=add(h,1,name,SFS_FILE); assert(clock_calls==1); }
    metadata_commit(h); assert(disk_level(1)>=2&&disk_level(2)>=2); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE); receipt("metadata-six-row-deep-index-full",&r);
    sfs_view view; OK(sfs_image_begin(h,&r)); clock_calls=0; OK(sfs_image_snapshot(h,"deep",4,&view,&r)); metadata_commit(h); assert(!clock_calls); close_image(h);
    size_t n; unsigned char *before=bytes("image",&n); struct stat identity,after; assert(!lstat("image",&identity)); reset("",0); open_readonly(&h,&r);
    unsigned h_i=disk_level(1)+1,h_n=disk_level(2)+1, made=aux_created; reset("",0); clock_calls=0; sfs_metadata_entry m=metadata_get(h,0,ids[299]);
    assert(m.mode==0100600&&m.uid==(uint32_t)geteuid()&&m.gid==(uint32_t)getegid()&&timestamp_is(m.birth,1299,1300)&&!m.referenced_data_bytes);
    assert(image_read_bytes<=((uint64_t)h_i+h_n)*CELL&&!raw_hash_input&&!raw_hashes&&!aux_write_bytes&&aux_created==made&&!clock_calls); image_unwritten(); counters("metadata-cold-indexed-getter");
    reset("",0); m=metadata_get(h,0,ids[299]); assert(!image_read_bytes&&!raw_hash_input&&!aux_write_bytes&&!clock_calls); image_unwritten();
    reset("",0); m=metadata_get(h,0,1); assert(!raw_hash_input&&!aux_write_bytes&&!clock_calls&&!m.referenced_data_bytes); image_unwritten();
    reset("",0); m=metadata_get(h,view,ids[299]); assert(timestamp_is(m.birth,1299,1300)&&image_read_bytes<=((uint64_t)h_i+h_n+4)*CELL&&!raw_hash_input&&!aux_write_bytes&&!clock_calls); image_unwritten(); close_image(h); unchanged("image",before,n); assert(!lstat("image",&after)); identical_identity(&identity,&after); free(before);
    /* A cold getter failure leaves the whole combined output intact and does not sample time. */
    for(unsigned failure=0;failure<2;failure++) {
        reset("",0); open_readonly(&h,&r); sfs_verify_budget stop=generous; unsigned polls=0; stop.cancelled=cancel_now; stop.context=&polls;
        assert(sfs_image_verify(h,&stop,&r)==SFS_INCOMPLETE&&polls&&!r.system_errno);
        sfs_metadata_entry output,canary; memset(&canary,0xA5,sizeof(canary)); output=canary; reset(failure?"":"read_error",1); if(failure) fail_allocation=allocation_calls+1; clock_calls=0; clock_failure=1;
        assert(sfs_image_stat_metadata(h,0,ids[299],&output,&r)==(failure?SFS_NOMEM:SFS_IO)&&hit&&r.phase==SFS_PHASE_READ&&r.system_errno==(failure?ENOMEM:EIO)&&!memcmp(&output,&canary,sizeof(output))&&!clock_calls); image_unwritten(); receipt("metadata-getter-failure-output-atomic",&r);
        reset("",0); if(failure) { m=metadata_get(h,0,ids[299]); } else { assert(sfs_image_stat_metadata(h,0,ids[299],&output,&r)==SFS_POISONED&&!memcmp(&output,&canary,sizeof(output))); }
        close_image(h);
    }
    clock_failure=0; open_image(&h); OK(sfs_image_begin(h,&r));
    for(unsigned i=0;i<297;i++) { metadata_clock(2000+i); OK(sfs_image_remove(h,ids[i],&r)); assert(clock_calls==1); }
    metadata_commit(h); assert(disk_level(1)==0); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE);
    for(unsigned i=297;i<300;i++) { m=metadata_get(h,0,ids[i]); assert(timestamp_is(m.birth,1000+i,1001+i)); }
    m=metadata_get(h,view,ids[0]); assert(timestamp_is(m.birth,1000,1001)); close_image(h);
}
static void metadata_invalid_requests(sfs_image *h,sfs_inode a,sfs_inode b) {
    sfs_result r; sfs_metadata_update update={0}; sfs_metadata_initial in=metadata_input(SFS_FILE); size_t n; unsigned char *before=bytes("image",&n); reset("",0); clock_calls=0;
    const unsigned fields[]={128,SFS_META_UID,SFS_META_ACCESS,SFS_META_MODE,SFS_META_MODIFICATION};
    for(unsigned i=0;i<5;i++) {
        memset(&update,0,sizeof(update)); update.fields=fields[i];
        if(i==1) update.now=SFS_META_UID; if(i==2) update.now=SFS_META_BIRTH; if(i==3) update.mode=0040600; if(i==4) update.modification.nanoseconds=1000000000;
        assert(sfs_image_set_metadata(h,a,&update,&r)==SFS_INVALID&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    }
    memset(&update,0,sizeof(update)); update.fields=SFS_META_FLAGS; update.flags=2;
    assert(sfs_image_set_metadata(h,a,&update,&r)==SFS_UNSUPPORTED&&r.phase==SFS_PHASE_NONE&&!r.system_errno);
    in.flags=2; sfs_inode out=UINT64_MAX; assert(sfs_image_add_metadata(h,1,"invalid",7,SFS_FILE,&in,&out,&r)==SFS_UNSUPPORTED&&out==UINT64_MAX);
    in.flags=0; in.restore=8; assert(sfs_image_add_metadata(h,1,"invalid",7,SFS_FILE,&in,&out,&r)==SFS_INVALID&&out==UINT64_MAX);
    in.restore=0; in.mode=0040700; assert(sfs_image_add_metadata(h,1,"invalid",7,SFS_FILE,&in,&out,&r)==SFS_INVALID&&out==UINT64_MAX);
    assert(!clock_calls); image_unwritten(); unchanged("image",before,n); free(before);
    /* Empty setter validates the other owner without flushing A; unknown inode is not a no-op. */
    memset(&update,0,sizeof(update)); OK(sfs_image_set_metadata(h,b,&update,&r)); assert(sfs_image_set_metadata(h,UINT64_MAX,&update,&r)==SFS_NOT_FOUND); assert(!clock_calls); image_unwritten();
}
static void metadata_failures(void) {
    sfs_image *h=NULL; sfs_result r; sfs_metadata_initial in=metadata_input(SFS_DIRECTORY);
    for(unsigned failure=0;failure<3;failure++) { reset("",0); clock_at(5,failure==1?-1:failure==2?1000000000:0); clock_failure=failure==0;
        assert(sfs_image_create_metadata(root,"image",TEST_CAPACITY,&in,&h,&r)==SFS_TIME_UNAVAILABLE&&!h&&r.phase==SFS_PHASE_NONE&&r.system_errno==(failure?0:ENXIO)&&clock_calls==1);
        assert(access("image",F_OK)==-1&&errno==ENOENT); image_unwritten();
    }
    /* Invalid caller fields and unsupported flags are rejected before the source is sampled. */
    clock_at(5,6); in.flags=2; assert(sfs_image_create_metadata(root,"image",TEST_CAPACITY,&in,&h,&r)==SFS_UNSUPPORTED&&!h&&!clock_calls); in.flags=0; in.modification.nanoseconds=1000000000;
    assert(sfs_image_create_metadata(root,"image",TEST_CAPACITY,&in,&h,&r)==SFS_INVALID&&!h&&!clock_calls); assert(access("image",F_OK)==-1&&errno==ENOENT);
    fixture f=indexed_fixture_version(2,1,1,3); fixture_save(&f); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r)); metadata_clock(210); OK(sfs_image_write(h,2,0,"pending",7,&r)); assert(clock_calls==1);
    metadata_invalid_requests(h,2,3); size_t n; unsigned char *before=bytes("image",&n); sfs_metadata_entry old=metadata_get(h,0,2); sfs_metadata_update update={0}; update.fields=SFS_META_UID; update.uid=77;
    for(unsigned failure=0;failure<3;failure++) {
        reset("",0); clock_at(7,failure==1?-1:failure==2?1000000000:0); clock_failure=failure==0;
        assert(sfs_image_set_metadata(h,2,&update,&r)==SFS_TIME_UNAVAILABLE&&r.phase==SFS_PHASE_NONE&&r.system_errno==(failure?0:ENXIO)&&clock_calls==1); image_unwritten(); unchanged("image",before,n);
        sfs_metadata_entry current=metadata_get(h,0,2); metadata_equal(&current,&old);
    }
    for(unsigned operation=0;operation<3;operation++) {
        reset("",0); metadata_clock(219); clock_failure=1; sfs_inode output=UINT64_MAX; sfs_metadata_initial initial=metadata_input(SFS_FILE); enum sfs_status status;
        if(operation==0) status=sfs_image_rename(h,2,1,"renamed",7,&r); else if(operation==1) status=sfs_image_remove(h,3,&r); else status=sfs_image_add_metadata(h,1,"new",3,SFS_FILE,&initial,&output,&r);
        assert(status==SFS_TIME_UNAVAILABLE&&r.phase==SFS_PHASE_NONE&&r.system_errno==ENXIO&&clock_calls==1&&output==UINT64_MAX); image_unwritten(); unchanged("image",before,n);
    }
    reset("",0); metadata_clock(220); fail_allocation=allocation_calls+1;
    assert(sfs_image_set_metadata(h,2,&update,&r)==SFS_NOMEM&&hit&&r.system_errno==ENOMEM); image_unwritten(); unchanged("image",before,n); reset("",0); metadata_commit(h); expect(h,0,2,"pending"); expect(h,1,2,"shared"); close_image(h); free(before); retain(1230);
    /* Late NOMEM and image I/O retain tails but cannot expose a partial tuple/data edit. */
    for(unsigned failure=0;failure<2;failure++) {
        f=indexed_fixture_version(2,1,1,3); fixture_save(&f); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r)); metadata_clock(230); OK(sfs_image_write(h,2,0,"pending",7,&r)); before=bytes("image",&n);
        reset(failure?"write_error":"",failure?2:0); if(!failure) fail_after_append=1; metadata_clock(231);
        enum sfs_status status=sfs_image_set_metadata(h,2,&update,&r); receipt(failure?"metadata-late-image-io":"metadata-late-nomem",&r);
        assert(hit&&status==(failure?SFS_IO:SFS_NOMEM)&&r.system_errno==(failure?EIO:ENOMEM)&&clock_calls==1&&!fulls);
        reset("",0); assert(sfs_image_commit(h,&r)==(failure?SFS_POISONED:SFS_STATE)); close_image(h);
        size_t tail_n; unsigned char *tail=bytes("image",&tail_n); assert(tail_n>n&&!memcmp(tail+8192,before+8192,n-8192)); free(before); free(tail);
        open_image(&h); expect(h,0,2,"shared"); expect(h,1,2,"shared"); sfs_metadata_entry m=metadata_get(h,0,2); assert(m.uid==1234); close_image(h); retain(1231+(int)failure);
    }
    f=indexed_fixture_version(2,1,1,3); fixture_save(&f); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r));
    sfs_verify_budget stop=generous; unsigned polls=0; stop.cancelled=cancel_now; stop.context=&polls; assert(sfs_image_verify(h,&stop,&r)==SFS_INCOMPLETE&&polls);
    before=bytes("image",&n); reset("read_error",1); metadata_clock(239); clock_failure=1;
    assert(sfs_image_set_metadata(h,2,&update,&r)==SFS_IO&&hit&&r.phase==SFS_PHASE_READ&&r.system_errno==EIO&&!clock_calls); image_unwritten(); assert(sfs_image_commit(h,&r)==SFS_POISONED); close_image(h); unchanged("image",before,n); free(before); retain(1236); clock_failure=0;
    /* Observed image I/O remains fatal even when a later charge would stop verification. */
    for(unsigned io=0;io<2;io++) {
        f=indexed_fixture_version(2,1,1,3); fixture_save(&f); reset("",0); open_image(&h); OK(sfs_image_begin(h,&r)); metadata_clock(240); OK(sfs_image_write(h,2,0,"pending",7,&r)); before=bytes("image",&n);
        sfs_verify_budget budget=generous; budget.metadata_read_bytes=CELL; reset(io?"slot_reads":"",io?1:0); clock_calls=0;
        assert(sfs_image_verify(h,&budget,&r)==(io?SFS_IO:SFS_INCOMPLETE)&&r.system_errno==(io?EIO:0)&&r.phase==SFS_PHASE_READ&&!clock_calls); assert(io?hit:!hit); image_unwritten(); unchanged("image",before,n);
        reset("",0); if(io) { assert(sfs_image_set_metadata(h,2,&update,&r)==SFS_POISONED&&sfs_image_commit(h,&r)==SFS_POISONED); } else { metadata_commit(h); expect(h,0,2,"pending"); }
        close_image(h); free(before); retain(1233+(int)io);
    }
}
static void metadata_capacity(void);
static void metadata_atomic(void) { metadata_failures(); metadata_capacity(); metadata_indexes(); }
static fixture metadata_parent_fixture(void) {
    fixture f=indexed_fixture_version(4,1,0,3); unsigned char *space=namespace_at(f.p,f.p,f.n), *first=leaf_row(f.p,space+64,2,f.n,440), ext[56]; memcpy(ext,first+32,56);
    unsigned char inodes[4*440]={0}, names[4*280]={0}; const char *text[]={"p","q","a","b"};
    for(unsigned i=0;i<4;i++) {
        unsigned char *row=inodes+i*440; put64(row,i+2); put64(row+8,i<2?1:i); put32(row+16,i<2?SFS_DIRECTORY:SFS_FILE); put32(row+20,1); row[88]=(unsigned char)text[i][0];
        fixture_tuple(row+352,i<2?SFS_DIRECTORY:SFS_FILE,i<2?0:1); if(i>=2) { put64(row+24,6); memcpy(row+32,ext,56); }
        row=names+i*280; put64(row,i<2?1:i); put32(row+8,1); row[12]=(unsigned char)text[i][0]; put64(row+267,i+2);
    }
    fixture_node ir=tree(&f,1,inodes,4), nr=tree(&f,2,names,4), historical=namespace_cell(&f,ir,nr,6,4);
    unsigned char row[328]={0}; put32(row,1); memcpy(row+8,historical.ref,56); put32(row+64,6); memcpy(row+68,"before",6);
    fixture_node catalog=tree(&f,4,row,1), current=namespace_cell(&f,ir,nr,6,4); finish_fixture(&f,current,catalog); return f;
}
static void metadata_capacity(void) {
    const unsigned remaining[]={6,5,26,25,24,18};
    /* Heights are one; old pending seal is3. Upper reservations are plan-derived, not timed. */
    for(unsigned operation=0;operation<6;operation++) for(unsigned fit=0;fit<2;fit++) {
        fixture f=metadata_parent_fixture(); size_t initial=f.n;
        uint64_t capacity=initial+(UINT64_C(1)+remaining[operation]-(fit?0:1))*CELL;
        for(unsigned i=0;i<2;i++) { put64(f.p+i*CELL+144,capacity); slot_hash(f.p+i*CELL); } fixture_save(&f);
        sfs_image *h; sfs_result r; reset("",0); open_image(&h); OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE);
        sfs_metadata_entry a=metadata_get(h,0,4), parent=metadata_get(h,0,2), other_parent=metadata_get(h,0,3), root_before=metadata_get(h,0,1);
        OK(sfs_image_begin(h,&r)); metadata_clock(300); OK(sfs_image_write(h,4,0,"pending",7,&r)); assert(clock_calls==1);
        size_t n; unsigned char *before=bytes("image",&n); assert(n==initial+CELL&&capacity-n==(remaining[operation]-(fit?0:1))*CELL); reset("",0); metadata_clock(301);
        sfs_metadata_update update={0}; update.fields=SFS_META_UID; update.uid=77; sfs_metadata_initial in=metadata_input(SFS_FILE); sfs_inode output=UINT64_MAX;
        enum sfs_status status;
        if(operation<2) status=sfs_image_set_metadata(h,operation?1:4,&update,&r);
        else if(operation==2) status=sfs_image_rename(h,4,3,"renamed",7,&r);
        else if(operation==3) status=sfs_image_rename(h,4,2,"renamed",7,&r);
        else if(operation==4) status=sfs_image_add_metadata(h,3,"new",3,SFS_FILE,&in,&output,&r);
        else status=sfs_image_remove(h,5,&r);
        printf("{\"metadata_capacity_operation\":%u,\"reservation_cells\":%u,\"fit\":%s,\"status\":%d,\"phase\":%d,\"appended_bytes\":%llu}\n",operation,remaining[operation],fit?"true":"false",status,r.phase,(unsigned long long)image_append_bytes); fflush(stdout);
        if(!fit) {
            assert(status==SFS_LIMIT&&r.phase==SFS_PHASE_ADMISSION&&!r.system_errno&&r.physical_end==n); image_unwritten(); unchanged("image",before,n);
            assert(sfs_image_commit(h,&r)==SFS_STATE); sfs_metadata_entry m=metadata_get(h,0,4); metadata_equal(&m,&a); m=metadata_get(h,1,4); metadata_equal(&m,&a); m=metadata_get(h,0,2); metadata_equal(&m,&parent); m=metadata_get(h,0,3); metadata_equal(&m,&other_parent); m=metadata_get(h,0,1); metadata_equal(&m,&root_before); expect(h,0,4,"shared"); expect(h,1,4,"shared");
            OK(sfs_image_begin(h,&r)); OK(sfs_image_abort(h,&r));
        } else {
            ok(status,&r); assert(clock_calls==1); metadata_commit(h); OK(sfs_image_stat_metadata(h,0,4,&a,&r)); assert(r.physical_end<=capacity); expect(h,0,4,"pending"); expect(h,1,4,"shared"); sfs_metadata_entry m=metadata_get(h,0,4); assert(m.entry.size==7&&m.referenced_data_bytes==CELL); assert(timestamp_is(m.modification,300,301));
            if(operation==0) assert(m.uid==77&&timestamp_is(m.change,301,302));
            if(operation==2||operation==3) assert(m.entry.parent==(operation==2?3:2)&&timestamp_is(m.change,301,302));
            if(operation==1) { m=metadata_get(h,0,1); assert(m.uid==77); }
            if(operation==4) assert(output!=UINT64_MAX);
            OK(sfs_image_verify(h,&generous,&r)); assert(r.coverage==SFS_COVERAGE_FULL_REACHABLE);
        }
        close_image(h); if(!fit) unchanged("image",before,n); free(before); retain(1240+(int)(operation*2+fit));
    }
}

/* Format 0.4 targets are opaque bytes; none of these fixtures follows a target. */
static sfs_metadata_initial symlink_input(void) {
    sfs_metadata_initial in = metadata_input(SFS_FILE); in.mode = 0120753; return in;
}
static void symlink_create(sfs_image **h, uint64_t capacity) {
    sfs_result r; sfs_metadata_initial in = metadata_input(SFS_DIRECTORY);
    reset("", 0); metadata_clock(400);
    OK(sfs_image_create_metadata_version(root, "image", capacity, 4, &in, h, &r));
    assert(clock_calls == 1 && r.coverage == SFS_COVERAGE_FULL_REACHABLE);
}
static sfs_inode symlink_add(sfs_image *h, sfs_inode parent, const char *name, const void *target_bytes, size_t n) {
    sfs_result r; sfs_inode out = UINT64_MAX; sfs_metadata_initial in = symlink_input();
    unsigned calls = clock_calls;
    OK(sfs_image_symlink_metadata(h, parent, name, strlen(name), target_bytes, n, &in, &out, &r));
    assert(out != UINT64_MAX && clock_calls == calls + 1); return out;
}
static void symlink_expect(sfs_image *h, sfs_view view, sfs_inode id, const void *expected, size_t n) {
    unsigned char output[CELL + 2]; memset(output, 0xA5, sizeof(output));
    size_t got = SIZE_MAX; sfs_result r; unsigned calls = clock_calls;
    OK(sfs_image_readlink(h, view, id, output + 1, n, &got, &r));
    assert(r.coverage == SFS_COVERAGE_TOUCHED && got == n && !memcmp(output + 1, expected, n));
    assert(output[0] == 0xA5 && output[n + 1] == 0xA5 && clock_calls == calls);
}
static void symlink_full(sfs_image *h) {
    sfs_result r; unsigned calls = clock_calls;
    OK(sfs_image_verify(h, &generous, &r));
    assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && clock_calls == calls);
}
static void symlink_versions(void) {
    sfs_image *h = NULL; sfs_result r; sfs_metadata_initial in = metadata_input(SFS_DIRECTORY);
    const uint32_t unsupported[] = {0, 2, 7, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(unsupported) / sizeof(*unsupported); i++) {
        reset("", 0); metadata_clock(401); h = (sfs_image *)(uintptr_t)1; uint64_t allocations_before = allocation_calls;
        assert(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, unsupported[i], &in, &h, &r) == SFS_UNSUPPORTED);
        assert(!h && r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls && allocation_calls == allocations_before);
        image_unwritten(); assert(access("image", F_OK) < 0 && errno == ENOENT);
    }
    for (unsigned minor = 2; minor <= 4; minor++) {
        reset("", 0); metadata_clock(402);
        if (minor == 2) OK(sfs_image_create(root, "image", TEST_CAPACITY, &h, &r));
        else OK(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, minor, &in, &h, &r));
        assert(clock_calls == (minor == 2 ? 0 : 1));
        OK(sfs_image_begin(h, &r)); metadata_clock(403); sfs_inode id = add(h, 1, "regular", SFS_FILE);
        OK(sfs_image_write(h, id, 0, "regular", 7, &r)); metadata_commit(h); expect(h, 0, id, "regular"); symlink_full(h);
        OK(sfs_image_begin(h, &r)); reset("", 0); clock_calls = 0;
        OK(sfs_image_write(h, id, 0, NULL, 0, &r)); OK(sfs_image_resize(h, id, 7, &r));
        sfs_metadata_update empty = {0};
        if (minor != 2) OK(sfs_image_set_metadata(h, id, &empty, &r));
        assert(!clock_calls); image_unwritten(); OK(sfs_image_abort(h, &r));
        unsigned char buffer[8]; memset(buffer, 0xA5, sizeof(buffer)); size_t count = 99; sfs_inode output = UINT64_MAX;
        sfs_metadata_initial link = symlink_input(); OK(sfs_image_begin(h, &r));
        if (minor != 4) {
            assert(sfs_image_symlink_metadata(h, 1, "link", 4, "target", 6, &link, &output, &r) == SFS_UNSUPPORTED && output == UINT64_MAX);
            assert(sfs_image_readlink(h, 0, id, buffer, sizeof(buffer), &count, &r) == SFS_UNSUPPORTED && !count);
            assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls); image_unwritten();
        }
        OK(sfs_image_abort(h, &r)); close_image(h);
        size_t n; unsigned char *p = bytes("image", &n); assert(get32(p + 12) == minor && get32(p + CELL + 12) == minor); free(p);
        open_image(&h); expect(h, 0, id, "regular"); symlink_full(h); close_image(h); retain(1300 + (int)minor);
    }
    /* Each candidate has its own supported codec; ordinary admission requires an exact pair. */
    fixture f = indexed_fixture_version(2, 1, 0, 3); unsigned char slot[CELL]; memcpy(slot, f.p, CELL);
    f.minor = 4; fixture_node empty = {0}, ns = namespace_cell(&f, empty, empty, 2, 0); finish_fixture(&f, ns, empty);
    memcpy(f.p, slot, CELL); fixture_save(&f); reset("", 0); h = NULL;
    assert(sfs_image_open(root, "image", &h, &r) == SFS_RECOVERY_REQUIRED && !h); image_unwritten();
    sfs_recovery recovery; OK(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r));
    assert(!recovery.pair_valid && recovery.slots[0].status == SFS_OK && recovery.slots[1].status == SFS_OK);
    for (unsigned i = 0; i < 2; i++) { OK(sfs_image_select(h, i, &generous, &r)); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); }
    close_image(h); retain(1305);
    /* A 0.3 reader rejects 0.4 framing/domain; a changed slot version is not conversion. */
    f = indexed_fixture_version(2, 1, 0, 4); put32(f.p + 12, 3); put32(f.p + CELL + 12, 3); slot_hash(f.p); slot_hash(f.p + CELL); fixture_save(&f);
    reset("", 0); h = NULL; assert(sfs_image_open(root, "image", &h, &r) != SFS_OK && !h); image_unwritten(); retain(1306);
}
static void symlink_bytes(void) {
    sfs_image *h; sfs_result r; symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r));
    static const unsigned char opaque[] = {0xFF, '/', '.', '.', '/', 0x80, '/', '.'};
    const char *classes[] = {"x", "missing", "../directory", "/outside/not-present", ".", "..", "a//b/./../c", "target-7"};
    sfs_inode ids[8];
    for (unsigned i = 0; i < 8; i++) { char name[20]; snprintf(name, sizeof(name), "target-%u", i); ids[i] = symlink_add(h, 1, name, classes[i], strlen(classes[i])); }
    sfs_inode binary = symlink_add(h, 1, "opaque", opaque, sizeof(opaque));
    unsigned char large[CELL]; for (unsigned i = 0; i < CELL; i++) large[i] = (unsigned char)(1 + i % 255);
    sfs_inode maximum = symlink_add(h, 1, "maximum", large, sizeof(large)); metadata_commit(h);
    for (unsigned i = 0; i < 8; i++) symlink_expect(h, 0, ids[i], classes[i], strlen(classes[i]));
    symlink_expect(h, 0, binary, opaque, sizeof(opaque)); symlink_expect(h, 0, maximum, large, CELL);
    unsigned char out[CELL + 2], before[CELL + 2]; memset(before, 0xA5, sizeof(before)); size_t got;
    OK(sfs_image_begin(h, &r)); sfs_inode pending = add(h, 1, "pending", SFS_FILE);
    OK(sfs_image_write(h, pending, 0, "staged", 6, &r)); reset("", 0); clock_calls = 0;
    sfs_metadata_initial in = symlink_input(); sfs_inode id = UINT64_MAX; unsigned char with_nul[] = {'a', 0, 'b'};
    for (unsigned which = 0; which < 4; which++) {
        const void *target_bytes = which == 1 ? with_nul : which == 3 ? NULL : large;
        size_t length = which == 0 ? 0 : which == 1 ? 3 : which == 2 ? CELL + 1 : 1;
        assert(sfs_image_symlink_metadata(h, 1, "bad", 3, target_bytes, length, &in, &id, &r) == SFS_INVALID && id == UINT64_MAX);
        assert(!clock_calls); image_unwritten();
    }
    memcpy(out, before, sizeof(out)); got = 99;
    assert(sfs_image_readlink(h, 0, maximum, NULL, 1, &got, &r) == SFS_INVALID && got == 99);
    assert(sfs_image_readlink(h, 0, maximum, out, CELL, NULL, &r) == SFS_INVALID && !memcmp(out, before, sizeof(out)));
    for (unsigned size = 0; size < 2; size++) {
        got = 99; reset("", 0);
        assert(sfs_image_readlink(h, 0, maximum, size ? out : NULL, size ? CELL - 1 : 0, &got, &r) == SFS_LIMIT && !got);
        assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !raw_hash_input && !memcmp(out, before, sizeof(out))); image_unwritten();
    }
    got = 99; assert(sfs_image_readlink(h, 0, 1, out, sizeof(out), &got, &r) == SFS_INVALID && !got);
    got = 99; assert(sfs_image_readlink(h, 0, UINT64_MAX, out, sizeof(out), &got, &r) == SFS_NOT_FOUND && !got);
    got = 99; assert(sfs_image_readlink(h, 32, maximum, out, sizeof(out), &got, &r) == SFS_NOT_FOUND && !got);
    assert(!memcmp(out, before, sizeof(out))); metadata_commit(h); expect(h, 0, pending, "staged"); symlink_full(h); close_image(h);
    open_image(&h); symlink_expect(h, 0, maximum, large, CELL); close_image(h);
}
static void symlink_namespace(void) {
    sfs_image *h; sfs_result r; symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r));
    sfs_inode directory_id = add(h, 1, "directory", SFS_DIRECTORY), link = symlink_add(h, 1, "link", "directory", 9);
    metadata_commit(h); unsigned char output[32]; memset(output, 0xA5, sizeof(output)); size_t got = 99;
    sfs_entry entry; sfs_cookie cookie = {0}, canary; memset(&canary, 0xA5, sizeof(canary)); int found = 99; sfs_inode id = UINT64_MAX;
    OK(sfs_image_begin(h, &r)); reset("", 0); clock_calls = 0; sfs_metadata_initial in = symlink_input();
    assert(sfs_image_symlink_metadata(h, 1, "link", 4, "other", 5, &in, &id, &r) == SFS_EXISTS && id == UINT64_MAX);
    assert(sfs_image_symlink_metadata(h, 1, "bad/name", 8, "other", 5, &in, &id, &r) == SFS_INVALID);
    assert(sfs_image_symlink_metadata(h, link, "child", 5, "other", 5, &in, &id, &r) == SFS_INVALID);
    assert(sfs_image_add(h, 1, "generic", 7, SFS_SYMLINK, &id, &r) == SFS_INVALID);
    assert(sfs_image_add(h, link, "child", 5, SFS_FILE, &id, &r) == SFS_INVALID);
    assert(sfs_image_lookup(h, 0, link, "child", 5, &entry, &r) == SFS_INVALID);
    assert(sfs_image_next(h, 0, link, &cookie, &entry, &found, &r) == SFS_INVALID);
    sfs_result identity; OK(sfs_image_stat(h, 0, link, &entry, &r)); identity = r; cookie = canary;
    assert(sfs_image_resume_after(h, 0, identity.generation, identity.root_digest, link, directory_id, &cookie, &r) == SFS_INVALID && !memcmp(&cookie, &canary, sizeof(cookie)));
    assert(sfs_image_read(h, 0, link, 0, output, 0, &got, &r) == SFS_INVALID && !got);
    assert(sfs_image_write(h, link, 0, NULL, 0, &r) == SFS_INVALID);
    assert(sfs_image_resize(h, link, 9, &r) == SFS_INVALID);
    sfs_metadata_update wrong_mode = {0}; wrong_mode.fields = SFS_META_MODE; wrong_mode.mode = 0100600;
    assert(sfs_image_set_metadata(h, link, &wrong_mode, &r) == SFS_INVALID);
    assert(!clock_calls); image_unwritten(); symlink_expect(h, 0, link, "directory", 9);
    metadata_clock(410); OK(sfs_image_rename(h, link, directory_id, "moved", 5, &r)); assert(clock_calls == 1); metadata_commit(h);
    OK(sfs_image_lookup(h, 0, directory_id, "moved", 5, &entry, &r)); assert(entry.inode == link && entry.kind == SFS_SYMLINK);
    cookie = (sfs_cookie){0}; OK(sfs_image_resume_after(h, 0, r.generation, r.root_digest, directory_id, link, &cookie, &r));
    OK(sfs_image_next(h, 0, directory_id, &cookie, &entry, &found, &r)); assert(!found);
    symlink_expect(h, 0, link, "directory", 9); OK(sfs_image_begin(h, &r)); OK(sfs_image_remove(h, link, &r)); metadata_commit(h);
    assert(sfs_image_stat(h, 0, link, &entry, &r) == SFS_NOT_FOUND); OK(sfs_image_stat(h, 0, directory_id, &entry, &r));
    OK(sfs_image_begin(h, &r)); char long_name[256]; memset(long_name, 'n', sizeof(long_name)); reset("", 0); clock_calls = 0;
    assert(sfs_image_symlink_metadata(h, 1, long_name, sizeof(long_name), "target", 6, &in, &id, &r) == SFS_LIMIT && id == UINT64_MAX && !clock_calls);
    image_unwritten(); assert(sfs_image_commit(h, &r) == SFS_STATE); symlink_full(h); close_image(h);
}
static void symlink_views(void) {
    sfs_image *h; sfs_result r; symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r)); metadata_clock(420);
    sfs_inode link = symlink_add(h, 1, "link", "../old", 6); assert(clock_calls == 1);
    sfs_entry missing; assert(sfs_image_stat(h, 0, link, &missing, &r) == SFS_NOT_FOUND); metadata_commit(h);
    sfs_metadata_initial initial = symlink_input(); sfs_metadata_entry old = metadata_get(h, 0, link), parent = metadata_get(h, 0, 1);
    assert(old.entry.kind == SFS_SYMLINK && old.entry.size == 6 && old.referenced_data_bytes == CELL && old.link_count == 1);
    assert(old.mode == initial.mode && old.uid == initial.uid && old.gid == initial.gid && old.flags == initial.flags);
    assert(timestamp_equal(old.birth, initial.birth) && timestamp_equal(old.access, initial.access) && timestamp_equal(old.modification, initial.modification));
    metadata_changed(&old, 420, 0); metadata_changed(&parent, 420, 1);
    OK(sfs_image_begin(h, &r)); sfs_view view; OK(sfs_image_snapshot(h, "before-link", 11, &view, &r)); metadata_commit(h); assert(view == 1);
    OK(sfs_image_begin(h, &r)); sfs_metadata_update update = {0}; update.fields = SFS_META_MODE | SFS_META_UID; update.mode = 0120601; update.uid = 77;
    metadata_clock(421); OK(sfs_image_set_metadata(h, link, &update, &r)); assert(clock_calls == 1); OK(sfs_image_abort(h, &r));
    sfs_metadata_entry current = metadata_get(h, 0, link); metadata_equal(&current, &old);
    OK(sfs_image_begin(h, &r)); metadata_clock(422); OK(sfs_image_set_metadata(h, link, &update, &r)); metadata_commit(h);
    current = metadata_get(h, 0, link); assert(current.mode == 0120601 && current.uid == 77 && current.gid == old.gid && current.flags == old.flags);
    assert(timestamp_equal(current.birth, old.birth) && timestamp_equal(current.access, old.access) && timestamp_equal(current.modification, old.modification)); metadata_changed(&current, 422, 0);
    sfs_metadata_entry history = metadata_get(h, view, link); metadata_equal(&history, &old); symlink_expect(h, 0, link, "../old", 6);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_remove(h, link, &r)); sfs_inode replacement = symlink_add(h, 1, "link", "/new", 4); metadata_commit(h); assert(replacement != link);
    symlink_expect(h, 0, replacement, "/new", 4); symlink_expect(h, view, link, "../old", 6); symlink_full(h); close_image(h);
    size_t n; unsigned char *before = bytes("image", &n); reset("", 0); open_readonly(&h, &r);
    symlink_expect(h, 0, replacement, "/new", 4); symlink_expect(h, view, link, "../old", 6); assert(sfs_image_begin(h, &r) == SFS_STATE); image_unwritten(); close_image(h); unchanged("image", before, n);
    sfs_recovery recovery; reset("", 0); OK(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r));
    for (unsigned i = 0; i < 2; i++) { assert(recovery.slots[i].status == SFS_OK); OK(sfs_image_select(h, i, &generous, &r)); symlink_expect(h, view, link, "../old", 6); assert(sfs_image_begin(h, &r) == SFS_STATE); }
    image_unwritten(); close_image(h); unchanged("image", before, n); free(before);
}
/* Promotion is test construction, never an image conversion API. Every incoming digest is rebuilt. */
static fixture symlink_parent_fixture(void) {
    fixture f = metadata_parent_fixture(); unsigned char *original = malloc(f.n); assert(original); memcpy(original, f.p, f.n);
    f.minor = 4;
    for (size_t at = 8192; at < f.n; at += CELL) if (!memcmp(f.p + at, "SFSREC03", 8)) memcpy(f.p + at, "SFSREC04", 8);
    put32(f.p + 12, 4); put32(f.p + CELL + 12, 4); metadata_repair(f.p, original, f.n);
    assert(metadata_guard(f.p, original, f.n)); free(original); return f;
}
static void symlink_failures(void) {
    sfs_result r; sfs_image *h; sfs_metadata_initial in = symlink_input();
    /* Complete pending-owner reservation precedes its seal, including the retained raw tail. */
    for (unsigned nonroot = 0; nonroot < 2; nonroot++) for (unsigned fit = 0; fit < 2; fit++) {
        fixture f = symlink_parent_fixture(); size_t initial = f.n; unsigned required = nonroot ? 26 : 25;
        uint64_t capacity = initial + (UINT64_C(1) + required - (fit ? 0 : 1)) * CELL;
        for (unsigned i = 0; i < 2; i++) { put64(f.p + i * CELL + 144, capacity); slot_hash(f.p + i * CELL); }
        fixture_save(&f); reset("", 0); open_image(&h); symlink_full(h);
        sfs_metadata_entry old_parent = metadata_get(h, 0, nonroot ? 3 : 1), old_file = metadata_get(h, 0, 4);
        OK(sfs_image_begin(h, &r)); metadata_clock(430); OK(sfs_image_write(h, 4, 0, "pending", 7, &r));
        size_t n; unsigned char *before = bytes("image", &n); assert(n == initial + CELL && capacity - n == (required - (fit ? 0 : 1)) * CELL);
        sfs_inode out = UINT64_MAX; reset("", 0); metadata_clock(431);
        enum sfs_status status = sfs_image_symlink_metadata(h, nonroot ? 3 : 1, "link", 4, "target", 6, &in, &out, &r);
        receipt("symlink-pending-complete-reservation", &r);
        if (!fit) {
            assert(status == SFS_LIMIT && r.phase == SFS_PHASE_ADMISSION && !r.system_errno && r.physical_end == n && out == UINT64_MAX);
            image_unwritten(); unchanged("image", before, n); assert(sfs_image_commit(h, &r) == SFS_STATE);
            expect(h, 0, 4, "shared"); expect(h, 1, 4, "shared");
            sfs_metadata_entry unchanged_parent = metadata_get(h, 0, nonroot ? 3 : 1), unchanged_file = metadata_get(h, 0, 4), historical_file = metadata_get(h, 1, 4);
            metadata_equal(&unchanged_parent, &old_parent); metadata_equal(&unchanged_file, &old_file); metadata_equal(&historical_file, &old_file);
            sfs_entry missing; assert(sfs_image_lookup(h, 0, nonroot ? 3 : 1, "link", 4, &missing, &r) == SFS_NOT_FOUND);
            OK(sfs_image_begin(h, &r)); OK(sfs_image_abort(h, &r));
        } else {
            ok(status, &r); assert(out != UINT64_MAX && clock_calls == 1); metadata_commit(h);
            assert(r.physical_end <= capacity); expect(h, 0, 4, "pending"); expect(h, 1, 4, "shared"); symlink_expect(h, 0, out, "target", 6); symlink_full(h);
        }
        close_image(h); free(before); retain(1320 + (int)(nonroot * 2 + fit));
    }
    /* With no pending batch two dirty leaf roots need exactly six new cells. */
    for (unsigned fit = 0; fit < 2; fit++) {
        symlink_create(&h, (UINT64_C(4) + 6 - (fit ? 0 : 1)) * CELL); OK(sfs_image_begin(h, &r));
        size_t n; unsigned char *before = bytes("image", &n); assert(n == 4 * CELL); reset("", 0); metadata_clock(432); sfs_inode out = UINT64_MAX;
        enum sfs_status status = sfs_image_symlink_metadata(h, 1, "link", 4, "target", 6, &in, &out, &r);
        if (fit) { ok(status, &r); metadata_commit(h); struct stat st; assert(!lstat("image", &st) && st.st_size == 10 * CELL); symlink_expect(h, 0, out, "target", 6); symlink_full(h); }
        else { assert(status == SFS_LIMIT && r.phase == SFS_PHASE_ADMISSION && !r.system_errno && out == UINT64_MAX); image_unwritten(); unchanged("image", before, n); assert(sfs_image_commit(h, &r) == SFS_STATE); }
        close_image(h); free(before); retain(1324 + (int)fit);
    }
    fixture f = symlink_parent_fixture(); fixture_save(&f); reset("", 0); open_image(&h); OK(sfs_image_begin(h, &r)); metadata_clock(433); OK(sfs_image_write(h, 4, 0, "pending", 7, &r));
    size_t n; unsigned char *before = bytes("image", &n);
    for (unsigned failure = 0; failure < 2; failure++) {
        reset("", 0); metadata_clock(434); sfs_inode out = UINT64_MAX;
        if (failure) fail_allocation = allocation_calls + 1; else clock_failure = 1;
        enum sfs_status status = sfs_image_symlink_metadata(h, 3, "link", 4, "target", 6, &in, &out, &r);
        assert(status == (failure ? SFS_NOMEM : SFS_TIME_UNAVAILABLE) && r.system_errno == (failure ? ENOMEM : ENXIO) && out == UINT64_MAX);
        assert(failure ? hit > 0 : clock_calls == 1); image_unwritten(); unchanged("image", before, n);
    }
    reset("", 0); metadata_commit(h); expect(h, 0, 4, "pending"); expect(h, 1, 4, "shared"); close_image(h); free(before); retain(1326);
    /* An allocation failure after the previous batch starts sealing is late and discards all staging. */
    f = symlink_parent_fixture(); fixture_save(&f); reset("", 0); open_image(&h); OK(sfs_image_begin(h, &r)); metadata_clock(434);
    OK(sfs_image_write(h, 4, 0, "pending", 7, &r)); before = bytes("image", &n); reset("", 0); metadata_clock(435);
    fail_after_append = 1; sfs_inode late_output = UINT64_MAX;
    assert(sfs_image_symlink_metadata(h, 3, "link", 4, "target", 6, &in, &late_output, &r) == SFS_NOMEM && hit && image_append_bytes && !fulls && late_output == UINT64_MAX && r.system_errno == ENOMEM);
    assert(sfs_image_commit(h, &r) == SFS_STATE); reset("", 0); expect(h, 0, 4, "shared"); expect(h, 1, 4, "shared");
    size_t late_n; unsigned char *late = bytes("image", &late_n); assert(late_n > n && !memcmp(late, before, n)); free(late); free(before);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_abort(h, &r)); close_image(h); retain(1334);
    /* Faults after the raw and extent writes discard staging and retain charged tails. */
    for (unsigned nth = 2; nth <= 3; nth++) {
        symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r)); before = bytes("image", &n);
        reset("write_error", (int)nth); metadata_clock(435); sfs_inode out = UINT64_MAX;
        assert(sfs_image_symlink_metadata(h, 1, "link", 4, "target", 6, &in, &out, &r) == SFS_IO && hit && out == UINT64_MAX && r.system_errno == EIO && r.phase == SFS_PHASE_RECORDS);
        assert(image_append_bytes == (nth - 1) * CELL && !fulls && !slots); receipt("symlink-partial-append-failure", &r);
        assert(sfs_image_commit(h, &r) == SFS_POISONED); reset("", 0); close_image(h);
        size_t tail_n; unsigned char *tail = bytes("image", &tail_n); assert(tail_n == n + (nth - 1) * CELL && !memcmp(before, tail, n)); free(tail); free(before);
        open_image(&h); sfs_entry e; assert(sfs_image_lookup(h, 0, 1, "link", 4, &e, &r) == SFS_NOT_FOUND); close_image(h); retain(1327 + (int)nth);
    }
    symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r)); sfs_inode link = symlink_add(h, 1, "link", "target", 6);
    reset("slot_error", 1); assert(sfs_image_commit(h, &r) == SFS_OUTCOME_UNKNOWN && hit && r.system_errno == EIO && r.phase == SFS_PHASE_SLOT0);
    assert(sfs_image_begin(h, &r) == SFS_POISONED); reset("", 0); close_image(h); retain(1330);
    /* Readlink validates the pinned descriptor even when its inode is warm. */
    symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r)); link = symlink_add(h, 1, "link", "target", 6); metadata_commit(h);
    symlink_expect(h, 0, link, "target", 6); OK(sfs_image_begin(h, &r));
    int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); struct stat st; assert(!fstat(fd, &st) && !ftruncate(fd, st.st_size + 1) && !close(fd));
    before = bytes("image", &n); unsigned char out[8], canary[8]; memset(canary, 0xA5, sizeof(canary)); memcpy(out, canary, sizeof(out)); size_t count = 99; reset("", 0);
    assert(sfs_image_readlink(h, 0, link, out, sizeof(out), &count, &r) == SFS_IO && r.phase == SFS_PHASE_IDENTITY && r.system_errno == ESTALE && !count && !memcmp(out, canary, sizeof(out)));
    image_unwritten(); assert(sfs_image_commit(h, &r) == SFS_POISONED); count = 99;
    assert(sfs_image_readlink(h, 0, link, out, sizeof(out), &count, &r) == SFS_POISONED && count == 99 && !memcmp(out, canary, sizeof(out)));
    close_image(h); unchanged("image", before, n); free(before); retain(1331);
    /* Sufficient-buffer NOMEM is a nonpoisoning read failure; raw I/O is fatal. */
    for (unsigned io = 0; io < 2; io++) {
        symlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r)); link = symlink_add(h, 1, "link", "target", 6); metadata_commit(h); close_image(h);
        reset("", 0); open_image(&h); (void)metadata_get(h, 0, link); before = bytes("image", &n);
        unsigned char *ns = namespace_at(before, selected_slot(before), n), *row = leaf_row(before, ns + 64, link, n, 440), *extent = record(before, row + 32, n);
        read_at[0] = get64(extent + 648 + 8); reset(io ? "candidate_reads" : "", io ? 1 : 0); if (!io) fail_allocation = allocation_calls + 1;
        memcpy(out, canary, sizeof(out)); count = 99;
        assert(sfs_image_readlink(h, 0, link, out, sizeof(out), &count, &r) == (io ? SFS_IO : SFS_NOMEM) && hit && !count && !memcmp(out, canary, sizeof(out)));
        assert(r.phase == SFS_PHASE_READ && r.system_errno == (io ? EIO : ENOMEM)); image_unwritten();
        reset("", 0); if (io) assert(sfs_image_begin(h, &r) == SFS_POISONED); else { symlink_expect(h, 0, link, "target", 6); OK(sfs_image_begin(h, &r)); OK(sfs_image_abort(h, &r)); }
        close_image(h); unchanged("image", before, n); free(before); retain(1332 + (int)io);
    }
}
/* Fixed two-inode graph: whole extent or just raw sharing, with independently chosen traversal order. */
static fixture symlink_graph(unsigned link_first, unsigned large, unsigned interior_nul) {
    fixture f = fixture_start(); f.minor = 4; put32(f.p + 12, 4);
    unsigned char raw[CELL] = {0}; memcpy(raw, "shared", 6); if (interior_nul) raw[2] = 0;
    fixture_node data = append_cell(&f, 6, raw), fill = {0};
    if (large) { unsigned char filler[CELL] = {0}; memcpy(filler, "filler", 6); fill = append_cell(&f, 6, filler); }
    unsigned char er[72] = {0}; memcpy(er + 8, data.ref, 56); put16(er + 64, 6);
    fixture_node link_extent = tree(&f, 3, er, 1), regular_extent = link_extent;
    unsigned extent_count = large ? 48 * 1201 : 1;
    if (large) {
        unsigned char *rows = calloc(extent_count, 72); assert(rows);
        for (unsigned i = 0; i < extent_count; i++) { put64(rows + i * 72, i); memcpy(rows + i * 72 + 8, i ? fill.ref : data.ref, 56); put16(rows + i * 72 + 64, 6); }
        regular_extent = tree(&f, 3, rows, extent_count); free(rows);
    }
    unsigned char ir[880] = {0}, nr[560] = {0};
    for (unsigned i = 0; i < 2; i++) {
        unsigned link = i == (link_first ? 0u : 1u); unsigned char *a = ir + i * 440, *b = nr + i * 280;
        put64(a, i + 2); put64(a + 8, 1); put32(a + 16, link ? SFS_SYMLINK : SFS_FILE); put32(a + 20, 1); a[88] = (unsigned char)('a' + i);
        put64(a + 24, link ? 6 : (extent_count - 1) * (uint64_t)CELL + 6); memcpy(a + 32, link ? link_extent.ref : regular_extent.ref, 56);
        fixture_tuple(a + 352, SFS_FILE, link ? 1 : extent_count); if (link) put32(a + 416, 0120600);
        put64(b, 1); put32(b + 8, 1); b[12] = (unsigned char)('a' + i); put64(b + 267, i + 2);
    }
    fixture_node inodes = tree(&f, 1, ir, 2), names = tree(&f, 2, nr, 2), history = namespace_cell(&f, inodes, names, 4, 2);
    unsigned char catalog_rows[656] = {0};
    for (unsigned i = 0; i < 2; i++) { unsigned char *a = catalog_rows + i * 328; put32(a, i + 1); memcpy(a + 8, history.ref, 56); put32(a + 64, 1); a[68] = (unsigned char)('x' + i); }
    fixture_node catalog = tree(&f, 4, catalog_rows, 2), current = namespace_cell(&f, inodes, names, 4, 2); finish_fixture(&f, current, catalog); return f;
}
/* Repair all incoming references on the untouched topology, including zeroed semantic edges. */
static void symlink_repair_ref(unsigned char *p, const unsigned char *original, unsigned char *ref, const unsigned char *old_ref, size_t n, unsigned depth) {
    assert(depth < 32); if (!get32(ref)) { assert(!memcmp(ref, (unsigned char[56]){0}, 56)); return; }
    assert(!memcmp(ref, old_ref, 24)); const unsigned char *old = record((unsigned char *)original, old_ref, n); unsigned char *cell = record(p, ref, n); unsigned type = get32(ref);
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) symlink_repair_ref(p, original, cell + 64 + i * 56, old + 64 + i * 56, n, depth + 1);
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = level ? (map == 2 ? 328 : 72) : map == 1 ? 440 : map == 2 ? 280 : map == 3 ? 72 : 328;
        for (unsigned i = 0; i < count; i++) { unsigned at = 640 + i * stride + (level ? (map == 2 ? 271 : 16) : map == 1 ? 32 : 8);
            if (level || map != 2) symlink_repair_ref(p, original, cell + at, old + at, n, depth + 1);
        }
    }
    ref_hash(p, ref, n);
}
static void symlink_repair(unsigned char *p, const unsigned char *original, size_t n) {
    for (unsigned i = 0; i < 2; i++) { symlink_repair_ref(p, original, p + i * CELL + 48, original + i * CELL + 48, n, 0); slot_hash(p + i * CELL); }
}
/* Guard only framing/digests/physical reference order, not link shape, kind, size or bytes. */
static int symlink_ref_guard(unsigned char *p, const unsigned char *original, const unsigned char *ref, const unsigned char *old_ref, size_t n, uint64_t parent, unsigned depth) {
    if (!get32(ref)) return !memcmp(ref, (unsigned char[56]){0}, 56);
    if (depth >= 32 || memcmp(ref, old_ref, 24)) return 0;
    uint64_t at = get64(ref + 8); if (at < 8192 || at % CELL || at >= parent || at > n || CELL > n - at || get64(ref + 16) != CELL || get32(ref + 4)) return 0;
    unsigned char checked[56]; memcpy(checked, ref, 56); ref_hash(p, checked, n); if (memcmp(checked + 24, ref + 24, 32)) return 0;
    unsigned type = get32(ref); unsigned char *cell = p + at; const unsigned char *old = original + at;
    if (type != 6 && (memcmp(cell, "SFSREC04", 8) || get32(cell + 8) != type || get32(cell + 12) || get64(cell + 16) != 4032 || memcmp(cell + 24, p + 24, 16) || memcmp(cell + 40, (unsigned char[24]){0}, 24))) return 0;
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) if (!symlink_ref_guard(p, original, cell + 64 + i * 56, old + 64 + i * 56, n, at, depth + 1)) return 0;
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = level ? (map == 2 ? 328 : 72) : map == 1 ? 440 : map == 2 ? 280 : map == 3 ? 72 : 328;
        for (unsigned i = 0; i < count; i++) { unsigned offset = 640 + i * stride + (level ? (map == 2 ? 271 : 16) : map == 1 ? 32 : 8);
            if ((level || map != 2) && !symlink_ref_guard(p, original, cell + offset, old + offset, n, at, depth + 1)) return 0;
        }
    }
    return 1;
}
static int symlink_guard(unsigned char *p, const unsigned char *original, size_t n) {
    for (unsigned i = 0; i < 2; i++) {
        unsigned char checked[CELL], *slot = p + i * CELL; memcpy(checked, slot, CELL); slot_hash(checked);
        if (get32(slot + 12) != 4 || memcmp(checked + 112, slot + 112, 32) || !symlink_ref_guard(p, original, slot + 48, original + i * CELL + 48, n, get64(slot + 104), 0)) return 0;
    }
    return 1;
}
/* Same bounded sparse address shape as the existing auxiliary eviction fixture. */
static void symlink_sparse_save(fixture *f) {
    size_t cells = f->n / CELL; unsigned char *mapping = calloc(cells, 56); assert(mapping);
    int fd = open("image", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); assert(fd >= 0); uint64_t end = 0;
    for (size_t i = 2; i < cells; i++) {
        unsigned char *p = f->p + i * CELL; unsigned type = !memcmp(p, "SFSREC04", 8) ? get32(p + 8) : 6;
        if (type == 2 || type == 4) { mapped_ref(p + 64, mapping, cells); mapped_ref(p + 120, mapping, cells); }
        if (type == 5) {
            unsigned map = get32(p + 64), level = get16(p + 68), count = get16(p + 70), stride = level ? (map == 2 ? 328 : 72) : map == 1 ? 440 : map == 2 ? 280 : map == 3 ? 72 : 328;
            for (unsigned j = 0; j < count; j++) { unsigned char *row = p + 640 + j * stride; if (level) mapped_ref(row + (map == 2 ? 271 : 16), mapping, cells); else if (map == 1) mapped_ref(row + 32, mapping, cells); else if (map == 3 || map == 4) mapped_ref(row + 8, mapping, cells); }
        }
        unsigned char *ref = mapping + i * 56; put32(ref, type); uint64_t at = (2 + (i - 2) * 32) * UINT64_C(4096); put64(ref + 8, at); put64(ref + 16, CELL);
        if (type == 6) {
            unsigned char domain[36]; memcpy(domain, "SFSDAT04", 8); memcpy(domain + 8, f->p + 24, 16); put32(domain + 24, 6); put64(domain + 28, CELL);
            CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c, domain, 36); CC_SHA256_Update(&c, p, CELL); CC_SHA256_Final(ref + 24, &c);
        } else CC_SHA256(p, CELL, ref + 24);
        raw_write(fd, p, CELL, (off_t)at); end = at + CELL;
    }
    assert(end <= UINT64_C(268435456));
    for (unsigned i = 0; i < 2; i++) { unsigned char *slot = f->p + i * CELL; mapped_ref(slot + 48, mapping, cells); put64(slot + 104, end); put64(slot + 144, UINT64_C(268435456)); slot_hash(slot); raw_write(fd, slot, CELL, i * CELL); }
    assert(!close(fd)); printf("{\"case\":\"symlink-sparse-eviction\",\"stored_cell_bytes\":%llu,\"logical_end\":%llu,\"filesystem_allocation_claim\":false}\n", (unsigned long long)(cells * CELL), (unsigned long long)end); fflush(stdout);
    free(mapping); free(f->p); f->p = NULL;
}
static int symlink_cancel_after_raw(void *context) {
    unsigned *fired = context;
    if (raw_hash_input >= 4132) { (*fired)++; return 1; }
    return 0;
}
static void memo_target_start(const unsigned char reference[56], uint64_t first_zero, int enabled) {
    assert(get32(reference) == 6 && get64(reference + 8) == 8192);
    memcpy(memo_target_reference, reference, 56); memo_target_first_zero = first_zero;
    memo_target_enabled = enabled; memo_target_passes = 0; memo_target_sequence = 0;
    memset(memo_target_pass, 0, sizeof(memo_target_pass)); memset(memo_target_fd, 0, sizeof(memo_target_fd));
    watch_payload(0, reference); watch_count = 1; watch_clear();
}
static void memo_target_check(unsigned passes, int rejected_first_link) {
    assert(memo_target_passes == passes);
    for (unsigned i = 0; i < passes; i++) {
        if (rejected_first_link) assert(!memo_target_pass[i].writes && !memo_target_pass[i].reloads);
        else assert(memo_target_pass[i].writes && memo_target_pass[i].reloads && memo_target_pass[i].first_write < memo_target_pass[i].first_reload);
        printf("{\"case\":\"target-raw-memo-pass\",\"pass\":%u,\"aux_fd\":%d,\"first_zero\":%llu,\"zero_loads\":%u,\"writes\":%u,\"reloads\":%u,\"write_sequence\":%llu,\"reload_sequence\":%llu,\"early_link_refusal\":%s}\n", i, memo_target_pass[i].fd,
               (unsigned long long)memo_target_first_zero, memo_target_pass[i].zero_loads, memo_target_pass[i].writes, memo_target_pass[i].reloads,
               (unsigned long long)memo_target_pass[i].first_write, (unsigned long long)memo_target_pass[i].first_reload, rejected_first_link ? "true" : "false");
    }
    fflush(stdout);
}
static void symlink_verify(void) {
    sfs_image *h; sfs_result r; sfs_recovery recovery;
    for (unsigned first = 0; first < 2; first++) for (unsigned bad = 0; bad < 2; bad++) {
        fixture f = symlink_graph(first, 0, bad); assert(symlink_guard(f.p, f.p, f.n)); fixture_save(&f);
        reset("", 0); clock_calls = 0;
        if (!bad) {
            open_image(&h); reset("", 0); symlink_full(h); assert(raw_hashes == 1 && raw_hash_input == 4132); counters("symlink-whole-extent-shared-valid");
            for (unsigned view = 0; view < 3; view++) { symlink_expect(h, view, first ? 2 : 3, "shared", 6); expect(h, view, first ? 3 : 2, "shared"); }
            close_image(h);
        } else {
            h = NULL; enum sfs_status status = sfs_image_inspect(root, "image", &h, &recovery, &generous, &r);
            assert(status == SFS_RECOVERY_REQUIRED && !h && r.phase == SFS_PHASE_READ && !r.system_errno && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT);
            assert(raw_hash_input == 2 * UINT64_C(4132)); image_unwritten(); receipt("symlink-interior-nul-both-orders", &r);
        }
        retain(1340 + (int)(first * 2 + bad));
    }
    /* Isolate link semantics: the other inode is an empty regular file, not a second damaged alias. */
    fixture f = symlink_graph(0, 0, 0); unsigned char *original = malloc(f.n); assert(original); memcpy(original, f.p, f.n);
    unsigned char *ns = namespace_at(f.p, f.p, f.n), *regular = leaf_row(f.p, ns + 64, 2, f.n, 440);
    put64(regular + 24, 0); memset(regular + 32, 0, 56); put64(regular + 432, 0); symlink_repair(f.p, original, f.n); free(original);
    size_t n = f.n; unsigned char *baseline = malloc(n); assert(baseline); memcpy(baseline, f.p, n); assert(symlink_guard(f.p, baseline, n)); fixture_save(&f);
    reset("", 0); open_image(&h); symlink_full(h); symlink_expect(h, 0, 3, "shared", 6); close_image(h); retain(1344);
    const char *cases[] = {"absent-extent", "extra-row", "block", "visible", "mapping-count", "suffix", "interior-nul", "digest", "domain"};
    for (unsigned kind = 0; kind < sizeof(cases) / sizeof(*cases); kind++) {
        unsigned char *p = malloc(n); assert(p); memcpy(p, baseline, n); ns = namespace_at(p, p, n);
        unsigned char *link = leaf_row(p, ns + 64, 3, n, 440), *extent = record(p, link + 32, n), *raw = record(p, extent + 648, n);
        if (kind == 0) memset(link + 32, 0, 56);
        else if (kind == 1) { memcpy(extent + 712, extent + 640, 72); put64(extent + 712, 1); put16(extent + 70, 2); big64(extent + 375, 1); }
        else if (kind == 2) { put64(extent + 640, 1); big64(extent + 112, 1); big64(extent + 375, 1); }
        else if (kind == 3) put16(extent + 704, 5);
        else if (kind == 4) put64(link + 432, 0);
        else if (kind == 5) raw[6] = 'X'; else if (kind == 6) raw[2] = 0;
        symlink_repair(p, baseline, n);
        /* The added row copies an independently digest-valid RAW reference; its framing is checked separately. */
        if (kind == 1) { unsigned char check[56]; memcpy(check, extent + 720, 56); ref_hash(p, check, n); assert(!memcmp(check, extent + 720, 56)); }
        assert(symlink_guard(p, baseline, n));
        if (kind == 7 || kind == 8) {
            /* Deliberately invalid digests/domain are distinct from semantic negatives. */
            if (kind == 7) raw[0] ^= 1;
            else {
                unsigned char domain[36]; memcpy(domain, "SFSDAT03", 8); memcpy(domain + 8, p + 24, 16); put32(domain + 24, 6); put64(domain + 28, CELL);
                CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c, domain, 36); CC_SHA256_Update(&c, raw, CELL); CC_SHA256_Final(extent + 672, &c);
                /* Hash metadata ancestors without repairing the intentional raw-domain mismatch. */
                ref_hash(p, link + 32, n); ref_hash(p, ns + 64, n);
                unsigned char *root_page = record(p, p + 48, n), *catalog = record(p, root_page + 120, n), *history = record(p, catalog + 648, n);
                memcpy(history + 64, ns + 64, 56);
                for (unsigned i = 0; i < 2; i++) ref_hash(p, catalog + 648 + i * 328, n);
                ref_hash(p, root_page + 64, n); ref_hash(p, root_page + 120, n);
                for (unsigned i = 0; i < 2; i++) { ref_hash(p, p + i * CELL + 48, n); slot_hash(p + i * CELL); }
            }
        }
        save("image", p, n); reset("", 0); h = NULL;
        enum sfs_status status = sfs_image_inspect(root, "image", &h, &recovery, &generous, &r);
        printf("{\"symlink_semantic_case\":\"%s\",\"digest_framing_valid\":%s,\"status\":%d,\"slot0\":%d,\"slot1\":%d}\n", cases[kind], kind < 7 ? "true" : "false", status, recovery.slots[0].status, recovery.slots[1].status); fflush(stdout);
        assert(status == SFS_RECOVERY_REQUIRED && !h && r.phase == SFS_PHASE_READ && !r.system_errno && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT);
        image_unwritten(); unchanged("image", p, n);
        if (kind == 5 || kind == 6) {
            reset("", 0); open_image(&h); unsigned char out[8], canary[8]; memset(canary, 0xA5, sizeof(canary)); memcpy(out, canary, sizeof(out)); size_t count = 99;
            assert(sfs_image_readlink(h, 0, 3, out, sizeof(out), &count, &r) == SFS_CORRUPT && !count && !memcmp(out, canary, sizeof(out)));
            assert(r.phase == SFS_PHASE_READ && !r.system_errno && sfs_image_begin(h, &r) == SFS_POISONED); image_unwritten(); close_image(h); unchanged("image", p, n);
        }
        free(p); retain(1345 + (int)kind);
    }
    free(baseline);
    /* Distinct raw and metadata counters, controlled stops and fatal-before-budget behavior. */
    f = symlink_graph(0, 0, 0); fixture_save(&f); reset("", 0); open_image(&h);
    for (unsigned cap = 0; cap < 3; cap++) {
        sfs_verify_budget budget = generous; unsigned polls = 0;
        if (cap == 0) budget.raw_cells = 1; else if (cap == 1) budget.checks = 1; else { budget.cancelled = cancel_now; budget.context = &polls; }
        reset("", 0); enum sfs_status status = sfs_image_verify(h, &budget, &r);
        if (!cap) { ok(status, &r); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && raw_hash_input == 4132 && raw_hashes == 1); }
        else { assert(status == SFS_INCOMPLETE && !r.system_errno && r.coverage != SFS_COVERAGE_FULL_REACHABLE && r.incomplete_reason == (cap == 1 ? SFS_INCOMPLETE_CHECKS : SFS_INCOMPLETE_CANCELLED)); if (cap == 2) assert(polls); }
        image_unwritten(); counters("symlink-controlled-verification");
    }
    OK(sfs_image_begin(h, &r)); sfs_verify_budget budget = generous; budget.metadata_read_bytes = CELL; reset("slot_reads", 1);
    assert(sfs_image_verify(h, &budget, &r) == SFS_IO && hit && r.phase == SFS_PHASE_READ && r.system_errno == EIO); assert(sfs_image_commit(h, &r) == SFS_POISONED); reset("", 0); close_image(h); retain(1360);
    /* The first link exposes NUL immediately after hashing; no later cancellation may mask it. */
    f = symlink_graph(1, 0, 1); fixture_save(&f); reset("", 0); open_image(&h); unsigned fired = 0;
    budget = generous; budget.cancelled = symlink_cancel_after_raw; budget.context = &fired; reset("", 0);
    assert(sfs_image_verify(h, &budget, &r) == SFS_CORRUPT && !r.system_errno && raw_hash_input == 4132 && !fired);
    assert(sfs_image_begin(h, &r) == SFS_POISONED); image_unwritten(); close_image(h); retain(1370);
    /* Reuse the established 1201-leaf eviction size and <=256MiB sparse address bound. */
    for (unsigned first = 0; first < 2; first++) for (unsigned sparse = 0; sparse < 2; sparse++) {
        f = symlink_graph(first, 1, 0);
        unsigned char target_ref[56], *space = namespace_at(f.p, f.p, f.n);
        unsigned char *link_extent = record(f.p, leaf_row(f.p, space + 64, first ? 2 : 3, f.n, 440) + 32, f.n);
        memcpy(target_ref, link_extent + 648, 56);
        assert(get16(record(f.p, leaf_row(f.p, space + 64, first ? 3 : 2, f.n, 440) + 32, f.n) + 68) > 0);
        assert(symlink_guard(f.p, f.p, f.n));
        if (sparse) symlink_sparse_save(&f); else fixture_save(&f);
        uint64_t length; unsigned char before[32], after[32]; file_digest("image", before, &length); assert(length <= UINT64_C(268435456));
        struct stat identity, after_identity; assert(!lstat("image", &identity));
        reset("", 0); open_image(&h); reset("", 0); memo_target_start(target_ref, 6, (int)sparse); symlink_full(h);
        assert(raw_hash_input == 8264 && raw_hashes == 2 && watch_bytes[0] == CELL && watch_reads[0] == 1 && metadata_hash_input > 4194304);
        if (sparse) { assert(aux_write_calls && aux_write_bytes && aux_read_bytes); memo_target_check(1, 0); }
        counters("symlink-shared-raw-eviction"); memo_target_enabled = 0;
        symlink_expect(h, 0, first ? 2 : 3, "shared", 6); symlink_expect(h, 2, first ? 2 : 3, "shared", 6);
        /* A fresh verification must fetch/hash the shared raw again, not trust any handle memo. */
        reset("", 0); memo_target_start(target_ref, 6, (int)sparse); symlink_full(h);
        assert(raw_hash_input == 8264 && raw_hashes == 2 && watch_bytes[0] == CELL && watch_reads[0] == 1);
        if (sparse) memo_target_check(1, 0); memo_target_enabled = 0;
        uint64_t after_length; file_digest("image", after, &after_length); assert(after_length == length && !memcmp(before, after, 32));
        assert(!lstat("image", &after_identity)); identical_identity(&identity, &after_identity);
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); unsigned char changed = 'X'; raw_write(fd, &changed, 1, 8192); assert(!close(fd));
        reset("", 0); assert(sfs_image_verify(h, &generous, &r) == SFS_CORRUPT && raw_hash_input == 4132 && raw_hashes == 1);
        assert(sfs_image_begin(h, &r) == SFS_POISONED); image_unwritten(); close_image(h); retain(1361 + (int)(first * 2 + sparse));
        /* Regular-first NUL is rejected after target reload; link-first correctly rejects before eviction. */
        f = symlink_graph(first, 1, 1); space = namespace_at(f.p, f.p, f.n);
        link_extent = record(f.p, leaf_row(f.p, space + 64, first ? 2 : 3, f.n, 440) + 32, f.n); memcpy(target_ref, link_extent + 648, 56);
        assert(symlink_guard(f.p, f.p, f.n));
        if (sparse) symlink_sparse_save(&f); else fixture_save(&f);
        reset("", 0); memo_target_start(target_ref, 2, (int)sparse); h = NULL;
        enum sfs_status status = sfs_image_inspect(root, "image", &h, &recovery, &generous, &r);
        assert(status == SFS_RECOVERY_REQUIRED && !h && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT);
        assert(r.phase == SFS_PHASE_READ && !r.system_errno && watch_bytes[0] == 2 * CELL && watch_reads[0] == 2);
        assert(raw_hashes == (first ? 2u : 4u) && raw_hash_input == (first ? 8264u : 16528u));
        if (sparse) memo_target_check(2, (int)first);
        memo_target_enabled = 0; watch_count = 0; image_unwritten(); retain(1365 + (int)(first * 2 + sparse));
    }
}

/* Opaque attribute bytes have no path or resource-fork interpretation. */
#define XEXPECT(call, wanted) do { enum sfs_status actual_status = (call); assert(actual_status == (wanted) && r.status == actual_status); } while (0)
static void xattr_create(sfs_image **h, uint64_t capacity) {
    sfs_result r; sfs_metadata_initial in = metadata_input(SFS_DIRECTORY); reset("", 0); metadata_clock(600);
    XEXPECT(sfs_image_create_metadata_version(root, "image", capacity, 5, &in, h, &r), SFS_OK);
    assert(clock_calls == 1 && r.coverage == SFS_COVERAGE_FULL_REACHABLE);
}
static sfs_result xattr_binding(sfs_image *h) {
    sfs_result r; sfs_entry e; XEXPECT(sfs_image_stat(h, 0, 1, &e, &r), SFS_OK); return r;
}
static void xattr_expect(sfs_image *h, sfs_view view, sfs_inode owner, const void *name, size_t length, const void *value, size_t n) {
    sfs_result r; uint64_t size = UINT64_MAX; unsigned calls = clock_calls;
    XEXPECT(sfs_image_xattr_size(h, view, owner, name, length, &size, &r), SFS_OK);
    assert(size == n && r.coverage == SFS_COVERAGE_TOUCHED);
    unsigned char *out = malloc(n + 3); assert(out); memset(out, 0xA5, n + 3); size_t got = SIZE_MAX;
    XEXPECT(sfs_image_read_xattr(h, view, owner, name, length, 0, out + 1, n + 1, &got, &r), SFS_OK);
    assert(got == n && (!n || !memcmp(out + 1, value, n)) && out[0] == 0xA5 && out[n + 1] == 0xA5 && out[n + 2] == 0xA5);
    assert(r.coverage == SFS_COVERAGE_TOUCHED && clock_calls == calls); free(out);
}
static void xattr_absent(sfs_image *h, sfs_view view, sfs_inode owner, const char *name) {
    sfs_result r; uint64_t size = UINT64_MAX; unsigned char out[8], canary[8]; memset(canary, 0xA5, sizeof(canary)); memcpy(out, canary, sizeof(out)); size_t got = 99;
    XEXPECT(sfs_image_xattr_size(h, view, owner, name, strlen(name), &size, &r), SFS_NOT_FOUND); assert(size == UINT64_MAX && !r.system_errno);
    XEXPECT(sfs_image_read_xattr(h, view, owner, name, strlen(name), 0, out, sizeof(out), &got, &r), SFS_NOT_FOUND);
    assert(!got && !memcmp(out, canary, sizeof(out)) && !r.system_errno);
}
static void xattr_versions(void) {
    sfs_image *h; sfs_result r; sfs_metadata_initial in = metadata_input(SFS_DIRECTORY);
    for (unsigned minor = 2; minor < 5; minor++) {
        reset("", 0); metadata_clock(601);
        if (minor == 2) XEXPECT(sfs_image_create(root, "image", TEST_CAPACITY, &h, &r), SFS_OK);
        else if (minor == 3) XEXPECT(sfs_image_create_metadata(root, "image", TEST_CAPACITY, &in, &h, &r), SFS_OK);
        else XEXPECT(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, minor, &in, &h, &r), SFS_OK);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode id = add(h, 1, "file", SFS_FILE);
        XEXPECT(sfs_image_write(h, id, 0, "before", 6, &r), SFS_OK); metadata_commit(h);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, id, 0, "pending", 7, &r), SFS_OK);
        size_t n; unsigned char *before = bytes("image", &n); sfs_result binding = xattr_binding(h); reset("", 0); clock_calls = 0;
        uint64_t size = UINT64_MAX; size_t got = 99; unsigned char out[8]; memset(out, 0xA5, sizeof(out));
        sfs_xattr_entry entry, canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary; int found = 99;
        XEXPECT(sfs_image_set_xattr(h, id, "key", 3, "value", 5, &r), SFS_UNSUPPORTED);
        assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
        XEXPECT(sfs_image_remove_xattr(h, id, "key", 3, &r), SFS_UNSUPPORTED); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
        XEXPECT(sfs_image_xattr_size(h, 0, id, "key", 3, &size, &r), SFS_UNSUPPORTED); assert(size == UINT64_MAX && r.phase == SFS_PHASE_NONE && !r.system_errno);
        XEXPECT(sfs_image_read_xattr(h, 0, id, "key", 3, 0, out, sizeof(out), &got, &r), SFS_UNSUPPORTED); assert(!got && r.phase == SFS_PHASE_NONE && !r.system_errno);
        XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, id, NULL, 0, &entry, &found, &r), SFS_UNSUPPORTED);
        assert(found == 99 && !memcmp(&entry, &canary, sizeof(entry)) && r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
        for (unsigned i = 0; i < sizeof(out); i++) assert(out[i] == 0xA5); image_unwritten(); unchanged("image", before, n); free(before);
        metadata_commit(h); expect(h, 0, id, "pending"); close_image(h); open_image(&h); expect(h, 0, id, "pending"); close_image(h);
        before = bytes("image", &n); assert(get32(before + 12) == minor && get32(before + CELL + 12) == minor); free(before); retain(2000 + (int)minor);
    }
    reset("", 0); metadata_clock(602); h = (sfs_image *)(uintptr_t)1; uint64_t allocations_before = allocation_calls;
    XEXPECT(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, 7, &in, &h, &r), SFS_UNSUPPORTED);
    assert(!h && !clock_calls && allocation_calls == allocations_before && r.phase == SFS_PHASE_NONE && !r.system_errno && access("image", F_OK) < 0 && errno == ENOENT); image_unwritten();
    xattr_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    XEXPECT(sfs_image_set_xattr(h, 1, "root", 4, NULL, 0, &r), SFS_OK); metadata_commit(h); xattr_expect(h, 0, 1, "root", 4, NULL, 0); symlink_full(h);
    size_t n; unsigned char *p = bytes("image", &n), *space = namespace_at(p, selected_slot(p), n), *attributes = record(p, space + 280, n);
    assert(get32(p + 12) == 5 && !memcmp(space, "SFSREC05", 8) && !get64(space + 184) && get32(attributes + 64) == 5 && get16(attributes + 70) == 1);
    assert(get64(attributes + 640) == 1 && get32(attributes + 648) == 4 && !memcmp(attributes + 652, "root", 4) && !get64(attributes + 912) && !get32(attributes + 920) && !get64(attributes + 976)); free(p);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode link = symlink_add(h, 1, "link", "../opaque", 9); metadata_commit(h); symlink_expect(h, 0, link, "../opaque", 9); xattr_expect(h, 0, 1, "root", 4, NULL, 0); symlink_full(h); close_image(h); retain(2005);
    fixture f = indexed_fixture_version(2, 1, 0, 4); unsigned char old_slot[CELL]; memcpy(old_slot, f.p, CELL);
    f.minor = 5; fixture_node empty = {0}, ns = namespace_cell(&f, empty, empty, 2, 0); finish_fixture(&f, ns, empty); memcpy(f.p, old_slot, CELL); fixture_save(&f);
    reset("", 0); h = NULL; XEXPECT(sfs_image_open(root, "image", &h, &r), SFS_RECOVERY_REQUIRED); assert(!h); image_unwritten();
    sfs_recovery recovery; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    assert(!recovery.pair_valid && recovery.slots[0].status == SFS_OK && recovery.slots[1].status == SFS_OK);
    for (unsigned slot = 0; slot < 2; slot++) { assert(recovery.slots[slot].coverage == SFS_COVERAGE_FULL_REACHABLE); XEXPECT(sfs_image_select(h, slot, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); }
    close_image(h); retain(2006);
    f = indexed_fixture_version(2, 1, 0, 5); put32(f.p + 12, 4); put32(f.p + CELL + 12, 4); slot_hash(f.p); slot_hash(f.p + CELL); fixture_save(&f);
    reset("", 0); h = NULL; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED);
    assert(!h && r.phase == SFS_PHASE_READ && !r.system_errno && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT); image_unwritten();
}
typedef struct { const unsigned char *name; size_t n; } xattr_name;
static int xattr_name_order(const void *left, const void *right) {
    const xattr_name *a = left, *b = right; size_t n = a->n < b->n ? a->n : b->n; int order = memcmp(a->name, b->name, n);
    return order ? order : a->n < b->n ? -1 : a->n > b->n;
}
static void xattr_values(void) {
    sfs_image *h; sfs_result r; xattr_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    sfs_inode neighbor = add(h, 1, "neighbor", SFS_FILE);
    static const unsigned char user[] = "user attribute\0\xff", fork[] = "resource\0fork\xff", binary_name[] = {0xFF, '/', 0x80};
    unsigned char longest[255]; memset(longest, 0x7F, sizeof(longest));
    xattr_name names[] = {{(const unsigned char *)"user.stallionfs-test", sizeof("user.stallionfs-test") - 1}, {(const unsigned char *)"com.apple.ResourceFork", 22}, {(const unsigned char *)".", 1}, {(const unsigned char *)"..", 2}, {(const unsigned char *)"/", 1}, {(const unsigned char *)"A", 1}, {(const unsigned char *)"a", 1}, {binary_name, sizeof(binary_name)}, {longest, sizeof(longest)}};
    for (unsigned i = 0; i < sizeof(names) / sizeof(*names); i++) XEXPECT(sfs_image_set_xattr(h, 1, names[i].name, names[i].n, NULL, 0, &r), SFS_OK);
    XEXPECT(sfs_image_set_xattr(h, 1, names[0].name, names[0].n, user, sizeof(user) - 1, &r), SFS_OK);
    XEXPECT(sfs_image_set_xattr(h, 1, names[1].name, names[1].n, fork, sizeof(fork) - 1, &r), SFS_OK);
    XEXPECT(sfs_image_set_xattr(h, neighbor, "other-owner", 11, "neighbor", 8, &r), SFS_OK); metadata_commit(h);
    xattr_expect(h, 0, 1, names[0].name, names[0].n, user, sizeof(user) - 1); xattr_expect(h, 0, 1, names[1].name, names[1].n, fork, sizeof(fork) - 1);
    for (unsigned i = 2; i < sizeof(names) / sizeof(*names); i++) xattr_expect(h, 0, 1, names[i].name, names[i].n, NULL, 0);
    qsort(names, sizeof(names) / sizeof(*names), sizeof(*names), xattr_name_order); sfs_result binding = xattr_binding(h);
    for (unsigned i = 0; i <= sizeof(names) / sizeof(*names); i++) {
        sfs_xattr_entry entry, canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary; int found = 99;
        XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, i ? names[i - 1].name : NULL, i ? names[i - 1].n : 0, &entry, &found, &r), SFS_OK);
        if (i == sizeof(names) / sizeof(*names)) assert(!found && !memcmp(&entry, &canary, sizeof(entry)));
        else assert(found == 1 && entry.name_length == names[i].n && !memcmp(entry.name, names[i].name, names[i].n));
        assert(r.coverage == SFS_COVERAGE_TOUCHED);
    }
    sfs_xattr_entry entry; int found; XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, "Z", 1, &entry, &found, &r), SFS_OK);
    assert(found == 1 && entry.name_length == 1 && entry.name[0] == 'a');
    const size_t lengths[] = {4095, 4096, 4097, 65537};
    for (unsigned which = 0; which < 4; which++) {
        size_t n = lengths[which]; unsigned char *value = malloc(n), *out = malloc(n + 2); assert(value && out);
        for (size_t i = 0; i < n; i++) value[i] = (unsigned char)(i * 73 + 19);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(650 + which); XEXPECT(sfs_image_set_xattr(h, 1, "range", 5, value, n, &r), SFS_OK); assert(clock_calls == 1); metadata_commit(h); xattr_expect(h, 0, 1, "range", 5, value, n);
        const uint64_t offsets[] = {0, 4094, 4096, n, n + 1};
        for (unsigned j = 0; j < 5; j++) {
            size_t capacity = j == 0 ? 0 : 7, got = 99; memset(out, 0xA5, n + 2);
            XEXPECT(sfs_image_read_xattr(h, 0, 1, "range", 5, offsets[j], capacity ? out + 1 : NULL, capacity, &got, &r), SFS_OK);
            size_t expected = offsets[j] >= n ? 0 : n - (size_t)offsets[j]; if (expected > capacity) expected = capacity;
            assert(got == expected && (!got || !memcmp(out + 1, value + offsets[j], got)) && out[0] == 0xA5 && out[expected + 1] == 0xA5);
        }
        free(value); free(out);
    }
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); reset("", 0); clock_calls = 0;
    unsigned char invalid_name[256]; memset(invalid_name, 'n', sizeof(invalid_name)); const unsigned char nul_name[] = {'a', 0, 'b'};
    const void *bad_names[] = {NULL, "", invalid_name, nul_name}; const size_t bad_lengths[] = {1, 0, sizeof(invalid_name), sizeof(nul_name)};
    for (unsigned i = 0; i < 4; i++) {
        uint64_t size = UINT64_MAX; size_t got = 99; unsigned char out[8]; memset(out, 0xA5, sizeof(out));
        XEXPECT(sfs_image_set_xattr(h, 1, bad_names[i], bad_lengths[i], "x", 1, &r), SFS_INVALID); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
        XEXPECT(sfs_image_remove_xattr(h, 1, bad_names[i], bad_lengths[i], &r), SFS_INVALID);
        XEXPECT(sfs_image_xattr_size(h, 0, 1, bad_names[i], bad_lengths[i], &size, &r), SFS_INVALID); assert(size == UINT64_MAX);
        XEXPECT(sfs_image_read_xattr(h, 0, 1, bad_names[i], bad_lengths[i], 0, out, sizeof(out), &got, &r), SFS_INVALID); assert(got == 99);
    }
    uint64_t size = UINT64_MAX; size_t got = 99; unsigned char out[8]; memset(out, 0xA5, sizeof(out));
    XEXPECT(sfs_image_set_xattr(h, 1, "key", 3, NULL, 1, &r), SFS_INVALID);
    XEXPECT(sfs_image_xattr_size(h, 0, 1, "range", 5, NULL, &r), SFS_INVALID);
    XEXPECT(sfs_image_read_xattr(h, 0, 1, "range", 5, UINT64_MAX, out, 1, &got, &r), SFS_INVALID); assert(got == 99);
    XEXPECT(sfs_image_read_xattr(h, 0, 1, "range", 5, 0, NULL, 1, &got, &r), SFS_INVALID); assert(got == 99);
    XEXPECT(sfs_image_read_xattr(h, 0, 1, "range", 5, 0, out, sizeof(out), NULL, &r), SFS_INVALID);
    sfs_xattr_entry canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary; found = 99; binding = xattr_binding(h);
    XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, NULL, 1, &entry, &found, &r), SFS_INVALID);
    assert(found == 99 && !memcmp(&entry, &canary, sizeof(entry)) && size == UINT64_MAX && !clock_calls);
    XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, NULL, 0, NULL, &found, &r), SFS_INVALID); assert(found == 99);
    XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, NULL, 0, &entry, NULL, &r), SFS_INVALID); assert(!memcmp(&entry, &canary, sizeof(entry)));
    XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, NULL, 1, NULL, 0, &entry, &found, &r), SFS_INVALID); assert(found == 99 && !memcmp(&entry, &canary, sizeof(entry)));
    for (unsigned missing = 0; missing < 2; missing++) {
        sfs_view view = missing ? 32 : 0; sfs_inode owner = missing ? 1 : UINT64_MAX; got = 99;
        XEXPECT(sfs_image_xattr_size(h, view, owner, "range", 5, &size, &r), SFS_NOT_FOUND); assert(size == UINT64_MAX);
        XEXPECT(sfs_image_read_xattr(h, view, owner, "range", 5, 0, out, sizeof(out), &got, &r), SFS_NOT_FOUND); assert(!got);
        XEXPECT(sfs_image_next_xattr(h, view, binding.generation, binding.root_digest, owner, NULL, 0, &entry, &found, &r), SFS_NOT_FOUND); assert(found == 99 && !memcmp(&entry, &canary, sizeof(entry)));
    }
    assert(sfs_image_set_xattr(h, 1, NULL, 1, "x", 1, NULL) == SFS_INVALID);
    assert(sfs_image_remove_xattr(h, 1, "missing", 7, NULL) == SFS_NOT_FOUND && !clock_calls);
    assert(sfs_image_xattr_size(h, 0, 1, "missing", 7, &size, NULL) == SFS_NOT_FOUND && size == UINT64_MAX);
    got = 99; assert(sfs_image_read_xattr(h, 0, 1, "missing", 7, 0, out, sizeof(out), &got, NULL) == SFS_NOT_FOUND && !got);
    assert(sfs_image_next_xattr(h, 0, binding.generation + 1, binding.root_digest, 1, NULL, 0, &entry, &found, NULL) == SFS_STATE && found == 99 && !memcmp(&entry, &canary, sizeof(entry)));
    for (unsigned i = 0; i < sizeof(out); i++) assert(out[i] == 0xA5); image_unwritten();
    assert(sfs_image_set_xattr(h, 1, "null-result", 11, NULL, 0, NULL) == SFS_OK); metadata_commit(h);
    assert(sfs_image_xattr_size(h, 0, 1, "null-result", 11, &size, NULL) == SFS_OK && !size);
    got = 99; assert(sfs_image_read_xattr(h, 0, 1, "null-result", 11, 0, out, sizeof(out), &got, NULL) == SFS_OK && !got);
    binding = xattr_binding(h); found = 99; assert(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 1, "null-resuls", 11, &entry, &found, NULL) == SFS_OK && found == 1 && entry.name_length == 11 && !memcmp(entry.name, "null-result", 11));
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); assert(sfs_image_remove_xattr(h, 1, "null-result", 11, NULL) == SFS_OK); metadata_commit(h); xattr_absent(h, 0, 1, "null-result"); symlink_full(h); close_image(h);
}
/* Independent0.5 namespaces add exactly one attribute root at byte280. */
static fixture_node xattr_space(fixture *f, fixture_node inodes, fixture_node names, fixture_node attrs, uint64_t next, uint64_t count) {
    unsigned char p[CELL]; envelope(f, p, 2); memcpy(p + 64, inodes.ref, 56); memcpy(p + 120, names.ref, 56);
    put64(p + 176, next); put64(p + 184, count); fixture_tuple(p + 192, SFS_DIRECTORY, 0); memcpy(p + 280, attrs.ref, 56); return append_cell(f, 2, p);
}
static void xattr_row(unsigned char *row, uint64_t owner, const void *name, size_t n, uint64_t size, const unsigned char *extent, uint64_t count) {
    assert(n && n <= 255); memset(row, 0, 352); put64(row, owner); put32(row + 8, (uint32_t)n); memcpy(row + 12, name, n);
    put64(row + 272, size); if (extent) memcpy(row + 280, extent, 56); put64(row + 336, count);
}
static fixture xattr_fixture(unsigned rows, unsigned primary, unsigned snapshots) {
    assert(rows == 1 || rows == 3); fixture f = fixture_start(); f.minor = 5; put32(f.p + 12, 5);
    unsigned char raw[CELL] = {0}; memcpy(raw, "shared", 6); fixture_node data = append_cell(&f, 6, raw);
    unsigned char extents[216] = {0};
    for (unsigned i = 0; i < rows; i++) { put64(extents + i * 72, i); memcpy(extents + i * 72 + 8, data.ref, 56); put16(extents + i * 72 + 64, i + 1 == rows ? 6 : CELL); }
    fixture_node extent = tree(&f, 3, extents, rows); uint64_t size = (rows - 1) * (uint64_t)CELL + 6;
    unsigned char inodes[880] = {0}, names[560] = {0};
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *a = inodes + i * 440, *b = names + i * 280; put64(a, i ? 4 : 2); put64(a + 8, 1); put32(a + 16, SFS_FILE); put32(a + 20, 1); a[88] = (unsigned char)('a' + i);
        if (primary & (1u << i)) { put64(a + 24, size); memcpy(a + 32, extent.ref, 56); }
        fixture_tuple(a + 352, SFS_FILE, primary & (1u << i) ? rows : 0);
        put64(b, 1); put32(b + 8, 1); b[12] = (unsigned char)('a' + i); put64(b + 267, i ? 4 : 2);
    }
    fixture_node ir = tree(&f, 1, inodes, 2), nr = tree(&f, 2, names, 2); unsigned char row[352]; xattr_row(row, 2, "key", 3, size, extent.ref, rows);
    fixture_node attrs = tree(&f, 5, row, 1), history = xattr_space(&f, ir, nr, attrs, 5, 2), catalog = {0};
    if (snapshots) {
        assert(snapshots <= 2); unsigned char sr[656] = {0};
        for (unsigned i = 0; i < snapshots; i++) { put32(sr + i * 328, i + 1); memcpy(sr + i * 328 + 8, history.ref, 56); put32(sr + i * 328 + 64, 1); sr[i * 328 + 68] = (unsigned char)('x' + i); }
        catalog = tree(&f, 4, sr, snapshots);
    }
    fixture_node current = xattr_space(&f, ir, nr, attrs, 5, 2); finish_fixture(&f, current, catalog); return f;
}
static unsigned xattr_stride(unsigned map, unsigned level) {
    if (level) return map == 2 || map == 5 ? 328 : 72;
    return map == 1 ? 440 : map == 2 ? 280 : map == 3 ? 72 : map == 4 ? 328 : 352;
}
static unsigned xattr_edge(unsigned map, unsigned level) { return level ? (map == 2 || map == 5 ? 271 : 16) : map == 1 ? 32 : map == 5 ? 280 : 8; }
static void xattr_fences(unsigned char *p, unsigned char *cell, unsigned map, unsigned level, size_t n) {
    unsigned count = get16(cell + 70); assert(count && count <= 48); unsigned stride = xattr_stride(map, level); unsigned char low[263] = {0}, high[263] = {0}; uint16_t lo, hi;
    if (level) {
        unsigned edge = xattr_edge(map, level); unsigned char *first = record(p, cell + 640 + edge, n), *last = record(p, cell + 640 + (count - 1) * stride + edge, n);
        lo = get16(first + 88); hi = get16(last + 90); assert(lo <= 263 && hi <= 263); memcpy(low, first + 112, lo); memcpy(high, last + 375, hi);
    } else { row_key(map, cell + 640, low, &lo); row_key(map, cell + 640 + (count - 1) * stride, high, &hi); }
    put16(cell + 88, lo); put16(cell + 90, hi); memset(cell + 112, 0, 526); memcpy(cell + 112, low, lo); memcpy(cell + 375, high, hi);
}
/* All reachable aliases are repaired using the untouched graph's edges, never a semantic parser. */
static void xattr_repair_ref(unsigned char *p, const unsigned char *old_image, unsigned char *ref, const unsigned char *old_ref, size_t n, unsigned depth, int raw_hashes_too) {
    assert(depth < 32); if (!get32(ref)) { assert(!memcmp(ref, (unsigned char[56]){0}, 56)); return; }
    assert(!memcmp(ref, old_ref, 24)); unsigned char *cell = record(p, ref, n); const unsigned char *old = record((unsigned char *)old_image, old_ref, n); unsigned type = get32(ref);
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) xattr_repair_ref(p, old_image, cell + 64 + i * 56, old + 64 + i * 56, n, depth + 1, raw_hashes_too);
    if (type == 2) xattr_repair_ref(p, old_image, cell + 280, old + 280, n, depth + 1, raw_hashes_too);
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = xattr_stride(map, level), edge = xattr_edge(map, level);
        for (unsigned i = 0; i < count; i++) if (level || map != 2) xattr_repair_ref(p, old_image, cell + 640 + i * stride + edge, old + 640 + i * stride + edge, n, depth + 1, raw_hashes_too);
        xattr_fences(p, cell, map, level, n);
    }
    if (type != 6 || raw_hashes_too) ref_hash(p, ref, n);
}
static void xattr_repair(unsigned char *p, const unsigned char *original, size_t n) {
    for (unsigned i = 0; i < 2; i++) { xattr_repair_ref(p, original, p + i * CELL + 48, original + i * CELL + 48, n, 0, 1); slot_hash(p + i * CELL); }
}
static void xattr_repair_metadata(unsigned char *p, const unsigned char *original, size_t n) {
    for (unsigned i = 0; i < 2; i++) { xattr_repair_ref(p, original, p + i * CELL + 48, original + i * CELL + 48, n, 0, 0); slot_hash(p + i * CELL); }
}
static int xattr_key_compare(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int order = memcmp(a, b, an < bn ? an : bn); return order ? order : an < bn ? -1 : an > bn;
}
/* Digest/framing/order/context only: not owner existence, density, time or name policy. */
static int xattr_ref_guard(unsigned char *p, const unsigned char *old_image, const unsigned char *ref, const unsigned char *old_ref, size_t n, uint64_t parent, unsigned depth) {
    if (!get32(ref)) return !memcmp(ref, (unsigned char[56]){0}, 56);
    if (depth >= 32 || memcmp(ref, old_ref, 24)) return 0; uint64_t at = get64(ref + 8); unsigned type = get32(ref);
    if (at < 8192 || at % CELL || at >= parent || at > n || CELL > n - at || get64(ref + 16) != CELL || get32(ref + 4)) return 0;
    unsigned char checked[56]; memcpy(checked, ref, 56); ref_hash(p, checked, n); if (memcmp(checked + 24, ref + 24, 32)) return 0;
    unsigned char *cell = p + at; const unsigned char *old = old_image + at;
    if (type != 6 && (memcmp(cell, "SFSREC05", 8) || get32(cell + 8) != type || get32(cell + 12) || get64(cell + 16) != 4032 || memcmp(cell + 24, p + 24, 16) || memcmp(cell + 40, (unsigned char[24]){0}, 24))) return 0;
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) if (!xattr_ref_guard(p, old_image, cell + 64 + i * 56, old + 64 + i * 56, n, at, depth + 1)) return 0;
    if (type == 2 && !xattr_ref_guard(p, old_image, cell + 280, old + 280, n, at, depth + 1)) return 0;
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = xattr_stride(map, level), edge = xattr_edge(map, level);
        if (get16(cell + 68) != level) return 0;
        for (unsigned i = 0; i < count; i++) {
            const unsigned char *child_ref = cell + 640 + i * stride + edge;
            if ((level || map != 2) && !xattr_ref_guard(p, old_image, child_ref, old + 640 + i * stride + edge, n, at, depth + 1)) return 0;
            if (level) {
                unsigned char *child = record(p, child_ref, n); const unsigned char *key = cell + 640 + i * stride + 8; unsigned key_n = get32(cell + 640 + i * stride);
                if (get32(child + 64) != get32(cell + 64) || (unsigned)get16(child + 68) + 1 != level || key_n != get16(child + 88) || memcmp(key, child + 112, key_n)) return 0;
                if (i) { unsigned char *previous = record(p, cell + 640 + (i - 1) * stride + edge, n); if (xattr_key_compare(previous + 375, get16(previous + 90), child + 112, get16(child + 88)) >= 0) return 0; }
            }
        }
        unsigned actual = get16(cell + 70); if (!actual || actual > 48) return 0;
        unsigned char low[263], high[263]; uint16_t lo, hi;
        if (level) { unsigned char *first = record(p, cell + 640 + edge, n), *last = record(p, cell + 640 + (actual - 1) * stride + edge, n); lo = get16(first + 88); hi = get16(last + 90); memcpy(low, first + 112, lo); memcpy(high, last + 375, hi); }
        else { row_key(map, cell + 640, low, &lo); row_key(map, cell + 640 + (actual - 1) * stride, high, &hi); }
        if (get16(cell + 88) != lo || get16(cell + 90) != hi || memcmp(cell + 112, low, lo) || memcmp(cell + 375, high, hi)) return 0;
    }
    return 1;
}
static int xattr_guard(unsigned char *p, const unsigned char *original, size_t n) {
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *slot = p + i * CELL, checked[CELL]; memcpy(checked, slot, CELL); slot_hash(checked);
        if (memcmp(slot, "SFSIMG01", 8) || get32(slot + 8) || get32(slot + 12) != 5 || get64(slot + 16) || memcmp(checked + 112, slot + 112, 32)) return 0;
        if (!xattr_ref_guard(p, original, slot + 48, original + i * CELL + 48, n, get64(slot + 104), 0)) return 0;
    }
    return 1;
}
static fixture_node xattr_minimum_tree(fixture *f, const unsigned char *rows, unsigned count) {
    assert(count == 3078); unsigned groups = 1026, at = 0; fixture_node *nodes = calloc(groups, sizeof(*nodes)); assert(nodes);
    for (unsigned i = 0; i < groups; i++) { nodes[i] = page(f, 5, 0, rows + at * 352, 3, 352, NULL); at += 3; }
    unsigned level = 0; const unsigned expected[] = {114, 13, 2, 1};
    while (groups > 1) {
        unsigned parents = (groups + 8) / 9, used = 0; assert(parents == expected[level]); level++;
        for (unsigned i = 0; i < parents; i++) { unsigned size = groups / parents + (i < groups % parents); assert(size >= (parents == 1 ? 2u : 3u) && size <= 9); nodes[i] = page(f, 5, level, NULL, size, 328, nodes + used); used += size; }
        groups = parents;
    }
    fixture_node root_node = nodes[0]; assert(root_node.level == 4); free(nodes); return root_node;
}
static fixture xattr_prefix_fixture(void) {
    fixture f = fixture_start(); f.minor = 5; f.capacity = UINT64_C(268435456); put32(f.p + 12, 5);
    unsigned char inodes[880] = {0}, names[560] = {0};
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *a = inodes + i * 440, *b = names + i * 280; put64(a, i ? 4 : 2); put64(a + 8, 1); put32(a + 16, SFS_FILE); put32(a + 20, 1); a[88] = (unsigned char)('a' + i); fixture_tuple(a + 352, SFS_FILE, 0);
        put64(b, 1); put32(b + 8, 1); b[12] = (unsigned char)('a' + i); put64(b + 267, i ? 4 : 2);
    }
    fixture_node ir = tree(&f, 1, inodes, 2), nr = tree(&f, 2, names, 2); unsigned char *rows = calloc(3078, 352); assert(rows);
    for (unsigned i = 0; i < 3078; i++) { char name[24]; int n = i < 3075 ? snprintf(name, sizeof(name), "attr-%04u", i) : snprintf(name, sizeof(name), "keep-%u", i - 3075); assert(n > 0); xattr_row(rows + i * 352, i < 3075 ? 2 : 4, name, (size_t)n, 0, NULL, 0); }
    size_t before = f.n; fixture_node attrs = xattr_minimum_tree(&f, rows, 3078); assert(f.n - before == 1156 * CELL); free(rows);
    fixture_node history = xattr_space(&f, ir, nr, attrs, 5, 2); unsigned char sr[328] = {0}; put32(sr, 1); memcpy(sr + 8, history.ref, 56); put32(sr + 64, 6); memcpy(sr + 68, "before", 6);
    fixture_node catalog = tree(&f, 4, sr, 1), current = xattr_space(&f, ir, nr, attrs, 5, 2); finish_fixture(&f, current, catalog);
    _Static_assert((UINT64_C(1164) + UINT64_C(3075) * 18 + 14) * CELL == UINT64_C(231538688), "prefix admission arithmetic");
    assert(f.n == 1164 * CELL && f.n < f.capacity); return f;
}
static void xattr_only_ctime(sfs_metadata_entry before, sfs_metadata_entry after, int64_t sample) {
    assert(timestamp_is(after.change, sample, (uint32_t)(sample + 1))); after.change = before.change; metadata_equal(&before, &after);
}
static void xattr_enumerate(sfs_image *h, sfs_view view, sfs_inode owner, const char *prefix, unsigned count) {
    sfs_result r, binding = xattr_binding(h); unsigned char previous[255]; size_t previous_n = 0;
    for (unsigned i = 0; i <= count; i++) {
        sfs_xattr_entry entry, canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary; int found = 99;
        XEXPECT(sfs_image_next_xattr(h, view, binding.generation, binding.root_digest, owner, previous_n ? previous : NULL, previous_n, &entry, &found, &r), SFS_OK);
        if (i == count) assert(!found && !memcmp(&entry, &canary, sizeof(entry)));
        else {
            char expected[32]; int n = !strcmp(prefix, "attr") ? snprintf(expected, sizeof(expected), "attr-%04u", i) : snprintf(expected, sizeof(expected), "keep-%u", i);
            assert(found == 1 && entry.size == 0 && entry.name_length == (size_t)n && !memcmp(entry.name, expected, (size_t)n));
            memcpy(previous, entry.name, entry.name_length); previous_n = entry.name_length;
        }
    }
}
static void xattr_namespace(void) {
    sfs_image *h; sfs_result r; xattr_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    sfs_inode p = add(h, 1, "p", SFS_DIRECTORY), q = add(h, 1, "q", SFS_DIRECTORY), file = add(h, p, "file", SFS_FILE), link = symlink_add(h, p, "link", "file", 4);
    XEXPECT(sfs_image_write(h, file, 0, "primary", 7, &r), SFS_OK); metadata_commit(h);
    const sfs_inode owners[] = {1, p, file, link}; const char *values[] = {"root-value", "dir-value", "file-value", "link-value"};
    sfs_metadata_entry old[4]; for (unsigned i = 0; i < 4; i++) old[i] = metadata_get(h, 0, owners[i]); sfs_metadata_entry q_before = metadata_get(h, 0, q);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    for (unsigned i = 0; i < 4; i++) { metadata_clock(700 + i); XEXPECT(sfs_image_set_xattr(h, owners[i], "user", 4, values[i], strlen(values[i]), &r), SFS_OK); assert(clock_calls == 1); xattr_absent(h, 0, owners[i], "user"); }
    metadata_commit(h);
    for (unsigned i = 0; i < 4; i++) { sfs_metadata_entry after = metadata_get(h, 0, owners[i]); xattr_only_ctime(old[i], after, 700 + i); xattr_expect(h, 0, owners[i], "user", 4, values[i], strlen(values[i])); }
    sfs_metadata_entry after = metadata_get(h, 0, q); metadata_equal(&q_before, &after); expect(h, 0, file, "primary"); symlink_expect(h, 0, link, "file", 4);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_view view; XEXPECT(sfs_image_snapshot(h, "before", 6, &view, &r), SFS_OK); metadata_commit(h); assert(view == 1);
    sfs_metadata_entry before = metadata_get(h, 0, file), snapshot_file = before; XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(710);
    XEXPECT(sfs_image_set_xattr(h, file, "user", 4, "file-value", 10, &r), SFS_OK); assert(clock_calls == 1); metadata_commit(h);
    after = metadata_get(h, 0, file); xattr_only_ctime(before, after, 710); expect(h, 0, file, "primary"); xattr_expect(h, view, file, "user", 4, "file-value", 10);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(711); XEXPECT(sfs_image_write(h, file, 0, "changed", 7, &r), SFS_OK);
    size_t n; unsigned char *physical = bytes("image", &n); reset("", 0); clock_calls = 0;
    XEXPECT(sfs_image_remove_xattr(h, file, "absent", 6, &r), SFS_NOT_FOUND); assert(!clock_calls && !r.system_errno); image_unwritten(); unchanged("image", physical, n); free(physical);
    metadata_commit(h); expect(h, 0, file, "changed"); xattr_expect(h, 0, file, "user", 4, "file-value", 10);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(720); XEXPECT(sfs_image_rename(h, file, q, "moved", 5, &r), SFS_OK); assert(clock_calls == 1); metadata_commit(h);
    xattr_expect(h, 0, file, "user", 4, "file-value", 10); expect(h, 0, file, "changed"); symlink_expect(h, 0, link, "file", 4);
    sfs_metadata_entry parents[] = {metadata_get(h, 0, 1), metadata_get(h, 0, p), metadata_get(h, 0, q)}; before = metadata_get(h, 0, link);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(730); XEXPECT(sfs_image_remove_xattr(h, link, "user", 4, &r), SFS_OK); assert(clock_calls == 1); metadata_commit(h);
    after = metadata_get(h, 0, link); xattr_only_ctime(before, after, 730); xattr_absent(h, 0, link, "user"); xattr_expect(h, 0, file, "user", 4, "file-value", 10);
    after = metadata_get(h, 0, 1); metadata_equal(&parents[0], &after); after = metadata_get(h, 0, p); metadata_equal(&parents[1], &after); after = metadata_get(h, 0, q); metadata_equal(&parents[2], &after);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_remove(h, file, &r), SFS_OK); metadata_commit(h); sfs_entry missing;
    XEXPECT(sfs_image_stat(h, 0, file, &missing, &r), SFS_NOT_FOUND); xattr_absent(h, 0, file, "user"); xattr_expect(h, view, file, "user", 4, "file-value", 10); after = metadata_get(h, view, file); metadata_equal(&snapshot_file, &after);
    xattr_expect(h, 0, 1, "user", 4, "root-value", 10); xattr_expect(h, 0, p, "user", 4, "dir-value", 9); symlink_expect(h, 0, link, "file", 4); symlink_full(h); close_image(h); retain(2200);
    /* Exactly1025 minimum-occupancy target leaves plus one neighboring-owner leaf. */
    fixture f = xattr_prefix_fixture(); assert(xattr_guard(f.p, f.p, f.n)); fixture_save(&f); reset("", 0); open_image(&h); symlink_full(h);
    uint64_t initial_length; unsigned char initial_digest[32]; file_digest("image", initial_digest, &initial_length); assert(initial_length == UINT64_C(1164) * CELL);
    xattr_enumerate(h, 0, 2, "attr", 3075); xattr_enumerate(h, 0, 4, "keep", 3); XEXPECT(sfs_image_begin(h, &r), SFS_OK); reset("", 0); metadata_clock(800);
    XEXPECT(sfs_image_remove(h, 2, &r), SFS_OK); assert(clock_calls == 1 && image_append_bytes <= UINT64_C(55364) * CELL); metadata_commit(h);
    XEXPECT(sfs_image_stat(h, 0, 4, &missing, &r), SFS_OK); assert(r.physical_end <= UINT64_C(231538688));
    XEXPECT(sfs_image_stat(h, 0, 2, &missing, &r), SFS_NOT_FOUND); xattr_enumerate(h, 0, 4, "keep", 3); xattr_enumerate(h, 1, 2, "attr", 3075); xattr_enumerate(h, 1, 4, "keep", 3); symlink_full(h);
    printf("{\"case\":\"xattr-prefix-removal\",\"target_rows\":3075,\"target_leaves\":1025,\"neighbor_rows\":3,\"initial_cells\":1164,\"height\":5,\"bound_cells\":55364,\"appended_bytes\":%llu,\"fresh_arena_runtime_claim\":false}\n", (unsigned long long)image_append_bytes); fflush(stdout); counters("xattr-prefix-owned-allocations"); close_image(h);
}
static void xattr_views(void) {
    sfs_image *h; sfs_result r; xattr_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode owner = add(h, 1, "owner", SFS_FILE);
    XEXPECT(sfs_image_set_xattr(h, owner, "key", 3, "old", 3, &r), SFS_OK); metadata_commit(h); sfs_result old_binding = xattr_binding(h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_set_xattr(h, owner, "key", 3, "new", 3, &r), SFS_OK); xattr_expect(h, 0, owner, "key", 3, "old", 3);
    sfs_view view; XEXPECT(sfs_image_snapshot(h, "before", 6, &view, &r), SFS_OK); metadata_commit(h); assert(view == 1); xattr_expect(h, 0, owner, "key", 3, "new", 3); xattr_expect(h, view, owner, "key", 3, "old", 3);
    sfs_xattr_entry output, canary; memset(&canary, 0xA5, sizeof(canary)); output = canary; int found = 99;
    XEXPECT(sfs_image_next_xattr(h, 0, old_binding.generation, old_binding.root_digest, owner, NULL, 0, &output, &found, &r), SFS_STATE); assert(found == 99 && !memcmp(&output, &canary, sizeof(output)));
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_remove_xattr(h, owner, "key", 3, &r), SFS_OK); XEXPECT(sfs_image_abort(h, &r), SFS_OK); xattr_expect(h, 0, owner, "key", 3, "new", 3);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_remove(h, owner, &r), SFS_OK); metadata_commit(h); xattr_absent(h, 0, owner, "key"); xattr_expect(h, view, owner, "key", 3, "old", 3); close_image(h);
    size_t n; unsigned char *before = bytes("image", &n); struct stat identity, after_identity; assert(!lstat("image", &identity)); reset("", 0); open_readonly(&h, &r);
    xattr_expect(h, view, owner, "key", 3, "old", 3); reset("", 0); clock_calls = 0;
    XEXPECT(sfs_image_set_xattr(h, 1, "key", 3, "no", 2, &r), SFS_STATE); XEXPECT(sfs_image_remove_xattr(h, 1, "key", 3, &r), SFS_STATE); assert(!clock_calls); image_unwritten(); close_image(h); unchanged("image", before, n);
    sfs_recovery recovery; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    for (unsigned slot = 0; slot < 2; slot++) {
        assert(recovery.slots[slot].status == SFS_OK && recovery.slots[slot].coverage == SFS_COVERAGE_FULL_REACHABLE);
        XEXPECT(sfs_image_select(h, slot, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE);
        xattr_expect(h, view, owner, "key", 3, "old", 3); XEXPECT(sfs_image_set_xattr(h, 1, "key", 3, NULL, 0, &r), SFS_STATE); XEXPECT(sfs_image_remove_xattr(h, 1, "key", 3, &r), SFS_STATE);
    }
    assert(!clock_calls); image_unwritten(); close_image(h); unchanged("image", before, n); assert(!lstat("image", &after_identity)); identical_identity(&identity, &after_identity); free(before); retain(2300);
    /* Two FULL-valid roots at the same generation bind different attribute names/values. */
    fixture a = xattr_fixture(1, 0, 0); size_t old_end = a.n; unsigned char slot0[CELL]; memcpy(slot0, a.p, CELL);
    fixture b = xattr_fixture(1, 0, 0); unsigned char *ns = namespace_at(b.p, b.p, b.n), *row = record(b.p, ns + 280, b.n) + 640;
    memcpy(row + 12, "alt", 3); xattr_repair(b.p, a.p, b.n); assert(xattr_guard(b.p, a.p, b.n));
    /* Keep two private graph copies; relocation preserves all framing, owner and value identities. */
    unsigned char *mapping = calloc(b.n / CELL, 56); assert(mapping);
    for (size_t i = 2; i < b.n / CELL; i++) {
        unsigned char *cell = b.p + i * CELL; unsigned type = !memcmp(cell, "SFSREC05", 8) ? get32(cell + 8) : 6;
        if (type == 2 || type == 4) { mapped_ref(cell + 64, mapping, b.n / CELL); mapped_ref(cell + 120, mapping, b.n / CELL); if (type == 2) mapped_ref(cell + 280, mapping, b.n / CELL); }
        if (type == 5) { unsigned map = get32(cell + 64), level = get16(cell + 68), count = get16(cell + 70), stride = xattr_stride(map, level), edge = xattr_edge(map, level); for (unsigned j = 0; j < count; j++) if (level || map != 2) mapped_ref(cell + 640 + j * stride + edge, mapping, b.n / CELL); }
        fixture_node moved = append_cell(&a, type, cell); memcpy(mapping + i * 56, moved.ref, 56);
    }
    memcpy(a.p, slot0, CELL); mapped_ref(b.p + 48, mapping, b.n / CELL); memcpy(a.p + CELL, b.p, CELL); put64(a.p + CELL + 104, a.n); slot_hash(a.p + CELL); free(mapping); free(b.p); assert(old_end < a.n); fixture_save(&a);
    reset("", 0); XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK); assert(!recovery.pair_valid && recovery.slots[0].status == SFS_OK && recovery.slots[1].status == SFS_OK);
    uint64_t unselected_size = UINT64_MAX; XEXPECT(sfs_image_xattr_size(h, 0, 2, "key", 3, &unselected_size, &r), SFS_STATE); assert(unselected_size == UINT64_MAX);
    XEXPECT(sfs_image_select(h, 0, &generous, &r), SFS_OK); sfs_result binding0 = r; xattr_expect(h, 0, 2, "key", 3, "shared", 6);
    XEXPECT(sfs_image_select(h, 1, &generous, &r), SFS_OK); assert(r.generation == binding0.generation && memcmp(r.root_digest, binding0.root_digest, 32)); xattr_expect(h, 0, 2, "alt", 3, "shared", 6);
    output = canary; found = 99; XEXPECT(sfs_image_next_xattr(h, 0, binding0.generation, binding0.root_digest, 2, NULL, 0, &output, &found, &r), SFS_STATE);
    assert(found == 99 && !memcmp(&output, &canary, sizeof(output))); image_unwritten(); close_image(h);
}
static void xattr_capacity(void) {
    const unsigned bound[] = {10, 18, 12, 23};
    unsigned char replacement[4097]; memset(replacement, 'Z', sizeof(replacement)); sfs_result r; sfs_image *h;
    for (unsigned operation = 0; operation < 4; operation++) for (unsigned fit = 0; fit < 2; fit++) {
        fixture f = xattr_fixture(1, 3, 1); size_t initial = f.n;
        uint64_t capacity = initial + (UINT64_C(1) + bound[operation] - (fit ? 0 : 1)) * CELL;
        for (unsigned slot = 0; slot < 2; slot++) { put64(f.p + slot * CELL + 144, capacity); slot_hash(f.p + slot * CELL); } assert(xattr_guard(f.p, f.p, f.n)); fixture_save(&f);
        reset("", 0); open_image(&h); symlink_full(h); sfs_metadata_entry owner_before = metadata_get(h, 0, 2), other_before = metadata_get(h, 0, 4);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode pending = operation == 0 || operation == 2 ? 2 : 4; metadata_clock(900);
        XEXPECT(sfs_image_write(h, pending, 0, "pending", 7, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n);
        assert(n == initial + CELL && capacity - n == (bound[operation] - (fit ? 0 : 1)) * CELL); reset("", 0); metadata_clock(901);
        enum sfs_status status;
        if (operation < 2) status = sfs_image_set_xattr(h, 2, operation ? "new" : "key", 3, replacement, sizeof(replacement), &r);
        else if (operation == 2) status = sfs_image_remove_xattr(h, 2, "key", 3, &r);
        else status = sfs_image_remove(h, 2, &r);
        assert(status == r.status); receipt("xattr-whole-operation-admission", &r);
        printf("{\"xattr_capacity_operation\":%u,\"bound_cells\":%u,\"fit\":%s,\"prior_raw_tail_cells\":1,\"appended_bytes\":%llu}\n", operation, bound[operation], fit ? "true" : "false", (unsigned long long)image_append_bytes); fflush(stdout);
        if (!fit) {
            assert(status == SFS_LIMIT && r.phase == SFS_PHASE_ADMISSION && !r.system_errno && r.physical_end == n); image_unwritten(); unchanged("image", before, n);
            XEXPECT(sfs_image_commit(h, &r), SFS_STATE); expect(h, 0, 2, "shared"); expect(h, 0, 4, "shared"); xattr_expect(h, 0, 2, "key", 3, "shared", 6); xattr_expect(h, 1, 2, "key", 3, "shared", 6);
            sfs_metadata_entry m = metadata_get(h, 0, 2); metadata_equal(&m, &owner_before); m = metadata_get(h, 0, 4); metadata_equal(&m, &other_before); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_abort(h, &r), SFS_OK);
        } else {
            assert(status == SFS_OK && clock_calls == 1 && image_append_bytes <= bound[operation] * UINT64_C(4096)); metadata_commit(h);
            expect(h, 0, pending, "pending"); expect(h, 1, pending, "shared"); xattr_expect(h, 1, 2, "key", 3, "shared", 6);
            if (operation < 2) xattr_expect(h, 0, 2, operation ? "new" : "key", 3, replacement, sizeof(replacement)); else xattr_absent(h, 0, 2, "key");
            if (operation != 3) { sfs_metadata_entry m = metadata_get(h, 0, 2); assert(timestamp_is(m.change, 901, 902)); if (pending == 2) { assert(m.entry.size == 7 && m.referenced_data_bytes == CELL && timestamp_is(m.modification, 900, 901)); } else assert(m.entry.size == owner_before.entry.size && timestamp_equal(m.modification, owner_before.modification)); }
            sfs_entry e; XEXPECT(sfs_image_stat(h, 0, 4, &e, &r), SFS_OK); assert(r.physical_end <= capacity); symlink_full(h);
        }
        close_image(h); free(before); retain(2400 + (int)(operation * 2 + fit));
    }
    /* Lold0 admits alignment padding after a pre-existing37-byte charged tail. */
    for (unsigned remove = 0; remove < 2; remove++) {
        fixture f = xattr_fixture(1, 3, 1); size_t initial = f.n; unsigned reservation = remove ? 9 : 6;
        uint64_t capacity = initial + (UINT64_C(1) + reservation) * CELL;
        for (unsigned i = 0; i < 2; i++) { put64(f.p + i * CELL + 144, capacity); slot_hash(f.p + i * CELL); } fixture_save(&f);
        unsigned char tail[37]; memset(tail, 0xA7, sizeof(tail)); int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, tail, sizeof(tail), (off_t)initial); assert(!close(fd));
        reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); assert(n == initial + 37 && n % CELL == 37); reset("", 0); metadata_clock(902);
        if (remove) XEXPECT(sfs_image_remove_xattr(h, 2, "key", 3, &r), SFS_OK); else XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, "newval", 6, &r), SFS_OK);
        assert(clock_calls == 1); metadata_commit(h); size_t end; unsigned char *after = bytes("image", &end);
        assert(end <= capacity && end > n && end - n == image_append_bytes && !memcmp(before + 8192, after + 8192, n - 8192) && !memcmp(after + initial, tail, sizeof(tail)));
        if (remove) xattr_absent(h, 0, 2, "key"); else xattr_expect(h, 0, 2, "key", 3, "newval", 6); xattr_expect(h, 1, 2, "key", 3, "shared", 6); symlink_full(h);
        printf("{\"case\":\"xattr-unaligned-tail-no-batch\",\"tail_bytes\":37,\"padding_bytes\":4059,\"remove\":%s,\"reservation_cells\":%u,\"appended_bytes\":%llu}\n", remove ? "true" : "false", reservation, (unsigned long long)image_append_bytes); fflush(stdout);
        free(before); free(after); close_image(h); retain(2410 + (int)remove);
    }
}
static void xattr_zero_seal_nomem(void) {
    for (unsigned remove_owner = 0; remove_owner < 2; remove_owner++) {
        fixture f = xattr_fixture(1, 3, 1); assert(xattr_guard(f.p, f.p, f.n)); fixture_save(&f); sfs_image *h; sfs_result r; reset("", 0); open_image(&h); symlink_full(h);
        sfs_metadata_entry original = metadata_get(h, 0, 4); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
        sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 9898; metadata_clock(910); XEXPECT(sfs_image_set_metadata(h, 4, &update, &r), SFS_OK);
        size_t n; unsigned char *before = bytes("image", &n); reset("", 0); metadata_clock(911); fail_arena_allocation = 3;
        enum sfs_status status = remove_owner ? sfs_image_remove(h, 2, &r) : sfs_image_remove_xattr(h, 2, "key", 3, &r);
        assert(status == SFS_NOMEM && r.status == status && r.phase == SFS_PHASE_READ && r.system_errno == ENOMEM && hit == 1 && arena_allocations == 3 && r.physical_end == n);
        assert(clock_calls == 1); image_unwritten(); unchanged("image", before, n); receipt(remove_owner ? "xattr-empty-prefix-third-arena" : "xattr-empty-delete-third-arena", &r);
        reset("", 0); xattr_expect(h, 0, 2, "key", 3, "shared", 6); expect(h, 0, 2, "shared"); metadata_commit(h);
        sfs_metadata_entry current = metadata_get(h, 0, 4); sfs_metadata_entry expected = original; expected.uid = 9898; expected.change = (sfs_timestamp){910, 911}; metadata_equal(&expected, &current);
        current = metadata_get(h, 1, 4); metadata_equal(&original, &current); xattr_expect(h, 0, 2, "key", 3, "shared", 6); xattr_expect(h, 1, 2, "key", 3, "shared", 6); expect(h, 0, 2, "shared"); expect(h, 0, 4, "shared"); symlink_full(h); close_image(h); free(before); retain(2420 + (int)remove_owner);
    }
}
static void xattr_failures(void) {
    xattr_capacity(); xattr_zero_seal_nomem(); sfs_image *h; sfs_result r; fixture f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, 4, 0, "pending", 7, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); reset("", 0); clock_calls = 0;
    const unsigned char one = 'x'; XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, &one, 4194305, &r), SFS_LIMIT);
    assert(r.phase == SFS_PHASE_ADMISSION && !r.system_errno && !clock_calls); image_unwritten(); unchanged("image", before, n); XEXPECT(sfs_image_commit(h, &r), SFS_STATE); expect(h, 0, 4, "shared"); close_image(h); free(before); retain(2422);
    f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(920); XEXPECT(sfs_image_write(h, 4, 0, "pending", 7, &r), SFS_OK); before = bytes("image", &n);
    for (unsigned failure = 0; failure < 2; failure++) {
        reset("", 0); metadata_clock(921); if (failure) fail_allocation = allocation_calls + 1; else clock_failure = 1;
        XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, "new", 3, &r), failure ? SFS_NOMEM : SFS_TIME_UNAVAILABLE);
        assert(r.system_errno == (failure ? ENOMEM : ENXIO)); if (failure) assert(hit); else assert(r.phase == SFS_PHASE_NONE && clock_calls == 1);
        image_unwritten(); unchanged("image", before, n);
    }
    reset("", 0); metadata_commit(h); expect(h, 0, 4, "pending"); xattr_expect(h, 0, 2, "key", 3, "shared", 6); close_image(h); free(before); retain(2423);
    unsigned char value[4097]; for (unsigned i = 0; i < sizeof(value); i++) value[i] = (unsigned char)(i * 17 + 3);
    for (unsigned nth = 1; nth <= 6; nth++) {
        f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); before = bytes("image", &n); reset("write_error", (int)nth); metadata_clock(922);
        XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, value, sizeof(value), &r), SFS_IO);
        assert(hit && r.phase == SFS_PHASE_RECORDS && r.system_errno == EIO && image_append_bytes == (nth - 1) * UINT64_C(4096) && !fulls && !slots);
        receipt("xattr-producer-write-error", &r); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); reset("", 0); close_image(h);
        size_t tail_n; unsigned char *tail = bytes("image", &tail_n); assert(tail_n == n + (nth - 1) * CELL && !memcmp(tail, before, n)); free(tail); free(before);
        open_image(&h); xattr_expect(h, 0, 2, "key", 3, "shared", 6); xattr_expect(h, 1, 2, "key", 3, "shared", 6); close_image(h); retain(2430 + (int)nth);
    }
    for (unsigned failure = 0; failure < 3; failure++) {
        f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); before = bytes("image", &n);
        reset(failure == 0 ? "write_eintr" : failure == 1 ? "write_short" : "enospc", 2); metadata_clock(923);
        enum sfs_status status = sfs_image_set_xattr(h, 2, "key", 3, value, sizeof(value), &r); assert(status == r.status);
        if (failure < 2) { assert(status == SFS_OK); if (!failure) assert(hit); else assert(writes > 6); metadata_commit(h); xattr_expect(h, 0, 2, "key", 3, value, sizeof(value)); }
        else { assert(status == SFS_IO && hit && r.phase == SFS_PHASE_RECORDS && r.system_errno == ENOSPC); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); }
        reset("", 0); close_image(h); free(before); retain(2440 + (int)failure);
    }
    f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); before = bytes("image", &n); reset("", 0); fail_after_append = 1; metadata_clock(924);
    XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, value, sizeof(value), &r), SFS_NOMEM); assert(hit && r.system_errno == ENOMEM && image_append_bytes && !fulls); receipt("xattr-late-allocation", &r);
    XEXPECT(sfs_image_commit(h, &r), SFS_STATE); reset("", 0); xattr_expect(h, 0, 2, "key", 3, "shared", 6); close_image(h); size_t tail_n; unsigned char *tail = bytes("image", &tail_n); assert(tail_n > n && !memcmp(tail, before, n)); free(tail); free(before); retain(2443);
    for (unsigned failure = 0; failure < 3; failure++) {
        f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, value, sizeof(value), &r), SFS_OK);
        reset(failure == 0 ? "slot_error" : "full", failure == 2 ? 2 : 1); clock_calls = 0;
        enum sfs_status status = sfs_image_commit(h, &r); assert(status == r.status && hit && !clock_calls);
        assert(status == (failure == 1 ? SFS_IO : SFS_OUTCOME_UNKNOWN) && r.system_errno == EIO && r.phase == (failure == 0 ? SFS_PHASE_SLOT0 : failure == 1 ? SFS_PHASE_RECORD_BARRIER : SFS_PHASE_COMMIT_BARRIER));
        receipt("xattr-commit-uncertainty", &r); XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); reset("", 0); close_image(h); open_image(&h);
        xattr_expect(h, 0, 2, "key", 3, failure == 2 ? value : (const unsigned char *)"shared", failure == 2 ? sizeof(value) : 6); xattr_expect(h, 1, 2, "key", 3, "shared", 6); close_image(h); retain(2444 + (int)failure);
    }
    for (unsigned corrupt = 0; corrupt < 2; corrupt++) {
        f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_set_xattr(h, 2, "key", 3, value, sizeof(value), &r), SFS_OK); metadata_commit(h); close_image(h);
        unsigned char *image = bytes("image", &n), *ns = namespace_at(image, selected_slot(image), n), *attrs = record(image, ns + 280, n), *extent = record(image, attrs + 640 + 280, n); read_at[0] = get64(extent + 640 + 72 + 8 + 8);
        open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 111; XEXPECT(sfs_image_set_metadata(h, 4, &update, &r), SFS_OK);
        if (corrupt) { int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); unsigned char changed = (unsigned char)(image[read_at[0]] ^ 1); raw_write(fd, &changed, 1, (off_t)read_at[0]); assert(!close(fd)); }
        free(image); before = bytes("image", &n); unsigned char out[4099]; memset(out, 0xA5, sizeof(out)); size_t got = 99; reset(corrupt ? "" : "candidate_reads", corrupt ? 0 : 1); clock_calls = 0;
        XEXPECT(sfs_image_read_xattr(h, 0, 2, "key", 3, 0, out + 1, sizeof(value), &got, &r), corrupt ? SFS_CORRUPT : SFS_IO);
        assert(got == CELL && !memcmp(out + 1, value, CELL) && out[0] == 0xA5 && out[CELL + 1] == 0xA5 && out[sizeof(out) - 1] == 0xA5 && r.phase == SFS_PHASE_READ && r.system_errno == (corrupt ? 0 : EIO) && !clock_calls); if (!corrupt) assert(hit);
        image_unwritten(); unchanged("image", before, n); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); reset("", 0); close_image(h); free(before); retain(2450 + (int)corrupt);
    }
    for (unsigned operation = 0; operation < 3; operation++) {
        f = xattr_fixture(1, 3, 1); fixture_save(&f); reset("", 0); open_image(&h); xattr_expect(h, 0, 2, "key", 3, "shared", 6); sfs_result binding = xattr_binding(h);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); struct stat st; assert(!fstat(fd, &st) && !ftruncate(fd, st.st_size + 1) && !close(fd));
        before = bytes("image", &n); reset("", 0); uint64_t size = UINT64_MAX; size_t got = 99; unsigned char out[8]; memset(out, 0xA5, sizeof(out)); sfs_xattr_entry output, canary; memset(&canary, 0xA5, sizeof(canary)); output = canary; int found = 99;
        if (operation == 0) XEXPECT(sfs_image_xattr_size(h, 0, 2, "key", 3, &size, &r), SFS_IO);
        else if (operation == 1) XEXPECT(sfs_image_read_xattr(h, 0, 2, "key", 3, 0, out, sizeof(out), &got, &r), SFS_IO);
        else XEXPECT(sfs_image_next_xattr(h, 0, binding.generation, binding.root_digest, 2, NULL, 0, &output, &found, &r), SFS_IO);
        assert(r.phase == SFS_PHASE_IDENTITY && r.system_errno == ESTALE && size == UINT64_MAX && got == (operation == 1 ? 0u : 99u) && found == 99 && !memcmp(&output, &canary, sizeof(output)));
        for (unsigned i = 0; i < sizeof(out); i++) assert(out[i] == 0xA5); image_unwritten(); unchanged("image", before, n); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); close_image(h); free(before); retain(2452 + (int)operation);
    }
}
static fixture xattr_eviction_fixture(unsigned retained, unsigned binary, unsigned invalid_link) {
    fixture f = fixture_start(); f.minor = 5; put32(f.p + 12, 5); unsigned char raw[CELL] = {0}; memcpy(raw, "shared", 6); if (binary) raw[2] = 0;
    fixture_node data = append_cell(&f, 6, raw); memset(raw, 0, CELL); memcpy(raw, "filler", 6); fixture_node filler = append_cell(&f, 6, raw);
    unsigned char one[72] = {0}; memcpy(one + 8, data.ref, 56); put16(one + 64, 6); fixture_node target = tree(&f, 3, one, 1);
    const unsigned count = 48 * 1201; unsigned char *rows = calloc(count, 72); assert(rows);
    for (unsigned i = 0; i < count; i++) { put64(rows + i * 72, i); memcpy(rows + i * 72 + 8, i ? filler.ref : data.ref, 56); put16(rows + i * 72 + 64, 6); }
    fixture_node regular = tree(&f, 3, rows, count); free(rows);
    unsigned char ir[880] = {0}, nr[560] = {0};
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *a = ir + i * 440, *b = nr + i * 280; put64(a, i + 2); put64(a + 8, 1); put32(a + 16, SFS_FILE); put32(a + 20, 1); a[88] = (unsigned char)('a' + i);
        if (!i) { put64(a + 24, (count - 1) * (uint64_t)CELL + 6); memcpy(a + 32, regular.ref, 56); } fixture_tuple(a + 352, SFS_FILE, i ? 0 : count);
        put64(b, 1); put32(b + 8, 1); b[12] = (unsigned char)('a' + i); put64(b + 267, i + 2);
    }
    fixture_node inodes = tree(&f, 1, ir, 2), names = tree(&f, 2, nr, 2); unsigned char attr[352]; xattr_row(attr, 3, "key", 3, 6, target.ref, 1); fixture_node attrs = tree(&f, 5, attr, 1);
    fixture_node history = xattr_space(&f, inodes, names, attrs, 4, 2);
    /* No current symlink can refresh T before the current or first retained xattr reuse. */
    if (!binary || invalid_link) { put32(ir + 440 + 16, SFS_SYMLINK); put64(ir + 440 + 24, 6); memcpy(ir + 440 + 32, target.ref, 56); put32(ir + 440 + 416, 0120600); put64(ir + 440 + 432, 1); }
    fixture_node later_inodes = tree(&f, 1, ir, 2), later = xattr_space(&f, later_inodes, names, attrs, 4, 2);
    unsigned char sr[656] = {0};
    for (unsigned i = 0; i < 2; i++) { put32(sr + i * 328, i + 1); memcpy(sr + i * 328 + 8, i ? later.ref : history.ref, 56); put32(sr + i * 328 + 64, 1); sr[i * 328 + 68] = (unsigned char)('x' + i); }
    fixture_node catalog = tree(&f, 4, sr, 2), empty = {0}, current = xattr_space(&f, inodes, names, retained ? empty : attrs, 4, 2); finish_fixture(&f, current, catalog); return f;
}
static void xattr_sparse_save(fixture *f) {
    size_t cells = f->n / CELL; unsigned char *mapping = calloc(cells, 56); assert(mapping); int fd = open("image", O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); assert(fd >= 0); uint64_t end = 0;
    for (size_t i = 2; i < cells; i++) {
        unsigned char *p = f->p + i * CELL; unsigned type = !memcmp(p, "SFSREC05", 8) ? get32(p + 8) : 6;
        if (type == 2 || type == 4) { mapped_ref(p + 64, mapping, cells); mapped_ref(p + 120, mapping, cells); if (type == 2) mapped_ref(p + 280, mapping, cells); }
        if (type == 5) { unsigned map = get32(p + 64), level = get16(p + 68), count = get16(p + 70), stride = xattr_stride(map, level), edge = xattr_edge(map, level); for (unsigned j = 0; j < count; j++) if (level || map != 2) mapped_ref(p + 640 + j * stride + edge, mapping, cells); }
        unsigned char *ref = mapping + i * 56; put32(ref, type); uint64_t at = (2 + (i - 2) * 32) * UINT64_C(4096); put64(ref + 8, at); put64(ref + 16, CELL);
        if (type == 6) { unsigned char domain[36]; memcpy(domain, "SFSDAT05", 8); memcpy(domain + 8, f->p + 24, 16); put32(domain + 24, 6); put64(domain + 28, CELL); CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c, domain, 36); CC_SHA256_Update(&c, p, CELL); CC_SHA256_Final(ref + 24, &c); }
        else CC_SHA256(p, CELL, ref + 24); raw_write(fd, p, CELL, (off_t)at); end = at + CELL;
    }
    assert(end <= UINT64_C(268435456));
    for (unsigned i = 0; i < 2; i++) { unsigned char *slot = f->p + i * CELL; mapped_ref(slot + 48, mapping, cells); put64(slot + 104, end); put64(slot + 144, UINT64_C(268435456)); slot_hash(slot); raw_write(fd, slot, CELL, i * CELL); }
    assert(!close(fd)); printf("{\"case\":\"xattr-sparse-target-memo\",\"stored_cell_bytes\":%llu,\"logical_end\":%llu,\"filesystem_allocation_claim\":false}\n", (unsigned long long)(cells * CELL), (unsigned long long)end); fflush(stdout); free(mapping); free(f->p); f->p = NULL;
}
static void xattr_verify(void) {
    fixture f = xattr_fixture(3, 0, 2); size_t n = f.n; unsigned char *baseline = malloc(n); assert(baseline); memcpy(baseline, f.p, n); assert(xattr_guard(f.p, baseline, n)); fixture_save(&f);
    sfs_image *h; sfs_result r; sfs_recovery recovery; reset("", 0); open_image(&h); symlink_full(h); close_image(h); retain(2500);
    const char *cases[] = {"owner-zero", "owner-range", "owner-missing", "wrong-map", "name-nul", "row-padding", "length-count", "empty-extent", "nonempty-null", "hole", "extra", "short-visible", "raw-suffix", "raw-digest", "namespace-padding", "wrong-raw-domain"};
    for (unsigned kind = 0; kind < sizeof(cases) / sizeof(*cases); kind++) {
        unsigned char *p = malloc(n); assert(p); memcpy(p, baseline, n); unsigned char *space = namespace_at(p, p, n), *attrs = record(p, space + 280, n), *row = attrs + 640;
        unsigned char *extent = record(p, row + 280, n), *raw = record(p, extent + 648, n);
        if (kind == 0) put64(row, 0); else if (kind == 1) put64(row, 5); else if (kind == 2) put64(row, 3);
        else if (kind == 3) put32(attrs + 64, 4); else if (kind == 4) row[13] = 0; else if (kind == 5) row[267] = 1;
        else if (kind == 6) put64(row + 336, 2); else if (kind == 7) { put64(row + 272, 0); put64(row + 336, 0); }
        else if (kind == 8) memset(row + 280, 0, 56);
        else if (kind == 9) { memcpy(extent + 712, extent + 784, 72); memset(extent + 784, 0, 72); put16(extent + 70, 2); }
        else if (kind == 10) { memcpy(extent + 856, extent + 784, 72); put64(extent + 856, 3); put16(extent + 70, 4); }
        else if (kind == 11) put16(extent + 704, CELL - 1); else if (kind == 12) raw[6] = 'X'; else if (kind == 14) space[336] = 1;
        xattr_repair(p, baseline, n);
        if (kind == 10) { unsigned char check[56]; memcpy(check, extent + 864, 56); ref_hash(p, check, n); assert(!memcmp(check, extent + 864, 56)); }
        assert(xattr_guard(p, baseline, n));
        if (kind == 13) raw[0] ^= 1;
        else if (kind == 15) {
            unsigned char domain[36], digest[32]; memcpy(domain, "SFSDAT04", 8); memcpy(domain + 8, p + 24, 16); put32(domain + 24, 6); put64(domain + 28, CELL);
            CC_SHA256_CTX c; CC_SHA256_Init(&c); CC_SHA256_Update(&c, domain, 36); CC_SHA256_Update(&c, raw, CELL); CC_SHA256_Final(digest, &c);
            for (unsigned i = 0; i < 3; i++) memcpy(extent + 648 + i * 72 + 24, digest, 32);
            xattr_repair_metadata(p, baseline, n);
        }
        if (kind == 13 || kind == 15) assert(!xattr_guard(p, baseline, n));
        save("image", p, n); reset("", 0); h = NULL; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED);
        assert(!h && r.phase == SFS_PHASE_READ && !r.system_errno && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT && recovery.slots[0].coverage != SFS_COVERAGE_FULL_REACHABLE && recovery.slots[1].coverage != SFS_COVERAGE_FULL_REACHABLE);
        printf("{\"xattr_semantic_case\":\"%s\",\"digest_framing_valid\":%s,\"aggregate_status\":%d,\"slot0\":%d,\"slot1\":%d}\n", cases[kind], (kind == 13 || kind == 15) ? "false" : "true", r.status, recovery.slots[0].status, recovery.slots[1].status); fflush(stdout); image_unwritten(); unchanged("image", p, n);
        if (kind == 9) {
            open_image(&h); unsigned char output[8198]; memset(output, 0xA5, sizeof(output)); size_t got = 99;
            XEXPECT(sfs_image_read_xattr(h, 0, 2, "key", 3, 0, output, sizeof(output), &got, &r), SFS_CORRUPT);
            assert(got == CELL && !memcmp(output, "shared", 6) && output[CELL] == 0xA5 && r.phase == SFS_PHASE_READ && !r.system_errno); for (unsigned i = 6; i < CELL; i++) assert(!output[i]); XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); close_image(h);
        }
        free(p); retain(2501 + (int)kind);
    }
    free(baseline);
    /* A successful intrinsic regular-file summary cannot certify a dense attribute. */
    f = xattr_fixture(3, 1, 2); assert(xattr_guard(f.p, f.p, f.n)); save("image", f.p, f.n); reset("", 0); open_image(&h); reset("", 0);
    XEXPECT(sfs_image_verify(h, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && raw_hashes == 1 && raw_hash_input == 4132); receipt("xattr-shared-regular-full-control", &r); close_image(h); retain(2519);
    unsigned char *old = malloc(f.n); assert(old); memcpy(old, f.p, f.n); unsigned char *space = namespace_at(f.p, f.p, f.n), *attrs = record(f.p, space + 280, f.n), *extent = record(f.p, attrs + 640 + 280, f.n);
    memcpy(extent + 712, extent + 784, 72); memset(extent + 784, 0, 72); put16(extent + 70, 2); unsigned char *inode = leaf_row(f.p, space + 64, 2, f.n, 440); put64(inode + 432, 2);
    xattr_repair(f.p, old, f.n); assert(xattr_guard(f.p, old, f.n)); fixture_save(&f); free(old); reset("", 0); h = NULL; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED);
    assert(!h && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT); image_unwritten(); retain(2520);
    /* Two owners share one extent root; each L/N is checked even after the first succeeds. */
    f = xattr_fixture(3, 1, 2); old = malloc(f.n); assert(old); memcpy(old, f.p, f.n); space = namespace_at(f.p, f.p, f.n); attrs = record(f.p, space + 280, f.n);
    memcpy(attrs + 992, attrs + 640, 352); put64(attrs + 992, 4); put16(attrs + 70, 2); xattr_repair(f.p, old, f.n);
    assert(xattr_ref_guard(f.p, old, attrs + 992 + 280, old + (attrs - f.p) + 640 + 280, f.n, (uint64_t)(attrs - f.p), 0)); assert(xattr_guard(f.p, old, f.n)); free(old);
    n = f.n; baseline = malloc(n); assert(baseline); memcpy(baseline, f.p, n); fixture_save(&f); reset("", 0); open_image(&h); reset("", 0); symlink_full(h); assert(raw_hashes == 1 && raw_hash_input == 4132); close_image(h); retain(2521);
    unsigned char *p = malloc(n); assert(p); memcpy(p, baseline, n); space = namespace_at(p, p, n); attrs = record(p, space + 280, n); put64(attrs + 992 + 272, CELL); put64(attrs + 992 + 336, 1); xattr_repair(p, baseline, n); assert(xattr_guard(p, baseline, n)); save("image", p, n);
    reset("", 0); h = NULL; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED); assert(!h && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT); image_unwritten(); unchanged("image", p, n); free(p); free(baseline); retain(2522);
    f = xattr_fixture(1, 0, 1); fixture_save(&f); reset("", 0); recovery_cancellation cancellation = {.after_hash = 0}; sfs_verify_budget budget = generous; budget.cancelled = cancel_recovery_once; budget.context = &cancellation;
    XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &budget, &r), SFS_OK);
    assert(cancellation.fired && recovery.slots[0].status == SFS_INCOMPLETE && recovery.slots[0].incomplete_reason == SFS_INCOMPLETE_CANCELLED && recovery.slots[0].coverage != SFS_COVERAGE_FULL_REACHABLE && recovery.slots[1].status == SFS_OK && recovery.slots[1].coverage == SFS_COVERAGE_FULL_REACHABLE);
    uint64_t size = UINT64_MAX; XEXPECT(sfs_image_xattr_size(h, 0, 2, "key", 3, &size, &r), SFS_STATE); assert(size == UINT64_MAX); XEXPECT(sfs_image_select(h, 0, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); xattr_expect(h, 0, 2, "key", 3, "shared", 6); close_image(h); retain(2523);
    for (unsigned stop = 0; stop < 5; stop++) {
        f = xattr_fixture(3, 0, 1); fixture_save(&f); reset("", 0); open_image(&h); budget = generous; unsigned polls = 0;
        if (stop == 0) budget.raw_cells = 1; else if (stop == 1) budget.checks = 1; else if (stop == 2) budget.auxiliary_bytes = 1; else if (stop == 3) budget.auxiliary_io_bytes = 1; else { budget.cancelled = cancel_now; budget.context = &polls; }
        reset("", 0); enum sfs_status status = sfs_image_verify(h, &budget, &r); assert(status == r.status);
        if (!stop) assert(status == SFS_OK && r.coverage == SFS_COVERAGE_FULL_REACHABLE && raw_hashes == 1 && raw_hash_input == 4132);
        else { const enum sfs_incomplete_reason why[] = {SFS_INCOMPLETE_NONE, SFS_INCOMPLETE_CHECKS, SFS_INCOMPLETE_AUX_LENGTH, SFS_INCOMPLETE_AUX_IO, SFS_INCOMPLETE_CANCELLED}; assert(status == SFS_INCOMPLETE && !r.system_errno && r.incomplete_reason == why[stop] && r.coverage != SFS_COVERAGE_FULL_REACHABLE); if (stop == 4) assert(polls); }
        image_unwritten(); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_abort(h, &r), SFS_OK); close_image(h); retain(2524 + (int)stop);
    }
    for (unsigned io = 0; io < 2; io++) {
        f = xattr_fixture(1, 0, 1); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 321; XEXPECT(sfs_image_set_metadata(h, 4, &update, &r), SFS_OK);
        budget = generous; budget.metadata_read_bytes = CELL; reset(io ? "slot_reads" : "", io ? 1 : 0);
        XEXPECT(sfs_image_verify(h, &budget, &r), io ? SFS_IO : SFS_INCOMPLETE); assert(r.phase == SFS_PHASE_READ && r.system_errno == (io ? EIO : 0)); if (io) assert(hit); else assert(r.incomplete_reason == SFS_INCOMPLETE_METADATA_READ);
        image_unwritten(); reset("", 0); if (io) XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); else { metadata_commit(h); sfs_metadata_entry m = metadata_get(h, 0, 4); assert(m.uid == 321); xattr_expect(h, 0, 2, "key", 3, "shared", 6); }
        close_image(h); retain(2529 + (int)io);
    }
    for (unsigned retained = 0; retained < 2; retained++) for (unsigned binary = 0; binary < 2; binary++) {
        f = xattr_eviction_fixture(retained, binary, 0); assert(xattr_guard(f.p, f.p, f.n)); unsigned char target_ref[56]; space = namespace_at(f.p, f.p, f.n);
        unsigned char *reference_space = space;
        if (retained) { unsigned char *commit = record(f.p, f.p + 48, f.n), *catalog = record(f.p, commit + 120, f.n); reference_space = record(f.p, catalog + 648, f.n); }
        attrs = record(f.p, reference_space + 280, f.n); extent = record(f.p, attrs + 640 + 280, f.n); memcpy(target_ref, extent + 648, 56); xattr_sparse_save(&f);
        unsigned char digest[32], after_digest[32]; uint64_t length, after_length; file_digest("image", digest, &length); assert(length <= UINT64_C(268435456)); struct stat identity, after_identity; assert(!lstat("image", &identity));
        reset("", 0); open_image(&h); reset("", 0); memo_target_start(target_ref, binary ? 2 : 6, 1); symlink_full(h); memo_target_check(1, 0);
        assert(raw_hashes == 2 && raw_hash_input == 8264 && watch_bytes[0] == CELL && watch_reads[0] == 1 && aux_write_calls && aux_read_bytes); counters("xattr-target-first-zero-reloaded"); memo_target_enabled = 0;
        unsigned char target[] = "shared"; if (binary) target[2] = 0; xattr_expect(h, retained ? 1 : 0, 3, "key", 3, target, 6); xattr_expect(h, 1, 3, "key", 3, target, 6); if (!binary) symlink_expect(h, 2, 3, "shared", 6);
        image_unwritten(); close_image(h); watch_count = 0; file_digest("image", after_digest, &after_length); assert(length == after_length && !memcmp(digest, after_digest, 32)); assert(!lstat("image", &after_identity)); identical_identity(&identity, &after_identity); retain(2531 + (int)(retained * 2 + binary));
    }
    /* Binary xattrs remain valid; only the later retained symlink rejects the same NUL target. */
    f = xattr_eviction_fixture(0, 1, 1); assert(xattr_guard(f.p, f.p, f.n)); space = namespace_at(f.p, f.p, f.n); attrs = record(f.p, space + 280, f.n); extent = record(f.p, attrs + 640 + 280, f.n); unsigned char target_ref[56]; memcpy(target_ref, extent + 648, 56); xattr_sparse_save(&f);
    reset("", 0); memo_target_start(target_ref, 2, 1); h = NULL; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED);
    assert(!h && r.phase == SFS_PHASE_READ && !r.system_errno && recovery.slots[0].status == SFS_CORRUPT && recovery.slots[1].status == SFS_CORRUPT && raw_hashes == 4 && raw_hash_input == 16528); memo_target_check(2, 0); memo_target_enabled = 0; watch_count = 0; image_unwritten();
}

/* Separate0.6 graph helpers leave the qualified0.5 corruption guard strict. */
static int hardlink_row_order(const void *left, const void *right) {
    const unsigned char *a = left, *b = right;
    if (get64(a) != get64(b)) return get64(a) < get64(b) ? -1 : 1;
    return xattr_key_compare(a + 12, get32(a + 8), b + 12, get32(b + 8));
}
static void hardlink_row(unsigned char *row, sfs_inode parent, const char *name, sfs_inode id) {
    size_t n = strlen(name); assert(n && n <= 255); memset(row, 0, 280); put64(row, parent); put32(row + 8, (uint32_t)n); memcpy(row + 12, name, n); put64(row + 267, id);
}
static fixture_node hardlink_space(fixture *f, fixture_node inodes, fixture_node names, fixture_node attrs, uint64_t count, uint64_t names_count, uint64_t next) {
    unsigned char p[CELL]; envelope(f, p, 2); memcpy(p + 64, inodes.ref, 56); memcpy(p + 120, names.ref, 56); memcpy(p + 280, attrs.ref, 56);
    put64(p + 176, next); put64(p + 184, count); put64(p + 336, names_count); fixture_tuple(p + 192, SFS_DIRECTORY, 0); return append_cell(f, 2, p);
}
static fixture_node hardlink_catalog(fixture *f, fixture_node history) {
    unsigned char row[328] = {0}; put32(row, 1); memcpy(row + 8, history.ref, 56); put32(row + 64, 3); memcpy(row + 68, "old", 3); return tree(f, 4, row, 1);
}
static fixture hardlink_fixture(unsigned links, unsigned parents, unsigned attrs, unsigned other_links) {
    assert(links && links <= 3 && parents <= 2 && attrs <= 2 && other_links && other_links <= 2);
    fixture f = fixture_start(); f.minor = 6; put32(f.p + 12, 6); unsigned char raw[CELL] = {0}; memcpy(raw, "old", 3); fixture_node payload = append_cell(&f, 6, raw);
    unsigned char extent_row[72] = {0}; memcpy(extent_row + 8, payload.ref, 56); put16(extent_row + 64, 3); fixture_node extent = tree(&f, 3, extent_row, 1);
    unsigned char names[7 * 280], owned[3 * 280], others[2 * 280]; unsigned total = 0; hardlink_row(names + total++ * 280, 1, "p", 2); hardlink_row(names + total++ * 280, 1, "q", 3);
    for (unsigned i = 0; i < links; i++) { const char *key = i == 0 ? "a" : i == 1 ? "b" : "c"; hardlink_row(owned + i * 280, parents ? 2 : 1, key, 4); memcpy(names + total++ * 280, owned + i * 280, 280); }
    for (unsigned i = 0; i < other_links; i++) { hardlink_row(others + i * 280, 1, i ? "other2" : "other", 5); memcpy(names + total++ * 280, others + i * 280, 280); }
    fixture_node reverse = {0}, reverse_other = {0}; if (links > 1) reverse = tree(&f, 6, owned, links); if (other_links > 1) reverse_other = tree(&f, 6, others, other_links);
    unsigned char inode[4 * 496] = {0};
    for (unsigned i = 0; i < 4; i++) {
        unsigned char *row = inode + i * 496; unsigned kind = i < 2 ? SFS_DIRECTORY : SFS_FILE; const unsigned char *name = i == 2 ? owned : i == 3 ? others : names + i * 280;
        put64(row, i + 2); put64(row + 8, get64(name)); put32(row + 16, kind); put32(row + 20, get32(name + 8)); memcpy(row + 88, name + 12, get32(name + 8)); put64(row + 344, i == 2 ? links : i == 3 ? other_links : 1);
        fixture_tuple(row + 352, kind, i >= 2 ? 1 : 0);
        if (i >= 2) { put64(row + 24, 3); memcpy(row + 32, extent.ref, 56); memcpy(row + 440, i == 2 ? reverse.ref : reverse_other.ref, 56); }
    }
    fixture_node inodes = tree(&f, 1, inode, 4); qsort(names, total, 280, hardlink_row_order); fixture_node global = tree(&f, 2, names, total);
    unsigned char attributes[3 * 352]; for (unsigned i = 0; i < attrs; i++) xattr_row(attributes + i * 352, 4, i ? "y" : "x", 1, 3, extent.ref, 1);
    xattr_row(attributes + attrs * 352, 5, "keep", 4, 3, extent.ref, 1); fixture_node attribute = tree(&f, 5, attributes, attrs + 1);
    fixture_node history = hardlink_space(&f, inodes, global, attribute, 4, total, 6), catalog = hardlink_catalog(&f, history), current = hardlink_space(&f, inodes, global, attribute, 4, total, 6);
    finish_fixture(&f, current, catalog); return f;
}
static unsigned hardlink_stride(unsigned map, unsigned level) {
    assert(map >= 1 && map <= 6);
    return level ? (map == 2 || map == 5 || map == 6 ? 328 : 72) : map == 1 ? 496 : map == 2 || map == 6 ? 280 : map == 3 ? 72 : map == 4 ? 328 : 352;
}
static unsigned hardlink_edge(unsigned map, unsigned level) {
    if (level) return map == 2 || map == 5 || map == 6 ? 271 : 16;
    return map == 1 ? 32 : map == 5 ? 280 : 8;
}
static void hardlink_fences(unsigned char *p, unsigned char *cell, unsigned map, unsigned level, size_t n) {
    unsigned count = get16(cell + 70); assert(count && count <= 48); unsigned stride = hardlink_stride(map, level); unsigned char low[263] = {0}, high[263] = {0}; uint16_t lo, hi;
    if (level) {
        unsigned edge = hardlink_edge(map, level); unsigned char *first = record(p, cell + 640 + edge, n), *last = record(p, cell + 640 + (count - 1) * stride + edge, n);
        lo = get16(first + 88); hi = get16(last + 90); assert(lo <= 263 && hi <= 263); memcpy(low, first + 112, lo); memcpy(high, last + 375, hi);
    } else { row_key(map, cell + 640, low, &lo); row_key(map, cell + 640 + (count - 1) * stride, high, &hi); }
    put16(cell + 88, lo); put16(cell + 90, hi); memset(cell + 112, 0, 526); memcpy(cell + 112, low, lo); memcpy(cell + 375, high, hi);
}
static void hardlink_repair_ref(unsigned char *p, const unsigned char *topology, unsigned char *ref, const unsigned char *old_ref, size_t n, unsigned depth, int raw_hashes_too) {
    assert(depth < 32 && !memcmp(ref, old_ref, 24)); if (!get32(ref)) { assert(!memcmp(ref, (unsigned char[56]){0}, 56)); return; }
    assert(!memcmp(ref, old_ref, 24)); unsigned char *cell = record(p, ref, n); const unsigned char *old = record((unsigned char *)topology, old_ref, n); unsigned type = get32(ref);
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) hardlink_repair_ref(p, topology, cell + 64 + i * 56, old + 64 + i * 56, n, depth + 1, raw_hashes_too);
    if (type == 2) hardlink_repair_ref(p, topology, cell + 280, old + 280, n, depth + 1, raw_hashes_too);
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = hardlink_stride(map, level), edge = hardlink_edge(map, level);
        for (unsigned i = 0; i < count; i++) if (level || (map != 2 && map != 6)) hardlink_repair_ref(p, topology, cell + 640 + i * stride + edge, old + 640 + i * stride + edge, n, depth + 1, raw_hashes_too);
        if (!level && map == 1) for (unsigned i = 0; i < count; i++) hardlink_repair_ref(p, topology, cell + 640 + i * stride + 440, old + 640 + i * stride + 440, n, depth + 1, raw_hashes_too);
        hardlink_fences(p, cell, map, level, n);
    }
    if (type != 6 || raw_hashes_too) ref_hash(p, ref, n);
}
static void hardlink_repair(unsigned char *p, const unsigned char *topology, size_t n) {
    for (unsigned i = 0; i < 2; i++) { hardlink_repair_ref(p, topology, p + i * CELL + 48, topology + i * CELL + 48, n, 0, 1); slot_hash(p + i * CELL); }
}
static int hardlink_ref_guard(unsigned char *p, const unsigned char *topology, const unsigned char *ref, const unsigned char *old_ref, size_t n, uint64_t parent, unsigned depth) {
    if (memcmp(ref, old_ref, 24)) return 0;
    if (!get32(ref)) return !memcmp(ref, (unsigned char[56]){0}, 56);
    if (depth >= 32 || memcmp(ref, old_ref, 24)) return 0; uint64_t at = get64(ref + 8); unsigned type = get32(ref);
    if (at < 8192 || at % CELL || at >= parent || at > n || CELL > n - at || get64(ref + 16) != CELL || get32(ref + 4)) return 0;
    unsigned char checked[56]; memcpy(checked, ref, 56); ref_hash(p, checked, n); if (memcmp(checked + 24, ref + 24, 32)) return 0;
    unsigned char *cell = p + at; const unsigned char *old = topology + at;
    if (type != 6 && (memcmp(cell, "SFSREC06", 8) || get32(cell + 8) != type || get32(cell + 12) || get64(cell + 16) != 4032 || memcmp(cell + 24, p + 24, 16) || memcmp(cell + 40, (unsigned char[24]){0}, 24))) return 0;
    if (type == 4 || type == 2) for (unsigned i = 0; i < 2; i++) if (!hardlink_ref_guard(p, topology, cell + 64 + i * 56, old + 64 + i * 56, n, at, depth + 1)) return 0;
    if (type == 2 && !hardlink_ref_guard(p, topology, cell + 280, old + 280, n, at, depth + 1)) return 0;
    if (type == 5) {
        unsigned map = get32(old + 64), level = get16(old + 68), count = get16(old + 70), stride = hardlink_stride(map, level), edge = hardlink_edge(map, level);
        if (get32(cell + 64) != map || get16(cell + 68) != level || get16(cell + 70) != count) return 0;
        if (!count || count > 48 || 640 + count * stride > CELL || memcmp(cell + 640 + count * stride, (unsigned char[CELL]){0}, CELL - 640 - count * stride)) return 0;
        for (unsigned i = 0; i < count; i++) {
            const unsigned char *child_ref = cell + 640 + i * stride + edge;
            if ((level || (map != 2 && map != 6)) && !hardlink_ref_guard(p, topology, child_ref, old + 640 + i * stride + edge, n, at, depth + 1)) return 0;
            if (!level && map == 1 && !hardlink_ref_guard(p, topology, cell + 640 + i * stride + 440, old + 640 + i * stride + 440, n, at, depth + 1)) return 0;
            if (!level && i) { unsigned char a[263], b[263]; uint16_t an, bn; row_key(map, cell + 640 + (i - 1) * stride, a, &an); row_key(map, cell + 640 + i * stride, b, &bn); if (xattr_key_compare(a, an, b, bn) >= 0) return 0; }
            if (level) {
                unsigned char *child = record(p, child_ref, n); const unsigned char *key = cell + 640 + i * stride + 8; unsigned key_n = get32(cell + 640 + i * stride);
                if (get32(child + 64) != get32(cell + 64) || (unsigned)get16(child + 68) + 1 != level || key_n != get16(child + 88) || memcmp(key, child + 112, key_n)) return 0;
                if (i) { unsigned char *previous = record(p, cell + 640 + (i - 1) * stride + edge, n); if (xattr_key_compare(previous + 375, get16(previous + 90), child + 112, get16(child + 88)) >= 0) return 0; }
            }
        }
        unsigned actual = get16(cell + 70); if (!actual || actual > 48) return 0;
        unsigned char low[263], high[263]; uint16_t lo, hi;
        if (level) { unsigned char *first = record(p, cell + 640 + edge, n), *last = record(p, cell + 640 + (actual - 1) * stride + edge, n); lo = get16(first + 88); hi = get16(last + 90); memcpy(low, first + 112, lo); memcpy(high, last + 375, hi); }
        else { row_key(map, cell + 640, low, &lo); row_key(map, cell + 640 + (actual - 1) * stride, high, &hi); }
        if (get16(cell + 88) != lo || get16(cell + 90) != hi || memcmp(cell + 112, low, lo) || memcmp(cell + 375, high, hi)) return 0;
    }
    return 1;
}
static int hardlink_guard(unsigned char *p, const unsigned char *topology, size_t n) {
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *slot = p + i * CELL, checked[CELL]; memcpy(checked, slot, CELL); slot_hash(checked);
        if (memcmp(slot, "SFSIMG01", 8) || get32(slot + 8) || get32(slot + 12) != 6 || get64(slot + 16) || memcmp(checked + 112, slot + 112, 32)) return 0;
        if (!hardlink_ref_guard(p, topology, slot + 48, topology + i * CELL + 48, n, get64(slot + 104), 0)) return 0;
    }
    return 1;
}
/* Only the exact listed old->new edge is allowed to change physical identity. */
static void hardlink_edge_change(unsigned char *p, unsigned char *topology, const unsigned char *control, size_t n, size_t at, const unsigned char expected[56], const unsigned char replacement[56]) {
    assert(at + 56 <= n && !memcmp(control + at, expected, 56) && !memcmp(p + at, expected, 56) && !memcmp(topology + at, expected, 56));
    if (get32(replacement)) {
        assert(get32(replacement) == 5 && !get32(replacement + 4) && get64(replacement + 16) == CELL && get64(replacement + 8) < at / CELL * CELL);
        unsigned char checked[56]; memcpy(checked, replacement, 56); ref_hash((unsigned char *)control, checked, n); assert(!memcmp(checked + 24, replacement + 24, 32));
        unsigned char *cell = record((unsigned char *)control, replacement, n); assert(get32(cell + 64) == 6 && !get16(cell + 68));
    } else assert(!memcmp(replacement, (unsigned char[56]){0}, 56));
    memcpy(p + at, replacement, 56); memcpy(topology + at, replacement, 56);
    printf("{\"case\":\"declared-hardlink-edge\",\"locator\":%llu,\"old_offset\":%llu,\"new_offset\":%llu}\n", (unsigned long long)at, (unsigned long long)get64(expected + 8), (unsigned long long)get64(replacement + 8));
}
static void hardlink_leaf_change(unsigned char *p, unsigned char *topology, const unsigned char *control, size_t n, size_t at, const unsigned char *rows, unsigned count) {
    assert(at + CELL <= n && !memcmp(p + at, control + at, CELL) && !memcmp(topology + at, control + at, CELL));
    unsigned char *cell = p + at; unsigned map = get32(cell + 64); assert((map == 2 || map == 6) && !get16(cell + 68) && count && count <= 12);
    put16(cell + 70, (uint16_t)count); memset(cell + 640, 0, CELL - 640); memcpy(cell + 640, rows, count * 280);
    memcpy(topology + at, cell, CELL);
    printf("{\"case\":\"declared-hardlink-row-edit\",\"offset\":%llu,\"map\":%u,\"old_rows\":%u,\"new_rows\":%u}\n", (unsigned long long)at, map, get16(control + at + 70), count);
}
static fixture hardlink_name_limit_fixture(void) {
    fixture f = fixture_start(); f.minor = 6; put32(f.p + 12, 6);
    unsigned char *names = calloc(1024, 280); assert(names);
    for (unsigned i = 0; i < 1024; i++) { char key[32]; snprintf(key, sizeof(key), "alias%04u", i); hardlink_row(names + i * 280, 1, key, 2); }
    fixture_node reverse = tree(&f, 6, names, 1024), global = tree(&f, 2, names, 1024); free(names);
    assert(reverse.level == 3 && global.level == 3);
    unsigned char inode[496] = {0}; put64(inode, 2); put64(inode + 8, 1); put32(inode + 16, SFS_FILE); put32(inode + 20, 9); memcpy(inode + 88, "alias0000", 9); put64(inode + 344, 1024); fixture_tuple(inode + 352, SFS_FILE, 0); memcpy(inode + 440, reverse.ref, 56);
    fixture_node inodes = tree(&f, 1, inode, 1), empty = {0}, space = hardlink_space(&f, inodes, global, empty, 1, 1024, 3); finish_fixture(&f, space, empty); return f;
}
static void hardlink_mixed_versions(void) {
    fixture f = xattr_fixture(1, 0, 0); assert(xattr_guard(f.p, f.p, f.n)); unsigned char slot[CELL]; memcpy(slot, f.p, CELL); size_t old_n = f.n;
    f.minor = 6; fixture_node empty = {0}, space = namespace_cell(&f, empty, empty, 2, 0); finish_fixture(&f, space, empty); memcpy(f.p, slot, CELL);
    assert(xattr_ref_guard(f.p, f.p, f.p + 48, slot + 48, f.n, old_n, 0));
    assert(hardlink_ref_guard(f.p, f.p, f.p + CELL + 48, f.p + CELL + 48, f.n, f.n, 0)); fixture_save(&f);
    sfs_image *h = NULL; sfs_result r; sfs_recovery recovery; reset("", 0);
    XEXPECT(sfs_image_open(root, "image", &h, &r), SFS_RECOVERY_REQUIRED); assert(!h); image_unwritten();
    XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    assert(!recovery.pair_valid && recovery.slots[0].status == SFS_OK && recovery.slots[1].status == SFS_OK && recovery.slots[0].coverage == SFS_COVERAGE_FULL_REACHABLE && recovery.slots[1].coverage == SFS_COVERAGE_FULL_REACHABLE);
    for (unsigned slot_id = 0; slot_id < 2; slot_id++) { XEXPECT(sfs_image_select(h, slot_id, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); sfs_metadata_entry m; XEXPECT(sfs_image_stat_metadata(h, 0, 1, &m, &r), SFS_OK); assert(m.link_count == 1); }
    image_unwritten(); close_image(h); retain(3008);
}

/* Format0.6 identity is independent of the name used to resolve it. */
static void hardlink_create(sfs_image **h, uint64_t capacity) {
    sfs_result r; sfs_metadata_initial initial = metadata_input(SFS_DIRECTORY);
    reset("", 0); metadata_clock(1100);
    XEXPECT(sfs_image_create_metadata_version(root, "image", capacity, 6, &initial, h, &r), SFS_OK);
    assert(clock_calls == 1 && r.coverage == SFS_COVERAGE_FULL_REACHABLE);
}
static sfs_metadata_entry hardlink_get(sfs_image *h, sfs_view view, sfs_inode id, uint64_t links) {
    sfs_result r; sfs_metadata_entry m; unsigned calls = clock_calls;
    XEXPECT(sfs_image_stat_metadata(h, view, id, &m, &r), SFS_OK);
    assert(m.entry.inode == id && m.link_count == links && r.coverage == SFS_COVERAGE_TOUCHED && calls == clock_calls);
    return m;
}
static void hardlink_name(sfs_image *h, sfs_view view, sfs_inode parent, const char *name, sfs_inode id) {
    sfs_result r; sfs_entry e;
    XEXPECT(sfs_image_lookup(h, view, parent, name, strlen(name), &e, &r), SFS_OK);
    assert(e.inode == id && e.parent == parent && e.name_length == strlen(name) && !memcmp(e.name, name, e.name_length));
}
static void hardlink_absent(sfs_image *h, sfs_view view, sfs_inode parent, const char *name) {
    sfs_result r; sfs_entry e, canary; memset(&canary, 0xA5, sizeof(canary)); e = canary;
    XEXPECT(sfs_image_lookup(h, view, parent, name, strlen(name), &e, &r), SFS_NOT_FOUND);
    assert(!memcmp(&e, &canary, sizeof(e)));
}
static void hardlink_owner_times(sfs_metadata_entry before, sfs_metadata_entry after, int64_t now) {
    assert(timestamp_is(after.change, now, (uint32_t)(now + 1)));
    before.entry = after.entry; before.link_count = after.link_count; before.change = after.change;
    metadata_equal(&before, &after);
}
static void hardlink_parent_times(sfs_metadata_entry before, sfs_metadata_entry after, int64_t now) {
    assert(timestamp_is(after.change, now, (uint32_t)(now + 1)) && timestamp_equal(after.change, after.modification));
    before.change = after.change; before.modification = after.modification; metadata_equal(&before, &after);
}
static void hardlink_counts(uint64_t inodes, uint64_t names, uint64_t next) {
    size_t n; unsigned char *p = bytes("image", &n), *space = namespace_at(p, selected_slot(p), n);
    assert(get32(selected_slot(p) + 12) == 6 && get64(space + 184) == inodes && get64(space + 336) == names && get64(space + 176) == next); free(p);
}
static void cache_release(sfs_image *h);
/* Numeric positions are checked against legacy cookies, never decoded from them. */
static unsigned position_equivalence(sfs_image *h, sfs_view view, sfs_inode parent, const sfs_result *binding, unsigned minor) {
    sfs_cookie legacy = {0}, numeric = {0}; sfs_result r, old; unsigned count = 0; size_t n;
    unsigned char *before = bytes("image", &n); unsigned made = aux_created; reset("", 0); clock_calls = 0;
    for (;;) {
        sfs_entry a, b, canary; memset(&canary, 0xA5, sizeof(canary)); a = b = canary; int fa = 99, fb = 99; uint64_t position = UINT64_MAX;
        ok(sfs_image_next(h, view, parent, &legacy, &a, &fa, &old), &old);
        XEXPECT(sfs_image_next_position(h, view, parent, &numeric, &b, &position, &fb, &r), SFS_OK);
        assert(fa == fb && old.status == r.status && old.coverage == r.coverage && !r.system_errno);
        assert(!memcmp(&legacy, &numeric, sizeof(legacy)));
        if (!fb) { assert(position == UINT64_MAX && !memcmp(&a, &canary, sizeof(a)) && !memcmp(&b, &canary, sizeof(b))); break; }
        equal_entry(&a, &b);
        assert(position >= 17); count++;
        sfs_cookie reconstructed, expected;
        XEXPECT(sfs_image_resume_after_position(h, view, binding->generation, binding->root_digest, parent, position, &reconstructed, &r), SFS_OK);
        assert(r.coverage == SFS_COVERAGE_TOUCHED && !r.system_errno && !memcmp(&numeric, &reconstructed, sizeof(numeric)));
        if (minor == 6) XEXPECT(sfs_image_resume_after_name(h, view, binding->generation, binding->root_digest, parent, b.name, b.name_length, &expected, &r), SFS_OK);
        else XEXPECT(sfs_image_resume_after(h, view, binding->generation, binding->root_digest, parent, b.inode, &expected, &r), SFS_OK);
        assert(!memcmp(&expected, &reconstructed, sizeof(expected)));
        assert(sfs_image_resume_after_position(h, view, binding->generation, binding->root_digest, parent, position, &reconstructed, NULL) == SFS_OK);
    }
    assert(!clock_calls && !raw_hash_input && !aux_write_calls && aux_created == made); image_unwritten(); unchanged("image", before, n); free(before); return count;
}
static void position_failure(sfs_image *h, sfs_view view, const sfs_result *binding, sfs_inode parent, uint64_t position,
                             enum sfs_status expected, enum sfs_phase phase, int error) {
    sfs_result r; sfs_cookie output, canary; memset(&canary, 0xA5, sizeof(canary)); output = canary;
    XEXPECT(sfs_image_resume_after_position(h, view, binding->generation, binding->root_digest, parent, position, &output, &r), expected);
    assert(r.phase == phase && r.system_errno == error && !memcmp(&output, &canary, sizeof(output)) && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
    image_unwritten();
}

static void hardlink_versions(void) {
    sfs_image *h; sfs_result r; sfs_metadata_initial initial = metadata_input(SFS_DIRECTORY);
    for (unsigned minor = 2; minor <= 6; minor++) {
        reset("", 0); metadata_clock(1101);
        if (minor == 2) XEXPECT(sfs_image_create(root, "image", TEST_CAPACITY, &h, &r), SFS_OK);
        else if (minor == 3) XEXPECT(sfs_image_create_metadata(root, "image", TEST_CAPACITY, &initial, &h, &r), SFS_OK);
        else XEXPECT(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, minor, &initial, &h, &r), SFS_OK);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode id = add(h, 1, "file", SFS_FILE);
        XEXPECT(sfs_image_write(h, id, 0, "old", 3, &r), SFS_OK); metadata_commit(h); symlink_full(h);
        if (minor >= 3) { hardlink_get(h, 0, id, 1); hardlink_get(h, 0, 1, 1); }
        size_t n; unsigned char *p = bytes("image", &n), *space = namespace_at(p, selected_slot(p), n);
        unsigned stride = minor == 2 ? 352 : minor == 6 ? 496 : 440;
        unsigned char *row = leaf_row(p, space + 64, id, n, stride), *leaf = record(p, space + 64, n);
        assert(!memcmp(leaf + 640, row, stride) && !memcmp(row + stride, (unsigned char[496]){0}, stride));
        assert(get64(row + 344) == (minor == 6 ? 1 : 0));
        if (minor == 6) assert(!get32(row + 440) && get64(space + 336) == 1); else assert(!get64(space + 336)); assert(!get16(leaf + 68) && get16(leaf + 70) == 1); free(p);
        sfs_result binding = xattr_binding(h); assert(position_equivalence(h, 0, 1, &binding, minor) == 1);
        sfs_cookie first_cookie = {0}; sfs_entry first_entry; uint64_t first_position = 0; int first_found = 99;
        XEXPECT(sfs_image_next_position(h, 0, 1, &first_cookie, &first_entry, &first_position, &first_found, &r), SFS_OK);
        assert(first_found && first_entry.inode == id && first_position == 17);
        p = bytes("image", &n); space = namespace_at(p, selected_slot(p), n); watch_payload(0, raw_ref(p, leaf_row(p, space + 64, id, n, stride), 0, n)); watch_count = 1;
        uint64_t raw_as_position = watch_at[0] + 1; read_at[0] = watch_at[0]; free(p); cache_release(h); reset("candidate_reads", 1); watch_clear();
        position_failure(h, 0, &binding, 1, raw_as_position, SFS_INVALID, SFS_PHASE_READ, 0); assert(!hit && !watch_reads[0] && !raw_hash_input); watch_count = 0; reset("", 0);
        sfs_cookie cookie, canary; memset(&canary, 0xA5, sizeof(canary)); cookie = canary;
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, id, 0, "pending", 7, &r), SFS_OK);
        p = bytes("image", &n); reset("", 0); clock_calls = 0;
        if (minor < 6) {
            XEXPECT(sfs_image_link(h, id, 1, "alias", 5, &r), SFS_UNSUPPORTED); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
            XEXPECT(sfs_image_unlink(h, 1, "file", 4, &r), SFS_UNSUPPORTED); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
            XEXPECT(sfs_image_rename_entry(h, 1, "file", 4, 1, "new", 3, &r), SFS_UNSUPPORTED); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
            XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 1, "file", 4, &cookie, &r), SFS_UNSUPPORTED);
            assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !memcmp(&cookie, &canary, sizeof(cookie)) && !clock_calls); image_unwritten(); unchanged("image", p, n);
        }
        free(p); metadata_commit(h); expect(h, 0, id, "pending");
        binding = xattr_binding(h); XEXPECT(sfs_image_resume_after(h, 0, binding.generation, binding.root_digest, 1, id, &cookie, &r), SFS_OK);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_rename(h, id, 1, "renamed", 7, &r), SFS_OK); metadata_commit(h); hardlink_name(h, 0, 1, "renamed", id);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_remove(h, id, &r), SFS_OK); metadata_commit(h);
        binding = xattr_binding(h); assert(!position_equivalence(h, 0, 1, &binding, minor)); position_failure(h, 0, &binding, 1, 17, SFS_INVALID, SFS_PHASE_READ, 0); close_image(h);
        open_image(&h); symlink_full(h); close_image(h); p = bytes("image", &n); assert(get32(selected_slot(p) + 12) == minor); free(p); retain(3000 + (int)minor);
    }
    reset("", 0); metadata_clock(1102); h = (sfs_image *)(uintptr_t)1; uint64_t calls = allocation_calls;
    XEXPECT(sfs_image_create_metadata_version(root, "image", TEST_CAPACITY, 7, &initial, &h, &r), SFS_UNSUPPORTED);
    assert(!h && !clock_calls && allocation_calls == calls && r.phase == SFS_PHASE_NONE && !r.system_errno && access("image", F_OK) < 0 && errno == ENOENT); image_unwritten();
    hardlink_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode link = symlink_add(h, 1, "link", "../opaque", 9);
    XEXPECT(sfs_image_set_xattr(h, link, "key", 3, "value", 5, &r), SFS_OK); metadata_commit(h); symlink_expect(h, 0, link, "../opaque", 9); xattr_expect(h, 0, link, "key", 3, "value", 5); symlink_full(h);
    unsigned char maximal[255]; memset(maximal, 'z', sizeof(maximal)); maximal[0] = 1;
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, link, 1, maximal, sizeof(maximal), &r), SFS_OK); metadata_commit(h);
    sfs_metadata_entry linked = hardlink_get(h, 0, link, 2); assert(linked.entry.parent == 1 && linked.entry.name_length == sizeof(maximal) && !memcmp(linked.entry.name, maximal, sizeof(maximal))); symlink_expect(h, 0, link, "../opaque", 9);
    sfs_result long_binding = xattr_binding(h); assert(position_equivalence(h, 0, 1, &long_binding, 6) == 2);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, 1, maximal, sizeof(maximal), &r), SFS_OK); metadata_commit(h); hardlink_get(h, 0, link, 1); symlink_full(h); close_image(h); retain(3007); hardlink_mixed_versions();
}
static void hardlink_shared(void) {
    sfs_image *h; sfs_result r; hardlink_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    sfs_inode p = add(h, 1, "p", SFS_DIRECTORY), q = add(h, 1, "q", SFS_DIRECTORY), id; sfs_metadata_initial initial = metadata_input(SFS_FILE);
    XEXPECT(sfs_image_add_metadata(h, p, "source", 6, SFS_FILE, &initial, &id, &r), SFS_OK);
    XEXPECT(sfs_image_resize(h, id, 2 * CELL + 3, &r), SFS_OK);
    XEXPECT(sfs_image_write(h, id, 0, "abc", 3, &r), SFS_OK); XEXPECT(sfs_image_write(h, id, 2 * CELL, "XYZ", 3, &r), SFS_OK);
    static const unsigned char user[] = "user attribute\0\xff", fork[] = "resource\0fork\xff";
    XEXPECT(sfs_image_set_xattr(h, id, "user.stallionfs-test", 20, user, sizeof(user) - 1, &r), SFS_OK);
    XEXPECT(sfs_image_set_xattr(h, id, "com.apple.ResourceFork", 22, fork, sizeof(fork) - 1, &r), SFS_OK); metadata_commit(h);
    sfs_result position_binding = xattr_binding(h); assert(position_equivalence(h, 0, p, &position_binding, 6) == 1);
    sfs_metadata_entry old = hardlink_get(h, 0, id, 1), pa = hardlink_get(h, 0, p, 1), pb = hardlink_get(h, 0, q, 1);
    assert(old.referenced_data_bytes == 2 * CELL && old.entry.size == 2 * CELL + 3 && old.mode == initial.mode && old.uid == initial.uid && old.gid == initial.gid && old.flags == initial.flags && timestamp_equal(old.birth, initial.birth) && timestamp_equal(old.access, initial.access));
    sfs_view before, after; XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_snapshot(h, "before", 6, &before, &r), SFS_OK);
    metadata_clock(1120); XEXPECT(sfs_image_link(h, id, q, "alias", 5, &r), SFS_OK); assert(clock_calls == 1); metadata_commit(h);
    hardlink_name(h, 0, p, "source", id); hardlink_name(h, 0, q, "alias", id); sfs_metadata_entry m = hardlink_get(h, 0, id, 2); hardlink_owner_times(old, m, 1120);
    sfs_metadata_entry parent = hardlink_get(h, 0, q, 1); hardlink_parent_times(pb, parent, 1120); parent = hardlink_get(h, 0, p, 1); metadata_equal(&pa, &parent); hardlink_get(h, before, id, 1); hardlink_absent(h, before, q, "alias");
    position_binding = xattr_binding(h); assert(position_equivalence(h, 0, q, &position_binding, 6) == 1); assert(position_equivalence(h, before, q, &position_binding, 6) == 0);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_snapshot(h, "after", 5, &after, &r), SFS_OK); metadata_commit(h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, p, "source", 6, &r), SFS_OK); XEXPECT(sfs_image_abort(h, &r), SFS_OK); hardlink_get(h, 0, id, 2);
    sfs_entry alias; XEXPECT(sfs_image_lookup(h, 0, q, "alias", 5, &alias, &r), SFS_OK);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(1121); XEXPECT(sfs_image_write(h, alias.inode, 1, "new", 3, &r), SFS_OK); XEXPECT(sfs_image_resize(h, id, CELL + 5, &r), SFS_OK);
    sfs_metadata_update update = {0}; update.fields = SFS_META_UID | SFS_META_FLAGS; update.uid = 77; update.flags = 1;
    XEXPECT(sfs_image_set_metadata(h, alias.inode, &update, &r), SFS_OK); XEXPECT(sfs_image_set_xattr(h, alias.inode, "user.stallionfs-test", 20, "changed", 7, &r), SFS_OK); metadata_commit(h);
    unsigned char expected[CELL + 5] = {0}, actual[sizeof(expected)]; memcpy(expected, "anew", 4); size_t got = 0;
    XEXPECT(sfs_image_read(h, 0, id, 0, actual, sizeof(actual), &got, &r), SFS_OK); assert(got == sizeof(actual) && !memcmp(actual, expected, got));
    m = hardlink_get(h, 0, id, 2); assert(m.uid == 77 && m.flags == 1 && m.referenced_data_bytes == CELL);
    xattr_expect(h, 0, id, "user.stallionfs-test", 20, "changed", 7); xattr_expect(h, after, id, "user.stallionfs-test", 20, user, sizeof(user) - 1);
    xattr_expect(h, 0, id, "com.apple.ResourceFork", 22, fork, sizeof(fork) - 1);
    parent = hardlink_get(h, 0, p, 1); metadata_equal(&pa, &parent); parent = hardlink_get(h, 0, q, 1); hardlink_parent_times(pb, parent, 1120);
    unsigned char *historical = calloc(2 * CELL + 3, 1), *historical_read = malloc(2 * CELL + 3); assert(historical && historical_read); memcpy(historical, "abc", 3); memcpy(historical + 2 * CELL, "XYZ", 3);
    for (unsigned i = 0; i < 2; i++) { XEXPECT(sfs_image_read(h, i ? after : before, id, 0, historical_read, 2 * CELL + 3, &got, &r), SFS_OK); assert(got == 2 * CELL + 3 && !memcmp(historical, historical_read, got)); } free(historical); free(historical_read);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_inode sl = symlink_add(h, p, "symbol", "source", 6);
    XEXPECT(sfs_image_set_xattr(h, sl, "target-meta", 11, "opaque", 6, &r), SFS_OK); XEXPECT(sfs_image_link(h, sl, q, "symbol-alias", 12, &r), SFS_OK); metadata_commit(h);
    hardlink_name(h, 0, q, "symbol-alias", sl); hardlink_get(h, 0, sl, 2); symlink_expect(h, 0, sl, "source", 6); xattr_expect(h, 0, sl, "target-meta", 11, "opaque", 6);
    m = hardlink_get(h, 0, id, 2); assert(m.entry.size == sizeof(expected) && m.uid == 77); symlink_full(h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, p, "source", 6, &r), SFS_OK); metadata_commit(h); hardlink_get(h, 0, id, 1); hardlink_absent(h, 0, p, "source"); xattr_expect(h, 0, id, "user.stallionfs-test", 20, "changed", 7); xattr_expect(h, 0, id, "com.apple.ResourceFork", 22, fork, sizeof(fork) - 1);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, q, "alias", 5, &r), SFS_OK); metadata_commit(h);
    hardlink_absent(h, 0, q, "alias"); hardlink_name(h, after, p, "source", id); hardlink_name(h, after, q, "alias", id); hardlink_get(h, before, id, 1); hardlink_get(h, after, id, 2);
    xattr_expect(h, after, id, "com.apple.ResourceFork", 22, fork, sizeof(fork) - 1); symlink_full(h); close_image(h);
    open_image(&h); hardlink_get(h, after, id, 2); symlink_expect(h, 0, sl, "source", 6); symlink_full(h); close_image(h);
}
/* Small independent expected-name set; order is parent big-endian then raw name bytes. */
typedef struct { sfs_inode parent; char name[32]; } hardlink_key;
static int hardlink_key_order(const void *left, const void *right) {
    const hardlink_key *a = left, *b = right;
    return a->parent < b->parent ? -1 : a->parent > b->parent ? 1 : strcmp(a->name, b->name);
}
static void hardlink_group(sfs_image *h, sfs_inode owner, hardlink_key *keys, unsigned count, uint64_t inodes, uint64_t next) {
    qsort(keys, count, sizeof(*keys), hardlink_key_order); sfs_result r; sfs_entry e;
    sfs_metadata_entry m = hardlink_get(h, 0, owner, count);
    assert(m.entry.parent == keys[0].parent && m.entry.name_length == strlen(keys[0].name) && !memcmp(m.entry.name, keys[0].name, m.entry.name_length));
    XEXPECT(sfs_image_stat(h, 0, owner, &e, &r), SFS_OK); assert(e.parent == m.entry.parent && e.name_length == m.entry.name_length && !memcmp(e.name, m.entry.name, e.name_length));
    for (unsigned i = 0; i < count; i++) hardlink_name(h, 0, keys[i].parent, keys[i].name, owner);
    hardlink_counts(inodes, inodes - 1 + count, next);
    size_t n; unsigned char *image = bytes("image", &n), *space = namespace_at(image, selected_slot(image), n), *row = leaf_row(image, space + 64, owner, n, 496);
    if (count == 1) assert(!memcmp(row + 440, (unsigned char[56]){0}, 56));
    else { unsigned char *reverse = record(image, row + 440, n); assert(get32(reverse + 64) == 6); if (count == 2) assert(!get16(reverse + 68) && get16(reverse + 70) == 2); if (count == 13) assert(get16(reverse + 68) == 1); }
    free(image); xattr_expect(h, 0, owner, "owned", 5, "one", 3); symlink_full(h);
}
static void hardlink_transitions(void) {
    sfs_image *h; sfs_result r; hardlink_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    sfs_inode p = add(h, 1, "p", SFS_DIRECTORY), q = add(h, 1, "q", SFS_DIRECTORY), owner = add(h, q, "z", SFS_FILE), other = add(h, 1, "other", SFS_FILE);
    XEXPECT(sfs_image_set_xattr(h, owner, "owned", 5, "one", 3, &r), SFS_OK); XEXPECT(sfs_image_set_xattr(h, other, "keep", 4, "two", 3, &r), SFS_OK); metadata_commit(h);
    hardlink_key keys[13] = {{q, "z"}}; unsigned count = 1; hardlink_group(h, owner, keys, count, 4, 6);
    const hardlink_key added[] = {{p, "z"}, {p, "a"}};
    for (unsigned i = 0; i < 2; i++) { XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, owner, added[i].parent, added[i].name, 1, &r), SFS_OK); metadata_commit(h); keys[count++] = added[i]; hardlink_group(h, owner, keys, count, 4, 6); }
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_rename_entry(h, q, "z", 1, p, "0", 1, &r), SFS_OK); metadata_commit(h);
    for (unsigned i = 0; i < count; i++) if (keys[i].parent == q) keys[i] = (hardlink_key){p, "0"}; hardlink_group(h, owner, keys, count, 4, 6);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_rename_entry(h, p, "0", 1, q, "zz", 2, &r), SFS_OK); metadata_commit(h);
    for (unsigned i = 0; i < count; i++) if (!strcmp(keys[i].name, "0")) keys[i] = (hardlink_key){q, "zz"}; hardlink_group(h, owner, keys, count, 4, 6);
    for (unsigned i = 0; i < 10; i++) {
        hardlink_key k = {q, ""}; snprintf(k.name, sizeof(k.name), "alias%02u", i);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, owner, q, k.name, strlen(k.name), &r), SFS_OK); metadata_commit(h);
        keys[count++] = k; hardlink_group(h, owner, keys, count, 4, 6);
    }
    sfs_view history; XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_snapshot(h, "thirteen", 8, &history, &r), SFS_OK); metadata_commit(h);
    while (count > 1) {
        qsort(keys, count, sizeof(*keys), hardlink_key_order); hardlink_key k = keys[0]; memmove(keys, keys + 1, (--count) * sizeof(*keys));
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, k.parent, k.name, strlen(k.name), &r), SFS_OK); metadata_commit(h); hardlink_group(h, owner, keys, count, 4, 6);
    }
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, keys[0].parent, keys[0].name, strlen(keys[0].name), &r), SFS_OK); metadata_commit(h); hardlink_counts(3, 3, 6);
    sfs_entry e; XEXPECT(sfs_image_stat(h, 0, owner, &e, &r), SFS_NOT_FOUND); xattr_absent(h, 0, owner, "owned"); xattr_expect(h, 0, other, "keep", 4, "two", 3);
    hardlink_get(h, history, owner, 13); xattr_expect(h, history, owner, "owned", 5, "one", 3); symlink_full(h); close_image(h);
}
static void hardlink_names(void) {
    sfs_image *h; sfs_result r; hardlink_create(&h, TEST_CAPACITY); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
    sfs_inode p = add(h, 1, "p", SFS_DIRECTORY), q = add(h, p, "child", SFS_DIRECTORY), empty = add(h, 1, "empty", SFS_DIRECTORY), owner = add(h, 1, "file", SFS_FILE);
    XEXPECT(sfs_image_write(h, owner, 0, "old", 3, &r), SFS_OK); XEXPECT(sfs_image_link(h, owner, q, "a", 1, &r), SFS_OK); XEXPECT(sfs_image_link(h, owner, q, "b", 1, &r), SFS_OK); metadata_commit(h);
    sfs_result binding = xattr_binding(h); assert(position_equivalence(h, 0, q, &binding, 6) == 2); sfs_cookie canary, cookie; memset(&canary, 0xA5, sizeof(canary)); cookie = canary;
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, owner, 0, "pending", 7, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); reset("", 0); clock_calls = 0;
    XEXPECT(sfs_image_link(h, 1, 1, "root", 4, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_link(h, p, 1, "dir-alias", 9, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_link(h, UINT64_MAX, 1, "missing", 7, &r), SFS_NOT_FOUND);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_link(h, owner, owner, "bad-parent", 10, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_link(h, owner, UINT64_MAX, "missing-parent", 14, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_link(h, owner, q, "a", 1, &r), SFS_EXISTS);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_unlink(h, q, "absent", 6, &r), SFS_NOT_FOUND);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_unlink(h, 1, "p", 1, &r), SFS_STATE);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_rename_entry(h, 1, "p", 1, q, "cycle", 5, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_rename_entry(h, q, "a", 1, q, "b", 1, &r), SFS_EXISTS);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_rename_entry(h, q, "absent", 6, q, "absent", 6, &r), SFS_NOT_FOUND);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !clock_calls);
    XEXPECT(sfs_image_rename_entry(h, q, "a", 1, q, "a", 1, &r), SFS_OK);
    XEXPECT(sfs_image_remove(h, owner, &r), SFS_STATE); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
    XEXPECT(sfs_image_rename(h, owner, UINT64_MAX, "new", 3, &r), SFS_STATE); assert(r.phase == SFS_PHASE_NONE && !r.system_errno);
    XEXPECT(sfs_image_resume_after(h, 0, binding.generation, binding.root_digest, q, owner, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    unsigned char too_long[256]; memset(too_long, 'z', sizeof(too_long)); const void *bad[] = {NULL, "", ".", "..", "a/b", "a\0b", too_long}; const size_t lengths[] = {1, 0, 1, 2, 3, 3, 256};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        cookie = canary;
        XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, q, bad[i], lengths[i], &cookie, &r), SFS_INVALID);
        assert(r.phase == SFS_PHASE_NONE && !r.system_errno && !memcmp(&cookie, &canary, sizeof(cookie)));
        if (i < 6) {
            XEXPECT(sfs_image_link(h, owner, q, bad[i], lengths[i], &r), SFS_INVALID);
            XEXPECT(sfs_image_unlink(h, q, bad[i], lengths[i], &r), SFS_INVALID);
            XEXPECT(sfs_image_rename_entry(h, q, "a", 1, q, bad[i], lengths[i], &r), SFS_INVALID);
        }
    }
    cookie = canary;
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, q, "aa", 2, &cookie, &r), SFS_NOT_FOUND); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    XEXPECT(sfs_image_resume_after_name(h, 99, binding.generation, binding.root_digest, q, "a", 1, &cookie, &r), SFS_NOT_FOUND); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, owner, "a", 1, &cookie, &r), SFS_INVALID); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation + 1, binding.root_digest, q, "a", 1, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    unsigned char wrong[32]; memcpy(wrong, binding.root_digest, 32); wrong[0] ^= 1;
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, wrong, q, "a", 1, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    assert(!clock_calls); image_unwritten(); unchanged("image", before, n); free(before); metadata_commit(h); expect(h, 0, owner, "pending"); hardlink_get(h, 0, owner, 3);
    binding = xattr_binding(h); XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, q, "a", 1, &cookie, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_TOUCHED);
    sfs_entry entry; int found = 99; XEXPECT(sfs_image_next(h, 0, q, &cookie, &entry, &found, &r), SFS_OK); assert(found == 1 && entry.inode == owner && entry.parent == q && entry.name_length == 1 && entry.name[0] == 'b');
    XEXPECT(sfs_image_next(h, 0, q, &cookie, &entry, &found, &r), SFS_OK); assert(!found);
    memset(&cookie, 0, sizeof(cookie));
    for (unsigned i = 0; i < 2; i++) { XEXPECT(sfs_image_next(h, 0, q, &cookie, &entry, &found, &r), SFS_OK); assert(found && entry.inode == owner && entry.name_length == 1 && entry.name[0] == 'a' + i); }
    /* NULL diagnostics use only returned statuses, including failure paths. */
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); assert(sfs_image_link(h, owner, q, "null", 4, NULL) == SFS_OK);
    assert(sfs_image_rename_entry(h, q, "null", 4, q, "null2", 5, NULL) == SFS_OK); assert(sfs_image_unlink(h, q, "null2", 5, NULL) == SFS_OK);
    assert(sfs_image_link(h, 1, q, "invalid", 7, NULL) == SFS_INVALID); assert(sfs_image_unlink(h, q, "missing", 7, NULL) == SFS_NOT_FOUND); assert(sfs_image_rename_entry(h, q, "a", 1, q, "b", 1, NULL) == SFS_EXISTS);
    cookie = canary; assert(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, q, "missing", 7, &cookie, NULL) == SFS_NOT_FOUND && !memcmp(&cookie, &canary, sizeof(cookie)));
    assert(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, q, "a", 1, &cookie, NULL) == SFS_OK); metadata_commit(h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_unlink(h, 1, "empty", 5, &r), SFS_OK); metadata_commit(h); XEXPECT(sfs_image_stat(h, 0, empty, &entry, &r), SFS_NOT_FOUND);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_rename(h, owner, 1, "bad/name", 8, &r), SFS_INVALID);
    XEXPECT(sfs_image_link(h, owner, 1, too_long, sizeof(too_long), &r), SFS_LIMIT); assert(r.phase == SFS_PHASE_ADMISSION && !r.system_errno); XEXPECT(sfs_image_commit(h, &r), SFS_STATE);
    for (unsigned operation = 0; operation < 3; operation++) {
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, owner, 0, "discard", 7, &r), SFS_OK); size_t z; unsigned char *saved = bytes("image", &z); reset("", 0); clock_calls = 0;
        if (operation == 0) XEXPECT(sfs_image_unlink(h, q, too_long, sizeof(too_long), &r), SFS_LIMIT);
        else if (operation == 1) XEXPECT(sfs_image_rename_entry(h, q, "a", 1, q, too_long, sizeof(too_long), &r), SFS_LIMIT);
        else XEXPECT(sfs_image_rename(h, owner, 1, too_long, sizeof(too_long), &r), SFS_LIMIT);
        assert(r.phase == SFS_PHASE_ADMISSION && !r.system_errno && !clock_calls); image_unwritten(); unchanged("image", saved, z); free(saved); XEXPECT(sfs_image_commit(h, &r), SFS_STATE); expect(h, 0, owner, "pending");
    }
    sfs_view view; XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_snapshot(h, "names", 5, &view, &r), SFS_OK); metadata_commit(h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_commit(h); symlink_full(h); close_image(h);
    before = bytes("image", &n); struct stat identity, later; assert(!lstat("image", &identity)); reset("", 0); open_readonly(&h, &binding);
    XEXPECT(sfs_image_resume_after_name(h, view, binding.generation, binding.root_digest, q, "a", 1, &cookie, &r), SFS_OK);
    XEXPECT(sfs_image_next(h, view, q, &cookie, &entry, &found, &r), SFS_OK); assert(found && entry.name[0] == 'b'); reset("", 0);
    XEXPECT(sfs_image_link(h, owner, 1, "readonly", 8, &r), SFS_STATE); XEXPECT(sfs_image_unlink(h, q, "a", 1, &r), SFS_STATE); XEXPECT(sfs_image_rename_entry(h, q, "a", 1, q, "b", 1, &r), SFS_STATE);
    image_unwritten(); close_image(h); sfs_recovery recovery;
    XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    cookie = canary; XEXPECT(sfs_image_resume_after_name(h, view, binding.generation, binding.root_digest, q, "a", 1, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    for (unsigned slot = 0; slot < 2; slot++) {
        assert(recovery.slots[slot].status == SFS_OK && recovery.slots[slot].coverage == SFS_COVERAGE_FULL_REACHABLE);
        ok(sfs_image_select(h, slot, &generous, &binding), &binding);
        XEXPECT(sfs_image_resume_after_name(h, view, binding.generation, binding.root_digest, q, "a", 1, &cookie, &r), SFS_OK);
        XEXPECT(sfs_image_next(h, view, q, &cookie, &entry, &found, &r), SFS_OK); assert(found && entry.inode == owner && entry.name[0] == 'b');
        XEXPECT(sfs_image_link(h, owner, 1, "recovery", 8, &r), SFS_STATE);
    }
    image_unwritten(); close_image(h); unchanged("image", before, n); assert(!lstat("image", &later)); identical_identity(&identity, &later); free(before);
}

/* API setup remains small; reservation numbers come from the admitted table. */
static void hardlink_failure_setup(unsigned links, unsigned parent_count, unsigned attributes, sfs_image **handle) {
    sfs_image *h; fixture f = hardlink_fixture(links, parent_count, attributes, 1); assert(hardlink_guard(f.p, f.p, f.n)); fixture_save(&f); reset("", 0); open_image(&h); symlink_full(h); *handle = h;
}
static enum sfs_status hardlink_edit(sfs_image *h, unsigned operation, unsigned parents, sfs_result *r) {
    sfs_inode parent = parents ? 2 : 1, destination = parents == 2 ? 3 : parent;
    if (operation < 2) return sfs_image_link(h, 4, parent, "new", 3, r);
    if (operation < 5) return sfs_image_unlink(h, parent, "a", 1, r);
    return sfs_image_rename_entry(h, parent, "a", 1, destination, "new", 3, r);
}
static void hardlink_reservation_case(unsigned operation, unsigned parents, unsigned pending, unsigned attrs, unsigned fit, unsigned serial) {
    static const unsigned base[] = {13, 21, 9, 15, 14, 18, 33};
    static const unsigned links[] = {1, 2, 2, 3, 1, 1, 2};
    unsigned bound = base[operation] + parents + (pending ? 3 : 0) + (attrs ? 12 : 0);
    if (parents == 2) assert((operation == 5 && bound == (pending ? 23 : 20)) || (operation == 6 && bound == (pending ? 38 : 35)));
    sfs_image *h; sfs_result r; hardlink_failure_setup(links[operation], parents, attrs, &h); close_image(h);
    size_t n; unsigned char *p = bytes("image", &n), *space = namespace_at(p, selected_slot(p), n), *inode = record(p, space + 64, n), *names = record(p, space + 120, n);
    assert(!get16(inode + 68) && get16(inode + 70) == 4 && !get16(names + 68));
    unsigned char *owner = leaf_row(p, space + 64, 4, n, 496);
    if (links[operation] > 1) { unsigned char *reverse = record(p, owner + 440, n); assert(!get16(reverse + 68)); }
    if (attrs) { unsigned char *attributes = record(p, space + 280, n); assert(!get16(attributes + 68)); }
    uint64_t capacity = n + (bound + (pending ? 1 : 0) - (fit ? 0 : 1)) * UINT64_C(4096);
    for (unsigned slot = 0; slot < 2; slot++) { put64(p + slot * CELL + 144, capacity); slot_hash(p + slot * CELL); }
    replace_image(p, n); free(p); reset("", 0); open_image(&h); symlink_full(h);
    sfs_metadata_entry original = hardlink_get(h, 0, 4, links[operation]), parent[2] = {hardlink_get(h, 0, parents ? 2 : 1, 1), hardlink_get(h, 0, 3, 1)};
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); metadata_clock(1199); if (pending) XEXPECT(sfs_image_write(h, pending == 1 ? 4 : 5, 0, "pending", 7, &r), SFS_OK);
    p = bytes("image", &n); assert(capacity - n == (bound - (fit ? 0 : 1)) * UINT64_C(4096)); reset("", 0); metadata_clock(1200);
    enum sfs_status status = hardlink_edit(h, operation, parents, &r); assert(status == r.status); receipt("hardlink-whole-reservation", &r);
    printf("{\"operation\":%u,\"nonroot_parents\":%u,\"pending\":%u,\"owner_xattrs\":%u,\"required_cells\":%u,\"fit\":%s,\"appended_bytes\":%llu}\n", operation, parents, pending, attrs, bound, fit ? "true" : "false", (unsigned long long)image_append_bytes); fflush(stdout);
    if (!fit) {
        assert(status == SFS_LIMIT && r.phase == SFS_PHASE_ADMISSION && !r.system_errno && clock_calls == 1 && r.physical_end == n); image_unwritten(); unchanged("image", p, n);
        XEXPECT(sfs_image_commit(h, &r), SFS_STATE); hardlink_name(h, 0, parents ? 2 : 1, "a", 4); expect(h, 0, 4, "old"); expect(h, 0, 5, "old");
        sfs_metadata_entry after = hardlink_get(h, 0, 4, links[operation]); metadata_equal(&original, &after); after = hardlink_get(h, 0, parents ? 2 : 1, 1); metadata_equal(&parent[0], &after); after = hardlink_get(h, 0, 3, 1); metadata_equal(&parent[1], &after); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_abort(h, &r), SFS_OK);
    } else {
        assert(status == SFS_OK && r.coverage == SFS_COVERAGE_TOUCHED && clock_calls == 1 && image_append_bytes <= (bound - 1) * UINT64_C(4096)); metadata_commit(h); assert(clock_calls == 1);
        if (operation == 4) { sfs_entry e; XEXPECT(sfs_image_stat(h, 0, 4, &e, &r), SFS_NOT_FOUND); for (unsigned i = 0; i < attrs; i++) xattr_absent(h, 0, 4, i ? "y" : "x"); }
        else {
            uint64_t expected_links = operation < 2 ? links[operation] + 1 : operation < 4 ? links[operation] - 1 : links[operation];
            sfs_metadata_entry after = hardlink_get(h, 0, 4, expected_links);
            if (!pending || pending == 2) hardlink_owner_times(original, after, 1200); else assert(after.entry.size == 7 && after.referenced_data_bytes == CELL && timestamp_is(after.change, 1200, 1201) && timestamp_is(after.modification, 1199, 1200));
            expect(h, 0, 4, pending == 1 ? "pending" : "old");
            if (operation < 2 || operation >= 5) hardlink_name(h, 0, parents == 2 ? 3 : parents ? 2 : 1, "new", 4);
        }
        sfs_metadata_entry after = hardlink_get(h, 0, parents ? 2 : 1, 1); hardlink_parent_times(parent[0], after, 1200);
        after = hardlink_get(h, 0, 3, 1); if (parents == 2) hardlink_parent_times(parent[1], after, 1200); else metadata_equal(&parent[1], &after);
        hardlink_counts(operation == 4 ? 3 : 4, 3 + links[operation] + (operation < 2 ? 1 : operation < 5 ? -1 : 0), 6);
        expect(h, 0, 5, pending == 2 ? "pending" : "old"); xattr_expect(h, 0, 5, "keep", 4, "old", 3); symlink_full(h);
    }
    hardlink_get(h, 1, 4, links[operation]); hardlink_name(h, 1, parents ? 2 : 1, "a", 4); expect(h, 1, 4, "old"); expect(h, 1, 5, "old");
    for (unsigned i = 0; i < attrs; i++) xattr_expect(h, 1, 4, i ? "y" : "x", 1, "old", 3);
    close_image(h); free(p); retain(3200 + (int)serial);
}
static void hardlink_capacity(void) {
    unsigned serial = 0;
    for (unsigned op = 0; op < 7; op++) for (unsigned parents = 0; parents < 2; parents++) for (unsigned pending = 0; pending < 3; pending++)
        for (unsigned attrs = 0; attrs <= (op == 4 ? 2u : 0u); attrs += 2) for (unsigned fit = 0; fit < 2; fit++) hardlink_reservation_case(op, parents, pending, attrs, fit, serial++);
    for (unsigned op = 5; op <= 6; op++) for (unsigned pending = 0; pending <= 2; pending += 2) for (unsigned fit = 0; fit < 2; fit++) hardlink_reservation_case(op, 2, pending, 0, fit, serial++);
    assert(serial == 104);
}
static void hardlink_mutation_faults(void) {
    sfs_image *h; sfs_result r;
    for (unsigned operation = 0; operation < 3; operation++) {
        hardlink_failure_setup(1, 0, 0, &h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, 5, 0, "pending", 7, &r), SFS_OK);
        size_t n; unsigned char *before = bytes("image", &n);
        for (unsigned allocation = 0; allocation < 2; allocation++) {
            reset("", 0); metadata_clock(1210); if (allocation) fail_allocation = allocation_calls + 1; else clock_failure = 1;
            enum sfs_status status = hardlink_edit(h, operation == 0 ? 0 : operation == 1 ? 4 : 5, 0, &r);
            assert(status == r.status && status == (allocation ? SFS_NOMEM : SFS_TIME_UNAVAILABLE) && r.system_errno == (allocation ? ENOMEM : ENXIO));
            if (allocation) assert(hit); else assert(clock_calls == 1 && r.phase == SFS_PHASE_NONE);
            image_unwritten(); unchanged("image", before, n);
        }
        reset("", 0); metadata_commit(h); expect(h, 0, 5, "pending"); hardlink_name(h, 0, 1, "a", 4); hardlink_absent(h, 0, 1, "new"); hardlink_get(h, 0, 4, 1); close_image(h); free(before); retain(3320 + (int)operation);
    }
    hardlink_failure_setup(2, 0, 0, &h); sfs_result binding = xattr_binding(h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, 5, 0, "pending", 7, &r), SFS_OK);
    size_t saved_n; unsigned char *saved_bytes = bytes("image", &saved_n); sfs_cookie read_cookie, read_canary; memset(&read_canary, 0xA5, sizeof(read_canary)); read_cookie = read_canary; reset("", 0); fail_allocation = allocation_calls + 1;
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 1, "a", 1, &read_cookie, &r), SFS_NOMEM);
    assert(hit && r.phase == SFS_PHASE_READ && r.system_errno == ENOMEM && !memcmp(&read_cookie, &read_canary, sizeof(read_cookie))); image_unwritten(); unchanged("image", saved_bytes, saved_n); reset("", 0); metadata_commit(h); expect(h, 0, 5, "pending"); hardlink_get(h, 0, 4, 2); close_image(h); free(saved_bytes); retain(3327);
    for (unsigned operation = 0; operation < 4; operation++) {
        hardlink_failure_setup(2, 0, 0, &h); sfs_result binding = xattr_binding(h); sfs_cookie cookie, canary; memset(&canary, 0xA5, sizeof(canary)); cookie = canary;
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, 5, 0, "pending", 7, &r), SFS_OK);
        size_t n; unsigned char *before = bytes("image", &n); int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); unsigned char tail[37]; memset(tail, 0xA7, sizeof(tail)); raw_write(fd, tail, sizeof(tail), (off_t)n); assert(!close(fd)); free(before); before = bytes("image", &n); reset("", 0);
        enum sfs_status status;
        if (operation == 3) status = sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 1, "a", 1, &cookie, &r);
        else status = hardlink_edit(h, operation == 0 ? 1 : operation == 1 ? 2 : 6, 0, &r);
        assert(status == SFS_IO && r.status == status && r.phase == SFS_PHASE_IDENTITY && r.system_errno == ESTALE && !memcmp(&cookie, &canary, sizeof(cookie))); image_unwritten(); unchanged("image", before, n);
        XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); close_image(h); free(before); retain(3323 + (int)operation);
    }
}
static void hardlink_name_limit(void) {
    fixture f = hardlink_name_limit_fixture(); assert(hardlink_guard(f.p, f.p, f.n)); fixture_save(&f); sfs_image *h; sfs_result r; reset("", 0); open_image(&h); symlink_full(h); close_image(h);
    reset("", 0); open_image(&h); sfs_result binding = xattr_binding(h); reset("", 0); sfs_cookie cookie = {{0}};
    XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 1, "alias1022", 9, &cookie, &r), SFS_OK);
    assert(r.coverage == SFS_COVERAGE_TOUCHED && !raw_hashes && image_read_bytes <= 17 * UINT64_C(4096)); counters("hardlink-name-resume-bounded-seek");
    sfs_entry e; int found = 99; XEXPECT(sfs_image_next(h, 0, 1, &cookie, &e, &found, &r), SFS_OK); assert(found && e.inode == 2 && e.name_length == 9 && !memcmp(e.name, "alias1023", 9));
    XEXPECT(sfs_image_next(h, 0, 1, &cookie, &e, &found, &r), SFS_OK); assert(!found);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_write(h, 2, 0, "pending", 7, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); reset("", 0); clock_calls = 0;
    XEXPECT(sfs_image_link(h, 2, 1, "overflow", 8, &r), SFS_LIMIT); assert(r.phase == SFS_PHASE_ADMISSION && !r.system_errno && !clock_calls); image_unwritten(); unchanged("image", before, n); XEXPECT(sfs_image_commit(h, &r), SFS_STATE);
    hardlink_counts(1, 1024, 3); hardlink_get(h, 0, 2, 1024); expect(h, 0, 2, ""); close_image(h); free(before); retain(3330);
}
static void hardlink_unaligned(void) {
    for (unsigned fit = 0; fit < 2; fit++) {
        fixture f = hardlink_fixture(1, 0, 0, 1); size_t initial = f.n; uint64_t capacity = initial + (fit ? 14 : 13) * UINT64_C(4096);
        for (unsigned slot = 0; slot < 2; slot++) { put64(f.p + slot * CELL + 144, capacity); slot_hash(f.p + slot * CELL); } assert(hardlink_guard(f.p, f.p, f.n)); fixture_save(&f);
        unsigned char tail[37]; memset(tail, 0xA7, sizeof(tail)); int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); raw_write(fd, tail, sizeof(tail), (off_t)initial); assert(!close(fd));
        sfs_image *h; sfs_result r; reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); assert(n == initial + 37); reset("", 0); metadata_clock(1220);
        XEXPECT(sfs_image_link(h, 4, 1, "new", 3, &r), fit ? SFS_OK : SFS_LIMIT); assert(clock_calls == 1);
        if (!fit) { assert(r.phase == SFS_PHASE_ADMISSION && !r.system_errno); image_unwritten(); unchanged("image", before, n); XEXPECT(sfs_image_commit(h, &r), SFS_STATE); hardlink_get(h, 0, 4, 1); }
        else { metadata_commit(h); assert(image_append_bytes <= 13 * UINT64_C(4096) + 4059 && r.physical_end <= capacity); hardlink_name(h, 0, 1, "new", 4); hardlink_get(h, 0, 4, 2); symlink_full(h); }
        size_t after_n; unsigned char *after = bytes("image", &after_n); assert(after_n <= capacity && after_n >= n && !memcmp(after + 8192, before + 8192, n - 8192) && !memcmp(after + initial, tail, sizeof(tail)));
        printf("{\"case\":\"hardlink-unaligned-complete-reservation\",\"tail_bytes\":37,\"gap_bytes\":4059,\"required_cells\":13,\"available_aligned_cells\":%u,\"fit\":%s}\n", fit ? 13 : 12, fit ? "true" : "false"); fflush(stdout);
        close_image(h); free(before); free(after); retain(3331 + (int)fit);
    }
}
static void hardlink_record_faults(void) {
    sfs_image *h; sfs_result r;
    /* Frozen order: global leaf, two-row reverse leaf, owner leaf, namespace. */
    for (unsigned nth = 1; nth <= 4; nth++) {
        hardlink_failure_setup(1, 0, 0, &h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n); assert(!(n % CELL)); reset("write_error", (int)nth); metadata_clock(1230);
        XEXPECT(sfs_image_link(h, 4, 1, "new", 3, &r), SFS_IO); assert(hit && r.phase == SFS_PHASE_RECORDS && r.system_errno == EIO && image_append_bytes == (nth - 1) * UINT64_C(4096) && !slots && !fulls && clock_calls == 1);
        receipt("hardlink-producer-write-error", &r); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); reset("", 0); close_image(h);
        size_t end; unsigned char *after = bytes("image", &end); assert(end == n + (nth - 1) * CELL && !memcmp(before, after, n)); free(before); free(after);
        open_image(&h); hardlink_get(h, 0, 4, 1); hardlink_absent(h, 0, 1, "new"); close_image(h); retain(3340 + (int)nth);
    }
    for (unsigned failure = 0; failure < 4; failure++) {
        hardlink_failure_setup(1, 0, 0, &h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n);
        reset(failure == 0 ? "write_eintr" : failure == 1 ? "write_short" : failure == 2 ? "enospc" : "", 2); if (failure == 3) fail_after_append = 1; metadata_clock(1231);
        enum sfs_status status = sfs_image_link(h, 4, 1, "new", 3, &r); assert(status == r.status);
        if (failure < 2) { assert(status == SFS_OK); if (!failure) assert(hit); else assert(writes > 4); metadata_commit(h); hardlink_get(h, 0, 4, 2); hardlink_name(h, 0, 1, "new", 4); }
        else if (failure == 2) { assert(status == SFS_IO && hit && r.system_errno == ENOSPC && r.phase == SFS_PHASE_RECORDS); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); }
        else { assert(status == SFS_NOMEM && hit && r.system_errno == ENOMEM && image_append_bytes && !slots && !fulls); XEXPECT(sfs_image_commit(h, &r), SFS_STATE); hardlink_get(h, 0, 4, 1); }
        reset("", 0); close_image(h); if (failure >= 2) { size_t end; unsigned char *after = bytes("image", &end); assert(end >= n && !memcmp(after, before, n)); free(after); } free(before); retain(3345 + (int)failure);
    }
    for (unsigned fence = 1; fence <= 2; fence++) {
        hardlink_failure_setup(1, 0, 0, &h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, 4, 1, "new", 3, &r), SFS_OK); reset("full", (int)fence);
        XEXPECT(sfs_image_commit(h, &r), fence == 1 ? SFS_IO : SFS_OUTCOME_UNKNOWN); assert(hit && r.system_errno == EIO); receipt("hardlink-commit-fence", &r); XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); reset("", 0); close_image(h);
        sfs_recovery recovery; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
        for (unsigned slot = 0; slot < 2; slot++) { assert(recovery.slots[slot].status == SFS_OK && recovery.slots[slot].coverage == SFS_COVERAGE_FULL_REACHABLE); XEXPECT(sfs_image_select(h, slot, &generous, &r), SFS_OK); hardlink_get(h, 0, 4, fence == 2 && recovery.slots[slot].generation == 2 ? 2 : 1); }
        image_unwritten(); close_image(h); retain(3350 + (int)fence);
    }
}
static void hardlink_failures(void) { hardlink_capacity(); hardlink_mutation_faults(); hardlink_name_limit(); hardlink_unaligned(); hardlink_record_faults(); }

static void hardlink_full_control(fixture *f) {
    assert(hardlink_guard(f->p, f->p, f->n)); save("image", f->p, f->n); sfs_image *h; sfs_result r; reset("", 0); open_image(&h); reset("", 0);
    XEXPECT(sfs_image_verify(h, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && raw_hashes == 1 && raw_hash_input == 4132); image_unwritten(); close_image(h);
}
static void hardlink_semantic_negatives(void) {
    const char *labels[] = {"zero-nlink", "nlink-overflow", "name-count", "inode-count", "single-with-reverse", "multiple-null-reverse", "missing-reverse-row", "extra-reverse-row", "reverse-owner", "global-retarget", "global-missing-row", "nonminimal-representative", "non-directory-parent", "directory-multiple-links", "directory-reverse", "other-owner-shared-reverse", "single-null-multiple-global"};
    fixture f = hardlink_fixture(2, 1, 2, 2); hardlink_full_control(&f); assert(!rename("image", "hardlink-full-control"));
    size_t n = f.n; const unsigned char *control = f.p; unsigned char *space = namespace_at(f.p, f.p, n), *inode = record(f.p, space + 64, n), *owner = leaf_row(f.p, space + 64, 4, n, 496), *other = leaf_row(f.p, space + 64, 5, n, 496), *reverse = record(f.p, owner + 440, n), *global = record(f.p, space + 120, n);
    unsigned char *commit = record(f.p, f.p + 48, n), *catalog = record(f.p, commit + 120, n), *history = record(f.p, catalog + 648, n);
    assert(!memcmp(space + 64, history + 64, 56) && !get16(inode + 68) && get16(inode + 70) == 4 && !get16(reverse + 68) && get16(reverse + 70) == 2 && get16(global + 70) == 6 && memcmp(owner + 440, other + 440, 24));
    size_t ns_at = (size_t)(space - f.p), owner_at = (size_t)(owner - f.p), other_at = (size_t)(other - f.p), reverse_at = (size_t)(reverse - f.p), global_at = (size_t)(global - f.p), directory_at = (size_t)(inode + 640 - f.p);
    for (unsigned kind = 0; kind < sizeof(labels) / sizeof(*labels); kind++) {
        unsigned char *p = malloc(n), *topology = malloc(n); assert(p && topology); memcpy(p, control, n); memcpy(topology, control, n);
        if (kind == 0 || kind == 1) put64(p + owner_at + 344, kind ? UINT64_MAX : 0);
        else if (kind == 2) put64(p + ns_at + 336, 7);
        else if (kind == 3) put64(p + ns_at + 184, 5);
        else if (kind == 4) put64(p + owner_at + 344, 1);
        else if (kind == 5 || kind == 16) {
            hardlink_edge_change(p, topology, control, n, owner_at + 440, control + owner_at + 440, (unsigned char[56]){0});
            if (kind == 16) put64(p + owner_at + 344, 1);
        } else if (kind == 6 || kind == 7) {
            unsigned char rows[3 * 280]; memcpy(rows, control + reverse_at + 640, 560);
            if (kind == 7) hardlink_row(rows + 560, 2, "c", 4);
            hardlink_leaf_change(p, topology, control, n, reverse_at, rows, kind == 6 ? 1 : 3);
        } else if (kind == 8) put64(p + reverse_at + 640 + 267, 5);
        else if (kind == 9 || kind == 10) {
            unsigned char rows[6 * 280]; memcpy(rows, control + global_at + 640, sizeof(rows));
            /* The two parent2 names follow all four root names. */
            assert(get64(rows + 4 * 280) == 2 && rows[4 * 280 + 12] == 'a' && rows[5 * 280 + 12] == 'b');
            if (kind == 9) { put64(rows + 5 * 280 + 267, 5); hardlink_leaf_change(p, topology, control, n, global_at, rows, 6); }
            else hardlink_leaf_change(p, topology, control, n, global_at, rows, 5);
        } else if (kind == 11) p[owner_at + 88] = 'b';
        else if (kind == 12) { put32(p + directory_at + 16, SFS_FILE); put32(p + directory_at + 352 + 64, 0100600); }
        else if (kind == 13) {
            put32(p + owner_at + 16, SFS_DIRECTORY); put64(p + owner_at + 24, 0); put32(p + owner_at + 352 + 64, 0040700); put64(p + owner_at + 432, 0);
            hardlink_edge_change(p, topology, control, n, owner_at + 32, control + owner_at + 32, (unsigned char[56]){0});
        } else if (kind == 14) hardlink_edge_change(p, topology, control, n, directory_at + 440, control + directory_at + 440, control + owner_at + 440);
        else { assert(kind == 15); hardlink_edge_change(p, topology, control, n, other_at + 440, control + other_at + 440, control + owner_at + 440); }
        hardlink_repair(p, topology, n); assert(hardlink_guard(p, topology, n)); save("image", p, n); reset("", 0);
        sfs_image *h = NULL; sfs_result r; sfs_recovery recovery; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_RECOVERY_REQUIRED);
        assert(!h && r.phase == SFS_PHASE_READ && !r.system_errno && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
        for (unsigned slot = 0; slot < 2; slot++) assert(recovery.slots[slot].status == SFS_CORRUPT && recovery.slots[slot].coverage != SFS_COVERAGE_FULL_REACHABLE && !recovery.slots[slot].system_errno);
        receipt(labels[kind], &r); image_unwritten(); unchanged("image", p, n); free(p); free(topology); retain(3400 + (int)kind);
    }
    free(f.p);
}
static fixture position_fixture(fixture_node leaves[6]);
static void hardlink_touched_failures(void) {
    fixture f = hardlink_fixture(2, 1, 0, 2); hardlink_full_control(&f); retain(3420); size_t n = f.n;
    unsigned char *original = malloc(n); assert(original); memcpy(original, f.p, n);
    unsigned char *space = namespace_at(f.p, f.p, n), *names = record(f.p, space + 120, n); assert(get64(names + 640 + 5 * 280) == 2 && names[640 + 5 * 280 + 12] == 'b'); put64(names + 640 + 5 * 280 + 267, 5);
    hardlink_repair(f.p, original, n); assert(hardlink_guard(f.p, original, n));
    for (unsigned operation = 0; operation < 9; operation++) {
        if (operation == 7) {
            memcpy(f.p, original, n); hardlink_full_control(&f); retain(3550);
            unsigned char *commit = record(f.p, f.p + 48, n), *catalog = record(f.p, commit + 120, n), *history = record(f.p, catalog + 648, n), *inodes = record(f.p, space + 64, n);
            assert(get64(space + 176) == 6 && get64(history + 176) == 6 && !get16(inodes + 68) && get16(inodes + 70) == 4 && get64(inodes + 640 + 3 * 496) == 5);
            /* Missing owner6 is within next_inode7, so row range checks cannot mask node_get. */
            put64(space + 176, 7); put64(history + 176, 7); put64(names + 640 + 5 * 280 + 267, 6);
            hardlink_repair(f.p, original, n); assert(hardlink_guard(f.p, original, n));
        }
        save("image", f.p, n); sfs_image *h; sfs_result r, binding; reset("", 0); open_readonly(&h, &binding); assert(binding.coverage == SFS_COVERAGE_ROOT_ONLY);
        if (operation >= 7) clock_calls = 0;
        sfs_entry entry, canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary; sfs_cookie cookie, saved; memset(&cookie, 0xA5, sizeof(cookie)); saved = cookie; int found = 99;
        if (operation == 0) XEXPECT(sfs_image_lookup(h, 0, 2, "b", 1, &entry, &r), SFS_CORRUPT);
        else if (operation == 1) {
            XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 2, "a", 1, &cookie, &r), SFS_OK); saved = cookie;
            XEXPECT(sfs_image_next(h, 0, 2, &cookie, &entry, &found, &r), SFS_CORRUPT); assert(!found);
        } else if (operation == 2) XEXPECT(sfs_image_resume_after_name(h, 0, binding.generation, binding.root_digest, 2, "b", 1, &cookie, &r), SFS_CORRUPT);
        else if (operation == 5 || operation == 7) XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 2, 22, &cookie, &r), SFS_CORRUPT);
        else if (operation == 6 || operation == 8) {
            XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 2, 21, &cookie, &r), SFS_OK); saved = cookie;
            uint64_t position = UINT64_MAX;
            XEXPECT(sfs_image_next_position(h, 0, 2, &cookie, &entry, &position, &found, &r), SFS_CORRUPT); assert(!found && position == UINT64_MAX);
        } else {
            close_image(h); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK);
            if (operation == 3) XEXPECT(sfs_image_rename_entry(h, 2, "a", 1, 2, "b", 1, &r), SFS_CORRUPT);
            else XEXPECT(sfs_image_link(h, 4, 2, "b", 1, &r), SFS_CORRUPT); /* An occupied corrupt destination must not become EXISTS. */
        }
        assert(r.phase == SFS_PHASE_READ && !r.system_errno && !memcmp(&entry, &canary, sizeof(entry)) && !memcmp(&cookie, &saved, sizeof(cookie)));
        if (operation >= 7) assert(!clock_calls && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
        if (operation < 3 || operation >= 5) poisoned_readonly(h, r.phase); else XEXPECT(sfs_image_commit(h, &r), SFS_POISONED);
        image_unwritten(); close_image(h); unchanged("image", f.p, n); retain(operation < 5 ? 3421 + (int)operation : operation < 7 ? 3520 + (int)operation : 3544 + (int)operation);
    }
    /* A separately rehashed nonminimal representative is reached by stat. */
    memcpy(f.p, original, n); space = namespace_at(f.p, f.p, n); unsigned char *owner = leaf_row(f.p, space + 64, 4, n, 496); owner[88] = 'b'; hardlink_repair(f.p, original, n); assert(hardlink_guard(f.p, original, n)); save("image", f.p, n);
    sfs_image *h; sfs_result r; reset("", 0); open_image(&h); sfs_metadata_entry output, canary; memset(&canary, 0xA5, sizeof(canary)); output = canary; XEXPECT(sfs_image_stat_metadata(h, 0, 4, &output, &r), SFS_CORRUPT); assert(!memcmp(&output, &canary, sizeof(output))); XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); image_unwritten(); close_image(h); unchanged("image", f.p, n);
    open_image(&h); sfs_entry entry, entry_canary; memset(&entry_canary, 0xA5, sizeof(entry_canary)); entry = entry_canary; XEXPECT(sfs_image_stat(h, 0, 4, &entry, &r), SFS_CORRUPT); assert(!memcmp(&entry, &entry_canary, sizeof(entry))); XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); image_unwritten(); close_image(h); unchanged("image", f.p, n); free(f.p); free(original); retain(3426);
    fixture_node leaves[6]; f = position_fixture(leaves); n = f.n; save("image", f.p, n); reset("", 0); open_image(&h); reset("", 0);
    XEXPECT(sfs_image_verify(h, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && !raw_hash_input); image_unwritten(); close_image(h); unchanged("image", f.p, n); retain(3553);
    original = malloc(n); unsigned char *topology = malloc(n); assert(original && topology); memcpy(original, f.p, n); memcpy(topology, f.p, n);
    size_t leaf_at = (size_t)get64(leaves[3].ref + 8); assert(get16(f.p + leaf_at + 70) == 4 && get32(f.p + leaf_at + 648) == 5 && !memcmp(f.p + leaf_at + 652, "n0011", 5));
    /* Declare four->three rows: framing stays valid, but a nonroot name leaf requires four. */
    hardlink_leaf_change(f.p, topology, original, n, leaf_at, original + leaf_at + 640, 3);
    hardlink_repair(f.p, topology, n); assert(hardlink_guard(f.p, topology, n) && !hardlink_guard(f.p, original, n));
    for (unsigned next = 0; next < 2; next++) {
        save("image", f.p, n); sfs_result binding; reset("", 0); open_readonly(&h, &binding); assert(binding.coverage == SFS_COVERAGE_ROOT_ONLY); clock_calls = 0;
        sfs_cookie cookie, saved; memset(&saved, 0xA5, sizeof(saved)); cookie = saved; entry = entry_canary; uint64_t position = UINT64_MAX; int found = 99;
        if (next) {
            XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 1, 1332, &cookie, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_TOUCHED && !r.system_errno); saved = cookie;
            XEXPECT(sfs_image_next_position(h, 0, 1, &cookie, &entry, &position, &found, &r), SFS_CORRUPT); assert(!found);
        } else XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 1, 1441, &cookie, &r), SFS_CORRUPT);
        assert(r.phase == SFS_PHASE_READ && !r.system_errno && r.coverage != SFS_COVERAGE_FULL_REACHABLE && !clock_calls && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&entry, &entry_canary, sizeof(entry)) && position == UINT64_MAX);
        poisoned_readonly(h, r.phase); image_unwritten(); close_image(h); unchanged("image", f.p, n); retain(3554 + (int)next);
    }
    free(f.p); free(original); free(topology);
}
static void hardlink_verify_budgets(void) {
    sfs_image *h; sfs_result r; sfs_recovery recovery; fixture f = hardlink_fixture(2, 1, 0, 2); assert(hardlink_guard(f.p, f.p, f.n)); fixture_save(&f); reset("", 0);
    recovery_cancellation cancellation = {.after_hash = 0}; sfs_verify_budget budget = generous; budget.cancelled = cancel_recovery_once; budget.context = &cancellation;
    XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &budget, &r), SFS_OK);
    assert(cancellation.fired && recovery.slots[0].status == SFS_INCOMPLETE && recovery.slots[0].incomplete_reason == SFS_INCOMPLETE_CANCELLED && recovery.slots[0].coverage != SFS_COVERAGE_FULL_REACHABLE && recovery.slots[1].status == SFS_OK && recovery.slots[1].coverage == SFS_COVERAGE_FULL_REACHABLE);
    sfs_cookie cookie, canary; memset(&canary, 0xA5, sizeof(canary)); cookie = canary;
    XEXPECT(sfs_image_resume_after_name(h, 0, 1, recovery.slots[1].root_digest, 2, "a", 1, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    XEXPECT(sfs_image_select(h, 0, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE); hardlink_name(h, 0, 2, "b", 4); image_unwritten(); close_image(h); retain(3430);
    for (unsigned mode = 0; mode < 4; mode++) {
        f = hardlink_fixture(2, 1, 0, 2); fixture_save(&f); reset("", 0); open_image(&h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 31337; XEXPECT(sfs_image_set_metadata(h, 5, &update, &r), SFS_OK);
        size_t n; unsigned char *before = bytes("image", &n); budget = generous; unsigned polls = 0;
        if (mode < 2) budget.metadata_read_bytes = CELL; else if (mode == 2) budget.checks = 1; else { budget.cancelled = cancel_now; budget.context = &polls; }
        reset(mode == 1 ? "slot_reads" : "", mode == 1 ? 1 : 0);
        XEXPECT(sfs_image_verify(h, &budget, &r), mode == 1 ? SFS_IO : SFS_INCOMPLETE);
        assert(r.coverage != SFS_COVERAGE_FULL_REACHABLE && r.phase == SFS_PHASE_READ && r.system_errno == (mode == 1 ? EIO : 0));
        if (mode == 1) assert(hit); else assert(r.incomplete_reason == (mode == 0 ? SFS_INCOMPLETE_METADATA_READ : mode == 2 ? SFS_INCOMPLETE_CHECKS : SFS_INCOMPLETE_CANCELLED));
        image_unwritten(); unchanged("image", before, n); reset("", 0);
        sfs_result position_binding; sfs_cookie position_cookie;
        if (mode == 1) { position_binding.generation = 1; memset(position_binding.root_digest, 0, 32);
            position_failure(h, 0, &position_binding, 1, 0, SFS_POISONED, SFS_PHASE_READ, 0);
            sfs_entry pe; uint64_t pp = UINT64_MAX; int pf = 99; position_cookie = (sfs_cookie){0};
            XEXPECT(sfs_image_next_position(h, 0, 1, &position_cookie, &pe, &pp, &pf, &r), SFS_POISONED); assert(pf == 99 && pp == UINT64_MAX);
            XEXPECT(sfs_image_commit(h, &r), SFS_POISONED);
        } else { position_binding = xattr_binding(h); assert(position_equivalence(h, 0, 2, &position_binding, 6) == 2); metadata_commit(h); sfs_metadata_entry m = hardlink_get(h, 0, 5, 2); assert(m.uid == 31337); hardlink_get(h, 0, 4, 2); symlink_full(h); }
        free(before); close_image(h); retain(3431 + (int)mode);
    }
}
/* Security control: a->2, b->3; optional c->2 has an exact owner2 reverse. */
static fixture hardlink_creation_fixture(unsigned multi) {
    fixture f = fixture_start(); f.minor = 6; put32(f.p + 12, 6); unsigned char raw[CELL] = {0}; memcpy(raw, "old", 3); fixture_node data = append_cell(&f, 6, raw);
    unsigned char extent_row[72] = {0}; memcpy(extent_row + 8, data.ref, 56); put16(extent_row + 64, 3); fixture_node extent = tree(&f, 3, extent_row, 1);
    unsigned char names[3 * 280], reverse_rows[2 * 280]; hardlink_row(names, 1, "a", 2); hardlink_row(names + 280, 1, "b", 3); fixture_node reverse = {0}, empty = {0};
    if (multi) { hardlink_row(names + 560, 1, "c", 2); memcpy(reverse_rows, names, 280); memcpy(reverse_rows + 280, names + 560, 280); reverse = tree(&f, 6, reverse_rows, 2); }
    unsigned char inode[2 * 496] = {0};
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *row = inode + i * 496; put64(row, i + 2); put64(row + 8, 1); put32(row + 16, SFS_FILE); put32(row + 20, 1); row[88] = (unsigned char)('a' + i); put64(row + 344, i ? 1 : multi ? 2 : 1); fixture_tuple(row + 352, SFS_FILE, i ? 0 : 1);
        if (!i) { put64(row + 24, 3); memcpy(row + 32, extent.ref, 56); memcpy(row + 440, reverse.ref, 56); }
    }
    fixture_node inodes = tree(&f, 1, inode, 2), global = tree(&f, 2, names, 2 + multi), space = hardlink_space(&f, inodes, global, empty, 2, 2 + multi, 6); finish_fixture(&f, space, empty); return f;
}
static void hardlink_creation_collisions(void) {
    sfs_metadata_initial initial = metadata_input(SFS_FILE), symbol = symlink_input();
    for (unsigned multi = 0; multi < 2; multi++) {
        fixture control = hardlink_creation_fixture(multi); hardlink_full_control(&control); retain(3450 + (int)multi);
        size_t n = control.n; unsigned char *space = namespace_at(control.p, control.p, n), *global = record(control.p, space + 120, n), *owner = leaf_row(control.p, space + 64, 2, n, 496); size_t row_at = (size_t)(global + 640 + 280 - control.p);
        assert(get64(control.p + row_at + 267) == 3 && control.p[row_at + 12] == 'b' && get64(owner + 344) == (multi ? 2 : 1));
        for (unsigned mode = 0; mode < (multi ? 5u : 3u); mode++) for (unsigned api = 0; api < 3; api++) {
            /* mode0 valid sole b; mode1 checked b->2; mode2 checked b->missing5;
             * mode3 valid multi c; mode4 the same multi destination with cold reverse I/O. */
            unsigned char *p = malloc(n); assert(p); memcpy(p, control.p, n);
            if (mode == 1 || mode == 2) {
                assert(get64(p + row_at + 267) == 3); put64(p + row_at + 267, mode == 1 ? 2 : 5); hardlink_repair(p, control.p, n); assert(hardlink_guard(p, control.p, n));
            } else assert(hardlink_guard(p, control.p, n));
            save("image", p, n); sfs_image *h; sfs_result r; reset("", 0); open_image(&h);
            /* open_image asserts ROOT_ONLY. Root-only staging leaves the cold
             * owner2 reverse tree untouched for the descriptor-targeted fault. */
            XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 777;
            XEXPECT(sfs_image_set_metadata(h, 1, &update, &r), SFS_OK); size_t before_n; unsigned char *before = bytes("image", &before_n); assert(before_n >= n);
            if (mode == 4) {
                /* Reuse the qualified cold-getter setup: a controlled stop clears
                 * metadata cache, retains root staging, and never certifies FULL. */
                sfs_verify_budget stop = generous; unsigned polls = 0; stop.cancelled = cancel_now; stop.context = &polls;
                XEXPECT(sfs_image_verify(h, &stop, &r), SFS_INCOMPLETE); assert(polls && r.incomplete_reason == SFS_INCOMPLETE_CANCELLED && !r.system_errno && r.coverage != SFS_COVERAGE_FULL_REACHABLE);
            }
            reset("", 0); clock_calls = 0; if (mode == 4) { read_at[0] = get64(owner + 440 + 8); assert(read_at[0] >= 8192); reset("candidate_reads", 1); }
            sfs_inode output = UINT64_MAX; const char *name = mode >= 3 ? "c" : "b"; enum sfs_status status;
            if (api == 0) status = sfs_image_add(h, 1, name, 1, SFS_FILE, &output, &r);
            else if (api == 1) status = sfs_image_add_metadata(h, 1, name, 1, SFS_FILE, &initial, &output, &r);
            else status = sfs_image_symlink_metadata(h, 1, name, 1, "opaque", 6, &symbol, &output, &r);
            enum sfs_status expected = mode == 1 || mode == 2 ? SFS_CORRUPT : mode == 4 ? SFS_IO : SFS_EXISTS;
            assert(status == expected && r.status == status && r.phase == SFS_PHASE_READ && r.system_errno == (mode == 4 ? EIO : 0) && output == UINT64_MAX && r.physical_end == before_n && !clock_calls);
            if (mode == 4) assert(hit); image_unwritten(); unchanged("image", before, before_n); receipt("hardlink-creation-collision", &r);
            printf("{\"case\":\"hardlink-creation-collision\",\"multi\":%u,\"mode\":%u,\"api\":%u,\"status\":%d,\"fault_hit\":%d}\n", multi, mode, api, status, hit); fflush(stdout); reset("", 0);
            if (expected == SFS_EXISTS) {
                metadata_commit(h); sfs_metadata_entry root_metadata = hardlink_get(h, 0, 1, 1); assert(root_metadata.uid == 777); hardlink_get(h, 0, 2, multi ? 2 : 1); symlink_full(h);
            } else {
                XEXPECT(sfs_image_begin(h, &r), SFS_POISONED); assert(r.phase == SFS_PHASE_READ && !r.system_errno); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); close_image(h); open_image(&h);
                sfs_metadata_entry root_metadata = hardlink_get(h, 0, 1, 1); assert(root_metadata.uid == 1234);
            }
            close_image(h); free(before); free(p); retain(3460 + (int)(multi * 15 + mode * 3 + api));
        }
        free(control.p);
    }
}

static void hardlink_conflicting_roots(void) {
    fixture a = hardlink_fixture(2, 1, 0, 2), b = hardlink_fixture(2, 1, 0, 2); hardlink_full_control(&a); retain(3440);
    unsigned char *space = namespace_at(b.p, b.p, b.n), *owner = leaf_row(b.p, space + 64, 4, b.n, 496), *reverse = record(b.p, owner + 440, b.n), *names = record(b.p, space + 120, b.n);
    assert(reverse[640 + 280 + 12] == 'b' && names[640 + 5 * 280 + 12] == 'b'); reverse[640 + 280 + 12] = 'z'; names[640 + 5 * 280 + 12] = 'z'; hardlink_repair(b.p, a.p, b.n); assert(hardlink_guard(b.p, a.p, b.n)); hardlink_full_control(&b); retain(3441);
    unsigned char slot[CELL]; memcpy(slot, a.p, CELL); unsigned char *mapping = calloc(b.n / CELL, 56); assert(mapping);
    for (size_t i = 2; i < b.n / CELL; i++) {
        unsigned char *cell = b.p + i * CELL; unsigned type = !memcmp(cell, "SFSREC06", 8) ? get32(cell + 8) : 6;
        if (type == 2 || type == 4) { mapped_ref(cell + 64, mapping, b.n / CELL); mapped_ref(cell + 120, mapping, b.n / CELL); if (type == 2) mapped_ref(cell + 280, mapping, b.n / CELL); }
        if (type == 5) {
            unsigned map = get32(cell + 64), level = get16(cell + 68), count = get16(cell + 70), stride = hardlink_stride(map, level), edge = hardlink_edge(map, level);
            for (unsigned j = 0; j < count; j++) {
                if (level || (map != 2 && map != 6)) mapped_ref(cell + 640 + j * stride + edge, mapping, b.n / CELL);
                if (!level && map == 1) mapped_ref(cell + 640 + j * stride + 440, mapping, b.n / CELL);
            }
        }
        fixture_node relocated = append_cell(&a, type, cell); memcpy(mapping + i * 56, relocated.ref, 56);
    }
    memcpy(a.p, slot, CELL); mapped_ref(b.p + 48, mapping, b.n / CELL); memcpy(a.p + CELL, b.p, CELL); put64(a.p + CELL + 104, a.n); slot_hash(a.p + CELL); free(mapping); free(b.p); fixture_save(&a);
    size_t n; unsigned char *before = bytes("image", &n); sfs_image *h = NULL; sfs_result r, first, second; sfs_recovery recovery; reset("", 0);
    XEXPECT(sfs_image_open(root, "image", &h, &r), SFS_RECOVERY_REQUIRED); assert(!h); XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    assert(!recovery.pair_valid && recovery.slots[0].status == SFS_OK && recovery.slots[1].status == SFS_OK && recovery.slots[0].coverage == SFS_COVERAGE_FULL_REACHABLE && recovery.slots[1].coverage == SFS_COVERAGE_FULL_REACHABLE);
    ok(sfs_image_select(h, 0, &generous, &first), &first); sfs_cookie numeric;
    XEXPECT(sfs_image_resume_after_position(h, 1, first.generation, first.root_digest, 2, 21, &numeric, &r), SFS_OK);
    sfs_cookie cookie, saved, canary; memset(&canary, 0xA5, sizeof(canary));
    XEXPECT(sfs_image_resume_after_name(h, 1, first.generation, first.root_digest, 2, "a", 1, &cookie, &r), SFS_OK); saved = cookie;
    sfs_entry e, entry_canary; memset(&entry_canary, 0xA5, sizeof(entry_canary)); e = entry_canary; int found = 99;
    ok(sfs_image_select(h, 1, &generous, &second), &second); assert(first.generation == second.generation && memcmp(first.root_digest, second.root_digest, 32)); cookie = canary;
    XEXPECT(sfs_image_resume_after_name(h, 1, first.generation, first.root_digest, 2, "a", 1, &cookie, &r), SFS_STATE); assert(!memcmp(&cookie, &canary, sizeof(cookie)));
    position_failure(h, 1, &first, 2, 21, SFS_STATE, SFS_PHASE_NONE, 0);
    uint64_t numeric_position = UINT64_MAX; sfs_cookie old_numeric = numeric;
    XEXPECT(sfs_image_next_position(h, 1, 2, &numeric, &e, &numeric_position, &found, &r), SFS_STATE);
    assert(!found && numeric_position == UINT64_MAX && !memcmp(&numeric, &old_numeric, sizeof(numeric)) && !memcmp(&e, &entry_canary, sizeof(e)));
    XEXPECT(sfs_image_resume_after_position(h, 1, second.generation, second.root_digest, 2, 21, &numeric, &r), SFS_OK);
    XEXPECT(sfs_image_next_position(h, 1, 2, &numeric, &e, &numeric_position, &found, &r), SFS_OK); assert(found && e.name_length == 1 && e.name[0] == 'z' && numeric_position == 22); e = entry_canary;
    cookie = saved; XEXPECT(sfs_image_next(h, 1, 2, &cookie, &e, &found, &r), SFS_STATE); assert(!found && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&e, &entry_canary, sizeof(e)));
    XEXPECT(sfs_image_resume_after_name(h, 1, second.generation, second.root_digest, 2, "a", 1, &cookie, &r), SFS_OK); XEXPECT(sfs_image_next(h, 1, 2, &cookie, &e, &found, &r), SFS_OK); assert(found && e.inode == 4 && e.name_length == 1 && e.name[0] == 'z');
    image_unwritten(); close_image(h); unchanged("image", before, n); free(before);
}
static void hardlink_verify(void) { hardlink_semantic_negatives(); hardlink_touched_failures(); hardlink_verify_budgets(); hardlink_creation_collisions(); hardlink_conflicting_roots(); }


/* A separate finite group lets cache changes run without replaying unrelated campaigns. */
static uint64_t cache_handle_bytes(sfs_image *h) {
    for (allocation_header *p = allocations; p; p = p->value.next) if (p + 1 == (void *)h) return p->value.bytes;
    assert(0); return 0;
}
static void cache_release(sfs_image *h) {
    assert(!clearing_cache); cache_frees = 0; clearing_cache = 1;
    sfs_image_clear_read_cache(h);
    clearing_cache = 0; assert(cache_frees <= 1001);
}
static void cache_binding(const sfs_result *a, const sfs_result *b) {
    assert(a->generation == b->generation && a->committed_end == b->committed_end && a->physical_end == b->physical_end);
    assert(a->device == b->device && a->inode == b->inode && !memcmp(a->uuid, b->uuid, 16) && !memcmp(a->root_digest, b->root_digest, 32));
}
/* These fixtures have no overlay/auxiliary allocations: only handle + cache. */
static unsigned cache_owned_allocations(void) {
    unsigned count = 0;
    for (allocation_header *p = allocations; p; p = p->value.next) count++;
    assert(count); return count - 1;
}
static void cache_commit_reuse(void) {
    fixture f = indexed_fixture(432, 1, 1); fixture_save(&f);
    reset("", 0); sfs_image *h; sfs_result r, before; open_image(&h);
    sfs_entry entry; uint64_t handle = cache_handle_bytes(h);
    for (unsigned i = 0; i < 432; ++i) OK(sfs_image_stat(h, 0, i + 2, &entry, &r));
    uint64_t pool = allocated; unsigned owned = cache_owned_allocations();
    assert(owned > 40 && pool <= handle + 4u * 1024u * 1024u);
    for (unsigned pass = 0; pass < 4; ++pass) {
        sfs_cookie cookie = {0}; int found;
        OK(sfs_image_next(h, 0, 1, &cookie, &entry, &found, &before)); assert(found);
        size_t n; unsigned char *image = bytes("image", &n), *slot = selected_slot(image);
        unsigned char *ns = namespace_at(image, slot, n);
        watch_payload(0, slot + 48);
        watch_at[1] = (uint64_t)(inode_row(image, ns, 2, n) - image) / CELL * CELL;
        watch_size[1] = CELL; watch_count = 2; watch_clear();
        OK(sfs_image_begin(h, &r)); reset("", 0);
        uint64_t calls = allocation_calls, frees = free_calls;
        OK(sfs_image_commit(h, &r));
        assert(allocation_calls == calls && free_calls == frees && allocated == pool);
        assert(r.generation == before.generation + 1 && r.fence_attempted == 3 && r.fence_succeeded == 3);
        assert(fulls == 2 && slots == 1 && image_read_bytes > 2 * CELL && metadata_hash_input > 2 * CELL);
        assert(watch_reads[0] && !watch_reads[1] && !r.poisoned && !r.transaction_active);
        assert(r.committed_end == before.committed_end + CELL && !memcmp(r.root_digest, before.root_digest, 32));
        reset("", 0);
        resume_failure(h, 0, &before, 1, entry.inode, SFS_STATE);
        /* The former deep hit was invalidated, even though its buffer survives. */
        reset("", 0); OK(sfs_image_stat(h, 0, 2, &entry, &r));
        assert(watch_reads[1] == 1 && image_read_bytes && metadata_hash_input);
        reset("", 0); OK(sfs_image_stat(h, 0, 2, &entry, &r));
        assert(!image_read_bytes && !metadata_hash_input);
        expect(h, 0, 2, "shared"); expect(h, 1, 2, "shared");
        assert(allocated == pool && cache_owned_allocations() == owned);
        watch_count = 0; free(image);
    }
    /* count has fallen well below allocated; clear must free the whole pool. */
    uint64_t calls = allocation_calls; cache_release(h);
    assert(cache_frees == owned && allocated == handle && allocation_calls == calls);
    cache_release(h); assert(!cache_frees && allocation_calls == calls);
    close_image(h); assert(!allocated); retain(3700);
}
static enum sfs_status cache_extent_probe(sfs_image *h, unsigned leaf, sfs_result *r) {
    unsigned char byte = 0; size_t got = 0;
    enum sfs_status e = sfs_image_read(h, 0, 2, (uint64_t)leaf * 48 * CELL, &byte, 1, &got, r);
    if (!e) assert(got == 1 && byte == 's'); else assert(!got);
    return e;
}
static void cache_commit_growth(void) {
    /* 1,050 leaves: bounded physical fixture, one shared raw cell per mapping. */
    fixture f = indexed_fixture(2, 48 * 1050, 0); fixture_save(&f);
    reset("", 0); sfs_image *h; sfs_result r; open_image(&h);
    uint64_t handle = cache_handle_bytes(h);
    for (unsigned i = 0; i < 16; ++i) OK(cache_extent_probe(h, i, &r));
    OK(sfs_image_begin(h, &r)); OK(sfs_image_commit(h, &r));
    uint64_t pool = allocated; unsigned owned = cache_owned_allocations();
    /* Reused slots must work; the first growth allocation fails before ownership
       or active count advances, and a retry can fill that very slot. */
    fail_allocation = allocation_calls + 1; unsigned failed = 1050;
    for (unsigned i = 0; i < 1050; ++i) {
        enum sfs_status e = cache_extent_probe(h, i, &r);
        if (e) { assert(e == SFS_NOMEM && hit && !r.poisoned && r.system_errno == ENOMEM); failed = i; break; }
    }
    assert(failed > 0 && failed < 1050 && allocated == pool && cache_owned_allocations() == owned);
    fail_allocation = 0;
    for (unsigned i = failed; i < 1050; ++i) OK(cache_extent_probe(h, i, &r));
    assert(cache_owned_allocations() == 1001 && allocated <= handle + 4u * 1024u * 1024u);
    pool = allocated; uint64_t calls = allocation_calls;
    reset("", 0); OK(cache_extent_probe(h, 0, &r)); assert(metadata_hash_input && allocation_calls == calls && allocated == pool);
    reset("", 0); OK(cache_extent_probe(h, 0, &r)); assert(!metadata_hash_input && allocation_calls == calls);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_commit(h, &r));
    assert(allocated == pool && allocation_calls == calls);
    cache_release(h); assert(cache_frees == 1001 && allocated == handle && allocation_calls == calls);
    /* Header succeeds, first buffer allocation fails before activation. */
    fail_allocation = allocation_calls + 2;
    assert(cache_extent_probe(h, 0, &r) == SFS_NOMEM && !r.poisoned);
    assert(cache_owned_allocations() == 1); calls = allocation_calls;
    cache_release(h); assert(cache_frees == 1 && allocated == handle && allocation_calls == calls);
    cache_release(h); assert(!cache_frees); fail_allocation = 0;
    close_image(h); assert(!allocated); retain(3701);
}
static void cache_commit_integrity(void) {
    /* Same-size root, namespace, and index-root corruption must not be masked
       by the warm cache. Targeted I/O failures exercise the same rereads. */
    for (unsigned io = 0; io < 2; ++io) for (unsigned level = 0; level < 3; ++level) {
        fixture f = indexed_fixture(432, 1, 1); size_t n = f.n;
        unsigned char *image = malloc(n); assert(image); memcpy(image, f.p, n);
        unsigned char *slot = selected_slot(image), *ns = namespace_at(image, slot, n);
        uint64_t offset = level == 0 ? get64(slot + 56) : level == 1 ? (uint64_t)(ns - image) : get64(ns + 72);
        fixture_save(&f); reset("", 0); sfs_image *h; sfs_result r; sfs_entry entry; open_image(&h);
        for (unsigned i = 0; i < 432; ++i) OK(sfs_image_stat(h, 0, i + 2, &entry, &r));
        uint64_t generation = r.generation, handle = cache_handle_bytes(h); unsigned owned = cache_owned_allocations();
        OK(sfs_image_begin(h, &r));
        if (io) { read_at[0] = offset; reset("candidate_reads", 1); }
        else { image[offset + 200] ^= 1; replace_image(image, n); reset("", 0); }
        assert(sfs_image_commit(h, &r) == (io ? SFS_IO : SFS_CORRUPT));
        assert(r.phase == SFS_PHASE_READ && r.system_errno == (io ? EIO : 0));
        assert(r.generation == generation && r.poisoned && !r.transaction_active);
        assert(!slots && !records && !fulls && !r.fence_attempted && !r.fence_succeeded);
        if (io) assert(hit);
        uint64_t calls = allocation_calls; cache_release(h);
        assert(cache_frees == owned && allocated == handle && allocation_calls == calls);
        cache_release(h); assert(!cache_frees); reset("", 0); close_image(h); assert(!allocated);
        free(image); retain(3710 + (int)(io * 3 + level));
    }
    /* Reconciliation does not walk this leaf. Its stale precommit contents must
       nevertheless be inaccessible when the page is first touched afterward. */
    fixture f = indexed_fixture(432, 1, 0); size_t n = f.n;
    unsigned char *image = malloc(n); assert(image); memcpy(image, f.p, n);
    unsigned char *ns = namespace_at(image, selected_slot(image), n);
    uint64_t leaf = (uint64_t)(inode_row(image, ns, 2, n) - image) / CELL * CELL;
    fixture_save(&f); reset("", 0); sfs_image *h; sfs_result r; sfs_entry entry; open_image(&h);
    OK(sfs_image_stat(h, 0, 2, &entry, &r)); OK(sfs_image_begin(h, &r));
    image[leaf + 200] ^= 1; replace_image(image, n);
    watch_at[0] = leaf; watch_size[0] = CELL; watch_count = 1; watch_clear(); reset("", 0);
    OK(sfs_image_commit(h, &r)); assert(!watch_reads[0] && r.fence_succeeded == 3);
    assert(sfs_image_stat(h, 0, 2, &entry, &r) == SFS_CORRUPT && r.poisoned && r.phase == SFS_PHASE_READ);
    assert(watch_reads[0] == 1); watch_count = 0;
    cache_release(h); close_image(h); assert(!allocated); free(image); retain(3716);
}
static void cache_commit(void) { cache_commit_reuse(); cache_commit_growth(); cache_commit_integrity(); }
static void cache_purge(void) {
    reset("", 0); cache_release(NULL); assert(!cache_frees && !allocated);
    fixture f = indexed_fixture(32, 1, 2); fixture_save(&f);
    size_t n; unsigned char *baseline = bytes("image", &n); sfs_image *h; sfs_result r, binding;
    struct stat identity, after; assert(!lstat("image", &identity)); open_readonly(&h, &binding);
    int owned = image_open_fd, fd_count = descriptors(); uint64_t handle = cache_handle_bytes(h);
    sfs_entry entry; OK(sfs_image_lookup(h, 0, 1, "f00000000", 9, &entry, &r)); expect(h, 0, 2, "shared");
    sfs_cookie cookie = {0}; int found;
    for (unsigned i = 0; i < 11; i++) { OK(sfs_image_next(h, 0, 1, &cookie, &entry, &found, &r)); assert(found && entry.inode == i + 2); }
    sfs_cookie saved = cookie; assert(allocated > handle); uint64_t warm = allocated;
    fail_allocation = allocation_calls + 1; uint64_t attempts = allocation_calls;
    cache_release(h); assert(cache_frees && allocated == handle && allocation_calls == attempts && !memcmp(&cookie, &saved, sizeof(cookie)));
    cache_release(h); assert(!cache_frees && allocated == handle && allocation_calls == attempts);
    sfs_entry canary; memset(&canary, 0xA5, sizeof(canary)); entry = canary;
    assert(sfs_image_lookup(h, 0, 1, "f00000000", 9, &entry, &r) == SFS_NOMEM && hit && r.phase == SFS_PHASE_READ && r.system_errno == ENOMEM && !memcmp(&entry, &canary, sizeof(entry)));
    fail_allocation = 0; reset("", 0);
    OK(sfs_image_lookup(h, 0, 1, "f00000000", 9, &entry, &r)); assert(entry.inode == 2 && image_read_bytes && metadata_hash_input); cache_binding(&binding, &r);
    expect(h, 0, 2, "shared"); assert(raw_hashes);
    for (unsigned i = 11; i < 32; i++) { OK(sfs_image_next(h, 0, 1, &cookie, &entry, &found, &r)); assert(found && entry.inode == i + 2); }
    saved = cookie; cache_release(h); assert(!memcmp(&cookie, &saved, sizeof(cookie)));
    OK(sfs_image_next(h, 0, 1, &cookie, &entry, &found, &r)); assert(!found);
    cache_release(h); OK(sfs_image_next(h, 0, 1, &cookie, &entry, &found, &r)); assert(!found);
    sfs_view view; OK(sfs_image_snapshot_view(h, "snapshot-0", 10, &view, &r)); assert(view == 1); cache_binding(&binding, &r);
    expect(h, view, 2, "shared"); OK(sfs_image_resume_after(h, view, binding.generation, binding.root_digest, 1, 13, &cookie, &r));
    saved = cookie; cache_release(h); assert(!memcmp(&cookie, &saved, sizeof(cookie)));
    sfs_cookie numeric_cookie = {0}; uint64_t numeric_position = 0;
    OK(sfs_image_next_position(h, view, 1, &numeric_cookie, &entry, &numeric_position, &found, &r)); assert(found && entry.inode == 2);
    uint64_t accepted_position = numeric_position; sfs_cookie accepted_cookie = numeric_cookie;
    cache_release(h); OK(sfs_image_resume_after_position(h, view, binding.generation, binding.root_digest, 1, accepted_position, &numeric_cookie, &r));
    assert(!memcmp(&numeric_cookie, &accepted_cookie, sizeof(numeric_cookie))); cache_binding(&binding, &r);
    cache_release(h); OK(sfs_image_next_position(h, view, 1, &numeric_cookie, &entry, &numeric_position, &found, &r)); assert(found && entry.inode == 3);
    assert(position_equivalence(h, 0, 1, &binding, 2) == 32); assert(position_equivalence(h, view, 1, &binding, 2) == 32);
    OK(sfs_image_next(h, view, 1, &cookie, &entry, &found, &r)); assert(found && entry.inode == 14);
    sfs_result stale = binding; stale.generation++; resume_failure(h, view, &stale, 1, 13, SFS_STATE);
    stale = binding; stale.root_digest[0] ^= 1; resume_failure(h, view, &stale, 1, 13, SFS_STATE);
    cookie = saved; assert(sfs_image_next(h, view, 2, &cookie, &entry, &found, &r) == SFS_INVALID);
    assert(fcntl(owned, F_GETFD) >= 0 && (fcntl(owned, F_GETFL) & O_ACCMODE) == O_RDONLY && descriptors() == fd_count);
    assert(!fstat(owned, &after)); identical_identity(&identity, &after);
    sfs_image *other = NULL; sfs_recovery recovery;
    assert(sfs_image_open(root, "image", &other, &r) == SFS_BUSY && !other);
    assert(sfs_image_inspect(root, "image", &other, &recovery, &generous, &r) == SFS_BUSY && !other);
    readonly_refusals(h, SFS_STATE, SFS_PHASE_NONE); close_image(h); assert(!allocated); unchanged("image", baseline, n);
    printf("{\"case\":\"cache-owned-release-refill-cookie\",\"released_requested_bytes\":%llu,\"rss_claim\":false}\n", (unsigned long long)(warm - handle));

    /* A failed page read leaves an allocated cache body which must also be freed. */
    reset("", 0); open_readonly(&h, &r); handle = cache_handle_bytes(h); cache_release(h); reset("read_error", 1);
    assert(sfs_image_lookup(h, 0, 1, "f00000000", 9, &entry, &r) == SFS_IO && hit && r.phase == SFS_PHASE_READ && r.system_errno == EIO);
    assert(allocated > handle); cache_release(h); assert(allocated == handle && cache_frees);
    poisoned_readonly(h, SFS_PHASE_READ); cache_release(h); assert(!cache_frees); reset("", 0); close_image(h); assert(!allocated);

    /* Neither unselected cleanup nor selected cleanup resets observed anchors. */
    recovery_cancellation observed = {.after_hash = 2 * CELL}; sfs_verify_budget budget = generous;
    budget.cancelled = cancel_recovery_once; budget.context = &observed; reset("", 0);
    OK(sfs_image_inspect(root, "image", &h, &recovery, &budget, &r));
    assert(observed.fired && observed.hash_at_cancel == 2 * CELL && recovery.slots[0].status == SFS_INCOMPLETE && recovery.slots[1].status == SFS_OK);
    cache_release(h); assert(sfs_image_stat(h, 0, 1, &entry, &r) == SFS_STATE);
    ok(sfs_image_select(h, 1, &generous, &binding), &binding); cache_release(h); expect(h, 1, 2, "shared");
    OK(sfs_image_stat(h, 0, 1, &entry, &r)); cache_binding(&binding, &r); assert(sfs_image_begin(h, &r) == SFS_STATE);
    unsigned char *changed = malloc(n); assert(changed); memcpy(changed, baseline, n); put64(changed + 40, 2); slot_hash(changed);
    cache_release(h); replace_image(changed, n); reset("", 0);
    assert(sfs_image_select(h, 0, &generous, &r) == SFS_CORRUPT && r.phase == SFS_PHASE_READ && !r.system_errno);
    replace_image(baseline, n); OK(sfs_image_select(h, 0, &generous, &r)); cache_release(h); expect(h, 0, 2, "shared");
    close_image(h); assert(!allocated); unchanged("image", baseline, n); free(changed); free(baseline); retain(1300);

    /* Minor6 retains pending overlays, shared owners, views and charged tail. */
    f = hardlink_fixture(2, 0, 1, 1); fixture_save(&f); reset("", 0); open_image(&h);
    metadata_clock(1500); OK(sfs_image_begin(h, &r)); OK(sfs_image_write(h, 4, 0, "new", 3, &r));
    expect(h, 0, 4, "old"); handle = cache_handle_bytes(h); cache_release(h); assert(allocated > handle);
    expect(h, 0, 4, "old"); sfs_metadata_entry m = hardlink_get(h, 0, 4, 2); assert(m.entry.size == 3);
    ok(sfs_image_commit(h, &binding), &binding); expect(h, 0, 4, "new"); expect(h, 1, 4, "old"); hardlink_name(h, 0, 1, "b", 4);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_write(h, 4, 0, "bad", 3, &r)); expect(h, 0, 4, "new");
    ok(sfs_image_stat(h, 0, 4, &entry, &binding), &binding); uint64_t charged = binding.physical_end; cache_release(h);
    OK(sfs_image_stat(h, 0, 4, &entry, &r)); cache_binding(&binding, &r); expect(h, 0, 4, "new");
    OK(sfs_image_abort(h, &r)); assert(r.physical_end == charged && r.generation == binding.generation && !memcmp(r.root_digest, binding.root_digest, 32));
    cache_release(h); expect(h, 0, 4, "new"); expect(h, 1, 4, "old");
    close_image(h); assert(!allocated); open_image(&h); expect(h, 0, 4, "new"); close_image(h); retain(1301);
}

/* One legal height-three global tree; the literal table is independent of cookies. */
static const uint64_t position_table[24] = {
    1297,1298,1299,1300, 1313,1314,1315,1316, 1329,1330,1331,1332,
    1441,1442,1443,1444, 1457,1458,1459,1460, 1473,1474,1475,1476
};
static fixture position_fixture(fixture_node leaves[6]) {
    fixture f = fixture_start(); f.minor = 6; put32(f.p + 12, 6);
    unsigned char names[24 * 280], inodes[2 * 496] = {0};
    hardlink_row(names, 1, "dir", 2);
    for (unsigned i = 0; i < 23; i++) { char name[16]; assert(snprintf(name, sizeof(name), "n%04u", i) == 5); hardlink_row(names + (i + 1) * 280, 1, name, 3); }
    fixture_node reverse = tree(&f, 6, names + 280, 23);
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *row = inodes + i * 496, *name = names + i * 280; unsigned kind = i ? SFS_FILE : SFS_DIRECTORY;
        put64(row, i + 2); put64(row + 8, 1); put32(row + 16, kind); put32(row + 20, get32(name + 8)); memcpy(row + 88, name + 12, get32(name + 8)); put64(row + 344, i ? 23 : 1); fixture_tuple(row + 352, kind, 0);
        if (i) memcpy(row + 440, reverse.ref, 56);
    }
    fixture_node inode = tree(&f, 1, inodes, 2), middle[2];
    for (unsigned i = 0; i < 6; i++) leaves[i] = page(&f, 2, 0, names + i * 4 * 280, 4, 280, NULL);
    for (unsigned i = 0; i < 2; i++) middle[i] = page(&f, 2, 1, NULL, 3, 328, leaves + i * 3);
    fixture_node global = page(&f, 2, 2, NULL, 2, 328, middle), zero = {0};
    fixture_node space = hardlink_space(&f, inode, global, zero, 2, 24, 4), catalog = hardlink_catalog(&f, space);
    finish_fixture(&f, space, catalog); assert(hardlink_guard(f.p, f.p, f.n));
    unsigned char *root_page = record(f.p, global.ref, f.n); assert(get16(root_page + 68) == 2 && get16(root_page + 70) == 2);
    for (unsigned i = 0; i < 2; i++) { unsigned char *p = record(f.p, middle[i].ref, f.n); assert(get16(p + 68) == 1 && get16(p + 70) == 3); }
    for (unsigned i = 0; i < 6; i++) { unsigned char *p = record(f.p, leaves[i].ref, f.n); assert(!get16(p + 68) && get16(p + 70) == 4); }
    return f;
}
static void position_outputs(sfs_image *h, const sfs_result *binding) {
    sfs_cookie cookie, saved; memset(&saved, 0xA5, sizeof(saved)); sfs_entry e, canary; memset(&canary, 0xA5, sizeof(canary)); sfs_result r;
    cookie = saved; e = canary; uint64_t unavailable_position = UINT64_MAX; int unavailable_found = 99;
    XEXPECT(sfs_image_next_position(NULL, 0, 1, &cookie, &e, &unavailable_position, &unavailable_found, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !r.system_errno && unavailable_found == 99 && unavailable_position == UINT64_MAX && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&e, &canary, sizeof(e)));
    position_failure(NULL, 0, binding, 1, 1297, SFS_INVALID, SFS_PHASE_NONE, 0);
    for (unsigned missing = 0; missing < 4; missing++) {
        cookie = saved; e = canary; uint64_t position = UINT64_MAX; int found = 99;
        XEXPECT(sfs_image_next_position(h, 0, 1, missing == 0 ? NULL : &cookie, missing == 1 ? NULL : &e,
            missing == 2 ? NULL : &position, missing == 3 ? NULL : &found, &r), SFS_INVALID);
        assert(found == 99 && position == UINT64_MAX && !memcmp(&e, &canary, sizeof(e)) && !memcmp(&cookie, &saved, sizeof(cookie)));
        assert(!r.system_errno && r.phase == SFS_PHASE_NONE);
    }
    /* The inherited malformed-cookie refusal is identical, including provenance. */
    sfs_cookie legacy_cookie = saved; sfs_entry legacy_entry = canary; int legacy_found = 99; sfs_result legacy_result;
    enum sfs_status legacy_status = sfs_image_next(h, 0, 1, &legacy_cookie, &legacy_entry, &legacy_found, &legacy_result);
    cookie = saved; e = canary; uint64_t malformed_position = UINT64_MAX; int malformed_found = 99;
    enum sfs_status numeric_status = sfs_image_next_position(h, 0, 1, &cookie, &e, &malformed_position, &malformed_found, &r);
    assert(legacy_status != SFS_OK && legacy_result.status == legacy_status && numeric_status == legacy_status && r.status == numeric_status);
    assert(r.phase == legacy_result.phase && r.system_errno == legacy_result.system_errno && r.coverage == legacy_result.coverage);
    assert(!legacy_found && !malformed_found && malformed_position == UINT64_MAX && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&legacy_cookie, &saved, sizeof(saved)) && !memcmp(&e, &canary, sizeof(e)) && !memcmp(&legacy_entry, &canary, sizeof(canary)));
    cookie = saved;
    XEXPECT(sfs_image_resume_after_position(h, 0, 0, binding->root_digest, 1, 1297, &cookie, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !memcmp(&cookie, &saved, sizeof(cookie)));
    XEXPECT(sfs_image_resume_after_position(h, 0, binding->generation, NULL, 1, 1297, &cookie, &r), SFS_INVALID);
    assert(r.phase == SFS_PHASE_NONE && !memcmp(&cookie, &saved, sizeof(cookie)));
    XEXPECT(sfs_image_resume_after_position(h, 0, binding->generation, binding->root_digest, 1, 1297, NULL, &r), SFS_INVALID); assert(r.phase == SFS_PHASE_NONE);
    assert(sfs_image_resume_after_position(h, 0, binding->generation, binding->root_digest, 1, 0, &cookie, NULL) == SFS_INVALID && !memcmp(&cookie, &saved, sizeof(cookie)));
    cookie = saved; e = canary; int refused_found = 99;
    assert(sfs_image_next_position(h, 0, 1, &cookie, &e, NULL, &refused_found, NULL) == SFS_INVALID && refused_found == 99 && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&e, &canary, sizeof(e)));
    cookie = (sfs_cookie){0}; e = canary; uint64_t position = 0; int found = 99;
    assert(sfs_image_next_position(h, 0, 1, &cookie, &e, &position, &found, NULL) == SFS_OK && found && position == 1297 && e.inode == 2);
    assert(!clock_calls); image_unwritten();
}
static void position_names(void) {
    retain(3500); fixture_node leaves[6]; fixture f = position_fixture(leaves); save("image", f.p, f.n);
    sfs_image *h; sfs_result r, binding; reset("", 0); open_image(&h); reset("", 0);
    XEXPECT(sfs_image_verify(h, &generous, &r), SFS_OK); assert(r.coverage == SFS_COVERAGE_FULL_REACHABLE && !raw_hash_input); image_unwritten(); close_image(h); retain(3501); save("image", f.p, f.n); reset("", 0); open_readonly(&h, &binding); int fd = image_open_fd; struct stat identity, after; assert(!fstat(fd, &identity));
    assert(position_equivalence(h, 0, 1, &binding, 6) == 24); assert(position_equivalence(h, 1, 1, &binding, 6) == 24);
    assert(position_equivalence(h, 0, 2, &binding, 6) == 0);
    sfs_cookie cookies[24], cursor = {0}; sfs_entry e; int found; uint64_t position;
    reset("", 0); clock_calls = 0;
    for (unsigned i = 0; i < 24; i++) {
        XEXPECT(sfs_image_next_position(h, 0, 1, &cursor, &e, &position, &found, &r), SFS_OK);
        assert(found && position == position_table[i] && e.parent == 1 && e.inode == (i ? 3 : 2));
        if (!i) assert(e.name_length == 3 && !memcmp(e.name, "dir", 3));
        else { char name[16]; assert(snprintf(name, sizeof(name), "n%04u", i - 1) == 5); assert(e.name_length == 5 && !memcmp(e.name, name, 5)); }
        cookies[i] = cursor; sfs_cookie resumed;
        XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 1, position_table[i], &resumed, &r), SFS_OK);
        assert(!memcmp(&resumed, &cursor, sizeof(cursor)));
    }
    /* Speculative advances are local: reconstruct the accepted position twice. */
    for (unsigned pass = 0; pass < 2; pass++) {
        unsigned previous = pass ? 2 : 11; cursor = cookies[previous];
        XEXPECT(sfs_image_next_position(h, 0, 1, &cursor, &e, &position, &found, &r), SFS_OK); assert(found && position == position_table[previous + 1]);
        XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 1, position_table[previous], &cursor, &r), SFS_OK);
        XEXPECT(sfs_image_next_position(h, 0, 1, &cursor, &e, &position, &found, &r), SFS_OK); assert(found && position == position_table[previous + 1]);
    }
    cache_release(h); watch_payload(0, leaves[2].ref); watch_payload(1, leaves[3].ref); watch_count = 2; watch_clear(); cursor = cookies[11];
    XEXPECT(sfs_image_next_position(h, 0, 1, &cursor, &e, &position, &found, &r), SFS_OK);
    assert(found && position == 1441 && e.name_length == 5 && !memcmp(e.name, "n0011", 5));
    assert(watch_reads[0] && watch_reads[1] && !raw_hash_input); watch_count = 0;
    /* Five distinct traversal pages, independent of extra membership lookups. */
    unsigned char *ns = namespace_at(f.p, selected_slot(f.p), f.n), *name_root = record(f.p, ns + 120, f.n);
    uint64_t union_offsets[5] = {get64(ns + 128), get64(name_root + 640 + 271 + 8), get64(name_root + 640 + 328 + 271 + 8), get64(leaves[2].ref + 8), get64(leaves[3].ref + 8)};
    for (unsigned i = 0; i < 5; i++) for (unsigned j = i + 1; j < 5; j++) assert(union_offsets[i] != union_offsets[j]);
    uint64_t power = 1; for (unsigned i = 0; i < 15; i++) power *= 9;
    uint64_t maximum = (2 * power - 1) * 16 + 12; assert(maximum == UINT64_C(6588516227028764) && maximum < (UINT64_C(1) << 53));
    uint64_t inverse = maximum / 16; assert(maximum % 16 == 12);
    for (unsigned i = 0; i < 15; i++) { assert(inverse % 9 == 8); inverse /= 9; } assert(inverse == 1);
    const uint64_t invalid[] = {0,1,2,3,16,1296,1301,1309,1311,17,145,11665,2593,1585,2449,1345,1425,UINT64_MAX-14,UINT64_MAX,UINT64_C(6588516227028764)};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) position_failure(h, 0, &binding, 1, invalid[i], SFS_INVALID, SFS_PHASE_READ, 0);
    position_failure(h, 0, &binding, 2, 1297, SFS_INVALID, SFS_PHASE_READ, 0);
    position_failure(h, 99, &binding, 1, 1297, SFS_NOT_FOUND, SFS_PHASE_READ, 0);
    position_failure(h, 0, &binding, 3, 1297, SFS_INVALID, SFS_PHASE_READ, 0);
    position_failure(h, 0, &binding, 0, 1297, SFS_INVALID, SFS_PHASE_READ, 0);
    position_failure(h, 0, &binding, UINT64_MAX, 1297, SFS_INVALID, SFS_PHASE_READ, 0);
    sfs_result stale = binding; stale.generation++; position_failure(h, 0, &stale, 1, 1297, SFS_STATE, SFS_PHASE_NONE, 0);
    stale = binding; stale.root_digest[0] ^= 1; position_failure(h, 0, &stale, 1, 1297, SFS_STATE, SFS_PHASE_NONE, 0);
    position_outputs(h, &binding);
    assert(fcntl(fd, F_GETFL) >= 0 && (fcntl(fd, F_GETFL) & O_ACCMODE) == O_RDONLY && !fstat(fd, &after)); identical_identity(&identity, &after);
    image_unwritten(); close_image(h); unchanged("image", f.p, f.n); free(f.p); retain(3502);
}
static void position_failures(void) {
    sfs_result r, binding; sfs_image *h; fixture_node leaves[6];
    fixture f = position_fixture(leaves); fixture_save(&f); reset("", 0); open_image(&h); binding = xattr_binding(h);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); sfs_metadata_update update = {0}; update.fields = SFS_META_UID; update.uid = 777;
    XEXPECT(sfs_image_set_metadata(h, 3, &update, &r), SFS_OK); size_t n; unsigned char *before = bytes("image", &n);
    reset("", 0); clock_calls = 0; fail_allocation = allocation_calls + 1;
    position_failure(h, 0, &binding, 1, 1297, SFS_NOMEM, SFS_PHASE_READ, ENOMEM); assert(hit); fail_allocation = 0;
    position_failure(h, 0, &binding, 1, 0, SFS_INVALID, SFS_PHASE_READ, 0);
    sfs_result stale_binding = binding; stale_binding.generation++; position_failure(h, 0, &stale_binding, 1, 1297, SFS_STATE, SFS_PHASE_NONE, 0);
    position_failure(h, 99, &binding, 1, 1297, SFS_NOT_FOUND, SFS_PHASE_READ, 0); unchanged("image", before, n);
    sfs_cookie cookie = {0}, saved = cookie; sfs_entry e, canary; memset(&canary, 0xA5, sizeof(canary)); e = canary; int found = 99; uint64_t position = UINT64_MAX;
    cache_release(h); reset("", 0); fail_allocation = allocation_calls + 1;
    XEXPECT(sfs_image_next_position(h, 0, 1, &cookie, &e, &position, &found, &r), SFS_NOMEM);
    assert(hit && !found && r.phase == SFS_PHASE_READ && r.system_errno == ENOMEM && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&e, &canary, sizeof(e)) && position == UINT64_MAX);
    fail_allocation = 0; image_unwritten(); unchanged("image", before, n); free(before); assert(!clock_calls); metadata_commit(h); sfs_metadata_entry m = hardlink_get(h, 0, 3, 23); assert(m.uid == 777); close_image(h); retain(3511);
    for (unsigned policy = 0; policy < 3; policy++) for (unsigned next = 0; next < 2; next++) {
        f = position_fixture(leaves); fixture_save(&f); reset("", 0);
        if (policy == 1) open_readonly(&h, &binding);
        else if (policy == 2) { sfs_recovery recovery; XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK); ok(sfs_image_select(h, 1, &generous, &binding), &binding); }
        else { open_image(&h); binding = xattr_binding(h); XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_set_metadata(h, 3, &update, &r), SFS_OK); }
        XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 1, 1332, &cookie, &r), SFS_OK); saved = cookie;
        before = bytes("image", &n); cache_release(h); read_at[0] = get64(leaves[3].ref + 8); reset("candidate_reads", 1); clock_calls = 0;
        if (next) {
            e = canary; position = UINT64_MAX; found = 99;
            XEXPECT(sfs_image_next_position(h, 0, 1, &cookie, &e, &position, &found, &r), SFS_IO);
            assert(!found && r.phase == SFS_PHASE_READ && r.system_errno == EIO && !memcmp(&cookie, &saved, sizeof(cookie)) && !memcmp(&e, &canary, sizeof(e)) && position == UINT64_MAX);
        } else position_failure(h, 0, &binding, 1, 1441, SFS_IO, SFS_PHASE_READ, EIO);
        assert(hit && !clock_calls); image_unwritten(); unchanged("image", before, n); reset("", 0);
        if (policy == 2) { cache_release(h); assert(position_equivalence(h, 0, 1, &binding, 6) == 24); }
        else {
            position_failure(h, 0, &binding, 1, 0, SFS_POISONED, SFS_PHASE_READ, 0);
            e = canary; cookie = saved; position = UINT64_MAX; found = 99;
            XEXPECT(sfs_image_next_position(h, 0, 1, &cookie, &e, &position, &found, &r), SFS_POISONED);
            assert(found == 99 && !memcmp(&e, &canary, sizeof(e)) && !memcmp(&cookie, &saved, sizeof(cookie)) && position == UINT64_MAX);
            if (!policy) XEXPECT(sfs_image_commit(h, &r), SFS_POISONED);
        }
        close_image(h); unchanged("image", before, n); free(before); retain(3540 + (int)(policy * 2 + next));
    }
    /* Identity precedes missing view/malformed token, but follows binding. */
    for (unsigned next = 0; next < 2; next++) {
        f = position_fixture(leaves); fixture_save(&f); reset("", 0); open_image(&h); binding = xattr_binding(h);
        XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_set_metadata(h, 3, &update, &r), SFS_OK);
        int fd = open("image", O_WRONLY | O_NOFOLLOW | O_CLOEXEC); assert(fd >= 0); struct stat st; assert(!fstat(fd, &st)); raw_write(fd, "!", 1, st.st_size); assert(!close(fd)); before = bytes("image", &n);
        reset("", 0); clock_calls = 0; sfs_result stale = binding; stale.generation++;
        position_failure(h, 99, &stale, 1, 0, SFS_STATE, SFS_PHASE_NONE, 0);
        if (!next) position_failure(h, 99, &binding, 1, 0, SFS_IO, SFS_PHASE_IDENTITY, ESTALE);
        else { cookie = (sfs_cookie){0}; saved = cookie; e = canary; position = UINT64_MAX; found = 99;
            XEXPECT(sfs_image_next_position(h, 0, 1, &cookie, &e, &position, &found, &r), SFS_IO);
            assert(!found && r.phase == SFS_PHASE_IDENTITY && r.system_errno == ESTALE && !memcmp(&e, &canary, sizeof(e)) && !memcmp(&cookie, &saved, sizeof(cookie)) && position == UINT64_MAX);
        }
        assert(!clock_calls); image_unwritten(); XEXPECT(sfs_image_commit(h, &r), SFS_POISONED); close_image(h); unchanged("image", before, n); free(before); retain(3516 + (int)next);
    }
}

static void position_views(void) {
    retain(3530); fixture f = hardlink_fixture(2, 1, 0, 1); fixture_save(&f); sfs_image *h; sfs_result r, binding; reset("", 0); open_image(&h); binding = xattr_binding(h);
    sfs_cookie cookie = {0}, committed, proposed; sfs_entry e; uint64_t position = 0; int found;
    XEXPECT(sfs_image_next_position(h, 0, 2, &cookie, &e, &position, &found, &r), SFS_OK); assert(found && e.inode == 4 && e.name[0] == 'a' && position == 20); committed = cookie;
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, 4, 1, "aaa", 3, &r), SFS_OK);
    assert(position_equivalence(h, 0, 2, &binding, 6) == 2);
    XEXPECT(sfs_image_resume_after_position(h, 0, binding.generation, binding.root_digest, 2, 20, &proposed, &r), SFS_OK); assert(!memcmp(&proposed, &committed, sizeof(proposed)));
    XEXPECT(sfs_image_abort(h, &r), SFS_OK); assert(position_equivalence(h, 0, 2, &binding, 6) == 2);
    XEXPECT(sfs_image_begin(h, &r), SFS_OK); XEXPECT(sfs_image_link(h, 4, 1, "aaa", 3, &r), SFS_OK); metadata_commit(h);
    sfs_result fresh = xattr_binding(h); reset("", 0); clock_calls = 0;
    position_failure(h, 0, &binding, 2, 20, SFS_STATE, SFS_PHASE_NONE, 0);
    position_failure(h, 1, &binding, 2, 20, SFS_STATE, SFS_PHASE_NONE, 0);
    sfs_entry canary; memset(&canary, 0xA5, sizeof(canary)); e = canary; cookie = committed; position = UINT64_MAX; found = 99;
    XEXPECT(sfs_image_next_position(h, 0, 2, &cookie, &e, &position, &found, &r), SFS_STATE);
    assert(!found && position == UINT64_MAX && !memcmp(&cookie, &committed, sizeof(cookie)) && !memcmp(&e, &canary, sizeof(e)));
    /* Same numeric seek, two explicitly authorized views, different preceding rows. */
    for (unsigned view = 0; view < 2; view++) {
        cookie = (sfs_cookie){0}; XEXPECT(sfs_image_next_position(h, view, 1, &cookie, &e, &position, &found, &r), SFS_OK);
        assert(found && position == 17 && e.inode == (view ? 5 : 4)); assert(e.name_length == (view ? 5u : 3u) && !memcmp(e.name, view ? "other" : "aaa", e.name_length));
        XEXPECT(sfs_image_resume_after_position(h, view, fresh.generation, fresh.root_digest, 1, 17, &proposed, &r), SFS_OK); assert(!memcmp(&cookie, &proposed, sizeof(cookie)));
    }
    close_image(h); size_t n; unsigned char *before = bytes("image", &n); reset("", 0); open_readonly(&h, &binding);
    assert(!memcmp(binding.root_digest, fresh.root_digest, 32) && binding.generation == fresh.generation);
    assert(position_equivalence(h, 0, 2, &binding, 6) == 2); assert(position_equivalence(h, 1, 2, &binding, 6) == 2); close_image(h);
    sfs_recovery recovery; reset("", 0); XEXPECT(sfs_image_inspect(root, "image", &h, &recovery, &generous, &r), SFS_OK);
    position_failure(h, 0, &binding, 1, 17, SFS_STATE, SFS_PHASE_NONE, 0);
    for (unsigned slot = 0; slot < 2; slot++) {
        assert(recovery.slots[slot].status == SFS_OK && recovery.slots[slot].coverage == SFS_COVERAGE_FULL_REACHABLE);
        ok(sfs_image_select(h, slot, &generous, &binding), &binding); assert(position_equivalence(h, 1, 2, &binding, 6) == 2);
    }
    image_unwritten(); close_image(h); unchanged("image", before, n); free(before); retain(3531);
}

#ifdef SFS_IMAGE_DIAGNOSTIC_TESTING
static void diagnostic_receipts(void) {
    sfs_image *h; sfs_result r; sfs_inode id; sfs_metadata_initial initial = metadata_input(SFS_FILE);
    hardlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r));
    OK(sfs_image_add_metadata(h, 1, "file", 4, SFS_FILE, &initial, &id, &r));
    OK(sfs_image_write(h, id, 0, "accepted", 8, &r)); OK(sfs_image_commit(h, &r));
    assert(r.fence_attempted == 3 && r.fence_succeeded == 3 && !r.transaction_active && !r.poisoned);
    uint64_t generation = r.generation;
    sfs_image_diagnostic_counters(h, UINT64_MAX, 0);
    assert(sfs_image_begin(h, &r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_STRUCTURE && !r.transaction_active);
    sfs_image_diagnostic_counters(h, 0, UINT64_MAX);
    OK(sfs_image_begin(h, &r));
    assert(sfs_image_write(h, id, 0, "no", 2, &r) == SFS_NOMEM && r.limit_reason == SFS_LIMIT_UNSPECIFIED);
    OK(sfs_image_abort(h, &r)); sfs_image_diagnostic_counters(h, 0, 0);
    OK(sfs_image_begin(h, &r));
    assert(sfs_image_write(h, id, SFS_FILE_MAX, "x", 1, &r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_FILE_SIZE && !r.transaction_active);
    assert(sfs_image_abort(h, &r) == SFS_STATE && r.limit_reason == SFS_LIMIT_UNSPECIFIED);
    OK(sfs_image_begin(h, &r)); OK(sfs_image_write(h, id, 0, "staged", 6, &r));
    clock_failure = 1;
    assert(sfs_image_write(h, id, CELL, "second", 6, &r) == SFS_TIME_UNAVAILABLE && r.transaction_active && !r.poisoned && r.system_errno == ENXIO);
    clock_failure = 0; OK(sfs_image_abort(h, &r)); expect(h, 0, id, "accepted");
    OK(sfs_image_begin(h, &r)); OK(sfs_image_write(h, id, 0, "staged", 6, &r));
    /* Fail the real cold reconciliation header allocation, not an allocation
       ordinal which disappears when commit reuses its existing cache pool. */
    cache_release(h); reset("", 0); fail_allocation = allocation_calls + 1;
    assert(sfs_image_commit(h, &r) == SFS_NOMEM && !r.transaction_active && !r.poisoned && r.generation == generation);
    fail_allocation = 0; assert(sfs_image_abort(h, &r) == SFS_STATE); expect(h, 0, id, "accepted");
    sfs_image_information information; OK(sfs_image_get_information(h, &information, &r));
    sfs_image_diagnostic_capacity(h, information.committed.physical_end);
    assert(sfs_image_begin(h, &r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_APPEND_CAPACITY && !r.transaction_active);
    sfs_image_diagnostic_capacity(h, TEST_CAPACITY); OK(sfs_image_begin(h, &r));
    OK(sfs_image_write(h, id, 0, "staged", 6, &r)); OK(sfs_image_get_information(h, &information, &r));
    sfs_image_diagnostic_capacity(h, information.committed.physical_end);
    assert(sfs_image_commit(h, &r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_APPEND_CAPACITY && !r.transaction_active);
    sfs_image_diagnostic_capacity(h, TEST_CAPACITY); expect(h, 0, id, "accepted");
    close_image(h); retain(3600);
    for (unsigned pass = 0; pass < 3; ++pass) {
        hardlink_create(&h, TEST_CAPACITY); OK(sfs_image_begin(h, &r));
        OK(sfs_image_add_metadata(h, 1, "file", 4, SFS_FILE, &initial, &id, &r)); OK(sfs_image_commit(h, &r));
        generation = r.generation; OK(sfs_image_begin(h, &r)); OK(sfs_image_write(h, id, 0, "x", 1, &r));
        reset(pass == 1 ? "slot_torn" : "full_enospc", pass == 2 ? 2 : 1);
        enum sfs_status status = sfs_image_commit(h, &r);
        assert(hit && status == (pass ? SFS_OUTCOME_UNKNOWN : SFS_IO) && r.system_errno == ENOSPC);
        assert(r.poisoned && !r.transaction_active && r.generation == generation && r.limit_reason == SFS_LIMIT_UNSPECIFIED);
        assert(r.fence_attempted == (pass == 2 ? 3u : 1u) && r.fence_succeeded == (pass ? 1u : 0u));
        assert(r.phase == (pass == 0 ? SFS_PHASE_RECORD_BARRIER : pass == 2 ? SFS_PHASE_COMMIT_BARRIER : SFS_PHASE_SLOT1));
        reset("", 0); close_image(h); retain(3601 + (int)pass);
    }
    fixture f = indexed_fixture(1, 1, 0); size_t size = f.n;
    for (unsigned slot = 0; slot < 2; ++slot) { put64(f.p + slot * CELL + 144, size + CELL); slot_hash(f.p + slot * CELL); }
    fixture_save(&f); open_image(&h); OK(sfs_image_begin(h, &r));
    assert(sfs_image_resize(h, 2, 8192, &r) == SFS_LIMIT && r.limit_reason == SFS_LIMIT_APPEND_CAPACITY);
    assert(!r.transaction_active && !r.poisoned); close_image(h);
}
#endif
static void metadata_information(void) {
    sfs_image *h = NULL; sfs_result r; sfs_image_information first, pending, current;
    sfs_metadata_initial initial = { .mode = S_IFDIR | 0700, .uid = geteuid(), .gid = getegid() };
    clock_at(1700000000, 0);
    assert(sfs_image_create_metadata_version(root, "information", TEST_CAPACITY, 6, &initial, &h, &r) == SFS_OK);
    uint64_t allocations_before = allocation_calls, reads_before = image_read_attempts;
    assert(sfs_image_get_information(h, &first, &r) == SFS_OK);
    assert(allocation_calls == allocations_before && image_read_attempts == reads_before);
    assert(first.major == 0 && first.minor == 6 && first.root_inode == 1 && first.capacity == TEST_CAPACITY);
    assert(first.committed.generation == 1 && first.committed.coverage == SFS_COVERAGE_ROOT_ONLY);
    assert(first.append_headroom == TEST_CAPACITY - first.committed.physical_end);
    assert(sfs_image_begin(h, &r) == SFS_OK);
    sfs_inode inode; initial.mode = S_IFREG | 0600;
    assert(sfs_image_add_metadata(h, 1, "unrelated", 9, SFS_FILE, &initial, &inode, &r) == SFS_OK);
    assert(sfs_image_get_information(h, &pending, &r) == SFS_OK);
    assert(pending.committed.generation == first.committed.generation);
    assert(!memcmp(pending.committed.root_digest, first.committed.root_digest, 32));
    assert(pending.append_headroom <= first.append_headroom);
    assert(sfs_image_commit(h, &r) == SFS_OK);
    assert(sfs_image_get_information(h, &current, &r) == SFS_OK);
    assert(current.committed.generation == first.committed.generation + 1);
    assert(!memcmp(current.committed.uuid, first.committed.uuid, 16));
    assert(current.committed.device == first.committed.device && current.committed.inode == first.committed.inode);
    assert(memcmp(current.committed.root_digest, first.committed.root_digest, 32));
    sfs_cookie cookie = {0}; sfs_entry entry; uint64_t position; int found;
    assert(sfs_image_next_position(h, 0, 1, &cookie, &entry, &position, &found, &r) == SFS_OK && found);
    assert(sfs_image_begin(h, &r) == SFS_OK);
    assert(sfs_image_add_metadata(h, 1, "second", 6, SFS_FILE, &initial, &inode, &r) == SFS_OK);
    assert(sfs_image_commit(h, &r) == SFS_OK);
    sfs_cookie unchanged_cookie = cookie;
    assert(sfs_image_resume_after_position(h, 0, current.committed.generation, current.committed.root_digest,
                                          1, position, &cookie, &r) == SFS_STATE);
    assert(!memcmp(&cookie, &unchanged_cookie, sizeof(cookie)));
    assert(sfs_image_get_information(h, &current, &r) == SFS_OK);
    assert(sfs_image_get_information(h, NULL, &r) == SFS_INVALID);
    memset(&pending, 0xa5, sizeof(pending)); sfs_image_information unchanged_info = pending;
    assert(sfs_image_get_information(NULL, &pending, &r) == SFS_INVALID);
    assert(!memcmp(&pending, &unchanged_info, sizeof(pending)));
    assert(sfs_image_close(h, &r) == SFS_OK);
    assert(sfs_image_open_readonly(root, "information", &h, &r) == SFS_OK);
    allocations_before = allocation_calls; reads_before = image_read_attempts;
    assert(sfs_image_get_information(h, &pending, &r) == SFS_OK);
    assert(allocation_calls == allocations_before && image_read_attempts == reads_before);
    assert(pending.committed.generation == current.committed.generation);
    assert(sfs_image_close(h, &r) == SFS_OK);
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
    else if(!strcmp(argv[1],"metadata")) metadata(); else if(!strcmp(argv[1],"metadata-codec")) metadata_codec(); else if(!strcmp(argv[1],"metadata-atomic")) metadata_atomic();
    else if(!strcmp(argv[1],"metadata-information")) metadata_information();
#ifdef SFS_IMAGE_DIAGNOSTIC_TESTING
    else if(!strcmp(argv[1],"diagnostic-receipts")) diagnostic_receipts();
#endif
    else if(!strcmp(argv[1],"hardlink-versions")) hardlink_versions();
    else if(!strcmp(argv[1],"hardlink-shared")) { hardlink_shared(); position_views(); }
    else if(!strcmp(argv[1],"hardlink-transitions")) hardlink_transitions();
    else if(!strcmp(argv[1],"hardlink-names")) { hardlink_names(); position_names(); }
    else if(!strcmp(argv[1],"hardlink-failures")) { hardlink_failures(); position_failures(); }
    else if(!strcmp(argv[1],"hardlink-verify")) hardlink_verify();
    else if(!strcmp(argv[1],"xattr-versions")) xattr_versions();
    else if(!strcmp(argv[1],"xattr-values")) xattr_values();
    else if(!strcmp(argv[1],"xattr-namespace")) xattr_namespace();
    else if(!strcmp(argv[1],"xattr-views")) xattr_views();
    else if(!strcmp(argv[1],"xattr-failures")) xattr_failures();
    else if(!strcmp(argv[1],"xattr-verify")) xattr_verify();
    else if(!strcmp(argv[1],"symlink-versions")) symlink_versions();
    else if(!strcmp(argv[1],"symlink-bytes")) symlink_bytes();
    else if(!strcmp(argv[1],"symlink-namespace")) symlink_namespace();
    else if(!strcmp(argv[1],"symlink-views")) symlink_views();
    else if(!strcmp(argv[1],"symlink-failures")) symlink_failures();
    else if(!strcmp(argv[1],"symlink-verify")) symlink_verify();
    else if(!strcmp(argv[1],"cache")) cache_purge();
    else if(!strcmp(argv[1],"cache-commit")) cache_commit();
    else if(!strcmp(argv[1],"readonly")) readonly(); else if(!strcmp(argv[1],"resume")) resume(); else assert(0);
    if(strcmp(argv[1],"cache")&&strcmp(argv[1],"diagnostic-receipts")&&strncmp(argv[1],"metadata",8)&&strncmp(argv[1],"symlink",7)&&strncmp(argv[1],"xattr",5)&&strncmp(argv[1],"hardlink",8)) assert(!clock_calls);
    unchanged("sentinel",sentinel,sizeof(sentinel)); free(durable); assert(!allocated); assert(descriptors()==before);
    printf("PASS %s\n",argv[1]); return 0;
}
