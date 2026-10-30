#include "image.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdatomic.h>

#define CELL 4096u
#define ALIGNMENT UINT64_C(4096)
#define DATA_START UINT64_C(8192)
#define REF_SIZE 56u
#define SLOT_HASH 112u
#define PAGE_HEAD 640u
#define MAX_HEIGHT 16u
_Static_assert(MAX_HEIGHT == 16, "directory position depth contract");
#define CACHE_COUNT 1000u
#define ARENA_COUNT 1024u
#define NO_CHILD UINT16_MAX
#define ARENA_BYTES (5u * 1024u * 1024u)
#define MAX_ROW 496u
_Static_assert(sizeof(off_t) >= 8, "64-bit file offsets required");
_Static_assert(SFS_SNAPSHOT_MAX > 0 && SFS_SNAPSHOT_MAX <= 32, "snapshot limit");
enum { NAMESPACE = 2, ROOT = 4, INDEX = 5, RAW = 6 };
enum { MAP_INODE = 1, MAP_NAME = 2, MAP_EXTENT = 3, MAP_SNAPSHOT = 4, MAP_XATTR = 5, MAP_BACKREF = 6 };
typedef struct { uint32_t type; uint64_t offset, length; uint8_t digest[32]; } reference;
typedef struct { uint16_t length; uint8_t bytes[263]; } key;
typedef struct {
    sfs_timestamp birth, access, modification, change;
    uint32_t mode, uid, gid, flags;
    uint64_t extents;
} attributes;
typedef struct { sfs_entry e; reference extent; attributes attributes; uint64_t nlink; reference reverse; } node;
typedef struct { uint64_t count, next_inode; reference inodes, names, ref; attributes attributes; reference xattrs; uint64_t name_count; } namespace;
typedef struct { uint32_t view, length; uint8_t name[SFS_NAME_MAX]; reference ns; } snapshot;
typedef struct { uint64_t generation, end, capacity; uint8_t uuid[16]; reference root; uint32_t minor; } anchor;
typedef struct { namespace ns; uint32_t count; snapshot snapshots[SFS_SNAPSHOT_MAX]; reference catalog; } state;
typedef struct { reference ref; uint64_t stamp; uint8_t *bytes; } cache_entry;
typedef struct { cache_entry entries[CACHE_COUNT]; uint64_t clock; unsigned count; } cache;
typedef struct arena arena;
typedef struct tree tree;
typedef struct batch batch;
typedef struct pin_slot pin_slot;
typedef struct pin_table pin_table;
typedef struct { sfs_inode id; pin_slot *detached; } mutation_target;
typedef struct { node inode; reference xattrs; uint64_t next_inode, end, generation; } pin_descriptor;
enum { PIN_FREE, PIN_RESERVED, PIN_LINKED, PIN_DETACHED };
struct pin_slot {
    uint64_t incarnation; sfs_inode id;
    uint32_t state, pending, dirty, next, previous, free_next;
    pin_descriptor committed, staged;
};
struct pin_table {
    uint64_t instance, bytes;
    uint8_t session[16];
    uint32_t count, hash_count, free_head, changed;
    pin_slot *slots; uint32_t *hash;
};
enum image_policy { ORDINARY_WRITABLE, ORDINARY_READONLY, RECOVERY };
struct sfs_image {
    int fd, aux_parent, selected, poisoned, transaction;
    enum image_policy policy;
    struct stat identity, parent_identity;
    uint64_t eof, epoch, token;
    anchor current, slots[2]; enum sfs_status slot_status[2]; int slot_error[2], slot_observed[2];
    state live, staged; enum sfs_phase phase; cache *cache; batch *batch;
    enum sfs_limit_reason limit_reason;
    unsigned fence_attempted, fence_succeeded;
    pin_table *pins;
#ifdef SFS_IMAGE_DIAGNOSTIC_TESTING
    uint64_t diagnostic_capacity;
#endif
};
typedef struct { uint64_t block, stamp; uint8_t *bytes; int valid, dirty; } aux_entry;
typedef struct {
    int fd, directory, created; char name[48]; uint64_t length, clock;
    aux_entry entries[CACHE_COUNT]; unsigned count;
} auxiliary;
typedef struct {
    sfs_image *h; anchor a; sfs_verify_budget *budget; auxiliary *aux;
    enum sfs_phase phase; enum sfs_incomplete_reason incomplete; int error;
} reader;
typedef struct { unsigned map, level; int root, last; unsigned minor; key lower, upper; uint64_t next_inode, eof; } context;
_Static_assert(sizeof(attributes) == 88 && _Alignof(attributes) == 8, "metadata tuple layout");
_Static_assert(sizeof(sfs_timestamp) == 16 && _Alignof(sfs_timestamp) == 8, "timestamp layout");
_Static_assert(sizeof(node) == 504 && sizeof(namespace) == 336 && sizeof(anchor) == 104, "metadata state layout");
_Static_assert(PAGE_HEAD + 6u * 496u <= CELL && PAGE_HEAD + 12u * 280u <= CELL, "hardlink row capacity");
_Static_assert(PAGE_HEAD + 9u * 352u <= CELL && PAGE_HEAD + 9u * 328u <= CELL, "xattr row capacity");
_Static_assert(sizeof(state) == sizeof(namespace) + 8 + SFS_SNAPSHOT_MAX * sizeof(snapshot) + sizeof(reference), "namespace state accounting");
_Static_assert(sizeof(context) == 568, "context format uses existing alignment space");
_Static_assert((time_t)-1 < 0 && sizeof(time_t) <= sizeof(int64_t), "signed representable clock seconds");
_Static_assert(sizeof(cache) + CACHE_COUNT * CELL <= 4u * 1024u * 1024u, "metadata cache bound");
_Static_assert(sizeof(auxiliary) + CACHE_COUNT * CELL <= 4u * 1024u * 1024u, "auxiliary cache bound");
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | (uint16_t)p[1] << 8); }
static uint32_t get32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }
static void put16(uint8_t *p, unsigned v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static void big64(uint8_t *p, uint64_t v) { for (unsigned i = 0; i < 8; ++i) p[7 - i] = (uint8_t)(v >> (8 * i)); }
static uint64_t from_big(const uint8_t *p) { uint64_t v = 0; for (unsigned i = 0; i < 8; ++i) v = (v << 8) | p[i]; return v; }
static int add64(uint64_t a, uint64_t b, uint64_t *out) { if (b > UINT64_MAX - a) return 0; *out = a + b; return 1; }
static int aligned(uint64_t n, uint64_t *out) { uint64_t v; if (!add64(n, ALIGNMENT - 1, &v)) return 0; *out = v & ~(ALIGNMENT - 1); return 1; }
static int zero(const void *p, size_t n) { const uint8_t *b = p; for (size_t i = 0; i < n; ++i) if (b[i]) return 0; return 1; }
static void encode_ref(uint8_t *p, const reference *r) { memset(p, 0, REF_SIZE); put32(p, r->type); put64(p + 8, r->offset); put64(p + 16, r->length); memcpy(p + 24, r->digest, 32); }
static int decode_ref(const uint8_t *p, reference *r) { if (get32(p + 4)) return 0; memset(r, 0, sizeof(*r)); r->type = get32(p); r->offset = get64(p + 8); r->length = get64(p + 16); memcpy(r->digest, p + 24, 32); return r->type || zero(p, REF_SIZE); }
static int same_ref(const reference *a, const reference *b) { return a->type == b->type && a->offset == b->offset && a->length == b->length && !memcmp(a->digest, b->digest, 32); }
static int valid_time(sfs_timestamp t) { return t.nanoseconds < UINT32_C(1000000000); }
static int metadata_capable(unsigned minor) { return minor == 3 || minor == 4 || minor == 5 || minor == 6; }
static int symlink_capable(unsigned minor) { return minor == 4 || minor == 5 || minor == 6; }
static int xattr_capable(unsigned minor) { return minor == 5 || minor == 6; }
static const char *record_magic(unsigned minor) { return minor == 2 ? "SFSREC02" : minor == 3 ? "SFSREC03" : minor == 4 ? "SFSREC04" : minor == 5 ? "SFSREC05" : minor == 6 ? "SFSREC06" : "SFSBAD00"; }
static const char *raw_domain(unsigned minor) { return minor == 2 ? "SFSDAT02" : minor == 3 ? "SFSDAT03" : minor == 4 ? "SFSDAT04" : minor == 5 ? "SFSDAT05" : minor == 6 ? "SFSDAT06" : "SFSBAD00"; }
static int valid_mode(uint32_t mode, unsigned kind) {
    uint32_t type = kind == SFS_DIRECTORY ? UINT32_C(0040000) : kind == SFS_FILE ? UINT32_C(0100000) : kind == SFS_SYMLINK ? UINT32_C(0120000) : 0;
    return type && !(mode & ~UINT32_C(0177777)) && (mode & UINT32_C(0170000)) == type;
}
static sfs_timestamp decode_time(const uint8_t *b) {
    uint64_t u = get64(b); sfs_timestamp t = { .seconds = u <= INT64_MAX ? (int64_t)u : -1 - (int64_t)(UINT64_MAX - u), .nanoseconds = get32(b + 8) }; return t;
}
static void encode_time(uint8_t *b, sfs_timestamp t) { put64(b, (uint64_t)t.seconds); put32(b + 8, t.nanoseconds); put32(b + 12, 0); }
static void decode_attributes(const uint8_t *b, attributes *a) {
    memset(a, 0, sizeof(*a)); a->birth = decode_time(b); a->access = decode_time(b + 16); a->modification = decode_time(b + 32); a->change = decode_time(b + 48);
    a->mode = get32(b + 64); a->uid = get32(b + 68); a->gid = get32(b + 72); a->flags = get32(b + 76); a->extents = get64(b + 80);
}
static void encode_attributes(uint8_t *b, const attributes *a) {
    encode_time(b, a->birth); encode_time(b + 16, a->access); encode_time(b + 32, a->modification); encode_time(b + 48, a->change);
    put32(b + 64, a->mode); put32(b + 68, a->uid); put32(b + 72, a->gid); put32(b + 76, a->flags); put64(b + 80, a->extents);
}
static int valid_attributes(const uint8_t *b, unsigned kind, uint64_t size, int extent, uint64_t end) {
    attributes a; decode_attributes(b, &a);
    for (unsigned i = 0; i < 4; ++i) if (get32(b + i * 16 + 8) >= UINT32_C(1000000000) || get32(b + i * 16 + 12)) return 0;
    if (!valid_mode(a.mode, kind) || (a.flags & ~SFS_FLAGS_SUPPORTED)) return 0;
    if (kind == SFS_DIRECTORY) return !a.extents;
    if (kind == SFS_SYMLINK) return a.extents == 1 && extent && size && size <= SFS_SYMLINK_MAX;
    return a.extents <= size / CELL + !!(size % CELL) && a.extents <= end / CELL * 48 && !!a.extents == !!extent;
}
static enum sfs_status clock_sample(sfs_timestamp *out, int *error) {
    struct timespec t; *error = 0;
    if (clock_gettime(CLOCK_REALTIME, &t)) { *error = errno; return SFS_TIME_UNAVAILABLE; }
    if (t.tv_nsec < 0 || t.tv_nsec >= 1000000000L) return SFS_TIME_UNAVAILABLE;
    *out = (sfs_timestamp){ .seconds = (int64_t)t.tv_sec, .nanoseconds = (uint32_t)t.tv_nsec }; return SFS_OK;
}
static enum sfs_status initial_valid(const sfs_metadata_initial *a, unsigned kind) {
    if (!a || (a->restore & ~7u) || !valid_mode(a->mode, kind) || ((a->restore & SFS_RESTORE_BIRTH) && !valid_time(a->birth)) || ((a->restore & SFS_RESTORE_ACCESS) && !valid_time(a->access)) || ((a->restore & SFS_RESTORE_MODIFICATION) && !valid_time(a->modification))) return SFS_INVALID;
    return a->flags & ~SFS_FLAGS_SUPPORTED ? SFS_UNSUPPORTED : SFS_OK;
}
static attributes initial_attributes(const sfs_metadata_initial *a, sfs_timestamp t) {
    attributes v = { .birth = t, .access = t, .modification = t, .change = t, .mode = a->mode, .uid = a->uid, .gid = a->gid, .flags = a->flags };
    if (a->restore & SFS_RESTORE_BIRTH) v.birth = a->birth; if (a->restore & SFS_RESTORE_ACCESS) v.access = a->access; if (a->restore & SFS_RESTORE_MODIFICATION) v.modification = a->modification; return v;
}
static void discard(sfs_image *h);
static void pins_discard(sfs_image *h);
static void pins_promote(sfs_image *h);
static void pins_free(sfs_image *h);
static enum sfs_status mutation_start(sfs_image *, sfs_result *);
static enum sfs_status mutation_failure(sfs_image *, enum sfs_status, enum sfs_phase, int, int, sfs_result *);
static void cache_clear(sfs_image *h) { if (!h->cache) return; for (unsigned i = 0; i < h->cache->count; ++i) free(h->cache->entries[i].bytes); free(h->cache); h->cache = NULL; }
void sfs_image_clear_read_cache(sfs_image *h) { if (h) cache_clear(h); }
static enum sfs_status result(sfs_image *h, enum sfs_status status, enum sfs_phase phase, int error, sfs_result *r) {
    if (r) { memset(r, 0, sizeof(*r)); r->status = status; r->phase = phase; r->system_errno = error;
        if (h) { r->generation = h->current.generation; r->committed_end = h->current.end; r->physical_end = h->eof; r->device = (uint64_t)h->identity.st_dev; r->inode = (uint64_t)h->identity.st_ino; memcpy(r->uuid, h->current.uuid, 16); memcpy(r->root_digest, h->current.root.digest, 32); }
        if (h) {
            r->limit_reason = status == SFS_LIMIT ? h->limit_reason : SFS_LIMIT_UNSPECIFIED;
            r->fence_attempted = h->fence_attempted; r->fence_succeeded = h->fence_succeeded;
            r->transaction_active = h->transaction; r->poisoned = h->poisoned;
        }
    } return status;
}
static enum sfs_status ready(sfs_image *h, int writing, int tx, sfs_result *r) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    h->limit_reason = SFS_LIMIT_UNSPECIFIED; h->fence_attempted = h->fence_succeeded = 0;
    if (h->poisoned) return result(h, SFS_POISONED, h->phase, 0, r);
    if (!h->selected || (writing && h->policy != ORDINARY_WRITABLE) || (tx && !h->transaction)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r); return SFS_OK;
}
static enum sfs_status read_result(sfs_image *h, enum sfs_status code, enum sfs_phase phase, int error, sfs_result *r) {
    if (h && h->policy != RECOVERY && (code == SFS_IO || code == SFS_CORRUPT || code == SFS_RECOVERY_REQUIRED || code == SFS_UNSUPPORTED)) { h->poisoned = 1; h->phase = phase; discard(h); }
    return result(h, code, phase, error, r);
}
static int read_exact(int fd, void *buffer, size_t n, uint64_t at) {
    uint8_t *p = buffer; while (n) { ssize_t k = pread(fd, p, n, (off_t)at); if (k < 0 && errno == EINTR) continue; if (k <= 0) { if (!k) errno = EIO; return -1; } if ((size_t)k > n) { errno = EIO; return -1; } p += k; n -= (size_t)k; at += (uint64_t)k; } return 0;
}
static int write_exact(int fd, const void *buffer, size_t n, uint64_t at) {
    const uint8_t *p = buffer; while (n) { ssize_t k = pwrite(fd, p, n, (off_t)at); if (k < 0 && errno == EINTR) continue; if (k <= 0) { if (!k) errno = EIO; return -1; } if ((size_t)k > n) { errno = EIO; return -1; } p += k; n -= (size_t)k; at += (uint64_t)k; } return 0;
}
static int fullsync(int fd) { return fcntl(fd, F_FULLFSYNC); }
static int valid_name(const void *name, size_t n) {
    if (!name || !n || n > SFS_NAME_MAX) return 0;
    const uint8_t *p = name;
    if ((n == 1 && p[0] == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) return 0;
    return !memchr(name, 0, n) && !memchr(name, '/', n);
}
static int valid_xattr_name(const void *name, size_t n) { return name && n && n <= SFS_NAME_MAX && !memchr(name, 0, n); }
static uint64_t dense_count(uint64_t size) { return size / CELL + (size % CELL != 0); }
static int component(const char *name) { return name && valid_name(name, strnlen(name, SFS_NAME_MAX + 1)); }
static int backing(int fd, struct statfs *out) {
    if (fstatfs(fd, out)) return -1;
    if (strcmp(out->f_fstypename, "apfs") || !(out->f_flags & MNT_LOCAL) || (out->f_flags & MNT_RDONLY)) { errno = ENOTSUP; return -1; }
    return 0;
}
static int same_identity(const struct stat *a, const struct stat *b) { return a->st_dev == b->st_dev && a->st_ino == b->st_ino; }
static int file_stat(int fd, struct stat *st) {
    if (fstat(fd, st)) return -1;
    if (!S_ISREG(st->st_mode) || st->st_uid != geteuid() || st->st_nlink != 1 || (st->st_mode & 0077) || !(st->st_mode & S_IRUSR) || !(st->st_mode & S_IWUSR) || st->st_size < 0) { errno = EINVAL; return -1; }
    if ((uint64_t)st->st_size > SFS_IMAGE_MAX) { errno = EFBIG; return -1; }
    return 0;
}
static int stable(sfs_image *h) {
    struct stat st;
    if (file_stat(h->fd, &st)) return -1;
    if (!same_identity(&st, &h->identity) || (uint64_t)st.st_size != h->eof) { errno = ESTALE; return -1; }
    return 0;
}
static enum sfs_status access_image(const char *directory, const char *name, int creating, enum image_policy policy,
                                  sfs_image **out, int *parent, sfs_result *r) {
    *out = NULL; *parent = -1;
    if (!directory || !component(name)) return result(NULL, SFS_INVALID, SFS_PHASE_PARENT, 0, r);
    int p = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (p < 0) return result(NULL, SFS_IO, SFS_PHASE_PARENT, errno, r);
    struct stat ps; struct statfs pf;
    enum sfs_status code = SFS_IO; int error = 0; enum sfs_phase phase = SFS_PHASE_PARENT;
    if (fstat(p, &ps)) goto fail;
    if (!S_ISDIR(ps.st_mode) || ps.st_uid != geteuid() || (ps.st_mode & 0077) || (ps.st_mode & 0700) != 0700) { errno = EINVAL; code = SFS_INVALID; goto fail; }
    if (backing(p, &pf)) { code = errno == ENOTSUP ? SFS_UNSUPPORTED : SFS_IO; goto fail; }
    phase = creating ? SFS_PHASE_CREATE : SFS_PHASE_VALIDATE;
    int flags = (policy == ORDINARY_WRITABLE ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (creating) flags |= O_CREAT | O_EXCL;
    int fd = openat(p, name, flags, 0600);
    if (fd < 0) { code = errno == EEXIST ? SFS_EXISTS : (errno == ELOOP ? SFS_INVALID : SFS_IO); goto fail; }
    sfs_image *h = calloc(1, sizeof(*h));
    if (!h) { error = ENOMEM; code = SFS_NOMEM; if (close(fd)) error = errno; goto fail_saved; }
    h->fd = fd; h->aux_parent = -1; h->policy = policy; h->parent_identity = ps;
    phase = SFS_PHASE_LOCK;
    if (flock(fd, LOCK_EX | LOCK_NB)) { code = errno == EWOULDBLOCK ? SFS_BUSY : SFS_IO; goto fail_handle; }
    phase = SFS_PHASE_VALIDATE;
    if (file_stat(fd, &h->identity)) { code = errno == EFBIG ? SFS_LIMIT : SFS_INVALID; goto fail_handle; }
    h->eof = (uint64_t)h->identity.st_size;
    struct statfs fs;
    if (backing(fd, &fs)) { code = errno == ENOTSUP ? SFS_UNSUPPORTED : SFS_IO; goto fail_handle; }
    if (memcmp(&fs.f_fsid, &pf.f_fsid, sizeof(fs.f_fsid)) || h->identity.st_dev != ps.st_dev) { errno = EXDEV; code = SFS_INVALID; goto fail_handle; }
    struct stat named;
    if (fstatat(p, name, &named, AT_SYMLINK_NOFOLLOW)) goto fail_handle;
    if (!same_identity(&named, &h->identity)) { errno = ESTALE; goto fail_handle; }
    h->aux_parent = fcntl(p, F_DUPFD_CLOEXEC, 0); if (h->aux_parent < 0) goto fail_handle;
    *out = h; *parent = p; return SFS_OK;
fail_handle:
    error = errno; result(h, code, phase, error, r);
    if (close(fd)) { error = errno; code = SFS_IO; phase = SFS_PHASE_CLOSE; }
    free(h);
    if (close(p)) { error = errno; code = SFS_IO; phase = SFS_PHASE_CLOSE; }
    if (r) { r->status = code; r->phase = phase; r->system_errno = error; }
    return code;
fail:
    error = errno;
fail_saved:
    if (close(p)) { error = errno; code = SFS_IO; phase = SFS_PHASE_CLOSE; }
    return result(NULL, code, phase, error, r);
}


static enum sfs_status io_failure(reader *r, enum sfs_phase phase) { r->error = errno; r->phase = phase; return SFS_IO; }
static enum sfs_status charge(reader *r, enum sfs_incomplete_reason which, uint64_t n) {
    if (!r->budget) return SFS_OK;
    if (r->budget->cancelled && r->budget->cancelled(r->budget->context)) { r->incomplete = SFS_INCOMPLETE_CANCELLED; return SFS_INCOMPLETE; }
    uint64_t *left = NULL;
    switch (which) {
        case SFS_INCOMPLETE_RAW: left = &r->budget->raw_cells; break;
        case SFS_INCOMPLETE_METADATA_READ: left = &r->budget->metadata_read_bytes; break;
        case SFS_INCOMPLETE_METADATA_HASH: left = &r->budget->metadata_hash_bytes; break;
        case SFS_INCOMPLETE_CHECKS: left = &r->budget->checks; break;
        case SFS_INCOMPLETE_AUX_LENGTH: left = &r->budget->auxiliary_bytes; break;
        case SFS_INCOMPLETE_AUX_IO: left = &r->budget->auxiliary_io_bytes; break;
        default: return SFS_INVALID;
    }
    if (*left < n) { r->incomplete = which; return SFS_INCOMPLETE; } *left -= n; return SFS_OK;
}
static int valid_budget(const sfs_verify_budget *b) { return b && b->raw_cells && b->metadata_read_bytes && b->metadata_hash_bytes && b->checks && b->auxiliary_bytes && b->auxiliary_io_bytes; }
static void hash_cell(const uint8_t b[CELL], unsigned type, const uint8_t uuid[16], uint8_t out[32], unsigned minor) {
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    if (type == RAW) { uint8_t domain[36] = {0}; memcpy(domain, raw_domain(minor), 8); memcpy(domain + 8, uuid, 16); put32(domain + 24, RAW); put64(domain + 28, CELL); CC_SHA256_Update(&ctx, domain, sizeof(domain)); }
    CC_SHA256_Update(&ctx, b, CELL); CC_SHA256_Final(out, &ctx);
}
static enum sfs_status bounds(reader *r, const reference *ref, unsigned type, uint64_t before) {
    enum sfs_status e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    uint64_t end;
    if (ref->type != type || ref->length != CELL || ref->offset < DATA_START || ref->offset % CELL || !add64(ref->offset, CELL, &end) || end > before || end > r->a.end || end > r->h->eof || end > r->a.capacity) return SFS_CORRUPT;
    return SFS_OK;
}
static enum sfs_status aux_begin(reader *r) {
    uint64_t cells = r->h->eof / CELL + !!(r->h->eof % CELL);
    if (cells > (uint64_t)INT64_MAX / 128) return SFS_LIMIT;
    uint64_t length = cells * 128; enum sfs_status e = charge(r, SFS_INCOMPLETE_AUX_LENGTH, length); if (e) return e;
    struct statfs fs; if (fstatfs(r->h->aux_parent, &fs)) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    if (fs.f_bsize <= 0 || (uint64_t)fs.f_bavail < (length + (uint64_t)fs.f_bsize - 1) / (uint64_t)fs.f_bsize) { r->phase = SFS_PHASE_ADMISSION; return SFS_LIMIT; }
    auxiliary *a = calloc(1, sizeof(*a)); if (!a) return SFS_NOMEM;
    a->fd = a->directory = -1; a->length = length; r->aux = a;
    uint64_t nonce[2]; arc4random_buf(nonce, sizeof(nonce)); snprintf(a->name, sizeof(a->name), ".sfs-verify-%016llx%016llx", (unsigned long long)nonce[0], (unsigned long long)nonce[1]);
    if (mkdirat(r->h->aux_parent, a->name, 0700)) return io_failure(r, SFS_PHASE_VERIFY_AUX); a->created = 1;
    a->directory = openat(r->h->aux_parent, a->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); if (a->directory < 0) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    struct stat st; if (fstat(a->directory, &st)) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    if (!S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) { errno = EINVAL; return io_failure(r, SFS_PHASE_VERIFY_AUX); }
    a->fd = openat(a->directory, "memo", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); if (a->fd < 0) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    if (ftruncate(a->fd, (off_t)length)) return io_failure(r, SFS_PHASE_VERIFY_AUX); return SFS_OK;
}
static enum sfs_status aux_finish(reader *r, enum sfs_status first) {
    auxiliary *a = r->aux; if (!a) return first;
    int error = 0, had_file = a->fd >= 0;
    for (unsigned i = 0; i < a->count; ++i) free(a->entries[i].bytes);
    if (a->fd >= 0 && close(a->fd)) error = errno;
    if (had_file && unlinkat(a->directory, "memo", 0) && !error) error = errno;
    if (a->directory >= 0 && close(a->directory) && !error) error = errno;
    if (a->created && unlinkat(r->h->aux_parent, a->name, AT_REMOVEDIR) && !error) error = errno;
    free(a); r->aux = NULL;
    if (!first && error) { r->error = error; r->phase = SFS_PHASE_VERIFY_AUX; return SFS_IO; }
    return first;
}
static enum sfs_status aux_bytes(reader *r, uint64_t at, uint8_t **out) {
    auxiliary *a = r->aux; uint64_t block = at / CELL;
    for (unsigned i = 0; i < a->count; ++i) if (a->entries[i].valid && a->entries[i].block == block) { a->entries[i].stamp = ++a->clock; *out = a->entries[i].bytes + at % CELL; return SFS_OK; }
    unsigned slot = a->count;
    if (slot == CACHE_COUNT) { slot = 0; for (unsigned i = 1; i < a->count; ++i) if (a->entries[i].stamp < a->entries[slot].stamp) slot = i; }
    else { a->entries[slot].bytes = calloc(1, CELL); if (!a->entries[slot].bytes) return SFS_NOMEM; a->count++; }
    aux_entry *v = &a->entries[slot]; enum sfs_status e;
    if (v->valid && v->dirty) { uint64_t offset = v->block * CELL; size_t n = a->length - offset < CELL ? (size_t)(a->length - offset) : CELL;
        e = charge(r, SFS_INCOMPLETE_AUX_IO, n); if (e) return e;
        if (write_exact(a->fd, v->bytes, n, offset)) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    }
    v->valid = v->dirty = 0;
    uint64_t offset = block * CELL; if (offset >= a->length || at > a->length - 128) return SFS_CORRUPT;
    size_t n = a->length - offset < CELL ? (size_t)(a->length - offset) : CELL;
    e = charge(r, SFS_INCOMPLETE_AUX_IO, n); if (e) return e;
    memset(v->bytes, 0, CELL); if (read_exact(a->fd, v->bytes, n, offset)) return io_failure(r, SFS_PHASE_VERIFY_AUX);
    v->block = block; v->stamp = ++a->clock; v->valid = 1; *out = v->bytes + at % CELL; return SFS_OK;
}
static enum sfs_status memo(reader *r, const reference *ref, uint8_t entry[128], int writing) {
    if (!r->aux) { if (!writing) memset(entry, 0, 128); return SFS_OK; }
    uint64_t at = (ref->offset / CELL) * 128; uint8_t *p; enum sfs_status e = aux_bytes(r, at, &p); if (e) return e;
    if (!writing) { memcpy(entry, p, 128); if (get32(entry + 4) && (get32(entry + 4) != ref->type || memcmp(entry + 8, ref->digest, 32))) return SFS_CORRUPT; if (!zero(entry + 64, 64)) return SFS_CORRUPT; }
    else { memcpy(p, entry, 128); for (unsigned i = 0; i < r->aux->count; ++i) if (r->aux->entries[i].valid && r->aux->entries[i].block == at / CELL) { r->aux->entries[i].dirty = 1; break; } }
    return SFS_OK;
}
static enum sfs_status metadata(reader *r, const reference *ref, unsigned type, uint64_t before, const uint8_t **out) {
    enum sfs_status e = bounds(r, ref, type, before); if (e) return e;
    if (type != NAMESPACE && type != ROOT && type != INDEX) return SFS_CORRUPT;
    uint8_t entry[128]; e = memo(r, ref, entry, 0); if (e) return e;
    if (r->aux && !get32(entry + 4)) { put32(entry + 4, type); memcpy(entry + 8, ref->digest, 32); e = memo(r, ref, entry, 1); if (e) return e; }
    if (!r->h->cache) { r->h->cache = calloc(1, sizeof(cache)); if (!r->h->cache) return SFS_NOMEM; }
    cache *c = r->h->cache;
    for (unsigned i = 0; i < c->count; ++i) if (same_ref(&c->entries[i].ref, ref)) { if (memcmp(c->entries[i].bytes, record_magic(r->a.minor), 8)) return SFS_CORRUPT; c->entries[i].stamp = ++c->clock; *out = c->entries[i].bytes; return SFS_OK; }
    e = charge(r, SFS_INCOMPLETE_METADATA_READ, CELL); if (e) return e;
    e = charge(r, SFS_INCOMPLETE_METADATA_HASH, CELL); if (e) return e;
    unsigned slot = c->count;
    if (slot == CACHE_COUNT) { slot = 0; for (unsigned i = 1; i < c->count; ++i) if (c->entries[i].stamp < c->entries[slot].stamp) slot = i; }
    else { c->entries[slot].bytes = malloc(CELL); if (!c->entries[slot].bytes) return SFS_NOMEM; c->count++; }
    cache_entry *v = &c->entries[slot]; memset(&v->ref, 0, sizeof(v->ref));
    if (read_exact(r->h->fd, v->bytes, CELL, ref->offset)) return io_failure(r, SFS_PHASE_READ);
    uint8_t digest[32]; hash_cell(v->bytes, type, r->a.uuid, digest, r->a.minor);
    if (memcmp(digest, ref->digest, 32) || memcmp(v->bytes, record_magic(r->a.minor), 8) || get32(v->bytes + 8) != type || get32(v->bytes + 12) || get64(v->bytes + 16) != 4032 || memcmp(v->bytes + 24, r->a.uuid, 16) || !zero(v->bytes + 40, 24)) return SFS_CORRUPT;
    v->ref = *ref; v->stamp = ++c->clock; *out = v->bytes; return SFS_OK;
}
static enum sfs_status raw_read(reader *r, const reference *ref, uint64_t before, unsigned visible, int require_no_nul, uint8_t *out) {
    enum sfs_status e = bounds(r, ref, RAW, before); if (e) return e;
    if (!visible || visible > CELL || (require_no_nul && !symlink_capable(r->a.minor))) return SFS_CORRUPT;
    if (require_no_nul) { e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e; }
    uint8_t entry[128]; e = memo(r, ref, entry, 0); if (e) return e;
    if (!zero(entry, sizeof(entry))) {
        uint64_t first_zero = get64(entry + 40), nonzero = get64(entry + 56);
        if (get32(entry) != 2 || get32(entry + 4) != RAW || memcmp(entry + 8, ref->digest, 32) || get64(entry + 48) || nonzero > CELL ||
            (symlink_capable(r->a.minor) ? first_zero > CELL || first_zero > nonzero : first_zero != 0)) return SFS_CORRUPT;
        if (nonzero > visible || (require_no_nul && first_zero < visible)) return SFS_CORRUPT;
        if (!out) return SFS_OK;
    }
    e = charge(r, SFS_INCOMPLETE_RAW, 1); if (e) return e;
    uint8_t bytes[CELL], digest[32]; if (read_exact(r->h->fd, bytes, CELL, ref->offset)) return io_failure(r, SFS_PHASE_READ);
    hash_cell(bytes, RAW, r->a.uuid, digest, r->a.minor); if (memcmp(digest, ref->digest, 32)) return SFS_CORRUPT;
    unsigned first_zero = CELL, nonzero = 0;
    if (symlink_capable(r->a.minor)) { for (unsigned i = 0; i < CELL; ++i) { if (bytes[i]) nonzero = i + 1; else if (first_zero == CELL) first_zero = i; } }
    else { nonzero = CELL; while (nonzero && !bytes[nonzero - 1]) nonzero--; }
    if (nonzero > visible || (require_no_nul && first_zero < visible)) return SFS_CORRUPT;
    memset(entry, 0, sizeof(entry)); put32(entry, 2); put32(entry + 4, RAW); memcpy(entry + 8, ref->digest, 32);
    if (symlink_capable(r->a.minor)) put64(entry + 40, first_zero); put64(entry + 56, nonzero);
    e = memo(r, ref, entry, 1); if (e) return e; if (out) memcpy(out, bytes, CELL); return SFS_OK;
}
static int keycmp(const key *a, const key *b) { size_t n = a->length < b->length ? a->length : b->length; int c = memcmp(a->bytes, b->bytes, n); return c ? c : a->length < b->length ? -1 : a->length > b->length; }
static key number_key(uint64_t v) { key k = { .length = 8 }; big64(k.bytes, v); return k; }
static key name_key(uint64_t parent, const void *name, size_t length) { key k = { .length = (uint16_t)(8 + length) }; big64(k.bytes, parent); if (length) memcpy(k.bytes + 8, name, length); return k; }
static unsigned page_level(const uint8_t *b) { return get16(b + 68); }
static unsigned page_count(const uint8_t *b) { return get16(b + 70); }
static int variable_key(unsigned map) { return map == MAP_NAME || map == MAP_XATTR || map == MAP_BACKREF; }
static unsigned stride(unsigned map, unsigned level, unsigned minor) { return level ? (variable_key(map) ? 328 : 72) : map == MAP_INODE ? (minor == 6 ? 496 : metadata_capable(minor) ? 440 : 352) : (map == MAP_NAME || map == MAP_BACKREF) ? 280 : map == MAP_EXTENT ? 72 : map == MAP_XATTR ? 352 : map == MAP_SNAPSHOT ? 328 : 0; }
/* Numeric directory positions require MAP_NAME fanout 9, leaf capacity 12 and
 * MAX_HEIGHT 16. Changing these limits requires a new position contract. */
static unsigned minimum(unsigned map, unsigned level, unsigned minor) { return level ? (variable_key(map) ? 3 : 16) : map == MAP_INODE ? (metadata_capable(minor) ? 2 : 3) : (map == MAP_SNAPSHOT || map == MAP_XATTR) ? 3 : (map == MAP_NAME || map == MAP_BACKREF) ? 4 : map == MAP_EXTENT ? 16 : 0; }
static unsigned maximum(unsigned map, unsigned level, unsigned minor) { return 3 * minimum(map, level, minor); }
static const uint8_t *row_at(const uint8_t *b, unsigned map, unsigned i, unsigned minor) { return b + PAGE_HEAD + stride(map, page_level(b), minor) * i; }
static key page_min(const uint8_t *b) { key k = { .length = get16(b + 88) }; if (k.length <= 263) memcpy(k.bytes, b + 112, k.length); return k; }
static key page_max(const uint8_t *b) { key k = { .length = get16(b + 90) }; if (k.length <= 263) memcpy(k.bytes, b + 375, k.length); return k; }
static key row_key(const uint8_t *v, unsigned map, unsigned level) { key k = {0}; if (level) { unsigned length = get32(v); if (length <= 263) { k.length = (uint16_t)length; memcpy(k.bytes, v + 8, k.length); } } else if (variable_key(map)) k = name_key(get64(v), v + 12, get32(v + 8) <= 255 ? get32(v + 8) : 0); else k = number_key(map == MAP_SNAPSHOT ? get32(v) : get64(v)); return k; }
static int child_ref(const uint8_t *v, unsigned map, reference *ref) { return decode_ref(v + (variable_key(map) ? 271 : 16), ref); }
static void put_child_ref(uint8_t *v, unsigned map, const reference *ref) { encode_ref(v + (variable_key(map) ? 271 : 16), ref); }
static context root_context(unsigned map, unsigned level, uint64_t next, uint64_t eof, unsigned minor) { context c; memset(&c, 0, sizeof(c)); c.map = map; c.level = level; c.minor = minor; c.root = 1; c.next_inode = next; c.eof = eof; return c; }
static context child_context(const uint8_t *b, unsigned i, context c) { c.root = 0; c.level--; c.lower = row_key(row_at(b, c.map, i, c.minor), c.map, c.level + 1); c.last = i + 1 == page_count(b); c.upper = c.last ? page_max(b) : row_key(row_at(b, c.map, i + 1, c.minor), c.map, c.level + 1); return c; }
static enum sfs_status page_read(reader *r, const reference *ref, uint64_t before, context c, const uint8_t **out) {
    if (c.minor != r->a.minor) return SFS_CORRUPT;
    enum sfs_status e = metadata(r, ref, INDEX, before, out); if (e) return e;
    e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    const uint8_t *b = *out; unsigned n = page_count(b), level = page_level(b); key min = page_min(b), max = page_max(b);
    if (c.map < MAP_INODE || c.map > MAP_BACKREF || (c.map == MAP_BACKREF && r->a.minor != 6) || (c.map == MAP_XATTR && !xattr_capable(r->a.minor)) || get32(b + 64) != c.map || level != c.level || level >= MAX_HEIGHT || !n || n > maximum(c.map, level, r->a.minor) || n < (c.root ? (level ? 2 : 1) : minimum(c.map, level, r->a.minor)) || !get64(b + 72) || get64(b + 72) > r->a.generation || !zero(b + 80, 8) || !zero(b + 92, 20) || !zero(b + 638, 2)) return SFS_CORRUPT;
    if (min.length < (variable_key(c.map) ? 9 : 8) || min.length > (variable_key(c.map) ? 263 : 8) || max.length < (variable_key(c.map) ? 9 : 8) || max.length > (variable_key(c.map) ? 263 : 8) || !zero(b + 112 + min.length, 263 - min.length) || !zero(b + 375 + max.length, 263 - max.length) || keycmp(&min, &max) > 0) return SFS_CORRUPT;
    if (!c.root && (keycmp(&min, &c.lower) || (c.last ? keycmp(&max, &c.upper) != 0 : keycmp(&max, &c.upper) >= 0))) return SFS_CORRUPT;
    unsigned step = stride(c.map, level, r->a.minor); if (!zero(b + PAGE_HEAD + step * n, CELL - PAGE_HEAD - step * n)) return SFS_CORRUPT;
    key previous = {0};
    for (unsigned i = 0; i < n; ++i) {
        e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
        const uint8_t *v = row_at(b, c.map, i, r->a.minor); key k = row_key(v, c.map, level);
        if (keycmp(&k, &max) > 0 || (i && keycmp(&previous, &k) >= 0) || (!i && keycmp(&min, &k))) return SFS_CORRUPT; previous = k;
        if (level) { reference child; unsigned len = get32(v), maxlen = variable_key(c.map) ? 263 : 8;
            if (len < (variable_key(c.map) ? 9u : 8u) || len > maxlen || get32(v + 4) || !zero(v + 8 + len, maxlen - len) || (variable_key(c.map) && v[327]) || !child_ref(v, c.map, &child)) return SFS_CORRUPT;
            e = bounds(r, &child, INDEX, ref->offset); if (e) return e;
        } else if (c.map == MAP_EXTENT) { reference data; uint64_t block = get64(v); unsigned visible = get16(v + 64);
            if (!decode_ref(v + 8, &data) || !visible || visible > CELL || !zero(v + 66, 6) || block > UINT64_MAX / CELL || block * CELL >= c.eof || visible > c.eof - block * CELL) return SFS_CORRUPT;
            e = bounds(r, &data, RAW, ref->offset); if (e) return e;
        } else if (c.map == MAP_INODE) { reference ext; uint64_t id = get64(v), parent = get64(v + 8), size = get64(v + 24); unsigned kind = get32(v + 16), len = get32(v + 20);
            if (id < 2 || id >= c.next_inode || !parent || parent >= c.next_inode || (kind != SFS_FILE && kind != SFS_DIRECTORY && !(kind == SFS_SYMLINK && symlink_capable(r->a.minor))) || !valid_name(v + 88, len) || !zero(v + 88 + len, (r->a.minor == 6 ? 256u : 264u) - len) || (kind == SFS_FILE && size > SFS_FILE_MAX) || (kind == SFS_SYMLINK && (!size || size > SFS_SYMLINK_MAX)) || !decode_ref(v + 32, &ext) || ((kind == SFS_DIRECTORY || !size) && ext.type) || (kind == SFS_DIRECTORY && size)) return SFS_CORRUPT;
            if (r->a.minor == 6) { reference reverse; uint64_t links = get64(v + 344);
                if (!links || links > c.eof || !decode_ref(v + 440, &reverse) || (kind == SFS_DIRECTORY ? links != 1 || reverse.type : (!!reverse.type != (links > 1)))) return SFS_CORRUPT;
                if (reverse.type) { e = bounds(r, &reverse, INDEX, ref->offset); if (e) return e; }
            }
            if (ext.type) { e = bounds(r, &ext, INDEX, ref->offset); if (e) return e; }
            if (metadata_capable(r->a.minor) && !valid_attributes(v + 352, kind, size, ext.type, r->a.end)) return SFS_CORRUPT;
        } else if (c.map == MAP_NAME || c.map == MAP_BACKREF) { uint64_t parent = get64(v), id = get64(v + 267); unsigned len = get32(v + 8);
            if (!parent || parent >= c.next_inode || id < 2 || id >= c.next_inode || !valid_name(v + 12, len) || !zero(v + 12 + len, 255 - len) || !zero(v + 275, 5) || (c.map == MAP_BACKREF && id != c.eof)) return SFS_CORRUPT;
        } else if (c.map == MAP_XATTR) { reference ext; uint64_t owner = get64(v), size = get64(v + 272), count = get64(v + 336); unsigned len = get32(v + 8);
            if (!owner || owner >= c.next_inode || !valid_xattr_name(v + 12, len) || !zero(v + 12 + len, 255 - len) || !zero(v + 267, 5) || size > SFS_FILE_MAX || count != dense_count(size) || !decode_ref(v + 280, &ext) || (!!count != !!ext.type) || get64(v + 344)) return SFS_CORRUPT;
            if (ext.type) { e = bounds(r, &ext, INDEX, ref->offset); if (e) return e; }
        } else if (c.map == MAP_SNAPSHOT) { reference ns; unsigned id = get32(v), len = get32(v + 64);
            if (!id || id > SFS_SNAPSHOT_MAX || get32(v + 4) || !decode_ref(v + 8, &ns) || !valid_name(v + 68, len) || !zero(v + 68 + len, 260 - len)) return SFS_CORRUPT;
            e = bounds(r, &ns, NAMESPACE, ref->offset); if (e) return e;
        } else return SFS_CORRUPT;
    }
    if (!level && keycmp(&previous, &max)) return SFS_CORRUPT; return SFS_OK;
}
static enum sfs_status root_page(reader *r, const reference *ref, unsigned map, uint64_t next, uint64_t eof, const uint8_t **out) {
    const uint8_t *b; enum sfs_status e = metadata(r, ref, INDEX, r->a.end, &b); if (e) return e;
    unsigned level = page_level(b); if (level >= MAX_HEIGHT) return SFS_CORRUPT; return page_read(r, ref, r->a.end, root_context(map, level, next, eof, r->a.minor), out);
}

/* Link shape and byte semantics are per-reference checks, never generic memo success. */
static enum sfs_status link_target(reader *r, const node *n, uint8_t *out) {
    enum sfs_status e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    if (!symlink_capable(r->a.minor) || n->e.kind != SFS_SYMLINK || !n->e.size || n->e.size > SFS_SYMLINK_MAX || n->attributes.extents != 1) return SFS_CORRUPT;
    const uint8_t *b; e = root_page(r, &n->extent, MAP_EXTENT, UINT64_MAX, n->e.size, &b); if (e) return e;
    if (page_level(b) || page_count(b) != 1) return SFS_CORRUPT;
    const uint8_t *v = row_at(b, MAP_EXTENT, 0, r->a.minor); reference raw;
    if (get64(v) || get16(v + 64) != n->e.size || !decode_ref(v + 8, &raw)) return SFS_CORRUPT;
    return raw_read(r, &raw, n->extent.offset, (unsigned)n->e.size, 1, out);
}

typedef struct { reference ref; uint64_t before; context context; unsigned index; } cursor_frame;
typedef struct { reader *reader; cursor_frame frames[MAX_HEIGHT]; unsigned depth, map; uint64_t next_inode, eof; } cursor;
_Static_assert(sizeof(cursor) == 10272, "bounded reusable cursor");
static enum sfs_status cursor_start(cursor *c, reader *r, reference root, unsigned map, uint64_t next, uint64_t eof, const key *seek) {
    memset(c, 0, sizeof(*c)); c->reader = r; c->map = map; c->next_inode = next; c->eof = eof;
    if (!root.type) return SFS_OK;
    const uint8_t *b; enum sfs_status e = root_page(r, &root, map, next, eof, &b); if (e) return e;
    c->frames[0] = (cursor_frame){ .ref = root, .before = r->a.end, .context = root_context(map, page_level(b), next, eof, r->a.minor) }; c->depth = 1;
    if (!seek) return SFS_OK;
    for (;;) {
        cursor_frame *f = &c->frames[c->depth - 1]; e = page_read(r, &f->ref, f->before, f->context, &b); if (e) return e;
        unsigned n = page_count(b), i = 0;
        if (!f->context.level) { while (i < n) { key k = row_key(row_at(b, map, i, r->a.minor), map, 0); if (keycmp(&k, seek) >= 0) break; i++; } f->index = i; return SFS_OK; }
        while (i + 1 < n) { key k = row_key(row_at(b, map, i + 1, r->a.minor), map, f->context.level); if (keycmp(&k, seek) > 0) break; i++; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, map, i, r->a.minor), map, &child)) return SFS_CORRUPT;
        context ctx = child_context(b, i, f->context); f->index = i + 1;
        c->frames[c->depth++] = (cursor_frame){ .ref = child, .before = f->ref.offset, .context = ctx };
    }
}
static enum sfs_status cursor_next(cursor *c, uint8_t out[MAX_ROW], int *found) {
    *found = 0;
    while (c->depth) {
        cursor_frame *f = &c->frames[c->depth - 1]; const uint8_t *b;
        enum sfs_status e = page_read(c->reader, &f->ref, f->before, f->context, &b); if (e) return e;
        unsigned n = page_count(b); if (f->index > n) return SFS_CORRUPT;
        if (f->index == n) { c->depth--; continue; }
        unsigned i = f->index++;
        if (!f->context.level) { memset(out, 0, MAX_ROW); memcpy(out, row_at(b, c->map, i, c->reader->a.minor), stride(c->map, 0, c->reader->a.minor)); *found = 1; return SFS_OK; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, c->map, i, c->reader->a.minor), c->map, &child)) return SFS_CORRUPT;
        context ctx = child_context(b, i, f->context);
        c->frames[c->depth++] = (cursor_frame){ .ref = child, .before = f->ref.offset, .context = ctx };
    } return SFS_OK;
}
static enum sfs_status index_get(reader *r, reference root, unsigned map, uint64_t next, uint64_t eof, const key *k, uint8_t out[MAX_ROW], int *found) {
    cursor c; enum sfs_status e = cursor_start(&c, r, root, map, next, eof, k); if (e) return e;
    e = cursor_next(&c, out, found); if (!e && *found) { key actual = row_key(out, map, 0); if (keycmp(&actual, k)) *found = 0; } return e;
}
static enum sfs_status namespace_read(reader *r, reference ref, uint64_t before, namespace *ns) {
    const uint8_t *b; enum sfs_status e = metadata(r, &ref, NAMESPACE, before, &b); if (e) return e;
    namespace n = { .ref = ref, .next_inode = get64(b + 176), .count = get64(b + 184) };
    n.name_count = r->a.minor == 6 ? get64(b + 336) : n.count;
    unsigned tail = r->a.minor == 6 ? 344 : xattr_capable(r->a.minor) ? 336 : metadata_capable(r->a.minor) ? 280 : 192;
    if (!decode_ref(b + 64, &n.inodes) || !decode_ref(b + 120, &n.names) || !zero(b + tail, CELL - tail) || n.next_inode < 2 || n.count > n.name_count || n.name_count > SFS_ENTRY_MAX || n.count > maximum(MAP_INODE, 0, r->a.minor) * (r->a.end / CELL) || n.name_count > maximum(MAP_NAME, 0, r->a.minor) * (r->a.end / CELL) || (!!n.count != !!n.inodes.type) || (!!n.count != !!n.names.type) || (!!n.name_count != !!n.names.type)) return SFS_CORRUPT;
    if (metadata_capable(r->a.minor)) { if (!valid_attributes(b + 192, SFS_DIRECTORY, 0, 0, r->a.end)) return SFS_CORRUPT; decode_attributes(b + 192, &n.attributes); }
    if (xattr_capable(r->a.minor) && !decode_ref(b + 280, &n.xattrs)) return SFS_CORRUPT;
    if (n.count) { e = bounds(r, &n.inodes, INDEX, ref.offset); if (e) return e; e = bounds(r, &n.names, INDEX, ref.offset); if (e) return e;
        e = root_page(r, &n.inodes, MAP_INODE, n.next_inode, n.name_count, &b); if (e) return e;
        e = root_page(r, &n.names, MAP_NAME, n.next_inode, UINT64_MAX, &b); if (e) return e;
    }
    if (n.xattrs.type) { e = bounds(r, &n.xattrs, INDEX, ref.offset); if (e) return e; e = root_page(r, &n.xattrs, MAP_XATTR, n.next_inode, UINT64_MAX, &b); if (e) return e; }
    *ns = n; return SFS_OK;
}
static enum sfs_status load_state(reader *r, state *s) {
    const uint8_t *b; enum sfs_status e = metadata(r, &r->a.root, ROOT, r->a.end, &b); if (e) return e;
    reference ns, catalog; if (!decode_ref(b + 64, &ns) || !decode_ref(b + 120, &catalog) || !zero(b + 176, CELL - 176)) return SFS_CORRUPT;
    memset(s, 0, sizeof(*s)); s->catalog = catalog;
    e = namespace_read(r, ns, r->a.root.offset, &s->ns); if (e) return e;
    if (!catalog.type) return SFS_OK;
    e = bounds(r, &catalog, INDEX, r->a.root.offset); if (e) return e;
    e = root_page(r, &catalog, MAP_SNAPSHOT, UINT64_MAX, UINT64_MAX, &b); if (e) return e; if (page_level(b) > 1) return SFS_CORRUPT;
    cursor c; e = cursor_start(&c, r, catalog, MAP_SNAPSHOT, UINT64_MAX, UINT64_MAX, NULL); if (e) return e;
    uint8_t row[MAX_ROW]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found) {
        if (s->count == SFS_SNAPSHOT_MAX) return SFS_CORRUPT;
        snapshot *snap = &s->snapshots[s->count]; snap->view = get32(row); snap->length = get32(row + 64); memcpy(snap->name, row + 68, snap->length);
        if (!decode_ref(row + 8, &snap->ns)) return SFS_CORRUPT;
        for (unsigned i = 0; i < s->count; ++i) if (s->snapshots[i].length == snap->length && !memcmp(s->snapshots[i].name, snap->name, snap->length)) return SFS_CORRUPT;
        namespace view; e = namespace_read(r, snap->ns, catalog.offset, &view); if (e) return e;
        if (view.next_inode > s->ns.next_inode) return SFS_CORRUPT; s->count++;
    } return e;
}
static void decode_node(const uint8_t row[MAX_ROW], node *n, unsigned minor) {
    memset(n, 0, sizeof(*n)); n->e.inode = get64(row); n->e.parent = get64(row + 8); n->e.kind = (enum sfs_kind)get32(row + 16); n->e.name_length = get32(row + 20); n->e.size = get64(row + 24); decode_ref(row + 32, &n->extent); memcpy(n->e.name, row + 88, n->e.name_length); if (metadata_capable(minor)) decode_attributes(row + 352, &n->attributes); n->nlink = minor == 6 ? get64(row + 344) : 1; if (minor == 6) decode_ref(row + 440, &n->reverse);
}
static void encode_node(uint8_t row[MAX_ROW], const node *n, unsigned minor) {
    memset(row, 0, MAX_ROW); put64(row, n->e.inode); put64(row + 8, n->e.parent); put32(row + 16, n->e.kind); put32(row + 20, (uint32_t)n->e.name_length); put64(row + 24, n->e.size); encode_ref(row + 32, &n->extent); memcpy(row + 88, n->e.name, n->e.name_length); if (metadata_capable(minor)) encode_attributes(row + 352, &n->attributes); if (minor == 6) { put64(row + 344, n->nlink); encode_ref(row + 440, &n->reverse); }
}
static void encode_name(uint8_t row[MAX_ROW], const node *n) { memset(row, 0, MAX_ROW); put64(row, n->e.parent); put32(row + 8, (uint32_t)n->e.name_length); memcpy(row + 12, n->e.name, n->e.name_length); put64(row + 267, n->e.inode); }
static void entry_name(node *n, const uint8_t row[MAX_ROW]) {
    n->e.parent = get64(row); n->e.name_length = get32(row + 8); memset(n->e.name, 0, sizeof(n->e.name)); memcpy(n->e.name, row + 12, n->e.name_length);
}
static enum sfs_status name_member(reader *r, const namespace *ns, const node *n, const key *k) {
    enum sfs_status e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    uint8_t row[MAX_ROW]; int found;
    e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, k, row, &found); if (e) return e;
    if (!found || get64(row + 267) != n->e.inode) return SFS_CORRUPT;
    if (n->nlink == 1) { key sole = name_key(n->e.parent, n->e.name, n->e.name_length); if (n->reverse.type || keycmp(&sole, k)) return SFS_CORRUPT; }
    else {
        e = index_get(r, n->reverse, MAP_BACKREF, ns->next_inode, n->e.inode, k, row, &found); if (e) return e;
        if (!found || get64(row + 267) != n->e.inode) return SFS_CORRUPT;
    }
    uint64_t parent = from_big(k->bytes); if (parent == 1) return SFS_OK;
    key pk = number_key(parent); e = index_get(r, ns->inodes, MAP_INODE, ns->next_inode, ns->name_count, &pk, row, &found); if (e) return e;
    return found && get32(row + 16) == SFS_DIRECTORY ? SFS_OK : SFS_CORRUPT;
}
static enum sfs_status reverse_first(reader *r, const namespace *ns, const node *n, uint8_t row[MAX_ROW]) {
    const uint8_t *b; enum sfs_status e = root_page(r, &n->reverse, MAP_BACKREF, ns->next_inode, n->e.inode, &b); if (e) return e;
    if (n->nlink == 2 && (page_level(b) || page_count(b) != 2)) return SFS_CORRUPT;
    key k = page_min(b); int found; e = index_get(r, n->reverse, MAP_BACKREF, ns->next_inode, n->e.inode, &k, row, &found);
    return e ? e : found && get64(row + 267) == n->e.inode ? SFS_OK : SFS_CORRUPT;
}
static enum sfs_status node_get(reader *r, const namespace *ns, sfs_inode id, int canonical, node *out) {
    if (id == 1) { memset(out, 0, sizeof(*out)); out->e.inode = out->e.parent = 1; out->e.kind = SFS_DIRECTORY; out->attributes = ns->attributes; out->nlink = 1; return SFS_OK; }
    key k = number_key(id); uint8_t row[MAX_ROW]; int found; enum sfs_status e = index_get(r, ns->inodes, MAP_INODE, ns->next_inode, ns->name_count, &k, row, &found); if (e) return e; if (!found) return SFS_NOT_FOUND;
    decode_node(row, out, r->a.minor);
    if (canonical) { k = name_key(out->e.parent, out->e.name, out->e.name_length);
        if (r->a.minor == 6) { e = name_member(r, ns, out, &k); if (e) return e; if (out->nlink > 1) { e = reverse_first(r, ns, out, row); if (e) return e; key first = row_key(row, MAP_BACKREF, 0); if (keycmp(&first, &k)) return SFS_CORRUPT; } }
        else { e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e; if (!found || get64(row + 267) != id) return SFS_CORRUPT; }
    }
    return SFS_OK;
}
static enum sfs_status directory_check(reader *r, const namespace *ns, sfs_inode id) { node n; enum sfs_status e = node_get(r, ns, id, 1, &n); if (e) return e == SFS_NOT_FOUND ? SFS_INVALID : e; return n.e.kind == SFS_DIRECTORY ? SFS_OK : SFS_INVALID; }
static enum sfs_status parent_step(reader *r, const namespace *ns, uint64_t id, uint64_t *out) {
    enum sfs_status e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    if (id == 1) { *out = 1; return SFS_OK; }
    node n; e = node_get(r, ns, id, 1, &n); if (e) return e == SFS_NOT_FOUND ? SFS_CORRUPT : e;
    if (n.e.kind != SFS_DIRECTORY) return SFS_CORRUPT; *out = n.e.parent; return SFS_OK;
}
static enum sfs_status parent_chain(reader *r, const namespace *ns, uint64_t start, uint64_t forbidden) {
    uint64_t slow = start, fast = start;
    for (uint64_t steps = 0; steps <= ns->count; ++steps) {
        if (slow == forbidden) return SFS_INVALID; if (slow == 1) return SFS_OK;
        enum sfs_status e = parent_step(r, ns, slow, &slow); if (e) return e;
        e = parent_step(r, ns, fast, &fast); if (e) return e; e = parent_step(r, ns, fast, &fast); if (e) return e;
        if (slow == fast && slow != 1) return SFS_CORRUPT;
    } return SFS_CORRUPT;
}
static enum sfs_status extent_growth(reader *r, reference root, uint64_t old_size) {
    key k = number_key(old_size / CELL); cursor c; enum sfs_status e = cursor_start(&c, r, root, MAP_EXTENT, UINT64_MAX, old_size, &k); if (e) return e;
    uint8_t row[MAX_ROW]; int found; e = cursor_next(&c, row, &found); if (e || !found) return e;
    if (!(old_size % CELL) || get64(row) != old_size / CELL || get16(row + 64) > old_size % CELL) return SFS_CORRUPT;
    e = cursor_next(&c, row, &found); return e ? e : found ? SFS_CORRUPT : SFS_OK;
}

typedef struct { uint8_t bytes[CELL]; reference source; uint64_t owner, token; unsigned map; uint16_t children[48]; int dirty; } overlay_page;
struct arena { overlay_page *pages[ARENA_COUNT]; unsigned used; uint64_t epoch, batch; reference lineage; };
struct tree { arena *arena; reader *reader; reference source; int root; unsigned map; uint64_t owner, next_inode, eof; };
struct batch { arena *arena; tree extent; node inode; uint64_t low, high, number; pin_slot *detached; uint64_t incarnation; };
_Static_assert(sizeof(batch) == 656, "bounded primary batch");
_Static_assert(sizeof(arena) + ARENA_COUNT * sizeof(overlay_page) + 17 * CELL <= ARENA_BYTES, "bounded overlay including merge cells");
static void arena_free(arena *a) { if (!a) return; for (unsigned i = 0; i < a->used; ++i) free(a->pages[i]); free(a); }
static arena *arena_new(sfs_image *h, uint64_t batch_number) { arena *a = calloc(1, sizeof(*a)); if (a) { a->epoch = h->epoch; a->batch = batch_number; a->lineage = h->staged.ns.ref; } return a; }
static void discard(sfs_image *h) { if (h->batch) { arena_free(h->batch->arena); free(h->batch); h->batch = NULL; } pins_discard(h); memset(&h->staged, 0, sizeof(h->staged)); h->transaction = 0; }
static void envelope(uint8_t b[CELL], unsigned type, const uint8_t uuid[16], unsigned minor) { memset(b, 0, CELL); memcpy(b, record_magic(minor), 8); put32(b + 8, type); put64(b + 16, CELL - 64); memcpy(b + 24, uuid, 16); }
static int arena_add(tree *t, unsigned level) {
    arena *a = t->arena; unsigned i = 0; while (i < a->used && a->pages[i]) i++; if (i == ARENA_COUNT || t->reader->h->token == UINT64_MAX) return -1;
    overlay_page *p = calloc(1, sizeof(*p)); if (!p) return -1;
    for (unsigned j = 0; j < 48; ++j) p->children[j] = NO_CHILD;
    p->map = t->map; p->owner = t->owner; p->token = ++t->reader->h->token; p->dirty = 1;
    envelope(p->bytes, INDEX, t->reader->a.uuid, t->reader->a.minor); put32(p->bytes + 64, t->map); put16(p->bytes + 68, level); put64(p->bytes + 72, t->reader->a.generation);
    a->pages[i] = p; if (i == a->used) a->used++; return (int)i;
}
static overlay_page *owned_page(tree *t, unsigned id) { if (id >= t->arena->used) return NULL; overlay_page *p = t->arena->pages[id]; return p && p->token && p->owner == t->owner && p->map == t->map ? p : NULL; }
static enum sfs_status tree_load(tree *t, reference ref, uint64_t before, context ctx, int *id) {
    const uint8_t *b; enum sfs_status e = page_read(t->reader, &ref, before, ctx, &b); if (e) return e;
    int n = arena_add(t, ctx.level); if (n < 0) return SFS_NOMEM;
    overlay_page *p = t->arena->pages[n]; memcpy(p->bytes, b, CELL); p->source = ref; p->dirty = 0;
    /* Check original immediate edges before rows can move during split/borrow/merge. */
    if (ctx.level) for (unsigned i = 0; i < page_count(p->bytes); ++i) { reference child; if (!child_ref(row_at(p->bytes, t->map, i, t->reader->a.minor), t->map, &child)) return SFS_CORRUPT;
        e = page_read(t->reader, &child, ref.offset, child_context(p->bytes, i, ctx), &b); if (e) return e;
    }
    *id = n; return SFS_OK;
}
static enum sfs_status tree_root(tree *t) {
    if (t->root >= 0) return SFS_OK;
    if (!t->source.type) { t->root = arena_add(t, 0); return t->root < 0 ? SFS_NOMEM : SFS_OK; }
    const uint8_t *b; enum sfs_status e = root_page(t->reader, &t->source, t->map, t->next_inode, t->eof, &b); if (e) return e;
    return tree_load(t, t->source, t->reader->a.end, root_context(t->map, page_level(b), t->next_inode, t->eof, t->reader->a.minor), &t->root);
}
static enum sfs_status shadow_child_mode(tree *t, unsigned parent, unsigned index, unsigned *out, int recomputing_max) {
    overlay_page *p = owned_page(t, parent); if (!p || !page_level(p->bytes) || index >= page_count(p->bytes)) return SFS_CORRUPT;
    if (p->children[index] != NO_CHILD) { if (!owned_page(t, p->children[index])) return SFS_CORRUPT; *out = p->children[index]; return SFS_OK; }
    reference ref; if (!child_ref(row_at(p->bytes, t->map, index, t->reader->a.minor), t->map, &ref)) return SFS_CORRUPT;
    const uint8_t *b; context ctx = root_context(t->map, page_level(p->bytes) - 1, t->next_inode, t->eof, t->reader->a.minor);
    if (!recomputing_max) ctx = child_context(p->bytes, index, root_context(t->map, page_level(p->bytes), t->next_inode, t->eof, t->reader->a.minor));
    enum sfs_status e = page_read(t->reader, &ref, t->reader->a.end, ctx, &b); if (e) return e;
    key min = page_min(b), expected = row_key(row_at(p->bytes, t->map, index, t->reader->a.minor), t->map, page_level(p->bytes));
    if (page_count(b) < minimum(t->map, ctx.level, t->reader->a.minor) || keycmp(&min, &expected)) return SFS_CORRUPT;
    int id; e = tree_load(t, ref, t->reader->a.end, ctx, &id); if (e) return e;
    p->children[index] = (uint16_t)id; *out = (unsigned)id; return SFS_OK;
}
static enum sfs_status shadow_child(tree *t, unsigned parent, unsigned index, unsigned *out) { return shadow_child_mode(t, parent, index, out, 0); }
static void set_page_range(uint8_t b[CELL], key min, key max) { put16(b + 88, min.length); put16(b + 90, max.length); memset(b + 112, 0, 263); memset(b + 375, 0, 263); memcpy(b + 112, min.bytes, min.length); memcpy(b + 375, max.bytes, max.length); }
static enum sfs_status refresh(tree *t, unsigned id) {
    overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT;
    unsigned n = page_count(p->bytes), level = page_level(p->bytes), step = stride(t->map, level, t->reader->a.minor);
    if (!n) { set_page_range(p->bytes, (key){0}, (key){0}); memset(p->bytes + PAGE_HEAD, 0, CELL - PAGE_HEAD); return SFS_OK; }
    key min, max;
    if (!level) { min = row_key(row_at(p->bytes, t->map, 0, t->reader->a.minor), t->map, 0); max = row_key(row_at(p->bytes, t->map, n - 1, t->reader->a.minor), t->map, 0); }
    else {
        for (unsigned i = 0; i < n; ++i) if (p->children[i] != NO_CHILD) { overlay_page *child = owned_page(t, p->children[i]); if (!child) return SFS_CORRUPT;
            key k = page_min(child->bytes); uint8_t *v = p->bytes + PAGE_HEAD + i * step; reference old; if (!child_ref(v, t->map, &old)) return SFS_CORRUPT;
            memset(v, 0, step); put32(v, k.length); memcpy(v + 8, k.bytes, k.length); put_child_ref(v, t->map, &old);
        }
        min = row_key(row_at(p->bytes, t->map, 0, t->reader->a.minor), t->map, level);
        /* The original edge was checked before movement; its new maximum is being computed here. */
        unsigned last; enum sfs_status e = shadow_child_mode(t, id, n - 1, &last, 1); if (e) return e; max = page_max(t->arena->pages[last]->bytes);
    }
    set_page_range(p->bytes, min, max); memset(p->bytes + PAGE_HEAD + n * step, 0, CELL - PAGE_HEAD - n * step); return SFS_OK;
}
static void shift_rows(overlay_page *p, unsigned map, unsigned to, unsigned from, unsigned n, unsigned minor) {
    unsigned step = stride(map, page_level(p->bytes), minor); if (n) { memmove(p->bytes + PAGE_HEAD + to * step, p->bytes + PAGE_HEAD + from * step, n * step); memmove(p->children + to, p->children + from, n * sizeof(uint16_t)); }
}
static enum sfs_status split_child(tree *t, unsigned parent_id, unsigned at) {
    unsigned left_id; enum sfs_status e = shadow_child(t, parent_id, at, &left_id); if (e) return e;
    overlay_page *parent = t->arena->pages[parent_id], *left = t->arena->pages[left_id]; unsigned level = page_level(left->bytes), n = page_count(left->bytes), split = n / 2, step = stride(t->map, level, t->reader->a.minor);
    if (n != maximum(t->map, level, t->reader->a.minor) || page_count(parent->bytes) >= maximum(t->map, level + 1, t->reader->a.minor)) return SFS_CORRUPT;
    int right_id = arena_add(t, level); if (right_id < 0) return SFS_NOMEM; overlay_page *right = t->arena->pages[right_id];
    if (t->reader->h->token == UINT64_MAX) return SFS_LIMIT; left->token = ++t->reader->h->token;
    memcpy(right->bytes + PAGE_HEAD, left->bytes + PAGE_HEAD + split * step, (n - split) * step); memcpy(right->children, left->children + split, (n - split) * sizeof(uint16_t));
    put16(left->bytes + 70, split); put16(right->bytes + 70, n - split); left->dirty = 1;
    for (unsigned i = split; i < 48; ++i) left->children[i] = NO_CHILD;
    unsigned pn = page_count(parent->bytes); shift_rows(parent, t->map, at + 2, at + 1, pn - at - 1, t->reader->a.minor); parent->children[at + 1] = (uint16_t)right_id;
    unsigned pstep = stride(t->map, level + 1, t->reader->a.minor); memset(parent->bytes + PAGE_HEAD + (at + 1) * pstep, 0, pstep); put16(parent->bytes + 70, pn + 1); parent->dirty = 1;
    e = refresh(t, left_id); if (!e) e = refresh(t, (unsigned)right_id); if (!e) e = refresh(t, parent_id); return e;
}
static enum sfs_status tree_search(tree *t, const key *k, unsigned path[MAX_HEIGHT], unsigned *depth, unsigned *at, int *found) {
    *depth = 0; *found = 0; if (!t->source.type && t->root < 0) return SFS_OK;
    enum sfs_status e = tree_root(t); if (e) return e; unsigned id = (unsigned)t->root;
    for (;;) {
        if (*depth == MAX_HEIGHT) return SFS_CORRUPT; path[(*depth)++] = id;
        overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT; unsigned n = page_count(p->bytes), level = page_level(p->bytes), i = 0;
        if (!level) { while (i < n) { key row = row_key(row_at(p->bytes, t->map, i, t->reader->a.minor), t->map, 0); int cmp = keycmp(&row, k); if (cmp >= 0) { *found = !cmp; break; } i++; } *at = i; return SFS_OK; }
        while (i + 1 < n) { key row = row_key(row_at(p->bytes, t->map, i + 1, t->reader->a.minor), t->map, level); if (keycmp(&row, k) > 0) break; i++; }
        e = shadow_child(t, id, i, &id); if (e) return e;
    }
}
static enum sfs_status tree_put(tree *t, const uint8_t row[MAX_ROW]) {
    key k = row_key(row, t->map, 0); unsigned path[MAX_HEIGHT], depth, at = 0; int found;
    enum sfs_status e = tree_search(t, &k, path, &depth, &at, &found); if (e) return e;
    if (found) { overlay_page *leaf = t->arena->pages[path[depth - 1]]; memcpy(leaf->bytes + PAGE_HEAD + at * stride(t->map, 0, t->reader->a.minor), row, stride(t->map, 0, t->reader->a.minor));
        while (depth) { unsigned id = path[--depth]; t->arena->pages[id]->dirty = 1; e = refresh(t, id); if (e) return e; } return SFS_OK;
    }
    e = tree_root(t); if (e) return e;
    overlay_page *root = t->arena->pages[t->root]; unsigned level = page_level(root->bytes);
    if (page_count(root->bytes) == maximum(t->map, level, t->reader->a.minor)) {
        if (level + 1 == MAX_HEIGHT) return SFS_LIMIT;
        unsigned old = (unsigned)t->root; int parent = arena_add(t, level + 1); if (parent < 0) return SFS_NOMEM;
        t->root = parent; overlay_page *p = t->arena->pages[parent]; p->children[0] = (uint16_t)old; put16(p->bytes + 70, 1);
        e = split_child(t, (unsigned)parent, 0); if (e) return e;
    }
    unsigned id = (unsigned)t->root; depth = 0;
    for (;;) {
        if (depth == MAX_HEIGHT) return SFS_CORRUPT; path[depth++] = id; overlay_page *p = t->arena->pages[id]; unsigned n = page_count(p->bytes); level = page_level(p->bytes); unsigned i = 0;
        if (!level) { while (i < n) { key v = row_key(row_at(p->bytes, t->map, i, t->reader->a.minor), t->map, 0); if (keycmp(&v, &k) > 0) break; i++; }
            shift_rows(p, t->map, i + 1, i, n - i, t->reader->a.minor); memcpy(p->bytes + PAGE_HEAD + i * stride(t->map, 0, t->reader->a.minor), row, stride(t->map, 0, t->reader->a.minor)); p->children[i] = NO_CHILD; put16(p->bytes + 70, n + 1); break;
        }
        while (i + 1 < n) { key v = row_key(row_at(p->bytes, t->map, i + 1, t->reader->a.minor), t->map, level); if (keycmp(&v, &k) > 0) break; i++; }
        unsigned child; e = shadow_child(t, id, i, &child); if (e) return e;
        if (page_count(t->arena->pages[child]->bytes) == maximum(t->map, level - 1, t->reader->a.minor)) { e = split_child(t, id, i); if (e) return e; key right = page_min(t->arena->pages[p->children[i + 1]]->bytes); if (keycmp(&k, &right) >= 0) i++; child = p->children[i]; }
        id = child;
    }
    while (depth) { id = path[--depth]; t->arena->pages[id]->dirty = 1; e = refresh(t, id); if (e) return e; } return SFS_OK;
}
static enum sfs_status rebalance_child(tree *t, unsigned parent_id, unsigned *at, unsigned *child_id) {
    overlay_page *parent = t->arena->pages[parent_id]; unsigned id; enum sfs_status e = shadow_child(t, parent_id, *at, &id); if (e) return e;
    overlay_page *child = t->arena->pages[id]; unsigned level = page_level(child->bytes), n = page_count(child->bytes), b = minimum(t->map, level, t->reader->a.minor), step = stride(t->map, level, t->reader->a.minor); *child_id = id;
    if (n > b) return SFS_OK; if (n != b) return SFS_CORRUPT;
    unsigned left = NO_CHILD, right = NO_CHILD;
    if (*at) { e = shadow_child(t, parent_id, *at - 1, &left); if (e) return e; }
    if (*at + 1 < page_count(parent->bytes)) { e = shadow_child(t, parent_id, *at + 1, &right); if (e) return e; }
    if (left != NO_CHILD && page_count(t->arena->pages[left]->bytes) > b) {
        overlay_page *s = t->arena->pages[left]; unsigned sn = page_count(s->bytes); shift_rows(child, t->map, 1, 0, n, t->reader->a.minor); memcpy(child->bytes + PAGE_HEAD, row_at(s->bytes, t->map, sn - 1, t->reader->a.minor), step); child->children[0] = s->children[sn - 1]; s->children[sn - 1] = NO_CHILD;
        put16(s->bytes + 70, sn - 1); put16(child->bytes + 70, n + 1); s->dirty = child->dirty = parent->dirty = 1; e = refresh(t, left); if (!e) e = refresh(t, id); if (!e) e = refresh(t, parent_id); return e;
    }
    if (right != NO_CHILD && page_count(t->arena->pages[right]->bytes) > b) {
        overlay_page *s = t->arena->pages[right]; unsigned sn = page_count(s->bytes); memcpy(child->bytes + PAGE_HEAD + n * step, s->bytes + PAGE_HEAD, step); child->children[n] = s->children[0]; shift_rows(s, t->map, 0, 1, sn - 1, t->reader->a.minor); s->children[sn - 1] = NO_CHILD;
        put16(s->bytes + 70, sn - 1); put16(child->bytes + 70, n + 1); s->dirty = child->dirty = parent->dirty = 1; e = refresh(t, right); if (!e) e = refresh(t, id); if (!e) e = refresh(t, parent_id); return e;
    }
    unsigned first = right != NO_CHILD ? id : left, second = right != NO_CHILD ? right : id, remove = right != NO_CHILD ? *at + 1 : *at;
    if (first == NO_CHILD || second == NO_CHILD) return SFS_CORRUPT;
    overlay_page *l = t->arena->pages[first], *rr = t->arena->pages[second]; unsigned ln = page_count(l->bytes), rn = page_count(rr->bytes);
    if (ln + rn > maximum(t->map, level, t->reader->a.minor)) return SFS_CORRUPT;
    if (t->reader->h->token == UINT64_MAX) return SFS_LIMIT; l->token = ++t->reader->h->token;
    memcpy(l->bytes + PAGE_HEAD + ln * step, rr->bytes + PAGE_HEAD, rn * step); memcpy(l->children + ln, rr->children, rn * sizeof(uint16_t)); put16(l->bytes + 70, ln + rn); l->dirty = parent->dirty = 1;
    unsigned pn = page_count(parent->bytes); shift_rows(parent, t->map, remove, remove + 1, pn - remove - 1, t->reader->a.minor); parent->children[pn - 1] = NO_CHILD; put16(parent->bytes + 70, pn - 1);
    free(rr); t->arena->pages[second] = NULL; if (right == NO_CHILD) (*at)--; *child_id = first;
    e = refresh(t, first); if (!e) e = refresh(t, parent_id); return e;
}
static enum sfs_status delete_page(tree *t, unsigned id, const key *k) {
    overlay_page *p = t->arena->pages[id]; unsigned level = page_level(p->bytes), n = page_count(p->bytes), i = 0;
    if (!level) {
        while (i < n) { key v = row_key(row_at(p->bytes, t->map, i, t->reader->a.minor), t->map, 0); if (!keycmp(&v, k)) break; i++; }
        if (i == n) return SFS_CORRUPT; shift_rows(p, t->map, i, i + 1, n - i - 1, t->reader->a.minor); p->children[n - 1] = NO_CHILD; put16(p->bytes + 70, n - 1);
    } else {
        while (i + 1 < n) { key v = row_key(row_at(p->bytes, t->map, i + 1, t->reader->a.minor), t->map, level); if (keycmp(&v, k) > 0) break; i++; }
        unsigned child; enum sfs_status e = rebalance_child(t, id, &i, &child); if (e) return e; e = delete_page(t, child, k); if (e) return e;
    }
    p->dirty = 1; return refresh(t, id);
}
static enum sfs_status tree_delete(tree *t, const key *k) {
    unsigned path[MAX_HEIGHT], depth, at; int found; enum sfs_status e = tree_search(t, k, path, &depth, &at, &found); if (e) return e; if (!found) return SFS_NOT_FOUND;
    e = delete_page(t, (unsigned)t->root, k); if (e) return e;
    overlay_page *p = t->arena->pages[t->root]; unsigned n = page_count(p->bytes);
    if (!n) { free(p); t->arena->pages[t->root] = NULL; t->root = -1; memset(&t->source, 0, sizeof(t->source)); }
    else if (page_level(p->bytes) && n == 1) { unsigned child; e = shadow_child(t, (unsigned)t->root, 0, &child); if (e) return e; free(p); t->arena->pages[t->root] = NULL; t->root = (int)child; }
    return SFS_OK;
}
static unsigned tree_dirty(tree *t, unsigned id) { overlay_page *p = owned_page(t, id); if (!p) return 0; unsigned n = !!p->dirty; if (page_level(p->bytes)) for (unsigned i = 0; i < page_count(p->bytes); ++i) if (p->children[i] != NO_CHILD) n += tree_dirty(t, p->children[i]); return n; }
static uint64_t pending_cells(tree *t) { return t->root >= 0 ? tree_dirty(t, (unsigned)t->root) : 0; }
static int reserve_cells(sfs_image *h, uint64_t cells) {
    uint64_t at, capacity = h->current.capacity;
#ifdef SFS_IMAGE_DIAGNOSTIC_TESTING
    if (h->diagnostic_capacity && h->diagnostic_capacity < capacity) capacity = h->diagnostic_capacity;
#endif
    if (!aligned(h->eof < DATA_START ? DATA_START : h->eof, &at) || cells > UINT64_MAX / CELL) {
        h->limit_reason = SFS_LIMIT_STRUCTURE; return 0;
    }
    if (at > capacity || cells * CELL > capacity - at) {
        h->limit_reason = SFS_LIMIT_APPEND_CAPACITY; return 0;
    }
    return 1;
}
static enum sfs_status append_prepared(sfs_image *h, unsigned type, const uint8_t b[CELL], reference *out, uint64_t *remaining, const reference *prepared) {
    if (!*remaining || !reserve_cells(h, 1)) return SFS_LIMIT;
    uint64_t at; if (!aligned(h->eof < DATA_START ? DATA_START : h->eof, &at)) return SFS_LIMIT;
    if (stable(h)) return SFS_IO;
    reference ref = { .type = type, .offset = at, .length = CELL }; if (prepared) { if (prepared->type != type || prepared->offset != at || prepared->length != CELL) return SFS_CORRUPT; ref = *prepared; } else hash_cell(b, type, h->current.uuid, ref.digest, h->current.minor);
    uint8_t padding[CELL] = {0}; uint64_t gap = h->eof < DATA_START ? DATA_START : h->eof;
    while (gap < at) { size_t n = at - gap < CELL ? (size_t)(at - gap) : CELL; if (write_exact(h->fd, padding, n, gap)) goto failed; gap += n; }
    if (write_exact(h->fd, b, CELL, at)) goto failed;
    h->eof = at + CELL; (*remaining)--; *out = ref; return SFS_OK;
failed: { int error = errno; struct stat st; if (!fstat(h->fd, &st) && st.st_size >= 0) h->eof = (uint64_t)st.st_size; errno = error; return SFS_IO; }
}
static enum sfs_status append_cell(sfs_image *h, unsigned type, const uint8_t b[CELL], reference *out, uint64_t *remaining) { return append_prepared(h, type, b, out, remaining, NULL); }
static enum sfs_status seal_page(tree *t, unsigned id, reference *out, uint64_t *remaining) {
    overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT;
    if (!p->dirty) { *out = p->source; return SFS_OK; }
    unsigned level = page_level(p->bytes);
    if (level) for (unsigned i = 0; i < page_count(p->bytes); ++i) if (p->children[i] != NO_CHILD) { reference child; enum sfs_status e = seal_page(t, p->children[i], &child, remaining); if (e) return e; put_child_ref(p->bytes + PAGE_HEAD + i * stride(t->map, level, t->reader->a.minor), t->map, &child); }
    put64(p->bytes + 72, t->reader->a.generation);
    enum sfs_status e = append_cell(t->reader->h, INDEX, p->bytes, out, remaining); if (!e) { p->source = *out; p->dirty = 0; } return e;
}
static enum sfs_status seal_tree(tree *t, reference *out, uint64_t *remaining) { if (t->root < 0) { *out = t->source; return SFS_OK; } return seal_page(t, (unsigned)t->root, out, remaining); }
static arena *arena_clone(arena *old) {
    arena *a = calloc(1, sizeof(*a)); if (!a) return NULL; a->used = old->used; a->epoch = old->epoch; a->batch = old->batch; a->lineage = old->lineage;
    for (unsigned i = 0; i < old->used; ++i) if (old->pages[i]) { a->pages[i] = malloc(sizeof(overlay_page)); if (!a->pages[i]) { arena_free(a); return NULL; } memcpy(a->pages[i], old->pages[i], sizeof(overlay_page)); } return a;
}
static reader current_reader(sfs_image *h, int staged) { reader r; memset(&r, 0, sizeof(r)); r.h = h; r.a = h->current; r.phase = SFS_PHASE_READ; if (staged) { r.a.end = h->eof; r.a.generation++; } return r; }
/* All lifetime storage is reserved up front. No pointer into the read cache is
 * retained. The hash owns inode uniqueness; tokens index slots directly. */
#define PIN_NONE UINT32_MAX
static atomic_uint_fast64_t pin_instances = ATOMIC_VAR_INIT(1);
static uint32_t pin_hash(const pin_table *t, uint64_t id) {
    id ^= id >> 30; id *= UINT64_C(0xbf58476d1ce4e5b9); id ^= id >> 27;
    id *= UINT64_C(0x94d049bb133111eb); id ^= id >> 31; return (uint32_t)id & (t->hash_count - 1);
}
static pin_slot *pin_find(sfs_image *h, sfs_inode id) {
    pin_table *t = h->pins; if (!t || !id) return NULL;
    uint32_t at = pin_hash(t, id);
    for (uint32_t n = 0; n < t->hash_count; ++n, at = (at + 1) & (t->hash_count - 1)) {
        uint32_t v = t->hash[at]; if (!v) return NULL;
        if (t->slots[v - 1].id == id) return &t->slots[v - 1];
    } return NULL;
}
static void pin_hash_insert(pin_table *t, pin_slot *p) {
    uint32_t at = pin_hash(t, p->id);
    while (t->hash[at]) at = (at + 1) & (t->hash_count - 1);
    t->hash[at] = (uint32_t)(p - t->slots) + 1;
}
static void pin_hash_remove(pin_table *t, pin_slot *p) {
    if (!p->id) return; uint32_t at = pin_hash(t, p->id);
    for (uint32_t n = 0; n < t->hash_count; ++n, at = (at + 1) & (t->hash_count - 1)) {
        if (!t->hash[at]) return;
        if (t->hash[at] == (uint32_t)(p - t->slots) + 1) {
            /* Backshift this cluster, without tombstones or a table rebuild. */
            uint32_t hole = at, scan = (at + 1) & (t->hash_count - 1), mask = t->hash_count - 1;
            while (t->hash[scan]) {
                uint32_t home = pin_hash(t, t->slots[t->hash[scan] - 1].id);
                if (((scan - home) & mask) >= ((scan - hole) & mask)) { t->hash[hole] = t->hash[scan]; hole = scan; }
                scan = (scan + 1) & mask;
            }
            t->hash[hole] = 0; return;
        }
    }
}
static void pin_touch(sfs_image *h, pin_slot *p) {
    if (p->dirty) return; pin_table *t = h->pins;
    p->pending = p->state; p->staged = p->committed; p->dirty = 1;
    p->previous = PIN_NONE; p->next = t->changed;
    if (t->changed != PIN_NONE) t->slots[t->changed].previous = (uint32_t)(p - t->slots);
    t->changed = (uint32_t)(p - t->slots);
}
static void pin_unchain(pin_table *t, pin_slot *p) {
    if (!p->dirty) return;
    if (p->previous == PIN_NONE) t->changed = p->next; else t->slots[p->previous].next = p->next;
    if (p->next != PIN_NONE) t->slots[p->next].previous = p->previous;
    p->dirty = 0; p->next = p->previous = PIN_NONE;
}
static void pin_retire(pin_table *t, pin_slot *p) {
    pin_unchain(t, p); pin_hash_remove(t, p); p->id = 0; p->state = p->pending = PIN_FREE;
    memset(&p->committed, 0, sizeof(p->committed)); memset(&p->staged, 0, sizeof(p->staged));
    /* Never wrap a slot incarnation. An exhausted slot stays unavailable. */
    if (p->incarnation != UINT64_MAX) { p->free_next = t->free_head; t->free_head = (uint32_t)(p - t->slots); }
}
static void pins_discard(sfs_image *h) {
    pin_table *t = h->pins; if (!t) return;
    while (t->changed != PIN_NONE) {
        pin_slot *p = &t->slots[t->changed];
        if (p->state == PIN_RESERVED) pin_retire(t, p);
        else { pin_unchain(t, p); p->pending = PIN_FREE; memset(&p->staged, 0, sizeof(p->staged)); }
    }
}
static void pins_promote(sfs_image *h) {
    pin_table *t = h->pins; if (!t) return;
    while (t->changed != PIN_NONE) {
        pin_slot *p = &t->slots[t->changed]; p->state = p->pending;
        p->committed = p->staged; pin_unchain(t, p); p->pending = PIN_FREE;
        memset(&p->staged, 0, sizeof(p->staged));
    }
}
static void pins_free(sfs_image *h) { if (h->pins) { free(h->pins->hash); free(h->pins->slots); free(h->pins); h->pins = NULL; } }
static enum sfs_status pin_resolve(sfs_image *h, sfs_pin token, pin_slot **out) {
    pin_table *t = h->pins;
    if (!t || token.reserved || token.instance != t->instance || memcmp(token.session, t->session, sizeof(t->session)) || token.slot >= t->count) return SFS_INVALID;
    pin_slot *p = &t->slots[token.slot];
    if (p->state == PIN_FREE || p->incarnation != token.incarnation || !token.incarnation) return SFS_INVALID;
    *out = p; return SFS_OK;
}
static enum sfs_status pin_gate(sfs_image *h, int writing, int tx, sfs_result *out) {
    if (h && h->selected && h->current.minor != 6) {
        h->limit_reason = SFS_LIMIT_UNSPECIFIED; h->fence_attempted = h->fence_succeeded = 0;
        return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, out);
    }
    return ready(h, writing, tx, out);
}
static unsigned pin_pending_state(const pin_slot *p) { return p->dirty ? p->pending : p->state; }
static pin_descriptor *pin_pending_descriptor(pin_slot *p) { return p->dirty ? &p->staged : &p->committed; }
static int pin_descriptor_valid(sfs_image *h, const pin_slot *p, const pin_descriptor *d, int staged) {
    return p->id > 1 && d->inode.e.inode == p->id && !d->inode.nlink && !d->inode.reverse.type &&
        d->next_inode > p->id && d->end >= DATA_START && d->end <= (staged ? h->eof : h->current.end) &&
        d->generation && d->generation <= h->current.generation + (unsigned)staged;
}
static enum sfs_status pin_mutation_target(sfs_image *h, sfs_pin token, mutation_target *out, sfs_result *r) {
    enum sfs_status e = pin_gate(h, 1, 1, r); if (e) return e; pin_slot *p;
    e = pin_resolve(h, token, &p); if (e) return result(h, e, SFS_PHASE_NONE, 0, r);
    unsigned state = pin_pending_state(p);
    if (state != PIN_LINKED && state != PIN_DETACHED) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    *out = (mutation_target){ p->id, state == PIN_DETACHED ? p : NULL }; return SFS_OK;
}
static int target_same(const batch *b, mutation_target target) { return b && b->inode.e.inode == target.id && b->detached == target.detached; }
static enum sfs_status target_get(reader *r, mutation_target target, node *out) {
    if (target.detached) {
        pin_descriptor *d = pin_pending_descriptor(target.detached);
        if (target.detached->id != target.id || pin_pending_state(target.detached) != PIN_DETACHED || !pin_descriptor_valid(r->h, target.detached, d, 1)) return SFS_CORRUPT;
        *out = d->inode; return SFS_OK;
    }
    enum sfs_status e = node_get(r, &r->h->staged.ns, target.id, 1, out);
    if (e != SFS_NOT_FOUND) return e;
    pin_slot *p = pin_find(r->h, target.id);
    return p && pin_pending_state(p) == PIN_LINKED ? SFS_CORRUPT : e;
}
static void target_store(reader *r, pin_slot *p, const node *n) {
    pin_touch(r->h, p); p->pending = PIN_DETACHED; p->staged.inode = *n;
    p->staged.end = r->h->eof; p->staged.generation = r->a.generation;
}
static tree make_tree(arena *a, reader *r, reference source, unsigned map, uint64_t owner, uint64_t next, uint64_t eof) { return (tree){ .arena = a, .reader = r, .source = source, .root = -1, .map = map, .owner = owner, .next_inode = next, .eof = eof }; }
static enum sfs_status mutation_failure(sfs_image *h, enum sfs_status e, enum sfs_phase phase, int error, int late, sfs_result *result_out) {
    if (e == SFS_LIMIT || late || e == SFS_IO || e == SFS_CORRUPT || e == SFS_UNSUPPORTED || e == SFS_RECOVERY_REQUIRED) discard(h);
    if (e == SFS_IO || e == SFS_CORRUPT || e == SFS_UNSUPPORTED || e == SFS_RECOVERY_REQUIRED) { h->poisoned = 1; h->phase = phase; }
    return result(h, e, e == SFS_LIMIT ? SFS_PHASE_ADMISSION : phase, e == SFS_IO || e == SFS_RECOVERY_REQUIRED ? error : e == SFS_NOMEM ? ENOMEM : 0, result_out);
}
static enum sfs_status write_namespace(sfs_image *h, namespace *ns, uint64_t *remaining) {
    uint8_t b[CELL]; envelope(b, NAMESPACE, h->current.uuid, h->current.minor); encode_ref(b + 64, &ns->inodes); encode_ref(b + 120, &ns->names); put64(b + 176, ns->next_inode); put64(b + 184, ns->count); if (metadata_capable(h->current.minor)) encode_attributes(b + 192, &ns->attributes); if (xattr_capable(h->current.minor)) encode_ref(b + 280, &ns->xattrs); if (h->current.minor == 6) put64(b + 336, ns->name_count); return append_cell(h, NAMESPACE, b, &ns->ref, remaining);
}

typedef struct { uint64_t count, max_inode, max_end; } summary;
static enum sfs_status intrinsic(reader *r, reference ref, uint64_t before, context ctx, summary *out) {
    const uint8_t *source; enum sfs_status e = page_read(r, &ref, before, ctx, &source); if (e) return e;
    uint8_t entry[128]; e = memo(r, &ref, entry, 0); if (e) return e;
    if (get32(entry) == 1) return SFS_CORRUPT;
    if (get32(entry) & 2) { *out = (summary){ get64(entry + 40), get64(entry + 48), get64(entry + 56) };
        if ((ctx.map == MAP_INODE || ctx.map == MAP_NAME || ctx.map == MAP_XATTR || ctx.map == MAP_BACKREF) && out->max_inode >= ctx.next_inode) return SFS_CORRUPT;
        if ((ctx.map == MAP_EXTENT || (ctx.map == MAP_INODE && r->a.minor == 6)) && out->max_end > ctx.eof) return SFS_CORRUPT; return SFS_OK;
    }
    memset(entry, 0, sizeof(entry)); put32(entry, 1); put32(entry + 4, INDEX); memcpy(entry + 8, ref.digest, 32); e = memo(r, &ref, entry, 1); if (e) return e;
    uint8_t b[CELL]; memcpy(b, source, CELL); summary s = {0}; unsigned n = page_count(b);
    for (unsigned i = 0; i < n; ++i) {
        const uint8_t *v = row_at(b, ctx.map, i, r->a.minor);
        if (ctx.level) { reference child; if (!child_ref(v, ctx.map, &child)) return SFS_CORRUPT; summary cs;
            e = intrinsic(r, child, ref.offset, child_context(b, i, ctx), &cs); if (e) return e;
            if (!add64(s.count, cs.count, &s.count)) return SFS_CORRUPT; if (cs.max_inode > s.max_inode) s.max_inode = cs.max_inode; if (cs.max_end > s.max_end) s.max_end = cs.max_end;
        } else {
            s.count++;
            if (ctx.map == MAP_INODE || ctx.map == MAP_NAME || ctx.map == MAP_BACKREF) { uint64_t id = ctx.map == MAP_INODE ? get64(v) : get64(v + 267), parent = get64(v + (ctx.map == MAP_INODE ? 8 : 0)); if (id > s.max_inode) s.max_inode = id; if (parent > s.max_inode) s.max_inode = parent; }
            if (ctx.map == MAP_INODE && r->a.minor == 6 && get64(v + 344) > s.max_end) s.max_end = get64(v + 344);
            if (ctx.map == MAP_XATTR && get64(v) > s.max_inode) s.max_inode = get64(v);
            if (ctx.map == MAP_EXTENT) { reference data; if (!decode_ref(v + 8, &data)) return SFS_CORRUPT; e = raw_read(r, &data, ref.offset, get16(v + 64), 0, NULL); if (e) return e;
                uint64_t end; if (!add64(get64(v) * CELL, get16(v + 64), &end)) return SFS_CORRUPT; if (end > s.max_end) s.max_end = end;
            }
        }
    }
    put32(entry, 2); put64(entry + 40, s.count); put64(entry + 48, s.max_inode); put64(entry + 56, s.max_end); e = memo(r, &ref, entry, 1); if (!e) *out = s; return e;
}
static enum sfs_status intrinsic_root(reader *r, reference ref, unsigned map, uint64_t next, uint64_t eof, summary *out) {
    memset(out, 0, sizeof(*out)); if (!ref.type) return SFS_OK;
    const uint8_t *b; enum sfs_status e = root_page(r, &ref, map, next, eof, &b); if (e) return e;
    return intrinsic(r, ref, r->a.end, root_context(map, page_level(b), next, eof, r->a.minor), out);
}
static enum sfs_status full_xattrs(reader *r, const namespace *ns) {
    summary attrs; enum sfs_status e = intrinsic_root(r, ns->xattrs, MAP_XATTR, ns->next_inode, UINT64_MAX, &attrs); if (e) return e;
    cursor c; e = cursor_start(&c, r, ns->xattrs, MAP_XATTR, ns->next_inode, UINT64_MAX, NULL); if (e) return e;
    uint8_t row[MAX_ROW]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found) {
        e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
        node owner; e = node_get(r, ns, get64(row), 1, &owner); if (e) return e == SFS_NOT_FOUND ? SFS_CORRUPT : e;
        reference extent; if (!decode_ref(row + 280, &extent)) return SFS_CORRUPT;
        uint64_t size = get64(row + 272), expected = get64(row + 336), count = 0;
        cursor values; e = cursor_start(&values, r, extent, MAP_EXTENT, UINT64_MAX, size, NULL); if (e) return e;
        uint8_t value[MAX_ROW]; int present;
        while (!(e = cursor_next(&values, value, &present)) && present) {
            e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
            unsigned visible = count + 1 == expected && size % CELL ? (unsigned)(size % CELL) : CELL;
            reference raw; if (count >= expected || get64(value) != count || get16(value + 64) != visible || !decode_ref(value + 8, &raw)) return SFS_CORRUPT;
            e = raw_read(r, &raw, extent.offset, visible, 0, NULL); if (e) return e; count++;
        }
        if (e) return e; if (count != expected) return SFS_CORRUPT;
    }
    return e;
}
static enum sfs_status full_hardlinks(reader *r, const namespace *ns) {
    cursor *c = malloc(sizeof(*c)); if (!c) return SFS_NOMEM;
    uint64_t next = 2, total = 0; uint8_t row[MAX_ROW]; int found; enum sfs_status e = SFS_OK; node n;
    for (;;) {
        key seek = number_key(next); e = cursor_start(c, r, ns->inodes, MAP_INODE, ns->next_inode, ns->name_count, &seek); if (e) break;
        e = cursor_next(c, row, &found); if (e || !found) break; decode_node(row, &n, r->a.minor); next = n.e.inode + 1;
        e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) break;
        if (!add64(total, n.nlink, &total) || total > ns->name_count) { e = SFS_CORRUPT; break; }
        key representative = name_key(n.e.parent, n.e.name, n.e.name_length);
        e = name_member(r, ns, &n, &representative); if (e) break;
        if (n.nlink == 1) continue;
        summary reverse; e = intrinsic_root(r, n.reverse, MAP_BACKREF, ns->next_inode, n.e.inode, &reverse); if (e) break;
        if (reverse.count != n.nlink) { e = SFS_CORRUPT; break; }
        e = reverse_first(r, ns, &n, row); if (e) break; key first = row_key(row, MAP_BACKREF, 0);
        if (keycmp(&first, &representative)) { e = SFS_CORRUPT; break; }
        e = cursor_start(c, r, n.reverse, MAP_BACKREF, ns->next_inode, n.e.inode, NULL); if (e) break;
        uint64_t count = 0;
        while (!(e = cursor_next(c, row, &found)) && found) {
            e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) break;
            if (!add64(count, 1, &count) || count > n.nlink || get64(row + 267) != n.e.inode) { e = SFS_CORRUPT; break; }
            key k = row_key(row, MAP_BACKREF, 0); e = name_member(r, ns, &n, &k); if (!e) e = parent_chain(r, ns, get64(row), 0); if (e) break;
        }
        if (e) break; if (count != n.nlink) { e = SFS_CORRUPT; break; }
    }
    if (!e && total != ns->name_count) e = SFS_CORRUPT;
    if (!e) e = cursor_start(c, r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, NULL);
    while (!e && !(e = cursor_next(c, row, &found)) && found) {
        e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) break;
        key k = row_key(row, MAP_NAME, 0); uint64_t parent = get64(row);
        e = node_get(r, ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
        if (!e) e = name_member(r, ns, &n, &k); if (!e) e = parent_chain(r, ns, parent, 0);
    }
    free(c); return e;
}
static enum sfs_status full_namespace(reader *r, namespace ns) {
    const uint8_t *b; enum sfs_status e = metadata(r, &ns.ref, NAMESPACE, r->a.end, &b); if (e) return e;
    uint8_t entry[128]; e = memo(r, &ns.ref, entry, 0); if (e) return e; if (get32(entry) & 4) return SFS_OK; if (get32(entry) == 1) return SFS_CORRUPT;
    memset(entry, 0, sizeof(entry)); put32(entry, 1); put32(entry + 4, NAMESPACE); memcpy(entry + 8, ns.ref.digest, 32); e = memo(r, &ns.ref, entry, 1); if (e) return e;
    summary inodes, names; e = intrinsic_root(r, ns.inodes, MAP_INODE, ns.next_inode, ns.name_count, &inodes); if (e) return e;
    e = intrinsic_root(r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &names); if (e) return e;
    if (inodes.count != ns.count || names.count != ns.name_count) return SFS_CORRUPT;
    cursor c; e = cursor_start(&c, r, ns.inodes, MAP_INODE, ns.next_inode, ns.name_count, NULL); if (e) return e;
    uint8_t row[MAX_ROW]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found) {
        node n; decode_node(row, &n, r->a.minor); key k = name_key(n.e.parent, n.e.name, n.e.name_length); uint8_t name[MAX_ROW]; int matched;
        e = index_get(r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k, name, &matched); if (e) return e; if (!matched || get64(name + 267) != n.e.inode) return SFS_CORRUPT;
        e = parent_chain(r, &ns, n.e.parent, 0); if (e) return e;
        if (n.e.kind == SFS_FILE) { summary ext; e = intrinsic_root(r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &ext); if (e) return e; if (metadata_capable(r->a.minor) && ext.count != n.attributes.extents) return SFS_CORRUPT; }
        else if (n.e.kind == SFS_SYMLINK) { e = link_target(r, &n, NULL); if (e) return e; }
    }
    if (!e && r->a.minor == 6) e = full_hardlinks(r, &ns);
    if (!e && xattr_capable(r->a.minor)) e = full_xattrs(r, &ns);
    if (e) return e; put32(entry, 6); put64(entry + 40, ns.count); put64(entry + 48, inodes.max_inode); return memo(r, &ns.ref, entry, 1);
}
static enum sfs_status full_state(reader *r, state *s) {
    enum sfs_status e = load_state(r, s); if (e) return e;
    summary catalog; e = intrinsic_root(r, s->catalog, MAP_SNAPSHOT, UINT64_MAX, UINT64_MAX, &catalog); if (e) return e; if (catalog.count != s->count) return SFS_CORRUPT;
    e = full_namespace(r, s->ns); if (e) return e;
    for (unsigned i = 0; i < s->count; ++i) { namespace ns; e = namespace_read(r, s->snapshots[i].ns, s->catalog.offset, &ns); if (e) return e; e = full_namespace(r, ns); if (e) return e; }
    return SFS_OK;
}
static void encode_slot(uint8_t b[CELL], const anchor *a) {
    memset(b, 0, CELL); memcpy(b, "SFSIMG01", 8); put32(b + 12, a->minor); memcpy(b + 24, a->uuid, 16); put64(b + 40, a->generation); encode_ref(b + 48, &a->root); put64(b + 104, a->end); put64(b + 144, a->capacity); hash_cell(b, ROOT, a->uuid, b + SLOT_HASH, a->minor);
}
static enum sfs_status decode_slot(reader *r, unsigned slot, anchor *a) {
    uint8_t b[CELL], digest[32], expected[32]; if (r->h->eof < (slot + 1) * ALIGNMENT) return SFS_CORRUPT;
    enum sfs_status e = charge(r, SFS_INCOMPLETE_METADATA_READ, CELL); if (e) return e; e = charge(r, SFS_INCOMPLETE_METADATA_HASH, CELL); if (e) return e;
    if (read_exact(r->h->fd, b, CELL, slot * ALIGNMENT)) return io_failure(r, SFS_PHASE_READ);
    memcpy(expected, b + SLOT_HASH, 32); memset(b + SLOT_HASH, 0, 32); hash_cell(b, ROOT, b + 24, digest, get32(b + 12));
    if (memcmp(b, "SFSIMG01", 8) || memcmp(digest, expected, 32)) return SFS_CORRUPT;
    if (get32(b + 8) || (get32(b + 12) != 2 && get32(b + 12) != 3 && get32(b + 12) != 4 && get32(b + 12) != 5 && get32(b + 12) != 6) || get64(b + 16)) return SFS_UNSUPPORTED;
    if (!zero(b + 152, CELL - 152) || !decode_ref(b + 48, &a->root)) return SFS_CORRUPT;
    a->minor = get32(b + 12); memcpy(a->uuid, b + 24, 16); a->generation = get64(b + 40); a->end = get64(b + 104); a->capacity = get64(b + 144);
    uint64_t end;
    if (zero(a->uuid, 16) || !a->generation || a->capacity < 16384 || a->capacity % CELL || a->capacity > SFS_IMAGE_MAX || a->capacity > (uint64_t)INT64_MAX || a->root.type != ROOT || a->root.offset < DATA_START || a->root.offset % CELL || a->root.length != CELL || !add64(a->root.offset, CELL, &end) || a->end != end || end > r->h->eof || end > a->capacity) return SFS_CORRUPT;
    if (r->h->eof > a->capacity) return SFS_LIMIT;
    /* Pin the first valid observation even if later candidate verification stops. */
    if (!r->h->slot_observed[slot]) { r->h->slots[slot] = *a; r->h->slot_observed[slot] = 1; }
    return SFS_OK;
}
static int same_anchor(const anchor *a, const anchor *b) { return a->minor == b->minor && a->generation == b->generation && a->end == b->end && a->capacity == b->capacity && !memcmp(a->uuid, b->uuid, 16) && same_ref(&a->root, &b->root); }
static int pair_valid(const anchor a[2]) {
    if (a[0].minor != a[1].minor || a[0].capacity != a[1].capacity || memcmp(a[0].uuid, a[1].uuid, 16)) return 0;
    if (a[0].generation == a[1].generation) return a[0].generation == 1 && same_anchor(&a[0], &a[1]);
    unsigned newest = a[0].generation > a[1].generation ? 0 : 1, old = 1 - newest;
    return a[old].generation != UINT64_MAX && a[newest].generation == a[old].generation + 1 && a[newest].end > a[old].end && a[newest].generation % 2 == newest;
}
static enum sfs_status predecessor_counter(reader *r, const anchor *previous, uint64_t current) {
    anchor selected = r->a; r->a = *previous; const uint8_t *b; enum sfs_status e = metadata(r, &previous->root, ROOT, previous->end, &b);
    if (!e) { reference ns, catalog; if (!decode_ref(b + 64, &ns) || !decode_ref(b + 120, &catalog) || !zero(b + 176, CELL - 176)) e = SFS_CORRUPT;
        else { if (catalog.type) e = bounds(r, &catalog, INDEX, previous->root.offset); namespace n; if (!e) e = namespace_read(r, ns, previous->root.offset, &n); if (!e && current < n.next_inode) e = SFS_CORRUPT; }
    }
    r->a = selected; return e;
}
static enum sfs_status reconcile(reader *r, state *fresh) {
    anchor a[2] = {0}; enum sfs_status code[2] = { SFS_INCOMPLETE, SFS_INCOMPLETE }; int errors[2] = {0};
    for (unsigned i = 0; i < 2; ++i) { code[i] = decode_slot(r, i, &a[i]); errors[i] = code[i] == SFS_IO ? r->error : 0; if (code[i] == SFS_INCOMPLETE) break; }
    /* A controlled stop cannot erase a fatal slot failure already observed. */
    if (r->h->policy != RECOVERY) {
        if (code[0] == SFS_UNSUPPORTED || code[1] == SFS_UNSUPPORTED) return SFS_UNSUPPORTED;
        if (code[0] == SFS_IO || code[1] == SFS_IO) { r->error = errors[0] ? errors[0] : errors[1]; r->phase = SFS_PHASE_READ; return SFS_IO; }
        if ((code[0] && code[0] != SFS_INCOMPLETE) || (code[1] && code[1] != SFS_INCOMPLETE)) return SFS_RECOVERY_REQUIRED;
    }
    if (code[0] == SFS_INCOMPLETE || code[1] == SFS_INCOMPLETE) return SFS_INCOMPLETE;
    if (r->h->policy != RECOVERY) {
        if (!pair_valid(a)) return SFS_RECOVERY_REQUIRED;
        unsigned i = a[0].generation > a[1].generation ? 0 : 1; if (!same_anchor(&a[i], &r->h->current)) return SFS_CORRUPT;
        enum sfs_status e = load_state(r, fresh); if (!e && a[1 - i].generation < a[i].generation) e = predecessor_counter(r, &a[1 - i], fresh->ns.next_inode); return e;
    }
    int matched = (!code[0] && same_anchor(&a[0], &r->h->current)) || (!code[1] && same_anchor(&a[1], &r->h->current));
    if (!matched) { r->error = errors[0] ? errors[0] : errors[1]; return r->error ? SFS_IO : SFS_CORRUPT; }
    return load_state(r, fresh);
}
static void candidate_result(reader *r, const anchor *a, enum sfs_status code, enum sfs_coverage coverage, sfs_result *out) {
    result(r->h, code, r->phase, code == SFS_IO || code == SFS_RECOVERY_REQUIRED ? r->error : code == SFS_NOMEM ? ENOMEM : 0, out);
    if (!out) return; if (a) { out->generation = a->generation; out->committed_end = a->end; memcpy(out->uuid, a->uuid, 16); memcpy(out->root_digest, a->root.digest, 32); }
    out->incomplete_reason = code == SFS_INCOMPLETE ? r->incomplete : SFS_INCOMPLETE_NONE; if (!code) out->coverage = coverage;
}
static enum sfs_status close_failed(sfs_image *h, int parent, enum sfs_status code, enum sfs_phase phase, int error, sfs_result *out) {
    struct stat st; if (!fstat(h->fd, &st) && st.st_size >= 0) h->eof = (uint64_t)st.st_size;
    result(h, code, phase, error, out);
    if (parent >= 0 && close(parent)) { error = errno; phase = SFS_PHASE_CLOSE; if (code != SFS_OUTCOME_UNKNOWN) code = SFS_IO; }
    if (h->aux_parent >= 0 && close(h->aux_parent)) { error = errno; phase = SFS_PHASE_CLOSE; if (code != SFS_OUTCOME_UNKNOWN) code = SFS_IO; }
    if (close(h->fd)) { error = errno; phase = SFS_PHASE_CLOSE; if (code != SFS_OUTCOME_UNKNOWN) code = SFS_IO; }
    discard(h); cache_clear(h); free(h); if (out) { out->status = code; out->phase = phase; out->system_errno = error; } return code;
}

static enum sfs_status create_image(const char *directory, const char *name, uint64_t capacity, const sfs_metadata_initial *initial, unsigned minor, sfs_image **out, sfs_result *r) {
    if (!out) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r); *out = NULL;
    if (capacity < 16384 || capacity % CELL || capacity > SFS_IMAGE_MAX || capacity > (uint64_t)INT64_MAX) return result(NULL, SFS_INVALID, SFS_PHASE_ADMISSION, 0, r);
    attributes root_attributes = {0};
    if (metadata_capable(minor)) { enum sfs_status e = initial_valid(initial, SFS_DIRECTORY); if (e) return result(NULL, e, SFS_PHASE_NONE, 0, r); if (!directory || !component(name)) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r); sfs_timestamp t; int error; e = clock_sample(&t, &error); if (e) return result(NULL, e, SFS_PHASE_NONE, error, r); root_attributes = initial_attributes(initial, t); }
    sfs_image *h; int parent; enum sfs_status code = access_image(directory, name, 1, ORDINARY_WRITABLE, &h, &parent, r); if (code) return code;
    h->current.minor = minor; h->live.ns.attributes = root_attributes;
    h->current.capacity = capacity; h->live.ns.next_inode = 2; arc4random_buf(h->current.uuid, 16); if (zero(h->current.uuid, 16)) h->current.uuid[0] = 1;
    anchor next = h->current; next.generation = 1; uint64_t remaining = 2; enum sfs_phase phase = SFS_PHASE_RECORDS; int published = 0;
    code = write_namespace(h, &h->live.ns, &remaining); if (code) goto failed;
    uint8_t b[CELL]; envelope(b, ROOT, h->current.uuid, h->current.minor); encode_ref(b + 64, &h->live.ns.ref); code = append_cell(h, ROOT, b, &next.root, &remaining); if (code) goto failed; next.end = h->eof;
    encode_slot(b, &next); phase = SFS_PHASE_RECORD_BARRIER; if (fullsync(h->fd)) goto io_failed;
    phase = SFS_PHASE_SLOT0; published = 1; if (write_exact(h->fd, b, CELL, 0)) goto io_failed;
    phase = SFS_PHASE_SLOT1; if (write_exact(h->fd, b, CELL, CELL)) goto io_failed;
    phase = SFS_PHASE_COMMIT_BARRIER; if (fullsync(h->fd)) goto io_failed;
    phase = SFS_PHASE_PARENT_BARRIER; if (fsync(parent)) goto io_failed;
    phase = SFS_PHASE_FINAL_BARRIER; if (fullsync(h->fd)) goto io_failed;
    phase = SFS_PHASE_IDENTITY; struct stat ps, named;
    if (fstat(parent, &ps)) goto io_failed;
    if (!same_identity(&ps, &h->parent_identity)) { errno = ESTALE; goto io_failed; }
    if (fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW)) goto io_failed;
    if (!same_identity(&named, &h->identity)) { errno = ESTALE; goto io_failed; }
    if (stable(h)) goto io_failed;
    phase = SFS_PHASE_CLOSE; if (close(parent)) { parent = -1; goto io_failed; } parent = -1;
    h->current = next; h->slots[0] = h->slots[1] = next; h->slot_observed[0] = h->slot_observed[1] = 1; h->selected = 1; *out = h; result(h, SFS_OK, SFS_PHASE_NONE, 0, r); if (r) r->coverage = SFS_COVERAGE_FULL_REACHABLE; return SFS_OK;
io_failed: code = SFS_IO;
failed: return close_failed(h, parent, published ? SFS_OUTCOME_UNKNOWN : code, phase, code == SFS_IO ? errno : 0, r);
}
enum sfs_status sfs_image_create(const char *directory, const char *name, uint64_t capacity, sfs_image **out, sfs_result *r) { return create_image(directory, name, capacity, NULL, 2, out, r); }
enum sfs_status sfs_image_create_metadata(const char *directory, const char *name, uint64_t capacity, const sfs_metadata_initial *root, sfs_image **out, sfs_result *r) { return create_image(directory, name, capacity, root, 3, out, r); }
enum sfs_status sfs_image_create_metadata_version(const char *directory, const char *name, uint64_t capacity, uint32_t minor, const sfs_metadata_initial *root, sfs_image **out, sfs_result *r) {
    if (!out) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r); *out = NULL;
    if (capacity < 16384 || capacity % CELL || capacity > SFS_IMAGE_MAX || capacity > (uint64_t)INT64_MAX) return result(NULL, SFS_INVALID, SFS_PHASE_ADMISSION, 0, r);
    if (!directory || !component(name) || !root) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (!metadata_capable(minor)) return result(NULL, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, r);
    return create_image(directory, name, capacity, root, minor, out, r);
}
static enum sfs_status open_common(const char *directory, const char *name, enum image_policy policy, sfs_image **out, sfs_recovery *report, const sfs_verify_budget *budget, sfs_result *result_out) {
    int inspection = policy == RECOVERY;
    if (!out || (inspection && (!report || !valid_budget(budget)))) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *out = NULL;
    sfs_image *h; int parent; enum sfs_status e = access_image(directory, name, 0, policy, &h, &parent, result_out); if (e) return e;
    if (close(parent)) return close_failed(h, -1, SFS_IO, SFS_PHASE_CLOSE, errno, result_out);
    sfs_verify_budget remaining; if (inspection) remaining = *budget;
    reader r = current_reader(h, 0); if (inspection) r.budget = &remaining; enum sfs_incomplete_reason slot_incomplete[2] = {0};
    for (unsigned i = 0; i < 2; ++i) { r.error = 0; r.incomplete = SFS_INCOMPLETE_NONE; h->slot_status[i] = decode_slot(&r, i, &h->slots[i]); h->slot_error[i] = h->slot_status[i] == SFS_IO ? r.error : 0; slot_incomplete[i] = r.incomplete; }
    int pair = !h->slot_status[0] && !h->slot_status[1] && pair_valid(h->slots); int error = h->slot_error[0] ? h->slot_error[0] : h->slot_error[1];
    if (!inspection) {
        if (h->slot_status[0] == SFS_UNSUPPORTED || h->slot_status[1] == SFS_UNSUPPORTED) return close_failed(h, -1, SFS_UNSUPPORTED, SFS_PHASE_READ, error, result_out);
        if (!pair) return close_failed(h, -1, SFS_RECOVERY_REQUIRED, SFS_PHASE_READ, error, result_out);
        unsigned i = h->slots[0].generation > h->slots[1].generation ? 0 : 1; h->current = h->slots[i]; r.a = h->current;
        e = load_state(&r, &h->live); if (!e && h->slots[1 - i].generation < h->current.generation) e = predecessor_counter(&r, &h->slots[1 - i], h->live.ns.next_inode);
        if (e) return close_failed(h, -1, e, r.phase, e == SFS_IO ? r.error : 0, result_out);
        if (stable(h)) return close_failed(h, -1, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
        h->selected = 1; *out = h; candidate_result(&r, &h->current, SFS_OK, SFS_COVERAGE_ROOT_ONLY, result_out); return SFS_OK;
    }
    memset(report, 0, sizeof(*report)); report->pair_valid = pair; report->latest_may_be_unknown = 1; unsigned usable = 0; enum sfs_incomplete_reason incomplete = SFS_INCOMPLETE_NONE;
    for (unsigned i = 0; i < 2; ++i) {
        e = h->slot_status[i]; r.error = h->slot_error[i]; r.incomplete = slot_incomplete[i]; r.phase = SFS_PHASE_READ;
        if (!e) { cache_clear(h); r.a = h->slots[i]; r.incomplete = SFS_INCOMPLETE_NONE; e = aux_begin(&r); state candidate; if (!e) e = full_state(&r, &candidate); e = aux_finish(&r, e); }
        if (e == SFS_INCOMPLETE) { if (!r.incomplete) r.incomplete = SFS_INCOMPLETE_METADATA_READ; incomplete = r.incomplete; }
        candidate_result(&r, h->slot_observed[i] ? &h->slots[i] : NULL, e, SFS_COVERAGE_FULL_REACHABLE, &report->slots[i]); h->slot_status[i] = e; h->slot_error[i] = e == SFS_IO ? r.error : 0; if (!e) usable++;
    }
    if (stable(h)) return close_failed(h, -1, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    if (!usable) { e = close_failed(h, -1, incomplete ? SFS_INCOMPLETE : SFS_RECOVERY_REQUIRED, SFS_PHASE_READ, incomplete ? 0 : h->slot_error[0] ? h->slot_error[0] : h->slot_error[1], result_out); if (result_out && e == SFS_INCOMPLETE) result_out->incomplete_reason = incomplete; return e; }
    *out = h; return result(h, SFS_OK, SFS_PHASE_READ, 0, result_out);
}
enum sfs_status sfs_image_open(const char *directory, const char *name, sfs_image **out, sfs_result *r) { return open_common(directory, name, ORDINARY_WRITABLE, out, NULL, NULL, r); }
enum sfs_status sfs_image_open_readonly(const char *directory, const char *name, sfs_image **out, sfs_result *r) { return open_common(directory, name, ORDINARY_READONLY, out, NULL, NULL, r); }
enum sfs_status sfs_image_get_information(sfs_image *h, sfs_image_information *out, sfs_result *r) {
    enum sfs_status e = ready(h, 0, 0, r); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    sfs_image_information information = {0}; uint64_t tail;
    information.minor = h->current.minor; information.capacity = h->current.capacity;
    information.root_inode = SFS_ROOT_INODE;
    if (aligned(h->eof, &tail) && tail < h->current.capacity)
        information.append_headroom = h->current.capacity - tail;
    result(h, SFS_OK, SFS_PHASE_NONE, 0, &information.committed);
    information.committed.coverage = SFS_COVERAGE_ROOT_ONLY;
    *out = information; if (r) *r = information.committed; return SFS_OK;
}
enum sfs_status sfs_image_inspect(const char *directory, const char *name, sfs_image **out, sfs_recovery *report, const sfs_verify_budget *budget, sfs_result *r) { return open_common(directory, name, RECOVERY, out, report, budget, r); }
enum sfs_status sfs_image_select(sfs_image *h, unsigned slot, const sfs_verify_budget *budget, sfs_result *out) {
    if (!h || h->policy != RECOVERY || slot > 1 || !valid_budget(budget)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    if (h->slot_status[slot] && h->slot_status[slot] != SFS_INCOMPLETE) return result(h, h->slot_status[slot], SFS_PHASE_READ, h->slot_error[slot], out);
    if (stable(h)) return result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, out);
    sfs_verify_budget remaining = *budget; reader r = current_reader(h, 0); r.budget = &remaining; anchor fresh = {0}; cache_clear(h);
    /* Successful decode captures an unseen anchor; known anchors are never rebased. */
    enum sfs_status e = decode_slot(&r, slot, &fresh); if (!e && !same_anchor(&fresh, &h->slots[slot])) e = SFS_CORRUPT;
    state s; if (!e) { r.a = fresh; e = aux_begin(&r); if (!e) e = full_state(&r, &s); e = aux_finish(&r, e); }
    if (!e && stable(h)) e = io_failure(&r, SFS_PHASE_IDENTITY);
    if (!e) { h->current = fresh; h->live = s; h->selected = 1; h->slot_status[slot] = SFS_OK; }
    candidate_result(&r, fresh.root.type ? &fresh : NULL, e, SFS_COVERAGE_FULL_REACHABLE, out); return e;
}
enum sfs_status sfs_image_close(sfs_image *h, sfs_result *out) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_CLOSE, 0, out);
    h->limit_reason = SFS_LIMIT_UNSPECIFIED; h->fence_attempted = h->fence_succeeded = 0;
    int error = 0; if (close(h->fd)) error = errno; if (close(h->aux_parent) && !error) error = errno;
    enum sfs_status e = result(h, error ? SFS_IO : SFS_OK, SFS_PHASE_CLOSE, error, out); discard(h); pins_free(h); cache_clear(h); free(h); return e;
}
enum sfs_status sfs_image_verify(sfs_image *h, const sfs_verify_budget *budget, sfs_result *out) {
    enum sfs_status e = ready(h, 0, 0, out); if (e) return e; if (!valid_budget(budget)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, out);
    sfs_verify_budget remaining = *budget; reader r = current_reader(h, 0); r.budget = &remaining; cache_clear(h);
    state s; e = aux_begin(&r); if (!e) e = reconcile(&r, &s); if (!e) e = full_state(&r, &s); e = aux_finish(&r, e);
    if (!e && stable(h)) e = io_failure(&r, SFS_PHASE_IDENTITY);
    read_result(h, e, r.phase, e == SFS_IO || e == SFS_RECOVERY_REQUIRED ? r.error : e == SFS_NOMEM ? ENOMEM : 0, out);
    if (out) { if (!e) out->coverage = SFS_COVERAGE_FULL_REACHABLE; if (e == SFS_INCOMPLETE) out->incomplete_reason = r.incomplete; } return e;
}
static enum sfs_status selected_namespace(reader *r, sfs_view view, namespace *out) {
    if (!view) { *out = r->h->live.ns; return SFS_OK; }
    for (unsigned i = 0; i < r->h->live.count; ++i) if (r->h->live.snapshots[i].view == view) return namespace_read(r, r->h->live.snapshots[i].ns, r->h->live.catalog.offset, out);
    return SFS_NOT_FOUND;
}
static enum sfs_status touched_result(reader *r, enum sfs_status e, sfs_result *out) { read_result(r->h, e, r->phase, e == SFS_IO ? r->error : e == SFS_NOMEM ? ENOMEM : 0, out); if (!e && out) out->coverage = SFS_COVERAGE_TOUCHED; return e; }
enum sfs_status sfs_image_pin_configure(sfs_image *h, uint32_t count, uint64_t max_bytes, sfs_result *out) {
    enum sfs_status e = pin_gate(h, 0, 0, out); if (e) return e;
    if (!count || !max_bytes || count > UINT32_MAX / 4) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    if (h->transaction || h->pins || h->policy == RECOVERY) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, out);
    uint32_t hash_count = 2; while (hash_count < count * 2u) hash_count *= 2;
    uint64_t bytes = sizeof(pin_table) + (uint64_t)count * sizeof(pin_slot) + (uint64_t)hash_count * sizeof(uint32_t);
    if (bytes > max_bytes || bytes > SIZE_MAX) { h->limit_reason = SFS_LIMIT_PIN_RESOURCES; return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, out); }
    uint_fast64_t instance = atomic_load_explicit(&pin_instances, memory_order_relaxed);
    do { if (instance == UINT64_MAX) { h->limit_reason = SFS_LIMIT_PIN_RESOURCES; return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, out); } }
    while (!atomic_compare_exchange_weak_explicit(&pin_instances, &instance, instance + 1, memory_order_relaxed, memory_order_relaxed));
    pin_table *t = calloc(1, sizeof(*t)); if (!t) return result(h, SFS_NOMEM, SFS_PHASE_NONE, ENOMEM, out);
    t->slots = calloc(count, sizeof(*t->slots)); t->hash = calloc(hash_count, sizeof(*t->hash));
    if (!t->slots || !t->hash) { free(t->slots); free(t->hash); free(t); return result(h, SFS_NOMEM, SFS_PHASE_NONE, ENOMEM, out); }
    t->instance = instance; t->bytes = bytes; t->count = count; t->hash_count = hash_count; t->changed = PIN_NONE;
    arc4random_buf(t->session, sizeof(t->session));
    for (uint32_t i = 0; i < count; ++i) { t->slots[i].free_next = i + 1 < count ? i + 1 : PIN_NONE; t->slots[i].next = t->slots[i].previous = PIN_NONE; }
    h->pins = t; return result(h, SFS_OK, SFS_PHASE_NONE, 0, out);
}
static enum sfs_status pin_allocate(sfs_image *h, unsigned state, sfs_inode id, sfs_pin *out, sfs_result *r) {
    pin_table *t = h->pins;
    if (!t) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    if (t->free_head == PIN_NONE) { h->limit_reason = SFS_LIMIT_PIN_RESOURCES; return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, r); }
    uint32_t index = t->free_head; pin_slot *p = &t->slots[index]; t->free_head = p->free_next;
    p->incarnation++; p->state = state; p->id = id;
    if (id) pin_hash_insert(t, p);
    if (state == PIN_RESERVED) pin_touch(h, p);
    sfs_pin token = { .instance = t->instance, .incarnation = p->incarnation, .slot = index };
    memcpy(token.session, t->session, sizeof(token.session)); *out = token;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_pin_acquire(sfs_image *h, sfs_inode id, sfs_pin *out, sfs_result *r) {
    enum sfs_status e = pin_gate(h, 0, 0, r); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (h->transaction) return result(h, SFS_BUSY, SFS_PHASE_NONE, 0, r);
    if (!h->pins) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    if (pin_find(h, id)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, r);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    reader rd = current_reader(h, 0); node n; e = node_get(&rd, &h->live.ns, id, 1, &n);
    if (e) return touched_result(&rd, e, r); return pin_allocate(h, PIN_LINKED, id, out, r);
}
enum sfs_status sfs_image_pin_reserve(sfs_image *h, sfs_pin *out, sfs_result *r) {
    enum sfs_status e = pin_gate(h, 1, 0, r); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (h->transaction) return result(h, SFS_BUSY, SFS_PHASE_NONE, 0, r);
    return pin_allocate(h, PIN_RESERVED, 0, out, r);
}
enum sfs_status sfs_image_pin_bind(sfs_image *h, sfs_pin token, sfs_inode id, sfs_result *out) {
    enum sfs_status e = pin_gate(h, 1, 1, out); if (e) return e; pin_slot *p;
    e = pin_resolve(h, token, &p); if (e) return result(h, e, SFS_PHASE_NONE, 0, out);
    if (p->state != PIN_RESERVED || p->pending != PIN_RESERVED || p->id || id < h->live.ns.next_inode) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, out);
    if (pin_find(h, id)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, out);
    e = mutation_start(h, out); if (e) return e;
    reader r = current_reader(h, 1); node n; e = node_get(&r, &h->staged.ns, id, 1, &n);
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    p->id = id; p->pending = PIN_LINKED; pin_hash_insert(h->pins, p); return result(h, SFS_OK, SFS_PHASE_NONE, 0, out);
}
enum sfs_status sfs_image_pin_release(sfs_image *h, sfs_pin token, sfs_result *out) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    h->limit_reason = SFS_LIMIT_UNSPECIFIED; h->fence_attempted = h->fence_succeeded = 0;
    if (h->current.minor != 6) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, out);
    if (h->transaction) return result(h, SFS_BUSY, SFS_PHASE_NONE, 0, out);
    pin_slot *p; enum sfs_status e = pin_resolve(h, token, &p);
    if (!e) pin_retire(h->pins, p); return result(h, e, SFS_PHASE_NONE, 0, out);
}
static enum sfs_status pin_committed(reader *r, sfs_pin token, node *n, reference *xattrs, uint64_t *next) {
    pin_slot *p; enum sfs_status e = pin_resolve(r->h, token, &p); if (e) return e;
    if (p->state == PIN_LINKED) {
        e = node_get(r, &r->h->live.ns, p->id, 1, n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
        *xattrs = r->h->live.ns.xattrs; *next = r->h->live.ns.next_inode; return e;
    }
    if (p->state != PIN_DETACHED) return SFS_STATE;
    if (!pin_descriptor_valid(r->h, p, &p->committed, 0)) return SFS_CORRUPT;
    *n = p->committed.inode; *xattrs = p->committed.xattrs; *next = p->committed.next_inode;
    r->a.end = p->committed.end; r->a.generation = p->committed.generation; return SFS_OK;
}
enum sfs_status sfs_image_snapshot_view(sfs_image *h, const void *name, size_t length, sfs_view *out, sfs_result *r) {
    enum sfs_status e = ready(h, 0, 0, r); if (e) return e; if (!out || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    for (unsigned i = 0; i < h->live.count; ++i) if (h->live.snapshots[i].length == length && !memcmp(h->live.snapshots[i].name, name, length)) { *out = h->live.snapshots[i].view; result(h, SFS_OK, SFS_PHASE_NONE, 0, r); if (r) r->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK; }
    return result(h, SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_stat(sfs_image *h, sfs_view view, sfs_inode id, sfs_entry *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; e = selected_namespace(&r, view, &ns); node n; if (!e) e = node_get(&r, &ns, id, 1, &n); if (!e) *out = n.e; return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_stat_metadata(sfs_image *h, sfs_view view, sfs_inode id, sfs_metadata_entry *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (!metadata_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n; e = selected_namespace(&r, view, &ns); if (!e) e = node_get(&r, &ns, id, 1, &n);
    if (!e && n.attributes.extents > UINT64_MAX / CELL) e = SFS_CORRUPT;
    if (!e) { sfs_metadata_entry v = {0}; v.entry = n.e; v.birth = n.attributes.birth; v.access = n.attributes.access; v.modification = n.attributes.modification; v.change = n.attributes.change; v.mode = n.attributes.mode; v.uid = n.attributes.uid; v.gid = n.attributes.gid; v.flags = n.attributes.flags; v.referenced_data_bytes = n.attributes.extents * CELL; v.link_count = n.nlink; *out = v; }
    return touched_result(&r, e, result_out);
}
static enum sfs_status pin_stat_value(const node *n, sfs_pin_stat *out) {
    if (n->attributes.extents > UINT64_MAX / CELL) return SFS_CORRUPT;
    sfs_pin_stat v = {0}; sfs_metadata_entry *m = &v.metadata;
    v.linked = !!n->nlink; m->entry = n->e;
    if (!v.linked) { m->entry.parent = 0; m->entry.name_length = 0; memset(m->entry.name, 0, sizeof(m->entry.name)); }
    m->birth = n->attributes.birth; m->access = n->attributes.access;
    m->modification = n->attributes.modification; m->change = n->attributes.change;
    m->mode = n->attributes.mode; m->uid = n->attributes.uid; m->gid = n->attributes.gid; m->flags = n->attributes.flags;
    m->referenced_data_bytes = n->attributes.extents * CELL; m->link_count = n->nlink; *out = v;
    return SFS_OK;
}
enum sfs_status sfs_image_pin_stat(sfs_image *h, sfs_pin token, sfs_pin_stat *out, sfs_result *result_out) {
    enum sfs_status e = pin_gate(h, 0, 0, result_out); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); node n; reference attrs; uint64_t next;
    e = pin_committed(&r, token, &n, &attrs, &next);
    if (!e) e = pin_stat_value(&n, out);
    return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_pin_stat_transaction(sfs_image *h, sfs_pin token, sfs_pin_stat *out, sfs_result *result_out) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, token, &target, result_out); if (e) return e;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    e = mutation_start(h, result_out); if (e) return e;
    reader r = current_reader(h, 1); node n;
    if (target_same(h->batch, target)) n = h->batch->inode;
    else e = target_get(&r, target, &n);
    if (!e) e = pin_stat_value(&n, out);
    return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_lookup(sfs_image *h, sfs_view view, sfs_inode parent, const void *name, size_t length, sfs_entry *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!out || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent);
    uint8_t row[MAX_ROW]; int found; key k = name_key(parent, name, length); node n;
    if (!e) { e = index_get(&r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k, row, &found); if (!e && !found) e = SFS_NOT_FOUND; }
    if (!e) { e = node_get(&r, &ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT; if (!e) { e = r.a.minor == 6 ? name_member(&r, &ns, &n, &k) : (n.e.parent != parent || n.e.name_length != length || memcmp(n.e.name, name, length)) ? SFS_CORRUPT : SFS_OK; if (!e) { n.e.parent = parent; n.e.name_length = length; memset(n.e.name, 0, sizeof(n.e.name)); memcpy(n.e.name, name, length); } } }
    if (!e) *out = n.e; return touched_result(&r, e, result_out);
}
static enum sfs_status read_target(sfs_image *h, sfs_view view, sfs_inode id, const sfs_pin *pin, uint64_t offset, void *data, size_t capacity, size_t *read_count, sfs_result *result_out) {
    enum sfs_status e = pin ? pin_gate(h, 0, 0, result_out) : ready(h, 0, 0, result_out); if (e) return e; if (!read_count || (capacity && !data)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *read_count = 0;
    uint64_t end; if (!add64(offset, capacity, &end)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n;
    if (pin) { reference attrs; uint64_t next; e = pin_committed(&r, *pin, &n, &attrs, &next); }
    else { e = selected_namespace(&r, view, &ns); if (!e) e = node_get(&r, &ns, id, 1, &n); }
    if (!e && n.e.kind != SFS_FILE) e = SFS_INVALID;
    while (!e && *read_count < capacity && offset + *read_count < n.e.size) {
        uint64_t position = offset + *read_count; size_t amount = CELL - position % CELL; if (amount > capacity - *read_count) amount = capacity - *read_count; if (amount > n.e.size - position) amount = (size_t)(n.e.size - position);
        uint8_t row[MAX_ROW], bytes[CELL] = {0}; int found; key k = number_key(position / CELL);
        e = index_get(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &k, row, &found); if (e) break;
        if (found) { reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; break; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), 0, bytes); if (e) break; }
        memcpy((uint8_t *)data + *read_count, bytes + position % CELL, amount); *read_count += amount;
    }
    return touched_result(&r, e, result_out);
}

enum sfs_status sfs_image_read(sfs_image *h, sfs_view v, sfs_inode id, uint64_t offset, void *data, size_t size, size_t *count, sfs_result *r) { return read_target(h, v, id, NULL, offset, data, size, count, r); }
enum sfs_status sfs_image_pin_read(sfs_image *h, sfs_pin pin, uint64_t offset, void *data, size_t size, size_t *count, sfs_result *r) { return read_target(h, 0, 0, &pin, offset, data, size, count, r); }
static enum sfs_status readlink_target(sfs_image *h, sfs_view view, sfs_inode id, const sfs_pin *pin, void *target, size_t capacity, size_t *read_count, sfs_result *result_out) {
    enum sfs_status e = pin ? pin_gate(h, 0, 0, result_out) : ready(h, 0, 0, result_out); if (e) return e;
    if (!read_count || (capacity && !target)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *read_count = 0;
    if (!symlink_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n;
    if (pin) { reference attrs; uint64_t next; e = pin_committed(&r, *pin, &n, &attrs, &next); }
    else { e = selected_namespace(&r, view, &ns); if (!e) e = node_get(&r, &ns, id, 1, &n); }
    if (!e && n.e.kind != SFS_SYMLINK) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (!e && capacity < n.e.size) return result(h, SFS_LIMIT, SFS_PHASE_NONE, 0, result_out);
    uint8_t *bytes = NULL;
    if (!e) { bytes = malloc(CELL); if (!bytes) e = SFS_NOMEM; }
    if (!e) e = link_target(&r, &n, bytes);
    if (!e) { memcpy(target, bytes, (size_t)n.e.size); *read_count = (size_t)n.e.size; }
    free(bytes); return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_readlink(sfs_image *h, sfs_view v, sfs_inode id, void *data, size_t size, size_t *count, sfs_result *r) { return readlink_target(h, v, id, NULL, data, size, count, r); }
enum sfs_status sfs_image_pin_readlink(sfs_image *h, sfs_pin pin, void *data, size_t size, size_t *count, sfs_result *r) { return readlink_target(h, 0, 0, &pin, data, size, count, r); }

static enum sfs_status xattr_get(reader *r, const namespace *ns, sfs_inode id, const void *name, size_t length, uint8_t row[MAX_ROW]) {
    node owner; enum sfs_status e = node_get(r, ns, id, 1, &owner); if (e) return e;
    key k = name_key(id, name, length); int found;
    e = index_get(r, ns->xattrs, MAP_XATTR, ns->next_inode, UINT64_MAX, &k, row, &found); return e ? e : found ? SFS_OK : SFS_NOT_FOUND;
}
static enum sfs_status xattr_read_target(reader *r, sfs_view view, sfs_inode id, const sfs_pin *pin, const void *name, size_t length, uint8_t row[MAX_ROW]) {
    namespace ns; enum sfs_status e;
    if (!pin) { e = selected_namespace(r, view, &ns); return e ? e : xattr_get(r, &ns, id, name, length, row); }
    node n; reference attrs; uint64_t next; e = pin_committed(r, *pin, &n, &attrs, &next); if (e) return e;
    key k = name_key(n.e.inode, name, length); int found;
    e = index_get(r, attrs, MAP_XATTR, next, UINT64_MAX, &k, row, &found);
    return e ? e : found ? SFS_OK : SFS_NOT_FOUND;
}
static enum sfs_status xattr_size_target(sfs_image *h, sfs_view view, sfs_inode id, const sfs_pin *pin, const void *name, size_t length, uint64_t *out, sfs_result *result_out) {
    enum sfs_status e = pin ? pin_gate(h, 0, 0, result_out) : ready(h, 0, 0, result_out); if (e) return e;
    if (!out || !valid_xattr_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (!xattr_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); uint8_t row[MAX_ROW];
    e = xattr_read_target(&r, view, id, pin, name, length, row);
    if (!e) *out = get64(row + 272); return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_xattr_size(sfs_image *h, sfs_view v, sfs_inode id, const void *n, size_t len, uint64_t *out, sfs_result *r) { return xattr_size_target(h, v, id, NULL, n, len, out, r); }
enum sfs_status sfs_image_pin_xattr_size(sfs_image *h, sfs_pin pin, const void *n, size_t len, uint64_t *out, sfs_result *r) { return xattr_size_target(h, 0, 0, &pin, n, len, out, r); }
static enum sfs_status read_xattr_target(sfs_image *h, sfs_view view, sfs_inode id, const sfs_pin *pin, const void *name, size_t length, uint64_t offset, void *data, size_t capacity, size_t *read_count, sfs_result *result_out) {
    enum sfs_status e = pin ? pin_gate(h, 0, 0, result_out) : ready(h, 0, 0, result_out); if (e) return e; uint64_t end;
    if (!read_count || (capacity && !data) || !valid_xattr_name(name, length) || !add64(offset, capacity, &end)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *read_count = 0;
    if (!xattr_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); uint8_t row[MAX_ROW]; reference extent;
    e = xattr_read_target(&r, view, id, pin, name, length, row); if (e) return touched_result(&r, e, result_out);
    uint64_t size = get64(row + 272); if (!decode_ref(row + 280, &extent)) return touched_result(&r, SFS_CORRUPT, result_out);
    if (end > size) end = size;
    while (offset < end) {
        uint64_t block = offset / CELL; key k = number_key(block); int found;
        e = index_get(&r, extent, MAP_EXTENT, UINT64_MAX, size, &k, row, &found); if (e) break;
        unsigned visible = block + 1 == dense_count(size) && size % CELL ? (unsigned)(size % CELL) : CELL;
        reference raw; if (!found || get64(row) != block || get16(row + 64) != visible || !decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; break; }
        uint8_t bytes[CELL]; e = raw_read(&r, &raw, extent.offset, visible, 0, bytes); if (e) break;
        size_t start = (size_t)(offset % CELL), count = visible - start; if (count > end - offset) count = (size_t)(end - offset);
        memcpy((uint8_t *)data + *read_count, bytes + start, count); *read_count += count; offset += count;
    }
    return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_read_xattr(sfs_image *h, sfs_view v, sfs_inode id, const void *n, size_t len, uint64_t offset, void *data, size_t size, size_t *count, sfs_result *r) { return read_xattr_target(h, v, id, NULL, n, len, offset, data, size, count, r); }
enum sfs_status sfs_image_pin_read_xattr(sfs_image *h, sfs_pin pin, const void *n, size_t len, uint64_t offset, void *data, size_t size, size_t *count, sfs_result *r) { return read_xattr_target(h, 0, 0, &pin, n, len, offset, data, size, count, r); }
static enum sfs_status next_xattr_target(sfs_image *h, sfs_view view, uint64_t expected_generation, const uint8_t expected_root_digest[32], sfs_inode owner, const sfs_pin *pin, const void *after_name, size_t after_length, sfs_xattr_entry *out, int *found, sfs_result *result_out) {
    enum sfs_status e = pin ? pin_gate(h, 0, 0, result_out) : ready(h, 0, 0, result_out); if (e) return e;
    if (!out || !found || !expected_root_digest || !expected_generation || (after_name || after_length ? !valid_xattr_name(after_name, after_length) : 0)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (!xattr_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (expected_generation != h->current.generation || memcmp(expected_root_digest, h->current.root.digest, 32)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns = {0}; node n; cursor c; uint8_t row[MAX_ROW]; int present = 0;
    if (pin) { e = pin_committed(&r, *pin, &n, &ns.xattrs, &ns.next_inode); if (!e) owner = n.e.inode; }
    else { e = selected_namespace(&r, view, &ns); if (!e) e = node_get(&r, &ns, owner, 1, &n); }
    key k = name_key(owner, after_name, after_length);
    if (!e) e = cursor_start(&c, &r, ns.xattrs, MAP_XATTR, ns.next_inode, UINT64_MAX, &k);
    if (!e) e = cursor_next(&c, row, &present);
    if (!e && present && after_length) { key actual = row_key(row, MAP_XATTR, 0); if (!keycmp(&actual, &k)) e = cursor_next(&c, row, &present); }
    if (!e) { present = present && get64(row) == owner; if (present) { sfs_xattr_entry entry = { .size = get64(row + 272), .name_length = get32(row + 8) }; memcpy(entry.name, row + 12, entry.name_length); *out = entry; } *found = present; }
    return touched_result(&r, e, result_out);
}

enum sfs_status sfs_image_next_xattr(sfs_image *h, sfs_view v, uint64_t generation, const uint8_t digest[32], sfs_inode id, const void *n, size_t len, sfs_xattr_entry *out, int *found, sfs_result *r) { return next_xattr_target(h, v, generation, digest, id, NULL, n, len, out, found, r); }
enum sfs_status sfs_image_pin_next_xattr(sfs_image *h, sfs_pin pin, uint64_t generation, const uint8_t digest[32], const void *n, size_t len, sfs_xattr_entry *out, int *found, sfs_result *r) { return next_xattr_target(h, 0, generation, digest, 0, &pin, n, len, out, found, r); }
static enum sfs_status index_height(reader *r, reference ref, unsigned map, uint64_t next, uint64_t eof, unsigned *height) {
    *height = 0; if (!ref.type) return SFS_OK; const uint8_t *b; enum sfs_status e = root_page(r, &ref, map, next, eof, &b); if (!e) *height = page_level(b) + 1; return e;
}
static enum sfs_status batch_cost(reader *r, uint64_t *cost) {
    *cost = 0; if (!r->h->batch) return SFS_OK;
    if (r->h->batch->detached) { *cost = pending_cells(&r->h->batch->extent); return SFS_OK; }
    unsigned hi; enum sfs_status e = index_height(r, r->h->staged.ns.inodes, MAP_INODE, r->h->staged.ns.next_inode, r->h->staged.ns.name_count, &hi); if (e) return e;
    *cost = pending_cells(&r->h->batch->extent) + hi + 1; return SFS_OK;
}
static enum sfs_status flush_batch(reader *r, int *wrote) {
    sfs_image *h = r->h; if (!h->batch) return SFS_OK; batch *b = h->batch;
    uint64_t liability; enum sfs_status e = batch_cost(r, &liability); if (e) return e; if (!reserve_cells(h, liability + 1)) return SFS_LIMIT;
    if (b->detached) {
        if (b->detached->incarnation != b->incarnation || pin_pending_state(b->detached) != PIN_DETACHED || b->detached->id != b->inode.e.inode) return SFS_CORRUPT;
        uint64_t remaining = liability; reference extent; b->extent.reader = r;
        if (remaining) *wrote = 1; r->phase = SFS_PHASE_RECORDS;
        e = seal_tree(&b->extent, &extent, &remaining); if (e) { if (e == SFS_IO) r->error = errno; return e; }
        if (remaining) return SFS_CORRUPT; b->inode.extent = extent; target_store(r, b->detached, &b->inode);
        arena_free(b->arena); free(b); h->batch = NULL; r->a.end = h->eof; r->phase = SFS_PHASE_READ; return SFS_OK;
    }
    arena *a = arena_new(h, b->number); if (!a) return SFS_NOMEM;
    tree inodes = make_tree(a, r, h->staged.ns.inodes, MAP_INODE, 0, h->staged.ns.next_inode, h->staged.ns.name_count); uint8_t row[MAX_ROW]; encode_node(row, &b->inode, r->a.minor);
    e = tree_put(&inodes, row); if (e) { arena_free(a); return e; }
    uint64_t remaining = pending_cells(&b->extent) + pending_cells(&inodes) + 1;
    if (remaining > liability) { arena_free(a); return SFS_CORRUPT; }
    reference extent; b->extent.reader = r; *wrote = 1; r->phase = SFS_PHASE_RECORDS;
    e = seal_tree(&b->extent, &extent, &remaining);
    if (!e) { b->inode.extent = extent; encode_node(row, &b->inode, r->a.minor); e = tree_put(&inodes, row); }
    namespace ns = h->staged.ns;
    if (!e) e = seal_tree(&inodes, &ns.inodes, &remaining);
    if (!e) e = write_namespace(h, &ns, &remaining);
    int error = e == SFS_IO ? errno : 0; arena_free(a); if (e) { r->error = error; return e; }
    if (remaining) return SFS_CORRUPT;
    h->staged.ns = ns; arena_free(b->arena); free(b); h->batch = NULL; r->a.end = h->eof; r->phase = SFS_PHASE_READ; return SFS_OK;
}
static enum sfs_status prepare_metadata(reader *r, unsigned inode_keys, unsigned name_keys, unsigned catalog_keys, int *late) {
    sfs_image *h = r->h; if (!h->batch) return SFS_OK;
    uint64_t total; enum sfs_status e = batch_cost(r, &total); if (e) return e; total += 2;
    unsigned keys[3] = { inode_keys, name_keys, catalog_keys }, maps[3] = { MAP_INODE, MAP_NAME, MAP_SNAPSHOT }; reference refs[3] = { h->staged.ns.inodes, h->staged.ns.names, h->staged.catalog };
    for (unsigned i = 0; i < 3; ++i) if (keys[i]) { unsigned height; e = index_height(r, refs[i], maps[i], h->staged.ns.next_inode, UINT64_MAX, &height); if (e) return e; if (height < MAX_HEIGHT) height++; total += keys[i] * (3u * height + 3u); }
    if (!reserve_cells(h, total)) return SFS_LIMIT; return flush_batch(r, late);
}
static enum sfs_status mutation_start(sfs_image *h, sfs_result *out) {
    enum sfs_status e = ready(h, 1, 1, out); if (e) return e;
    /* Remaining LIMIT sites in these mutators are arithmetic/tree bounds;
     * reserve_cells and explicit file bounds replace this reason at origin. */
    h->limit_reason = SFS_LIMIT_STRUCTURE;
    if (h->batch && (h->batch->arena != h->batch->extent.arena || h->batch->arena->epoch != h->epoch || h->batch->arena->batch != h->batch->number || !same_ref(&h->batch->arena->lineage, &h->staged.ns.ref) || h->batch->extent.owner != h->batch->inode.e.inode || h->batch->extent.map != MAP_EXTENT)) return mutation_failure(h, SFS_CORRUPT, SFS_PHASE_VALIDATE, 0, 0, out);
    if (h->batch && h->batch->detached && (h->batch->detached->incarnation != h->batch->incarnation || pin_pending_state(h->batch->detached) != PIN_DETACHED || h->batch->detached->id != h->batch->inode.e.inode)) return mutation_failure(h, SFS_CORRUPT, SFS_PHASE_VALIDATE, 0, 0, out);
    if (stable(h)) return mutation_failure(h, SFS_IO, SFS_PHASE_IDENTITY, errno, 0, out); return SFS_OK;
}
static enum sfs_status input_name(sfs_image *h, const void *name, size_t length, sfs_result *out) {
    if (length > SFS_NAME_MAX) return mutation_failure(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, 0, out);
    return valid_name(name, length) ? SFS_OK : result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
}
static enum sfs_status name_absent(reader *r, const namespace *ns, uint64_t parent, const void *name, size_t length, uint64_t except) {
    uint8_t row[MAX_ROW]; int found; key k = name_key(parent, name, length); enum sfs_status e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e;
    if (found && r->a.minor == 6) {
        node owner; e = node_get(r, ns, get64(row + 267), 1, &owner); if (e) return e == SFS_NOT_FOUND ? SFS_CORRUPT : e;
        e = name_member(r, ns, &owner, &k); if (e) return e;
    }
    return found && get64(row + 267) != except ? SFS_EXISTS : SFS_OK;
}
static enum sfs_status write_metadata_trees(reader *r, tree *inodes, tree *names, namespace *ns, int *late) {
    uint64_t count = pending_cells(inodes) + pending_cells(names) + 1; if (!reserve_cells(r->h, count + 1)) return SFS_LIMIT;
    *late = 1; r->phase = SFS_PHASE_RECORDS; enum sfs_status e = seal_tree(inodes, &ns->inodes, &count);
    if (!e) e = seal_tree(names, &ns->names, &count); if (!e) e = write_namespace(r->h, ns, &count); if (e == SFS_IO) r->error = errno; if (!e && count) e = SFS_CORRUPT;
    if (!e) r->h->staged.ns = *ns; return e;
}
enum sfs_status sfs_image_begin(sfs_image *h, sfs_result *out) {
    enum sfs_status e = ready(h, 1, 0, out); if (e) return e; if (h->transaction) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, out);
    h->limit_reason = SFS_LIMIT_STRUCTURE;
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, out);
    if (h->current.generation == UINT64_MAX || h->epoch == UINT64_MAX || !reserve_cells(h, 1)) return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, out);
    h->staged = h->live; h->transaction = 1; h->epoch++; return result(h, SFS_OK, SFS_PHASE_NONE, 0, out);
}
enum sfs_status sfs_image_abort(sfs_image *h, sfs_result *out) { enum sfs_status e = ready(h, 1, 1, out); if (e) return e; discard(h); return result(h, SFS_OK, SFS_PHASE_NONE, 0, out); }
#ifdef SFS_IMAGE_DIAGNOSTIC_TESTING
void sfs_image_diagnostic_counters(sfs_image *h, uint64_t epoch, uint64_t token) {
    if (h && !h->transaction) { h->epoch = epoch; h->token = token; }
}
void sfs_image_diagnostic_capacity(sfs_image *h, uint64_t capacity) { if (h) h->diagnostic_capacity = capacity; }
#endif
/* Probe the exact metadata edit before a pending batch can consume append space. */
static enum sfs_status probe_metadata(reader *r, unsigned operation, const node *before, const node *after) {
    if (!r->h->batch) return SFS_OK;
    namespace ns = r->h->staged.ns; if (operation == 1) { ns.next_inode++; ns.name_count++; }
    arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM;
    tree inodes = make_tree(a, r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count), names = make_tree(a, r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    uint8_t row[MAX_ROW]; enum sfs_status e = SFS_OK;
    if (before) { key nk = name_key(before->e.parent, before->e.name, before->e.name_length); e = tree_delete(&names, &nk); }
    if (!e && operation == 2) { key ik = number_key(before->e.inode); e = tree_delete(&inodes, &ik); }
    if (!e && after) { encode_node(row, after, r->a.minor); e = tree_put(&inodes, row); if (!e) { encode_name(row, after); e = tree_put(&names, row); } }
    arena_free(a); return e;
}
enum edit_operation { EDIT_ADD = 1, EDIT_REMOVE, EDIT_RENAME, EDIT_SET, EDIT_LINK };
typedef struct {
    node before[3], after[3]; unsigned count; int root_parent;
    namespace ns; attributes base_root; uint64_t base_count, base_next, base_names; key old_key, new_key;
} metadata_edit;
_Static_assert(sizeof(metadata_edit) <= 4096, "bounded heap metadata edit");
static enum sfs_status update_valid(const sfs_metadata_update *v, unsigned kind) {
    const unsigned times = SFS_META_BIRTH | SFS_META_ACCESS | SFS_META_MODIFICATION;
    if (!v || (v->fields & ~127u) || (v->now & ~(v->fields & times))) return SFS_INVALID;
    if ((v->fields & SFS_META_MODE) && !(kind ? valid_mode(v->mode, kind) : valid_mode(v->mode, SFS_FILE) || valid_mode(v->mode, SFS_DIRECTORY) || valid_mode(v->mode, SFS_SYMLINK))) return SFS_INVALID;
    if (((v->fields & SFS_META_BIRTH) && !(v->now & SFS_META_BIRTH) && !valid_time(v->birth)) || ((v->fields & SFS_META_ACCESS) && !(v->now & SFS_META_ACCESS) && !valid_time(v->access)) || ((v->fields & SFS_META_MODIFICATION) && !(v->now & SFS_META_MODIFICATION) && !valid_time(v->modification))) return SFS_INVALID;
    return (v->fields & SFS_META_FLAGS) && (v->flags & ~SFS_FLAGS_SUPPORTED) ? SFS_UNSUPPORTED : SFS_OK;
}
static void update_attributes(attributes *a, const sfs_metadata_update *v, sfs_timestamp t) {
    if (v->fields & SFS_META_MODE) a->mode = v->mode; if (v->fields & SFS_META_UID) a->uid = v->uid;
    if (v->fields & SFS_META_GID) a->gid = v->gid; if (v->fields & SFS_META_FLAGS) a->flags = v->flags;
    if (v->fields & SFS_META_BIRTH) a->birth = v->now & SFS_META_BIRTH ? t : v->birth;
    if (v->fields & SFS_META_ACCESS) a->access = v->now & SFS_META_ACCESS ? t : v->access;
    if (v->fields & SFS_META_MODIFICATION) a->modification = v->now & SFS_META_MODIFICATION ? t : v->modification;
    a->change = t;
}
static int same_attributes(const attributes *a, const attributes *b) { uint8_t x[88], y[88]; encode_attributes(x, a); encode_attributes(y, b); return !memcmp(x, y, sizeof(x)); }
static int same_logical_node(const node *a, const node *b) {
    return a->e.inode == b->e.inode && a->e.parent == b->e.parent && a->e.kind == b->e.kind && a->e.size == b->e.size && a->e.name_length == b->e.name_length && !memcmp(a->e.name, b->e.name, a->e.name_length) && same_attributes(&a->attributes, &b->attributes) && a->nlink == b->nlink && same_ref(&a->reverse, &b->reverse);
}
static enum sfs_status edit_parent(reader *r, metadata_edit *edit, sfs_inode id) {
    if (id == 1) { edit->root_parent = 1; return SFS_OK; }
    for (unsigned i = 0; i < edit->count; ++i) if (edit->before[i].e.inode == id) return i && edit->before[i].e.kind == SFS_DIRECTORY ? SFS_OK : SFS_CORRUPT;
    if (edit->count == 3) return SFS_CORRUPT;
    node *n = &edit->before[edit->count]; enum sfs_status e = node_get(r, &r->h->staged.ns, id, 1, n);
    if (e) return e == SFS_NOT_FOUND ? SFS_CORRUPT : e; if (n->e.kind != SFS_DIRECTORY) return SFS_CORRUPT;
    edit->after[edit->count] = *n; edit->count++; return SFS_OK;
}
static enum sfs_status apply_edit(tree *inodes, tree *names, const metadata_edit *edit, unsigned operation) {
    uint8_t row[MAX_ROW]; enum sfs_status e;
    /* Replace existing parents before a structural target insertion/deletion. */
    for (unsigned i = 1; i < edit->count; ++i) { encode_node(row, &edit->after[i], inodes->reader->a.minor); e = tree_put(inodes, row); if (e) return e; }
    const node *old = &edit->before[0], *next = &edit->after[0];
    if (operation == EDIT_REMOVE || operation == EDIT_RENAME) { key k = name_key(old->e.parent, old->e.name, old->e.name_length); e = tree_delete(names, &k); if (e) return e; }
    if (operation == EDIT_REMOVE) { key k = number_key(old->e.inode); return tree_delete(inodes, &k); }
    if (next->e.inode != 1) { encode_node(row, next, inodes->reader->a.minor); e = tree_put(inodes, row); if (e) return e; }
    if (operation == EDIT_ADD || operation == EDIT_RENAME) { encode_name(row, next); return tree_put(names, row); }
    return SFS_OK;
}
static enum sfs_status edit_bound(reader *r, const metadata_edit *edit, unsigned operation, uint64_t *out) {
    unsigned hi, hn; enum sfs_status e = index_height(r, r->h->staged.ns.inodes, MAP_INODE, r->h->staged.ns.next_inode, r->h->staged.ns.name_count, &hi); if (e) return e;
    if (operation == EDIT_SET) { *out = edit->after[0].e.inode == 1 ? 2 : hi + 2; return SFS_OK; }
    e = index_height(r, r->h->staged.ns.names, MAP_NAME, r->h->staged.ns.next_inode, UINT64_MAX, &hn); if (e) return e;
    unsigned ip = hi < MAX_HEIGHT ? hi + 1 : hi, np = hn < MAX_HEIGHT ? hn + 1 : hn;
    uint64_t parents = (edit->count - 1) * (uint64_t)hi;
    if (operation == EDIT_ADD) *out = 3u * ip + 3u + parents + 3u * np + 3u + 2;
    else if (operation == EDIT_REMOVE) *out = 3u * hi + 3u + parents + 3u * hn + 3u + 2;
    else *out = hi + parents + 2u * (3u * np + 3u) + 2;
    return SFS_OK;
}
/* One known leaf: future references remain private overlay bytes until sealing. */
static enum sfs_status prepare_link(tree *extent, node *n, const uint8_t *bytes, int probe, reference *raw) {
    reader *r = extent->reader; uint64_t at = 0, leaf_at = 0;
    if (!probe && (!aligned(r->h->eof, &at) || !add64(at, CELL, &leaf_at))) return SFS_LIMIT;
    *raw = (reference){ .type = RAW, .offset = at, .length = CELL };
    if (!probe) hash_cell(bytes, RAW, r->a.uuid, raw->digest, r->a.minor);
    uint8_t row[MAX_ROW] = {0}; encode_ref(row + 8, raw); put16(row + 64, (unsigned)n->e.size);
    enum sfs_status e = tree_put(extent, row); if (e) return e;
    overlay_page *p = owned_page(extent, (unsigned)extent->root);
    if (!p || page_level(p->bytes) || page_count(p->bytes) != 1 || pending_cells(extent) != 1) return SFS_CORRUPT;
    put64(p->bytes + 72, r->a.generation);
    n->extent = (reference){ .type = INDEX, .offset = leaf_at, .length = CELL };
    if (!probe) hash_cell(p->bytes, INDEX, r->a.uuid, n->extent.digest, r->a.minor);
    return SFS_OK;
}
static enum sfs_status xattr_prefix_count(reader *r, const namespace *ns, sfs_inode owner, uint64_t *count) {
    key prefix = name_key(owner, NULL, 0); cursor c; *count = 0;
    enum sfs_status e = cursor_start(&c, r, ns->xattrs, MAP_XATTR, ns->next_inode, UINT64_MAX, &prefix); if (e) return e;
    uint8_t row[MAX_ROW]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found && get64(row) == owner) if (!add64(*count, 1, count)) return SFS_LIMIT;
    return e;
}
/* Each deletion releases its overlay before traversing the new private root. */
static enum sfs_status remove_owner_xattrs(reader *r, namespace *ns, sfs_inode owner, uint64_t count, uint64_t bound, int *late) {
    key prefix = name_key(owner, NULL, 0);
    for (uint64_t i = 0; ; ++i) {
        cursor c; uint8_t row[MAX_ROW]; int found;
        enum sfs_status e = cursor_start(&c, r, ns->xattrs, MAP_XATTR, ns->next_inode, UINT64_MAX, &prefix); if (e) return e;
        e = cursor_next(&c, row, &found); if (e) return e;
        if (i == count) return found && get64(row) == owner ? SFS_CORRUPT : SFS_OK;
        if (!found || get64(row) != owner) return SFS_CORRUPT;
        arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM;
        tree attrs = make_tree(a, r, ns->xattrs, MAP_XATTR, 0, ns->next_inode, UINT64_MAX); key k = row_key(row, MAP_XATTR, 0);
        e = tree_delete(&attrs, &k); uint64_t remaining = pending_cells(&attrs);
        if (!e && remaining > bound) e = SFS_CORRUPT;
        if (!e) { if (remaining) *late = 1; r->phase = SFS_PHASE_RECORDS; e = seal_tree(&attrs, &ns->xattrs, &remaining); if (e == SFS_IO) r->error = errno; }
        arena_free(a); if (e) return e; if (remaining) return SFS_CORRUPT;
        r->a.end = r->h->eof; r->phase = SFS_PHASE_READ;
    }
}
enum name_operation { NAME_LINK, NAME_UNLINK, NAME_RENAME };
static void encode_named(uint8_t row[MAX_ROW], const key *k, uint64_t owner) {
    memset(row, 0, MAX_ROW); put64(row, from_big(k->bytes)); put32(row + 8, k->length - 8); memcpy(row + 12, k->bytes + 8, k->length - 8); put64(row + 267, owner);
}
static enum sfs_status reverse_pair(reader *r, const namespace *ns, const node *n, const key *removed, uint8_t survivor[MAX_ROW]) {
    const uint8_t *b; enum sfs_status e = root_page(r, &n->reverse, MAP_BACKREF, ns->next_inode, n->e.inode, &b); if (e) return e;
    if (n->nlink != 2 || page_level(b) || page_count(b) != 2) return SFS_CORRUPT;
    uint8_t rows[2][MAX_ROW] = {{0}}; memcpy(rows[0], row_at(b, MAP_BACKREF, 0, r->a.minor), 280); memcpy(rows[1], row_at(b, MAP_BACKREF, 1, r->a.minor), 280); int matched = 0;
    for (unsigned i = 0; i < 2; ++i) { key k = row_key(rows[i], MAP_BACKREF, 0); e = name_member(r, ns, n, &k); if (e) return e;
        if (removed && !keycmp(&k, removed)) matched++; else if (survivor) memcpy(survivor, rows[i], MAX_ROW);
    }
    return removed && matched != 1 ? SFS_CORRUPT : SFS_OK;
}
/* Each real name-tree edit owns one arena and publishes only a private root. */
static enum sfs_status seal_name_edit(reader *r, const namespace *ns, reference *root, unsigned map, uint64_t owner, const key *remove, const uint8_t *put, uint64_t bound, int *late) {
    arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM;
    tree t = make_tree(a, r, *root, map, owner, ns->next_inode, map == MAP_BACKREF ? owner : UINT64_MAX);
    enum sfs_status e = remove ? tree_delete(&t, remove) : tree_put(&t, put); uint64_t remaining = pending_cells(&t);
    if (!e && remaining > bound) e = SFS_CORRUPT;
    if (!e) { if (remaining) *late = 1; r->phase = SFS_PHASE_RECORDS; e = seal_tree(&t, root, &remaining); if (e == SFS_IO) r->error = errno; }
    arena_free(a); if (!e && remaining) e = SFS_CORRUPT; r->a.end = r->h->eof; if (!e) r->phase = SFS_PHASE_READ; return e;
}
static enum sfs_status name_mutation(sfs_image *h, unsigned operation, sfs_inode existing, sfs_inode old_parent, const void *old_name, size_t old_length, sfs_inode new_parent, const void *new_name, size_t new_length, sfs_result *result_out) {
    enum sfs_status e = ready(h, 1, 1, result_out); if (e) return e;
    if (operation != NAME_LINK) { e = input_name(h, old_name, old_length, result_out); if (e) return e; }
    if (operation != NAME_UNLINK) { e = input_name(h, new_name, new_length, result_out); if (e) return e; }
    if (h->current.minor != 6) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    e = mutation_start(h, result_out); if (e) return e;
    reader r = current_reader(h, 1); metadata_edit *edit = calloc(1, sizeof(*edit)); cursor *c = NULL; arena *a = NULL; int late = 0;
    if (!edit) { e = SFS_NOMEM; goto failed; } c = malloc(sizeof(*c)); if (!c) { e = SFS_NOMEM; goto failed; }
    edit->ns = h->staged.ns; edit->base_count = edit->ns.count; edit->base_names = edit->ns.name_count; edit->base_next = edit->ns.next_inode; edit->base_root = edit->ns.attributes; edit->count = 1;
    edit->old_key = name_key(old_parent, old_name, old_length); edit->new_key = name_key(new_parent, new_name, new_length);
    uint8_t row[MAX_ROW]; int found; node *before = &edit->before[0], *after = &edit->after[0];
    if (operation != NAME_LINK) {
        e = directory_check(&r, &h->staged.ns, old_parent); if (e) goto failed;
        e = cursor_start(c, &r, edit->ns.names, MAP_NAME, edit->ns.next_inode, UINT64_MAX, &edit->old_key); if (!e) e = cursor_next(c, row, &found); if (e) goto failed;
        key actual = found ? row_key(row, MAP_NAME, 0) : (key){0}; if (!found || keycmp(&actual, &edit->old_key)) { e = SFS_NOT_FOUND; goto failed; } existing = get64(row + 267);
    }
    e = node_get(&r, &h->staged.ns, existing, 1, before); if (e) { if (operation != NAME_LINK && e == SFS_NOT_FOUND) e = SFS_CORRUPT; goto failed; }
    if (operation == NAME_LINK && (existing == 1 || before->e.kind == SFS_DIRECTORY)) { e = SFS_INVALID; goto failed; }
    if (operation != NAME_LINK) { e = name_member(&r, &h->staged.ns, before, &edit->old_key); if (e) goto failed; }
    if (operation == NAME_RENAME && !keycmp(&edit->old_key, &edit->new_key)) goto success;
    if (h->batch && h->batch->inode.e.inode == existing) *before = h->batch->inode; *after = *before;
    if (operation == NAME_UNLINK && before->e.kind == SFS_DIRECTORY) {
        key prefix = name_key(existing, NULL, 0); e = cursor_start(c, &r, edit->ns.names, MAP_NAME, edit->ns.next_inode, UINT64_MAX, &prefix); if (!e) e = cursor_next(c, row, &found); if (e) goto failed;
        if (found && get64(row) == existing) { e = SFS_STATE; goto failed; }
    }
    if (operation != NAME_UNLINK) {
        e = directory_check(&r, &h->staged.ns, new_parent); if (!e) e = parent_chain(&r, &h->staged.ns, new_parent, before->e.kind == SFS_DIRECTORY ? existing : 0);
        if (!e) e = cursor_start(c, &r, edit->ns.names, MAP_NAME, edit->base_next, UINT64_MAX, &edit->new_key); if (!e) e = cursor_next(c, row, &found); if (e) goto failed;
        if (found) { key actual = row_key(row, MAP_NAME, 0); if (!keycmp(&actual, &edit->new_key)) {
            node destination; e = node_get(&r, &h->staged.ns, get64(row + 267), 1, &destination); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
            if (!e) e = name_member(&r, &h->staged.ns, &destination, &edit->new_key); if (!e) e = SFS_EXISTS; goto failed;
        } }

    }
    if (before->nlink == 2) { e = reverse_pair(&r, &h->staged.ns, before, operation == NAME_UNLINK ? &edit->old_key : NULL, row); if (e) goto failed; if (operation == NAME_UNLINK) entry_name(after, row); }
    if (operation == NAME_LINK) {
        if (edit->ns.name_count == SFS_ENTRY_MAX || !add64(edit->ns.name_count, 1, &edit->ns.name_count) || !add64(before->nlink, 1, &after->nlink)) { e = SFS_LIMIT; goto failed; }
    } else if (operation == NAME_UNLINK) {
        if (!edit->ns.name_count || !before->nlink || !edit->ns.count) { e = SFS_CORRUPT; goto failed; }
        edit->ns.name_count--; after->nlink--; if (!after->nlink) edit->ns.count--; if (after->nlink == 1) after->reverse = (reference){0};
    } else if (before->nlink == 1) { encode_named(row, &edit->new_key, existing); entry_name(after, row); }
    if (operation != NAME_LINK) { e = edit_parent(&r, edit, old_parent); if (e) goto failed; }
    if (operation != NAME_UNLINK) { e = edit_parent(&r, edit, new_parent); if (e) goto failed; }
    unsigned hi, hn, hb, ha; uint64_t old_cost, attrs = 0;
    e = index_height(&r, h->staged.ns.inodes, MAP_INODE, edit->base_next, edit->base_names, &hi);
    if (!e) e = index_height(&r, h->staged.ns.names, MAP_NAME, edit->base_next, UINT64_MAX, &hn);
    if (!e) e = index_height(&r, before->reverse, MAP_BACKREF, edit->base_next, existing, &hb);
    if (!e) e = index_height(&r, h->staged.ns.xattrs, MAP_XATTR, edit->base_next, UINT64_MAX, &ha);
    if (!e) e = batch_cost(&r, &old_cost); if (!e && !after->nlink) e = xattr_prefix_count(&r, &h->staged.ns, existing, &attrs); if (e) goto failed;
    uint64_t gd = operation == NAME_LINK ? 0 : 3u * hn + 3u, gi = operation == NAME_UNLINK ? 0 : 3u * (hn < MAX_HEIGHT ? hn + 1 : hn) + 3u;
    uint64_t rd = before->nlink > 1 && after->nlink > 1 && operation != NAME_LINK ? 3u * hb + 3u : 0;
    uint64_t ri = after->nlink > 1 && operation != NAME_UNLINK ? (before->nlink == 1 ? 1 : 3u * (hb < MAX_HEIGHT ? hb + 1 : hb) + 3u) : 0;
    uint64_t ib = after->nlink ? hi : 3u * hi + 3u, ab = 3u * ha + 3u, total = old_cost, start;
    uint64_t terms[] = { gd, gi, rd, ri, ib, (edit->count - 1) * (uint64_t)hi, 2 };
    for (unsigned i = 0; i < sizeof(terms) / sizeof(terms[0]); ++i) if (!add64(total, terms[i], &total)) { e = SFS_LIMIT; goto failed; }
    if (attrs > UINT64_MAX / ab || !add64(total, attrs * ab, &total) || !aligned(h->eof, &start)) { e = SFS_LIMIT; goto failed; }
    /* Probe exact global and reverse delete/insert sequences before any seal. */
    for (unsigned which = 0; which < 2; ++which) {
        if (which && !(rd || ri)) continue;
        a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
        tree t = make_tree(a, &r, which ? before->reverse : edit->ns.names, which ? MAP_BACKREF : MAP_NAME, which ? existing : 0, edit->base_next, which ? existing : UINT64_MAX);
        if (which && before->nlink == 1) { encode_name(row, before); e = tree_put(&t, row); }
        if (!e && (which ? rd : gd)) e = tree_delete(&t, &edit->old_key);
        if (!e && (which ? ri : gi)) { encode_named(row, &edit->new_key, existing); e = tree_put(&t, row); }
        if (!e && pending_cells(&t) > (which ? rd + ri : gd + gi)) e = SFS_CORRUPT;
        arena_free(a); a = NULL; if (e) goto failed;
    }
    a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
    uint64_t context_names = edit->base_names > edit->ns.name_count ? edit->base_names : edit->ns.name_count;
    tree inodes = make_tree(a, &r, edit->ns.inodes, MAP_INODE, 0, edit->base_next, context_names);
    for (unsigned i = 1; i < edit->count && !e; ++i) { encode_node(row, &edit->after[i], r.a.minor); e = tree_put(&inodes, row); }
    if (!e) { if (!after->nlink) { key k = number_key(existing); e = tree_delete(&inodes, &k); } else { encode_node(row, before, r.a.minor); e = tree_put(&inodes, row); } }
    if (!e && pending_cells(&inodes) > ib + (edit->count - 1) * (uint64_t)hi) e = SFS_CORRUPT;
    arena_free(a); a = NULL; if (e) goto failed;
    sfs_timestamp t; int clock_error; e = clock_sample(&t, &clock_error); if (e) { free(c); free(edit); return result(h, e, SFS_PHASE_NONE, clock_error, result_out); }
    if (!reserve_cells(h, total)) { e = SFS_LIMIT; goto failed; }
    after->attributes.change = t;
    for (unsigned i = 1; i < edit->count; ++i) edit->after[i].attributes.modification = edit->after[i].attributes.change = t;
    if (edit->root_parent) edit->ns.attributes.modification = edit->ns.attributes.change = t;
    e = flush_batch(&r, &late); if (e) goto failed;
    if ((old_cost && (h->eof < start || (h->eof - start) / CELL > old_cost)) || h->staged.ns.count != edit->base_count || h->staged.ns.name_count != edit->base_names || h->staged.ns.next_inode != edit->base_next || !same_attributes(&h->staged.ns.attributes, &edit->base_root) || !same_ref(&h->staged.ns.xattrs, &edit->ns.xattrs)) { e = SFS_CORRUPT; goto failed; }
    for (unsigned i = 0; i < edit->count; ++i) { node n; e = node_get(&r, &h->staged.ns, edit->before[i].e.inode, 1, &n); if (e) goto failed; if (!same_logical_node(&n, &edit->before[i])) { e = SFS_CORRUPT; goto failed; } edit->after[i].extent = n.extent; }
    edit->ns.inodes = h->staged.ns.inodes; edit->ns.names = h->staged.ns.names; edit->ns.ref = h->staged.ns.ref;
    if (gd) { e = seal_name_edit(&r, &edit->ns, &edit->ns.names, MAP_NAME, 0, &edit->old_key, NULL, gd, &late); if (e) goto failed; }
    if (gi) { encode_named(row, &edit->new_key, existing); e = seal_name_edit(&r, &edit->ns, &edit->ns.names, MAP_NAME, 0, NULL, row, gi, &late); if (e) goto failed; }
    if (ri && before->nlink == 1) {
        a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
        tree reverse = make_tree(a, &r, (reference){0}, MAP_BACKREF, existing, edit->base_next, existing);
        encode_name(row, before); e = tree_put(&reverse, row); if (!e) { encode_named(row, &edit->new_key, existing); e = tree_put(&reverse, row); }
        uint64_t remaining = pending_cells(&reverse); if (!e && remaining != 1) e = SFS_CORRUPT;
        if (!e) { late = 1; r.phase = SFS_PHASE_RECORDS; e = seal_tree(&reverse, &after->reverse, &remaining); if (e == SFS_IO) r.error = errno; }
        arena_free(a); a = NULL; if (e) goto failed; if (remaining) { e = SFS_CORRUPT; goto failed; } r.a.end = h->eof; r.phase = SFS_PHASE_READ;
    } else {
        if (rd) { e = seal_name_edit(&r, &edit->ns, &after->reverse, MAP_BACKREF, existing, &edit->old_key, NULL, rd, &late); if (e) goto failed; }
        if (ri) { encode_named(row, &edit->new_key, existing); e = seal_name_edit(&r, &edit->ns, &after->reverse, MAP_BACKREF, existing, NULL, row, ri, &late); if (e) goto failed; }
    }
    if (after->nlink) {
        if (after->nlink > 1) { e = reverse_first(&r, &edit->ns, after, row); if (e) goto failed; entry_name(after, row); if (after->nlink == 2) { e = reverse_pair(&r, &edit->ns, after, NULL, NULL); if (e) goto failed; } }
        key representative = name_key(after->e.parent, after->e.name, after->e.name_length); e = name_member(&r, &edit->ns, after, &representative); if (e) goto failed;
    } else {
        pin_slot *pin = pin_find(h, existing);
        if (pin) {
            if (pin_pending_state(pin) != PIN_LINKED) { e = SFS_CORRUPT; goto failed; }
            pin_touch(h, pin); pin->pending = PIN_DETACHED;
            pin->staged = (pin_descriptor){ .inode = *after, .xattrs = edit->ns.xattrs,
                .next_inode = edit->base_next, .end = h->eof, .generation = r.a.generation };
            /* The name removal has sealed; any subsequent failure discards Q. */
            late = 1;
        }
        if (attrs) { e = remove_owner_xattrs(&r, &edit->ns, existing, attrs, ab, &late); if (e) goto failed; }
    }
    /* Parents precede final owner deletion; each replacement has its own arena. */
    for (unsigned phase = 0; phase < edit->count; ++phase) {
        unsigned i = phase + 1 == edit->count ? 0 : phase + 1;
        a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
        inodes = make_tree(a, &r, edit->ns.inodes, MAP_INODE, 0, edit->base_next, context_names);
        if (!i && !after->nlink) { key k = number_key(existing); e = tree_delete(&inodes, &k); }
        else { encode_node(row, &edit->after[i], r.a.minor); e = tree_put(&inodes, row); }
        uint64_t remaining = pending_cells(&inodes); if (!e && remaining > (i ? hi : ib)) e = SFS_CORRUPT;
        if (!e) { if (remaining) late = 1; r.phase = SFS_PHASE_RECORDS; e = seal_tree(&inodes, &edit->ns.inodes, &remaining); if (e == SFS_IO) r.error = errno; }
        arena_free(a); a = NULL; if (e) goto failed; if (remaining) { e = SFS_CORRUPT; goto failed; } r.a.end = h->eof; r.phase = SFS_PHASE_READ;
    }
    uint64_t remaining = 1; late = 1; r.phase = SFS_PHASE_RECORDS; e = write_namespace(h, &edit->ns, &remaining); if (e == SFS_IO) r.error = errno; if (e) goto failed;
    if (remaining || h->eof < start || (h->eof - start) / CELL >= total) { e = SFS_CORRUPT; goto failed; } h->staged.ns = edit->ns;
success:
    free(c); free(edit); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed:
    arena_free(a); free(c); free(edit);
    if (!late && (e == SFS_INVALID || e == SFS_NOT_FOUND || e == SFS_EXISTS || e == SFS_STATE)) return result(h, e, SFS_PHASE_NONE, 0, result_out);
    return mutation_failure(h, e, r.phase, r.error, late, result_out);
}
enum sfs_status sfs_image_link(sfs_image *h, sfs_inode existing, sfs_inode parent, const void *name, size_t length, sfs_result *out) { return name_mutation(h, NAME_LINK, existing, 0, NULL, 0, parent, name, length, out); }
enum sfs_status sfs_image_unlink(sfs_image *h, sfs_inode parent, const void *name, size_t length, sfs_result *out) { return name_mutation(h, NAME_UNLINK, 0, parent, name, length, 0, NULL, 0, out); }
enum sfs_status sfs_image_rename_entry(sfs_image *h, sfs_inode old_parent, const void *old_name, size_t old_length, sfs_inode new_parent, const void *new_name, size_t new_length, sfs_result *out) { return name_mutation(h, NAME_RENAME, 0, old_parent, old_name, old_length, new_parent, new_name, new_length, out); }
static enum sfs_status staged_name(reader *r, sfs_inode parent, const void *name, size_t length, node *out) {
    namespace *ns = &r->h->staged.ns; enum sfs_status e = directory_check(r, ns, parent); if (e) return e;
    key k = name_key(parent, name, length); uint8_t row[MAX_ROW]; int found;
    e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e;
    if (!found) return SFS_NOT_FOUND;
    e = node_get(r, ns, get64(row + 267), 1, out); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
    return e ? e : name_member(r, ns, out, &k);
}
enum sfs_status sfs_image_unlink_expected(sfs_image *h, sfs_inode parent, const void *name, size_t length, sfs_inode expected, sfs_result *out) {
    enum sfs_status e = pin_gate(h, 1, 1, out); if (e) return e;
    if (!expected || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    e = mutation_start(h, out); if (e) return e; reader r = current_reader(h, 1); node n;
    e = staged_name(&r, parent, name, length, &n);
    if (!e && n.e.inode != expected) e = SFS_STATE;
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    return name_mutation(h, NAME_UNLINK, 0, parent, name, length, 0, NULL, 0, out);
}
enum sfs_status sfs_image_rename_replace(sfs_image *h, sfs_inode old_parent, const void *old_name, size_t old_length, sfs_inode expected_source, sfs_inode new_parent, const void *new_name, size_t new_length, sfs_inode expected_destination, sfs_result *out) {
    enum sfs_status e = pin_gate(h, 1, 1, out); if (e) return e;
    if (!expected_source || !valid_name(old_name, old_length) || !valid_name(new_name, new_length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
    e = mutation_start(h, out); if (e) return e; reader r = current_reader(h, 1); node source, destination;
    e = staged_name(&r, old_parent, old_name, old_length, &source);
    if (!e && source.e.inode != expected_source) e = SFS_STATE;
    if (!e) e = directory_check(&r, &h->staged.ns, new_parent);
    if (!e) e = parent_chain(&r, &h->staged.ns, new_parent, source.e.kind == SFS_DIRECTORY ? source.e.inode : 0);
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    e = staged_name(&r, new_parent, new_name, new_length, &destination);
    if (e == SFS_NOT_FOUND) { if (expected_destination) e = SFS_STATE; else e = SFS_OK; }
    else if (!e && destination.e.inode != expected_destination) e = SFS_STATE;
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    if (expected_destination && expected_source == expected_destination) { result(h, SFS_OK, SFS_PHASE_NONE, 0, out); if (out) out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK; }
    if (expected_destination) {
        if ((source.e.kind == SFS_DIRECTORY) != (destination.e.kind == SFS_DIRECTORY) || destination.e.inode == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
        if (destination.e.kind == SFS_DIRECTORY) {
            cursor c; uint8_t row[MAX_ROW]; int found; key k = name_key(destination.e.inode, NULL, 0);
            e = cursor_start(&c, &r, h->staged.ns.names, MAP_NAME, h->staged.ns.next_inode, UINT64_MAX, &k);
            if (!e) e = cursor_next(&c, row, &found);
            if (!e && found && get64(row) == destination.e.inode) e = SFS_STATE;
            if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
        }
        e = name_mutation(h, NAME_UNLINK, 0, new_parent, new_name, new_length, 0, NULL, 0, out); if (e) return e;
    }
    sfs_result receipt; e = name_mutation(h, NAME_RENAME, 0, old_parent, old_name, old_length, new_parent, new_name, new_length, &receipt);
    if (e && expected_destination) discard(h);
    result(h, e, receipt.phase, receipt.system_errno, out); if (!e && out) out->coverage = SFS_COVERAGE_TOUCHED; return e;
}

static enum sfs_status metadata_mutation(sfs_image *h, unsigned operation, sfs_inode id, sfs_inode parent, const void *name, size_t length, enum sfs_kind kind, const sfs_metadata_initial *initial, int supplied, const sfs_metadata_update *update, const void *target, size_t target_length, sfs_inode *out, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    int link = operation == EDIT_LINK; if (link) operation = EDIT_ADD;
    if (operation == EDIT_ADD) { if (!out || (link ? kind != SFS_SYMLINK : kind != SFS_FILE && kind != SFS_DIRECTORY)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); if (supplied) { e = initial_valid(initial, kind); if (e) return result(h, e, SFS_PHASE_NONE, 0, result_out); } }
    if (link && (!target || !target_length || target_length > SFS_SYMLINK_MAX || memchr(target, 0, target_length))) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (operation == EDIT_ADD || operation == EDIT_RENAME) { e = input_name(h, name, length, result_out); if (e) return e; }
    if ((operation == EDIT_REMOVE || operation == EDIT_RENAME) && id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (operation == EDIT_SET) { e = update_valid(update, 0); if (e) return result(h, e, SFS_PHASE_NONE, 0, result_out); }
    if (link ? !symlink_capable(h->current.minor) : !metadata_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    reader r = current_reader(h, 1); metadata_edit edit = {0}; edit.ns = h->staged.ns; edit.base_root = edit.ns.attributes; edit.base_count = edit.ns.count; edit.base_next = edit.ns.next_inode; edit.base_names = edit.ns.name_count; edit.count = 1;
    arena *a = NULL; uint8_t *link_bytes = NULL; reference link_raw = {0}; int late = 0; uint64_t xattr_count = 0, xattr_bound = 0, remove_total = 0, remove_start = 0; node *old = &edit.before[0], *next = &edit.after[0];
    if (operation != EDIT_ADD) { if (h->batch && !h->batch->detached && h->batch->inode.e.inode == id) *old = h->batch->inode; else { e = node_get(&r, &h->staged.ns, id, 1, old); if (e) goto failed; } *next = *old; }
    if (operation == EDIT_ADD || operation == EDIT_RENAME) { e = directory_check(&r, &h->staged.ns, parent); if (!e) e = parent_chain(&r, &h->staged.ns, parent, operation == EDIT_RENAME ? id : 0); if (!e) e = name_absent(&r, &h->staged.ns, parent, name, length, operation == EDIT_RENAME ? id : 0); if (e) goto failed; }
    if (operation == EDIT_REMOVE && old->e.kind == SFS_DIRECTORY) { key prefix = name_key(id, NULL, 0); cursor c; e = cursor_start(&c, &r, edit.ns.names, MAP_NAME, edit.ns.next_inode, UINT64_MAX, &prefix); uint8_t row[MAX_ROW]; int found; if (!e) { e = cursor_next(&c, row, &found); if (!e && found && get64(row) == id) e = SFS_STATE; } if (e) goto failed; }
    if (operation == EDIT_RENAME && old->e.parent == parent && old->e.name_length == length && !memcmp(old->e.name, name, length)) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out);
    if (operation == EDIT_SET) { e = update_valid(update, old->e.kind); if (e) return result(h, e, SFS_PHASE_NONE, 0, result_out); if (!update->fields) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); }
    if (operation == EDIT_ADD) { if (edit.ns.name_count >= SFS_ENTRY_MAX || edit.ns.next_inode == UINT64_MAX) { e = SFS_LIMIT; goto failed; } next->nlink = 1; next->e.inode = edit.ns.next_inode++; next->e.kind = kind; if (link) next->e.size = target_length; edit.ns.count++; edit.ns.name_count++; }
    if (operation == EDIT_REMOVE) { if (!edit.ns.count) { e = SFS_CORRUPT; goto failed; } edit.ns.count--; edit.ns.name_count--; }
    if (operation == EDIT_ADD || operation == EDIT_RENAME) { next->e.parent = parent; next->e.name_length = length; memset(next->e.name, 0, sizeof(next->e.name)); memcpy(next->e.name, name, length); e = edit_parent(&r, &edit, parent); if (e) goto failed; }
    if (operation == EDIT_REMOVE || operation == EDIT_RENAME) { e = edit_parent(&r, &edit, old->e.parent); if (e) goto failed; }
    if (operation == EDIT_REMOVE && xattr_capable(h->current.minor)) {
        unsigned ha; e = xattr_prefix_count(&r, &edit.ns, id, &xattr_count); if (!e) e = index_height(&r, edit.ns.xattrs, MAP_XATTR, edit.ns.next_inode, UINT64_MAX, &ha); if (e) goto failed;
        xattr_bound = 3u * ha + 3u;
    }
    if (link) { link_bytes = calloc(1, CELL); if (!link_bytes) { e = SFS_NOMEM; goto failed; } memcpy(link_bytes, target, target_length); }
    sfs_timestamp t; int clock_error; e = clock_sample(&t, &clock_error); if (e) { free(link_bytes); return result(h, e, SFS_PHASE_NONE, clock_error, result_out); }
    if (operation == EDIT_ADD) { sfs_metadata_initial defaults = {0}; if (!supplied) { defaults.mode = kind == SFS_DIRECTORY ? 0040700u : 0100600u; defaults.uid = (uint32_t)geteuid(); defaults.gid = (uint32_t)getegid(); initial = &defaults; } next->attributes = initial_attributes(initial, t); if (link) next->attributes.extents = 1; }
    else if (operation == EDIT_RENAME) next->attributes.change = t;
    else if (operation == EDIT_SET) { update_attributes(&next->attributes, update, t); if (id == 1) edit.ns.attributes = next->attributes; }
    for (unsigned i = 1; i < edit.count; ++i) edit.after[i].attributes.modification = edit.after[i].attributes.change = t;
    if (edit.root_parent) edit.ns.attributes.modification = edit.ns.attributes.change = t;
    a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
    tree inodes = make_tree(a, &r, edit.ns.inodes, MAP_INODE, 0, edit.ns.next_inode, edit.ns.name_count), names = make_tree(a, &r, edit.ns.names, MAP_NAME, 0, edit.ns.next_inode, UINT64_MAX);
    tree extent = make_tree(a, &r, (reference){0}, MAP_EXTENT, next->e.inode, UINT64_MAX, next->e.size);
    if (link) { e = prepare_link(&extent, next, link_bytes, !!h->batch, &link_raw); if (e) goto failed; }
    e = apply_edit(&inodes, &names, &edit, operation); if (e) goto failed;
    if (h->batch || xattr_count) {
        uint64_t old_cost, bound, total; e = batch_cost(&r, &old_cost); if (!e) e = edit_bound(&r, &edit, operation, &bound); if (e) goto failed;
        if (link) bound += 2;
        if (!add64(old_cost, bound, &total) || (xattr_count && xattr_count > UINT64_MAX / xattr_bound) || !add64(total, xattr_count * xattr_bound, &total) || !reserve_cells(h, total)) { e = SFS_LIMIT; goto failed; }
        if (xattr_count) { remove_total = total; if (!aligned(h->eof, &remove_start)) { e = SFS_LIMIT; goto failed; } }
        arena_free(a); a = NULL; e = flush_batch(&r, &late); if (e) goto failed;
        if (h->staged.ns.count != edit.base_count || h->staged.ns.name_count != edit.base_names || h->staged.ns.next_inode != edit.base_next || !same_attributes(&h->staged.ns.attributes, &edit.base_root)) { e = SFS_CORRUPT; goto failed; }
        for (unsigned i = 0; i < edit.count; ++i) if (edit.before[i].e.inode) { node n; e = node_get(&r, &h->staged.ns, edit.before[i].e.inode, 1, &n); if (e) goto failed; if (!same_logical_node(&n, &edit.before[i])) { e = SFS_CORRUPT; goto failed; } edit.after[i].extent = n.extent; }
        if (!same_ref(&edit.ns.xattrs, &h->staged.ns.xattrs)) { e = SFS_CORRUPT; goto failed; }
        edit.ns.inodes = h->staged.ns.inodes; edit.ns.names = h->staged.ns.names; edit.ns.ref = h->staged.ns.ref;
        if (xattr_count) { e = remove_owner_xattrs(&r, &edit.ns, id, xattr_count, xattr_bound, &late); if (e) goto failed; }
        a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
        inodes = make_tree(a, &r, edit.ns.inodes, MAP_INODE, 0, edit.ns.next_inode, edit.ns.name_count); names = make_tree(a, &r, edit.ns.names, MAP_NAME, 0, edit.ns.next_inode, UINT64_MAX);
        if (link) { extent = make_tree(a, &r, (reference){0}, MAP_EXTENT, next->e.inode, UINT64_MAX, next->e.size); e = prepare_link(&extent, next, link_bytes, 0, &link_raw); if (e) goto failed; }
        e = apply_edit(&inodes, &names, &edit, operation); if (e) goto failed;
        if (pending_cells(&inodes) + pending_cells(&names) + 2 + (link ? 2u : 0u) > bound) { e = SFS_CORRUPT; goto failed; }
    }
    if (link) {
        if (pending_cells(&extent) != 1) { e = SFS_CORRUPT; goto failed; }
        if (!reserve_cells(h, pending_cells(&inodes) + pending_cells(&names) + 4)) { e = SFS_LIMIT; goto failed; }
        uint64_t remaining = 1; reference appended; late = 1; r.phase = SFS_PHASE_RECORDS;
        e = append_prepared(h, RAW, link_bytes, &appended, &remaining, &link_raw);
        if (!e && (remaining || !same_ref(&appended, &link_raw))) e = SFS_CORRUPT;
        if (!e) { remaining = 1; e = seal_tree(&extent, &appended, &remaining); if (!e && (remaining || !same_ref(&appended, &next->extent))) e = SFS_CORRUPT; }
        if (e) { if (e == SFS_IO) r.error = errno; goto failed; }
    }
    e = write_metadata_trees(&r, &inodes, &names, &edit.ns, &late); if (e) goto failed;
    if (xattr_count && (h->eof < remove_start || (h->eof - remove_start) / CELL >= remove_total)) { e = SFS_CORRUPT; goto failed; }
    free(link_bytes); arena_free(a); if (operation == EDIT_ADD) *out = next->e.inode;
    result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed:
    free(link_bytes); arena_free(a); return mutation_failure(h, e, r.phase, r.error, late, result_out);
}
enum sfs_status sfs_image_add_metadata(sfs_image *h, sfs_inode parent, const void *name, size_t length, enum sfs_kind kind, const sfs_metadata_initial *initial, sfs_inode *out, sfs_result *r) { return metadata_mutation(h, EDIT_ADD, 0, parent, name, length, kind, initial, 1, NULL, NULL, 0, out, r); }
enum sfs_status sfs_image_symlink_metadata(sfs_image *h, sfs_inode parent, const void *name, size_t length, const void *target, size_t target_length, const sfs_metadata_initial *initial, sfs_inode *out, sfs_result *r) { return metadata_mutation(h, EDIT_LINK, 0, parent, name, length, SFS_SYMLINK, initial, 1, NULL, target, target_length, out, r); }
enum sfs_status sfs_image_set_metadata(sfs_image *h, sfs_inode id, const sfs_metadata_update *update, sfs_result *r) { return metadata_mutation(h, EDIT_SET, id, 0, NULL, 0, 0, NULL, 0, update, NULL, 0, NULL, r); }
enum sfs_status sfs_image_add(sfs_image *h, sfs_inode parent, const void *name, size_t length, enum sfs_kind kind, sfs_inode *out, sfs_result *result_out) {
    if (h && metadata_capable(h->current.minor)) return metadata_mutation(h, EDIT_ADD, 0, parent, name, length, kind, NULL, 0, NULL, NULL, 0, out, result_out);
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    if (!out || (kind != SFS_FILE && kind != SFS_DIRECTORY)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    e = input_name(h, name, length, result_out); if (e) return e;
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; int late = 0;
    e = directory_check(&r, &ns, parent); if (!e) e = parent_chain(&r, &ns, parent, 0); if (!e) e = name_absent(&r, &ns, parent, name, length, 0);
    if (!e && (ns.count >= SFS_ENTRY_MAX || ns.next_inode == UINT64_MAX)) e = SFS_LIMIT;
    if (!e && h->batch) { node proposed = {0}; proposed.e.inode = ns.next_inode; proposed.e.parent = parent; proposed.e.kind = kind; proposed.e.name_length = length; memcpy(proposed.e.name, name, length); e = probe_metadata(&r, 1, NULL, &proposed); }
    if (!e) e = prepare_metadata(&r, 1, 1, 0, &late);
    if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; node n = { .nlink = 1 }; n.e.inode = ns.next_inode++; n.e.parent = parent; n.e.kind = kind; n.e.name_length = length; memcpy(n.e.name, name, length); ns.count++; ns.name_count++;
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    uint8_t row[MAX_ROW]; encode_node(row, &n, h->current.minor); e = tree_put(&inodes, row); if (!e) { encode_name(row, &n); e = tree_put(&names, row); }
    if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late); int error = r.error; arena_free(a);
    if (e) return mutation_failure(h, e, r.phase, error, late, result_out); *out = n.e.inode; result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_remove(sfs_image *h, sfs_inode id, sfs_result *result_out) {
    if (h && h->current.minor == 6) {
        enum sfs_status e = mutation_start(h, result_out); if (e) return e; if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
        reader r = current_reader(h, 1); node n; e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, 0, result_out);
        if (n.nlink > 1) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
        return sfs_image_unlink(h, n.e.parent, n.e.name, n.e.name_length, result_out);
    }
    if (h && metadata_capable(h->current.minor)) return metadata_mutation(h, EDIT_REMOVE, id, 0, NULL, 0, 0, NULL, 0, NULL, NULL, 0, NULL, result_out);
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; node n; int late = 0; e = node_get(&r, &ns, id, 1, &n);
    if (!e && n.e.kind == SFS_DIRECTORY) { key prefix = name_key(id, NULL, 0); cursor c; e = cursor_start(&c, &r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &prefix); uint8_t row[MAX_ROW]; int found; if (!e) { e = cursor_next(&c, row, &found); if (!e && found && get64(row) == id) e = SFS_STATE; } }
    if (!e) e = probe_metadata(&r, 2, &n, NULL);
    if (!e) e = prepare_metadata(&r, 1, 1, 0, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; e = node_get(&r, &ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out); if (!ns.count) return mutation_failure(h, SFS_CORRUPT, r.phase, 0, late, result_out); ns.count--; ns.name_count--;
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    key ik = number_key(id), nk = name_key(n.e.parent, n.e.name, n.e.name_length); e = tree_delete(&inodes, &ik); if (!e) e = tree_delete(&names, &nk); if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late);
    int error = r.error; arena_free(a); if (e) return mutation_failure(h, e, r.phase, error, late, result_out); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_rename(sfs_image *h, sfs_inode id, sfs_inode parent, const void *name, size_t length, sfs_result *result_out) {
    if (h && h->current.minor == 6) {
        enum sfs_status e = mutation_start(h, result_out); if (e) return e; e = input_name(h, name, length, result_out); if (e) return e;
        if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
        reader r = current_reader(h, 1); node n; e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, 0, result_out);
        if (n.nlink > 1) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
        return sfs_image_rename_entry(h, n.e.parent, n.e.name, n.e.name_length, parent, name, length, result_out);
    }
    if (h && metadata_capable(h->current.minor)) return metadata_mutation(h, EDIT_RENAME, id, parent, name, length, 0, NULL, 0, NULL, NULL, 0, NULL, result_out);
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; e = input_name(h, name, length, result_out); if (e) return e; if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; node n; int late = 0;
    e = node_get(&r, &ns, id, 1, &n); if (!e) e = directory_check(&r, &ns, parent); if (!e) e = parent_chain(&r, &ns, parent, id); if (!e) e = name_absent(&r, &ns, parent, name, length, id);
    if (!e && n.e.parent == parent && n.e.name_length == length && !memcmp(n.e.name, name, length)) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out);
    if (!e && h->batch) { node proposed = n; proposed.e.parent = parent; proposed.e.name_length = length; memset(proposed.e.name, 0, sizeof(proposed.e.name)); memcpy(proposed.e.name, name, length); e = probe_metadata(&r, 3, &n, &proposed); }
    if (!e) e = prepare_metadata(&r, 1, 2, 0, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; e = node_get(&r, &ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    key old = name_key(n.e.parent, n.e.name, n.e.name_length); n.e.parent = parent; n.e.name_length = length; memset(n.e.name, 0, sizeof(n.e.name)); memcpy(n.e.name, name, length);
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX); uint8_t row[MAX_ROW];
    e = tree_delete(&names, &old); if (!e) { encode_name(row, &n); e = tree_put(&names, row); } if (!e) { encode_node(row, &n, h->current.minor); e = tree_put(&inodes, row); } if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late);
    int error = r.error; arena_free(a); if (e) return mutation_failure(h, e, r.phase, error, late, result_out); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_snapshot(sfs_image *h, const void *name, size_t length, sfs_view *out, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); e = input_name(h, name, length, result_out); if (e) return e;
    for (unsigned i = 0; i < h->staged.count; ++i) if (h->staged.snapshots[i].length == length && !memcmp(h->staged.snapshots[i].name, name, length)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, result_out);
    if (h->staged.count == SFS_SNAPSHOT_MAX || (h->staged.count && h->staged.snapshots[h->staged.count - 1].view == SFS_SNAPSHOT_MAX)) return mutation_failure(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, 0, result_out);
    reader r = current_reader(h, 1); int late = 0;
    snapshot snap = { .view = h->staged.count ? h->staged.snapshots[h->staged.count - 1].view + 1 : 1, .length = (uint32_t)length, .ns = h->live.ns.ref }; memcpy(snap.name, name, length);
    uint8_t row[MAX_ROW] = {0}; put32(row, snap.view); encode_ref(row + 8, &snap.ns); put32(row + 64, snap.length); memcpy(row + 68, snap.name, length);
    if (h->batch) { arena *probe = arena_new(h, 0); if (!probe) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, 0, result_out); tree catalog = make_tree(probe, &r, h->staged.catalog, MAP_SNAPSHOT, 0, UINT64_MAX, UINT64_MAX); e = tree_put(&catalog, row); arena_free(probe); if (e) return mutation_failure(h, e, r.phase, r.error, 0, result_out); }
    e = prepare_metadata(&r, 0, 0, 1, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree catalog = make_tree(a, &r, h->staged.catalog, MAP_SNAPSHOT, 0, UINT64_MAX, UINT64_MAX); e = tree_put(&catalog, row);
    uint64_t remaining = pending_cells(&catalog); if (!e && !reserve_cells(h, remaining + 1)) e = SFS_LIMIT;
    reference root; if (!e) { late = 1; r.phase = SFS_PHASE_RECORDS; e = seal_tree(&catalog, &root, &remaining); if (e == SFS_IO) r.error = errno; }
    int error = r.error; arena_free(a); if (e) return mutation_failure(h, e, r.phase, error, late, result_out);
    if (remaining) return mutation_failure(h, SFS_CORRUPT, r.phase, 0, late, result_out);
    h->staged.catalog = root; h->staged.snapshots[h->staged.count++] = snap; *out = snap.view; result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}

static void release_clean(tree *t, unsigned id) {
    overlay_page *p = t->arena->pages[id]; if (page_level(p->bytes)) for (unsigned i = 0; i < page_count(p->bytes); ++i) if (p->children[i] != NO_CHILD) release_clean(t, p->children[i]); free(p); t->arena->pages[id] = NULL;
}
static enum sfs_status prune_clean(tree *t, unsigned id) {
    overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT;
    if (page_level(p->bytes)) for (unsigned i = 0; i < page_count(p->bytes); ++i) if (p->children[i] != NO_CHILD) {
        unsigned child = p->children[i]; overlay_page *q = owned_page(t, child); if (!q) return SFS_CORRUPT;
        if (!q->dirty) { if (tree_dirty(t, child)) return SFS_CORRUPT; put_child_ref(p->bytes + PAGE_HEAD + i * stride(t->map, page_level(p->bytes), t->reader->a.minor), t->map, &q->source); release_clean(t, child); p->children[i] = NO_CHILD; }
        else { enum sfs_status e = prune_clean(t, child); if (e) return e; }
    }
    return SFS_OK;
}
static enum sfs_status tree_get(tree *t, const key *k, uint8_t row[MAX_ROW], int *found) {
    unsigned path[MAX_HEIGHT], depth, at; enum sfs_status e = tree_search(t, k, path, &depth, &at, found); if (e || !*found) return e;
    overlay_page *p = owned_page(t, path[depth - 1]); if (!p) return SFS_CORRUPT; memset(row, 0, MAX_ROW); memcpy(row, row_at(p->bytes, t->map, at, t->reader->a.minor), stride(t->map, 0, t->reader->a.minor)); return SFS_OK;
}
static enum sfs_status tree_growth(tree *t, uint64_t old_size) {
    enum sfs_status e = tree_root(t); if (e) return e; overlay_page *p = owned_page(t, (unsigned)t->root); if (!p) return SFS_CORRUPT; if (!page_count(p->bytes)) return SFS_OK;
    key max = page_max(p->bytes); uint64_t last = from_big(max.bytes), boundary = old_size / CELL;
    if (last > boundary || (last == boundary && !(old_size % CELL))) return SFS_CORRUPT;
    if (last == boundary) { uint8_t row[MAX_ROW]; int found; key k = number_key(boundary); e = tree_get(t, &k, row, &found); if (e) return e; if (!found || get16(row + 64) > old_size % CELL) return SFS_CORRUPT; }
    return SFS_OK;
}
static enum sfs_status write_target(sfs_image *h, mutation_target target, uint64_t offset, const void *data, size_t length, sfs_result *result_out) {
    sfs_inode id = target.id;
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    if ((length && !data) || length > 65536) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    uint64_t end;
    reader r = current_reader(h, 1); node n; unsigned transition_height = 0; uint64_t transition_bound = 0; int same = target_same(h->batch, target), late = 0; arena *a = NULL; batch *candidate = NULL; uint8_t *merge = NULL; tree ext;
    if (same) n = h->batch->inode; else { e = target_get(&r, target, &n); if (e) goto failed; }
    if (id == 1) { e = SFS_NOT_FOUND; goto failed; } if (n.e.kind != SFS_FILE) { e = SFS_INVALID; goto failed; }
    if (!add64(offset, length, &end) || end > SFS_FILE_MAX) { h->limit_reason = SFS_LIMIT_FILE_SIZE; e = SFS_LIMIT; goto failed; }
    if (!length) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out);
    sfs_timestamp operation_time = {0}; if (metadata_capable(h->current.minor)) { int error; e = clock_sample(&operation_time, &error); if (e) return result(h, e, SFS_PHASE_NONE, error, result_out); }
    uint64_t extent_count = n.attributes.extents;
    uint64_t low = offset / CELL, high = (end - 1) / CELL, next_low = low, next_high = high; unsigned count = (unsigned)(high - low + 1);
    if (same) { if (h->batch->low < next_low) next_low = h->batch->low; if (h->batch->high > next_high) next_high = h->batch->high; a = arena_clone(h->batch->arena); if (!a) { e = SFS_NOMEM; goto failed; } ext = h->batch->extent; ext.arena = a; ext.reader = &r; ext.eof = n.e.size; }
    int rollover = h->batch && (!same || next_high - next_low >= 256);
    if (end > n.e.size) { e = same ? tree_growth(&ext, n.e.size) : extent_growth(&r, n.extent, n.e.size); if (e) goto failed; }
    merge = calloc(count, CELL); if (!merge) { e = SFS_NOMEM; goto failed; }
    uint64_t new_size = end > n.e.size ? end : n.e.size;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t block = low + i, base = block * CELL; uint8_t row[MAX_ROW]; int found = 0; key k = number_key(block);
        if (base < n.e.size) { e = same ? tree_get(&ext, &k, row, &found) : index_get(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &k, row, &found); if (e) goto failed; }
        if (metadata_capable(h->current.minor) && !found && !add64(extent_count, 1, &extent_count)) { e = SFS_LIMIT; goto failed; }
        if (found) { reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; goto failed; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), 0, merge + i * CELL); if (e) goto failed; }
        uint64_t begin = offset > base ? offset : base, finish = end < base + CELL ? end : base + CELL;
        memcpy(merge + i * CELL + (size_t)(begin - base), (const uint8_t *)data + (size_t)(begin - offset), (size_t)(finish - begin));
    }
    if (metadata_capable(h->current.minor) && extent_count > new_size / CELL + !!(new_size % CELL)) { e = SFS_CORRUPT; goto failed; }
    unsigned hi = 0; if (!target.detached) e = index_height(&r, h->staged.ns.inodes, MAP_INODE, h->staged.ns.next_inode, h->staged.ns.name_count, &hi); if (e) goto failed;
    if (rollover) {
        unsigned he; if (same) { e = tree_root(&ext); if (e) goto failed; he = page_level(owned_page(&ext, (unsigned)ext.root)->bytes) + 1; }
        else { e = index_height(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &he); if (e) goto failed; }
        if (he < MAX_HEIGHT) he++; uint64_t old; e = batch_cost(&r, &old); if (e) goto failed;
        uint64_t required = old + count + (uint64_t)count * (3u * he + 3u) + hi + 2;
        if (!reserve_cells(h, required)) { e = SFS_LIMIT; goto failed; }
        transition_bound = (uint64_t)count * (3u * he + 3u);
        if (!a) { a = arena_new(h, h->token + 1); if (!a) { e = SFS_NOMEM; goto failed; } ext = make_tree(a, &r, n.extent, MAP_EXTENT, id, UINT64_MAX, n.e.size); }
        /* Check all insertion/split paths, including the height cap, before sealing. */
        for (unsigned i = 0; i < count; ++i) {
            uint8_t row[MAX_ROW] = {0}; reference provisional = { .type = RAW, .length = CELL }; put64(row, low + i); encode_ref(row + 8, &provisional);
            uint64_t visible = new_size - (low + i) * CELL; put16(row + 64, visible < CELL ? (unsigned)visible : CELL); e = tree_put(&ext, row); if (e) goto failed;
        }
        transition_height = page_level(owned_page(&ext, (unsigned)ext.root)->bytes) + 1;
        arena_free(a); a = NULL; e = flush_batch(&r, &late); if (e) goto failed;
        e = target_get(&r, target, &n); if (e) goto failed; same = 0; next_low = low; next_high = high;
    }
    if (!a) { a = arena_new(h, h->token + 1); if (!a) { e = SFS_NOMEM; goto failed; } ext = make_tree(a, &r, n.extent, MAP_EXTENT, id, UINT64_MAX, n.e.size); }
    candidate = calloc(1, sizeof(*candidate)); if (!candidate) { e = SFS_NOMEM; goto failed; }
    uint64_t at; if (!aligned(h->eof, &at)) { e = SFS_LIMIT; goto failed; } reference refs[17];
    for (unsigned i = 0; i < count; ++i) {
        refs[i] = (reference){ .type = RAW, .offset = at + i * CELL, .length = CELL }; hash_cell(merge + i * CELL, RAW, h->current.uuid, refs[i].digest, h->current.minor);
        uint8_t row[MAX_ROW] = {0}; put64(row, low + i); encode_ref(row + 8, &refs[i]); uint64_t visible = new_size - (low + i) * CELL; put16(row + 64, visible < CELL ? (unsigned)visible : CELL);
        e = tree_put(&ext, row); if (e) goto failed;
    }
    ext.eof = new_size; e = prune_clean(&ext, (unsigned)ext.root); if (e) goto failed;
    if (transition_height && (page_level(owned_page(&ext, (unsigned)ext.root)->bytes) + 1 != transition_height || pending_cells(&ext) > transition_bound)) { e = SFS_CORRUPT; goto failed; }
    if (!reserve_cells(h, count + pending_cells(&ext) + hi + 2)) { e = SFS_LIMIT; goto failed; }
    uint64_t remaining = count; late = 1; r.phase = SFS_PHASE_RECORDS;
    for (unsigned i = 0; i < count; ++i) { reference appended; e = append_prepared(h, RAW, merge + i * CELL, &appended, &remaining, &refs[i]); if (e) { if (e == SFS_IO) r.error = errno; goto failed; } }
    if (metadata_capable(h->current.minor)) { n.attributes.extents = extent_count; n.attributes.modification = n.attributes.change = operation_time; }
    n.e.size = new_size; candidate->arena = a; candidate->extent = ext; candidate->extent.reader = NULL; candidate->inode = n; candidate->low = next_low; candidate->high = next_high; candidate->number = a->batch;
    candidate->detached = target.detached; candidate->incarnation = target.detached ? target.detached->incarnation : 0;
    if (h->batch) { arena_free(h->batch->arena); free(h->batch); } h->batch = candidate; free(merge);
    result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed:
    arena_free(a); free(candidate); free(merge); return mutation_failure(h, e, r.phase, r.error, late, result_out);
}
enum sfs_status sfs_image_write(sfs_image *h, sfs_inode id, uint64_t offset, const void *data, size_t length, sfs_result *r) { return write_target(h, (mutation_target){id, NULL}, offset, data, length, r); }
enum sfs_status sfs_image_pin_write(sfs_image *h, sfs_pin pin, uint64_t offset, const void *data, size_t length, sfs_result *r) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, pin, &target, r); return e ? e : write_target(h, target, offset, data, length, r);
}

typedef struct { int shadow; reference ref; uint64_t before; context context; unsigned index; } extent_frame;
typedef struct { reader *reader; tree *overlay; extent_frame frames[MAX_HEIGHT]; unsigned depth; } extent_stream;
static enum sfs_status extent_frame_bytes(extent_stream *c, extent_frame *f, const uint8_t **out) {
    if (f->shadow < 0) return page_read(c->reader, &f->ref, f->before, f->context, out);
    overlay_page *p = owned_page(c->overlay, (unsigned)f->shadow); if (!p || page_level(p->bytes) != f->context.level) return SFS_CORRUPT; *out = p->bytes; return SFS_OK;
}
static enum sfs_status extent_stream_start(extent_stream *c, reader *r, reference ref, tree *overlay, uint64_t eof) {
    memset(c, 0, sizeof(*c)); c->reader = r; c->overlay = overlay; int shadow = overlay ? overlay->root : -1; const uint8_t *b;
    if (shadow >= 0) { overlay_page *p = owned_page(overlay, (unsigned)shadow); if (!p) return SFS_CORRUPT; b = p->bytes; if (!page_count(b)) return SFS_OK; }
    else { if (overlay) ref = overlay->source; if (!ref.type) return SFS_OK; enum sfs_status e = root_page(r, &ref, MAP_EXTENT, UINT64_MAX, eof, &b); if (e) return e; }
    c->frames[c->depth++] = (extent_frame){ .shadow = shadow, .ref = ref, .before = r->a.end, .context = root_context(MAP_EXTENT, page_level(b), UINT64_MAX, eof, r->a.minor) }; return SFS_OK;
}
static enum sfs_status extent_stream_next(extent_stream *c, uint8_t row[MAX_ROW], int *found) {
    *found = 0;
    while (c->depth) {
        extent_frame *f = &c->frames[c->depth - 1]; const uint8_t *b; enum sfs_status e = extent_frame_bytes(c, f, &b); if (e) return e;
        if (f->index >= page_count(b)) { c->depth--; continue; }
        unsigned at = f->index++; if (!f->context.level) { memset(row, 0, MAX_ROW); memcpy(row, row_at(b, MAP_EXTENT, at, c->reader->a.minor), 72); *found = 1; return SFS_OK; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, MAP_EXTENT, at, c->reader->a.minor), MAP_EXTENT, &child)) return SFS_CORRUPT;
        int shadow = -1; if (f->shadow >= 0) { overlay_page *p = owned_page(c->overlay, (unsigned)f->shadow); if (p->children[at] != NO_CHILD) shadow = p->children[at]; }
        extent_frame next = { .shadow = shadow, .ref = child, .before = f->shadow >= 0 ? c->reader->a.end : f->ref.offset, .context = child_context(b, at, f->context) }; c->frames[c->depth++] = next;
    } return SFS_OK;
}
typedef struct { uint8_t cells[MAX_HEIGHT][CELL]; uint64_t pages[MAX_HEIGHT], input[MAX_HEIGHT], emitted[MAX_HEIGHT]; unsigned rows[MAX_HEIGHT], levels; sfs_image *h; uint64_t generation; reference root; } prefix_builder;
static enum sfs_status prefix_shape(uint64_t rows, uint64_t pages[MAX_HEIGHT], unsigned *levels, uint64_t *total) {
    *levels = 0; *total = 0; while (rows) { if (*levels == MAX_HEIGHT) return SFS_LIMIT; rows = rows / 48 + (rows % 48 != 0); pages[(*levels)++] = rows; if (!add64(*total, rows, total)) return SFS_LIMIT; if (rows == 1) break; } return SFS_OK;
}
static enum sfs_status prefix_feed(prefix_builder *p, unsigned level, const uint8_t *row, key min, key max, uint64_t *remaining) {
    if (level >= p->levels || p->emitted[level] >= p->pages[level]) return SFS_CORRUPT;
    uint8_t *b = p->cells[level]; unsigned n = p->rows[level];
    if (!n) { envelope(b, INDEX, p->h->current.uuid, p->h->current.minor); put32(b + 64, MAP_EXTENT); put16(b + 68, level); put64(b + 72, p->generation); set_page_range(b, min, max); }
    else set_page_range(b, page_min(b), max);
    memcpy(b + PAGE_HEAD + n * 72, row, 72); put16(b + 70, ++n); p->rows[level] = n;
    uint64_t target = p->input[level] / p->pages[level] + (p->emitted[level] < p->input[level] % p->pages[level]);
    if (n < target) return SFS_OK; if (n != target || target > 48 || (p->pages[level] > 1 && target < 16)) return SFS_CORRUPT;
    reference child; enum sfs_status e = append_cell(p->h, INDEX, b, &child, remaining); if (e) return e; min = page_min(b); max = page_max(b); p->rows[level] = 0; p->emitted[level]++;
    if (level + 1 == p->levels) { p->root = child; return SFS_OK; }
    uint8_t parent[72] = {0}; put32(parent, 8); memcpy(parent + 8, min.bytes, 8); encode_ref(parent + 16, &child); return prefix_feed(p, level + 1, parent, min, max, remaining);
}
static void encode_xattr(uint8_t row[MAX_ROW], sfs_inode owner, const void *name, size_t name_length, uint64_t size, reference extent) {
    memset(row, 0, MAX_ROW); put64(row, owner); put32(row + 8, (uint32_t)name_length); memcpy(row + 12, name, name_length);
    put64(row + 272, size); encode_ref(row + 280, &extent); put64(row + 336, dense_count(size));
}
static enum sfs_status xattr_mutation(sfs_image *h, mutation_target target, const void *name, size_t name_length, const void *value, size_t length, int remove, sfs_result *result_out) {
    sfs_inode id = target.id;
    enum sfs_status e = ready(h, 1, 1, result_out); if (e) return e;
    if (!valid_xattr_name(name, name_length) || (!remove && length && !value)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (!xattr_capable(h->current.minor)) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    e = mutation_start(h, result_out); if (e) return e;
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; node before, owner;
    pin_descriptor *descriptor = target.detached ? pin_pending_descriptor(target.detached) : NULL;
    reference attr_source = descriptor ? descriptor->xattrs : ns.xattrs;
    uint64_t attr_next = descriptor ? descriptor->next_inode : ns.next_inode;
    arena *a = NULL; prefix_builder *builder = NULL; int late = 0, found; uint8_t row[MAX_ROW];
    key k = name_key(id, name, name_length);
    if (target_same(h->batch, target)) before = h->batch->inode;
    else { e = target_get(&r, target, &before); if (e) goto failed; }
    e = index_get(&r, attr_source, MAP_XATTR, attr_next, UINT64_MAX, &k, row, &found); if (e) goto failed;
    if (remove && !found) { e = SFS_NOT_FOUND; goto failed; }
    if (length > SFS_FILE_MAX) { e = SFS_LIMIT; goto failed; }
    unsigned hi, ha, levels; uint64_t pages[MAX_HEIGHT] = {0}, page_total, count = remove ? 0 : dense_count(length), old_cost;
    hi = 0; if (!target.detached) e = index_height(&r, ns.inodes, MAP_INODE, ns.next_inode, ns.name_count, &hi);
    if (!e) e = index_height(&r, attr_source, MAP_XATTR, attr_next, UINT64_MAX, &ha);
    if (!e) e = prefix_shape(count, pages, &levels, &page_total);
    if (!e) e = batch_cost(&r, &old_cost); if (e) goto failed;
    uint64_t attr_bound = remove ? 3u * ha + 3u : found ? ha : 3u * (ha < MAX_HEIGHT ? ha + 1 : ha) + 3u;
    uint64_t inode_bound = id == 1 ? 0 : hi, total = old_cost, start;
    if (!add64(total, count, &total) || !add64(total, page_total, &total) || !add64(total, attr_bound, &total) || !add64(total, inode_bound, &total) || !add64(total, 2, &total) || !reserve_cells(h, total) || !aligned(h->eof, &start)) { e = SFS_LIMIT; goto failed; }
    if (count) {
        builder = calloc(1, sizeof(*builder)); if (!builder) { e = SFS_NOMEM; goto failed; }
        builder->h = h; builder->generation = r.a.generation; builder->levels = levels; memcpy(builder->pages, pages, sizeof(pages)); builder->input[0] = count;
        for (unsigned i = 1; i < levels; ++i) builder->input[i] = pages[i - 1];
    }
    a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
    tree attrs = make_tree(a, &r, attr_source, MAP_XATTR, 0, attr_next, UINT64_MAX);
    /* A structural probe only: this placeholder is never sealed or read. */
    reference extent = count ? (reference){ .type = INDEX, .length = CELL } : (reference){0};
    if (remove) e = tree_delete(&attrs, &k);
    else { encode_xattr(row, id, name, name_length, length, extent); e = tree_put(&attrs, row); }
    if (!e && pending_cells(&attrs) > attr_bound) e = SFS_CORRUPT;
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count);
    if (!e && id != 1 && !target.detached) { encode_node(row, &before, h->current.minor); e = tree_put(&inodes, row); if (!e && pending_cells(&inodes) > inode_bound) e = SFS_CORRUPT; }
    arena_free(a); a = NULL; if (e) goto failed;
    sfs_timestamp t; int clock_error; e = clock_sample(&t, &clock_error);
    if (e) { free(builder); return result(h, e, SFS_PHASE_NONE, clock_error, result_out); }
    e = flush_batch(&r, &late); if (e) goto failed;
    if ((old_cost && (h->eof < start || (h->eof - start) / CELL > old_cost)) || h->staged.ns.count != ns.count || h->staged.ns.name_count != ns.name_count || h->staged.ns.next_inode != ns.next_inode || !same_attributes(&h->staged.ns.attributes, &ns.attributes) || !same_ref(&h->staged.ns.xattrs, &ns.xattrs)) { e = SFS_CORRUPT; goto failed; }
    e = target_get(&r, target, &owner); if (e) goto failed;
    if (!same_logical_node(&owner, &before)) { e = SFS_CORRUPT; goto failed; }
    ns = h->staged.ns; owner.attributes.change = t; extent = (reference){0};
    if (count) {
        uint64_t remaining; if (!add64(count, page_total, &remaining)) { e = SFS_LIMIT; goto failed; }
        size_t consumed = 0; uint64_t raw_count = 0; uint8_t bytes[CELL];
        for (; raw_count < count; ++raw_count) {
            size_t chunk = length - consumed < CELL ? length - consumed : CELL; memset(bytes, 0, CELL); memcpy(bytes, (const uint8_t *)value + consumed, chunk);
            reference raw; late = 1; r.phase = SFS_PHASE_RECORDS; e = append_cell(h, RAW, bytes, &raw, &remaining); if (e) { if (e == SFS_IO) r.error = errno; goto failed; }
            memset(row, 0, sizeof(row)); put64(row, raw_count); encode_ref(row + 8, &raw); put16(row + 64, (unsigned)chunk);
            e = prefix_feed(builder, 0, row, number_key(raw_count), number_key(raw_count), &remaining); if (e) { if (e == SFS_IO) r.error = errno; goto failed; } consumed += chunk;
        }
        if (consumed != length || raw_count != count || remaining || builder->root.type != INDEX) { e = SFS_CORRUPT; goto failed; }
        for (unsigned i = 0; i < levels; ++i) if (builder->rows[i] || builder->emitted[i] != pages[i]) { e = SFS_CORRUPT; goto failed; }
        extent = builder->root;
    }
    free(builder); builder = NULL; r.a.end = h->eof; r.phase = SFS_PHASE_READ;
    a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
    attrs = make_tree(a, &r, attr_source, MAP_XATTR, 0, attr_next, UINT64_MAX);
    if (remove) e = tree_delete(&attrs, &k);
    else { encode_xattr(row, id, name, name_length, length, extent); e = tree_put(&attrs, row); }
    uint64_t remaining = pending_cells(&attrs); if (!e && remaining > attr_bound) e = SFS_CORRUPT;
    reference changed_attrs;
    if (!e) { if (remaining) late = 1; r.phase = SFS_PHASE_RECORDS; e = seal_tree(&attrs, &changed_attrs, &remaining); if (e == SFS_IO) r.error = errno; }
    arena_free(a); a = NULL; if (e) goto failed; if (remaining) { e = SFS_CORRUPT; goto failed; }
    r.a.end = h->eof; r.phase = SFS_PHASE_READ;
    if (target.detached) {
        if (h->eof < start || (h->eof - start) / CELL >= total) { e = SFS_CORRUPT; goto failed; }
        target_store(&r, target.detached, &owner); target.detached->staged.xattrs = changed_attrs;
        target.detached->staged.next_inode = attr_next;
        result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
    }
    ns.xattrs = changed_attrs;
    if (id == 1) ns.attributes = owner.attributes;
    else {
        a = arena_new(h, 0); if (!a) { e = SFS_NOMEM; goto failed; }
        inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count); encode_node(row, &owner, h->current.minor); e = tree_put(&inodes, row);
        remaining = pending_cells(&inodes); if (!e && remaining > inode_bound) e = SFS_CORRUPT;
        if (!e) { late = 1; r.phase = SFS_PHASE_RECORDS; e = seal_tree(&inodes, &ns.inodes, &remaining); if (e == SFS_IO) r.error = errno; }
        arena_free(a); a = NULL; if (e) goto failed; if (remaining) { e = SFS_CORRUPT; goto failed; }
    }
    remaining = 1; late = 1; r.phase = SFS_PHASE_RECORDS; e = write_namespace(h, &ns, &remaining); if (e == SFS_IO) r.error = errno; if (e) goto failed;
    if (remaining || h->eof < start || (h->eof - start) / CELL >= total) { e = SFS_CORRUPT; goto failed; }
    h->staged.ns = ns; result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed:
    free(builder); arena_free(a); return mutation_failure(h, e, r.phase, r.error, late, result_out);
}
enum sfs_status sfs_image_set_xattr(sfs_image *h, sfs_inode id, const void *name, size_t name_length, const void *value, size_t length, sfs_result *result_out) { return xattr_mutation(h, (mutation_target){id, NULL}, name, name_length, value, length, 0, result_out); }
enum sfs_status sfs_image_remove_xattr(sfs_image *h, sfs_inode id, const void *name, size_t name_length, sfs_result *result_out) { return xattr_mutation(h, (mutation_target){id, NULL}, name, name_length, NULL, 0, 1, result_out); }
enum sfs_status sfs_image_pin_set_xattr(sfs_image *h, sfs_pin pin, const void *name, size_t length, const void *value, size_t size, sfs_result *r) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, pin, &target, r); return e ? e : xattr_mutation(h, target, name, length, value, size, 0, r);
}
enum sfs_status sfs_image_pin_remove_xattr(sfs_image *h, sfs_pin pin, const void *name, size_t length, sfs_result *r) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, pin, &target, r); return e ? e : xattr_mutation(h, target, name, length, NULL, 0, 1, r);
}

static enum sfs_status replace_inode(reader *r, mutation_target target, node *n, int *late) {
    if (target.detached) { if (!reserve_cells(r->h, 1)) return SFS_LIMIT; target_store(r, target.detached, n); return SFS_OK; }
    arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM; namespace ns = r->h->staged.ns;
    tree inodes = make_tree(a, r, ns.inodes, MAP_INODE, 0, ns.next_inode, ns.name_count); uint8_t row[MAX_ROW]; encode_node(row, n, r->a.minor); enum sfs_status e = tree_put(&inodes, row); uint64_t remaining = pending_cells(&inodes) + 1;
    if (!e && !reserve_cells(r->h, remaining + 1)) e = SFS_LIMIT;
    if (!e) { *late = 1; r->phase = SFS_PHASE_RECORDS; e = seal_tree(&inodes, &ns.inodes, &remaining); if (!e) e = write_namespace(r->h, &ns, &remaining); if (e == SFS_IO) r->error = errno; }
    arena_free(a); if (!e && remaining) e = SFS_CORRUPT; if (!e) r->h->staged.ns = ns; return e;
}
static enum sfs_status resize_target(sfs_image *h, mutation_target target, uint64_t size, sfs_result *result_out) {
    sfs_inode id = target.id;
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    reader r = current_reader(h, 1); node n; int same = target_same(h->batch, target), late = 0; arena *guard = NULL; prefix_builder *builder = NULL;
    if (same) n = h->batch->inode; else { e = target_get(&r, target, &n); if (e) goto failed; }
    if (id == 1) { e = SFS_NOT_FOUND; goto failed; } if (n.e.kind != SFS_FILE) { e = SFS_INVALID; goto failed; } if (size > SFS_FILE_MAX) { h->limit_reason = SFS_LIMIT_FILE_SIZE; e = SFS_LIMIT; goto failed; }
    uint64_t old_size = n.e.size, retained = 0, total = 0, pages[MAX_HEIGHT] = {0}; unsigned levels = 0, boundary = 0; uint8_t boundary_bytes[CELL], boundary_row[MAX_ROW];
    sfs_timestamp operation_time = {0}; if (metadata_capable(h->current.minor) && size != old_size) { int error; e = clock_sample(&operation_time, &error); if (e) return result(h, e, SFS_PHASE_NONE, error, result_out); }
    if (size > old_size) {
        if (same) { guard = arena_clone(h->batch->arena); if (!guard) { e = SFS_NOMEM; goto failed; } tree t = h->batch->extent; t.arena = guard; t.reader = &r; t.eof = old_size; e = tree_growth(&t, old_size); arena_free(guard); guard = NULL; }
        else e = extent_growth(&r, n.extent, old_size); if (e) goto failed;
    } else if (size && size < old_size) {
        extent_stream c; e = extent_stream_start(&c, &r, n.extent, same ? &h->batch->extent : NULL, old_size); if (e) goto failed; uint8_t row[MAX_ROW]; int found;
        while (!(e = extent_stream_next(&c, row, &found)) && found) {
            uint64_t block = get64(row); if (block >= (size + CELL - 1) / CELL) break; retained++;
            if (size % CELL && block == size / CELL) { memcpy(boundary_row, row, MAX_ROW); reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; goto failed; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), 0, boundary_bytes); if (e) goto failed; memset(boundary_bytes + size % CELL, 0, CELL - size % CELL); boundary = 1; }
        }
        if (e) goto failed; e = prefix_shape(retained, pages, &levels, &total); if (e) goto failed;
        if (retained) { builder = calloc(1, sizeof(*builder)); if (!builder) { e = SFS_NOMEM; goto failed; } builder->h = h; builder->generation = r.a.generation; builder->levels = levels; memcpy(builder->pages, pages, sizeof(pages)); builder->input[0] = retained; for (unsigned i = 1; i < levels; ++i) builder->input[i] = pages[i - 1]; }
    }
    if (metadata_capable(h->current.minor) && size < old_size && retained > n.attributes.extents) { e = SFS_CORRUPT; goto failed; }
    unsigned hi = 0; if (!target.detached) e = index_height(&r, h->staged.ns.inodes, MAP_INODE, h->staged.ns.next_inode, h->staged.ns.name_count, &hi); if (e) goto failed;
    uint64_t old; e = batch_cost(&r, &old); if (e) goto failed;
    uint64_t required = old + (size == old_size ? 1 : total + boundary + hi + 2); if (!reserve_cells(h, required)) { e = SFS_LIMIT; goto failed; }
    e = flush_batch(&r, &late); if (e) goto failed; if (size == old_size) { free(builder); return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); }
    e = target_get(&r, target, &n); if (e) goto failed;
    if (size < old_size) {
        reference new_boundary = {0}; uint64_t remaining = total + boundary; r.phase = SFS_PHASE_RECORDS;
        if (boundary) { late = 1; e = append_cell(h, RAW, boundary_bytes, &new_boundary, &remaining); if (e) { if (e == SFS_IO) r.error = errno; goto failed; } }
        if (retained) {
            cursor c; e = cursor_start(&c, &r, n.extent, MAP_EXTENT, UINT64_MAX, old_size, NULL); if (e) goto failed; uint8_t row[MAX_ROW]; int found;
            for (uint64_t i = 0; i < retained; ++i) {
                e = cursor_next(&c, row, &found); if (e) goto failed; if (!found || get64(row) >= (size + CELL - 1) / CELL) { e = SFS_CORRUPT; goto failed; }
                if (boundary && get64(row) == size / CELL) { if (memcmp(row, boundary_row, 72)) { e = SFS_CORRUPT; goto failed; } encode_ref(row + 8, &new_boundary); put16(row + 64, (unsigned)(size % CELL)); }
                key k = number_key(get64(row)); late = 1; r.phase = SFS_PHASE_RECORDS; e = prefix_feed(builder, 0, row, k, k, &remaining); if (e) { if (e == SFS_IO) r.error = errno; goto failed; }
            }
            for (unsigned i = 0; i < levels; ++i) if (builder->rows[i] || builder->emitted[i] != builder->pages[i]) { e = SFS_CORRUPT; goto failed; }
            n.extent = builder->root;
        } else memset(&n.extent, 0, sizeof(n.extent));
        if (remaining) { e = SFS_CORRUPT; goto failed; }
    }
    if (metadata_capable(h->current.minor)) { if (size < old_size) n.attributes.extents = retained; n.attributes.modification = n.attributes.change = operation_time; }
    n.e.size = size; e = replace_inode(&r, target, &n, &late); if (e) goto failed; free(builder); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed: arena_free(guard); free(builder); return mutation_failure(h, e, r.phase, r.error, late, result_out);
}
enum sfs_status sfs_image_resize(sfs_image *h, sfs_inode id, uint64_t size, sfs_result *r) { return resize_target(h, (mutation_target){id, NULL}, size, r); }
enum sfs_status sfs_image_pin_resize(sfs_image *h, sfs_pin pin, uint64_t size, sfs_result *r) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, pin, &target, r); return e ? e : resize_target(h, target, size, r);
}
enum sfs_status sfs_image_pin_set_metadata(sfs_image *h, sfs_pin pin, const sfs_metadata_update *update, sfs_result *out) {
    mutation_target target; enum sfs_status e = pin_mutation_target(h, pin, &target, out); if (e) return e;
    if (!target.detached) return sfs_image_set_metadata(h, target.id, update, out);
    e = mutation_start(h, out); if (e) return e; reader r = current_reader(h, 1); node n; int late = 0;
    e = target_get(&r, target, &n); if (!e) e = update_valid(update, n.e.kind);
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    if (!update->fields) return result(h, SFS_OK, SFS_PHASE_NONE, 0, out);
    sfs_timestamp t; int error; e = clock_sample(&t, &error); if (e) return result(h, e, SFS_PHASE_NONE, error, out);
    uint64_t pending; e = batch_cost(&r, &pending); if (!e && !reserve_cells(h, pending + 1)) e = SFS_LIMIT;
    if (!e) e = flush_batch(&r, &late); if (!e) e = target_get(&r, target, &n);
    if (!e) { update_attributes(&n.attributes, update, t); e = replace_inode(&r, target, &n, &late); }
    if (e) return mutation_failure(h, e, r.phase, r.error, late, out);
    result(h, SFS_OK, SFS_PHASE_NONE, 0, out); if (out) out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}

enum sfs_status sfs_image_commit(sfs_image *h, sfs_result *out) {
    enum sfs_status e = mutation_start(h, out); if (e) return e;
    if (h->pins) for (uint32_t i = h->pins->changed; i != PIN_NONE; i = h->pins->slots[i].next)
        if (h->pins->slots[i].pending == PIN_RESERVED) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, out);
    reader r = current_reader(h, 0); state fresh; cache_clear(h); e = reconcile(&r, &fresh);
    if (!e && h->staged.ns.next_inode < fresh.ns.next_inode) e = SFS_CORRUPT;
    if (e) return mutation_failure(h, e, r.phase, r.error, 1, out);
    r = current_reader(h, 1); uint64_t pending; e = batch_cost(&r, &pending); if (!e && !reserve_cells(h, pending + 1)) e = SFS_LIMIT;
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    int late = 0; e = flush_batch(&r, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, out);
    anchor next = h->current; next.generation++; uint8_t b[CELL]; envelope(b, ROOT, next.uuid, h->current.minor); encode_ref(b + 64, &h->staged.ns.ref); encode_ref(b + 120, &h->staged.catalog);
    uint64_t remaining = 1; e = append_cell(h, ROOT, b, &next.root, &remaining); if (e) return mutation_failure(h, e, SFS_PHASE_RECORDS, e == SFS_IO ? errno : 0, 1, out); next.end = h->eof;
    /* Finalize every reachable byte and the slot before the first fence. */
    encode_slot(b, &next); unsigned slot = (unsigned)(next.generation % 2); int published = 0; enum sfs_phase phase = SFS_PHASE_RECORD_BARRIER;
    h->fence_attempted |= 1;
    if (fullsync(h->fd)) goto failed;
    h->fence_succeeded |= 1;
    phase = slot ? SFS_PHASE_SLOT1 : SFS_PHASE_SLOT0; published = 1; if (write_exact(h->fd, b, CELL, slot * ALIGNMENT)) goto failed;
    phase = SFS_PHASE_COMMIT_BARRIER; h->fence_attempted |= 2; if (fullsync(h->fd)) goto failed;
    h->fence_succeeded |= 2;
    pins_promote(h);
    h->live = h->staged; memset(&h->staged, 0, sizeof(h->staged)); h->transaction = 0; h->current = next; h->slots[slot] = next; h->slot_observed[slot] = 1; h->slot_status[slot] = SFS_OK;
    result(h, SFS_OK, SFS_PHASE_NONE, 0, out); if (out) out->coverage = SFS_COVERAGE_ROOT_ONLY; return SFS_OK;
failed: { int error = errno; discard(h); h->poisoned = 1; h->phase = phase; return result(h, published ? SFS_OUTCOME_UNKNOWN : SFS_IO, phase, error, out); }
}
static enum sfs_status cookie_cursor(reader *r, const namespace *ns, uint64_t parent, const sfs_cookie *cookie, cursor *c) {
    const uint8_t *b = cookie->bytes; key prefix = name_key(parent, NULL, 0);
    if (zero(b, sizeof(cookie->bytes))) return cursor_start(c, r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &prefix);
    if (memcmp(b, ns->ref.digest, 32)) return SFS_STATE;
    unsigned depth = get32(b + 40), flags = get32(b + 44);
    if (get64(b + 32) != parent || depth > MAX_HEIGHT || (flags != 1 && flags != 3) || ((flags & 2) && depth) || (!(flags & 2) && !depth) || !zero(b + 48 + depth * 64, sizeof(cookie->bytes) - 48 - depth * 64)) return SFS_INVALID;
    memset(c, 0, sizeof(*c)); c->reader = r; c->map = MAP_NAME; c->next_inode = ns->next_inode; c->eof = UINT64_MAX;
    if (!depth) return SFS_OK; if (!ns->names.type) return SFS_INVALID;
    const uint8_t *page; enum sfs_status e = root_page(r, &ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &page); if (e) return e;
    reference expected = ns->names; uint64_t before = r->a.end; context ctx = root_context(MAP_NAME, page_level(page), ns->next_inode, UINT64_MAX, r->a.minor);
    for (unsigned i = 0; i < depth; ++i) {
        const uint8_t *v = b + 48 + i * 64; reference ref; unsigned index = get16(v + 56);
        if (!decode_ref(v, &ref) || !same_ref(&ref, &expected) || get16(v + 58) != ctx.level || !zero(v + 60, 4)) return SFS_INVALID;
        e = page_read(r, &ref, before, ctx, &page); if (e) return e;
        if (index > page_count(page) || (i + 1 < depth && (!index || !ctx.level))) return SFS_INVALID;
        c->frames[c->depth++] = (cursor_frame){ .ref = ref, .before = before, .context = ctx, .index = index };
        if (i + 1 < depth) { if (!child_ref(row_at(page, MAP_NAME, index - 1, r->a.minor), MAP_NAME, &expected)) return SFS_CORRUPT; before = ref.offset; ctx = child_context(page, index - 1, ctx); }
    }
    return SFS_OK;
}
static void save_cookie(sfs_cookie *cookie, const namespace *ns, uint64_t parent, const cursor *c) {
    uint8_t *b = cookie->bytes; memset(b, 0, sizeof(cookie->bytes)); memcpy(b, ns->ref.digest, 32); put64(b + 32, parent); put32(b + 40, c->depth); put32(b + 44, c->depth ? 1 : 3);
    for (unsigned i = 0; i < c->depth; ++i) { uint8_t *v = b + 48 + i * 64; encode_ref(v, &c->frames[i].ref); put16(v + 56, c->frames[i].index); put16(v + 58, c->frames[i].context.level); }
}
/* Only encode frames left by a successfully checked name row. */
static enum sfs_status cursor_position(const cursor *c, uint64_t *out) {
    if (!c->depth || c->depth > MAX_HEIGHT) return SFS_CORRUPT;
    uint64_t p = 1;
    for (unsigned i = 0; i + 1 < c->depth; ++i) {
        unsigned index = c->frames[i].index;
        if (!index || index > 9 || c->frames[i].context.level != c->depth - i - 1 || p > (UINT64_MAX - (index - 1)) / 9) return SFS_CORRUPT;
        p = 9 * p + index - 1;
    }
    const cursor_frame *leaf = &c->frames[c->depth - 1];
    if (leaf->context.level || !leaf->index || leaf->index > 12 || p > (UINT64_MAX - leaf->index) / 16) return SFS_CORRUPT;
    *out = 16 * p + leaf->index; return SFS_OK;
}
static enum sfs_status position_cursor(reader *r, const namespace *ns, uint64_t parent, uint64_t position, cursor *c) {
    unsigned next = (unsigned)(position & 15); uint64_t p = position / 16;
    if (!ns->names.type || !next || next > 12) return SFS_INVALID;
    const uint8_t *page; enum sfs_status e = root_page(r, &ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &page); if (e) return e;
    unsigned level = page_level(page); uint8_t branches[MAX_HEIGHT - 1];
    for (unsigned i = level; i; --i) { branches[i - 1] = (uint8_t)(p % 9); p /= 9; }
    if (p != 1) return SFS_INVALID;
    memset(c, 0, sizeof(*c)); c->reader = r; c->map = MAP_NAME; c->next_inode = ns->next_inode; c->eof = UINT64_MAX;
    reference ref = ns->names; uint64_t before = r->a.end; context ctx = root_context(MAP_NAME, level, ns->next_inode, UINT64_MAX, r->a.minor);
    for (unsigned i = 0; i <= level; ++i) {
        e = page_read(r, &ref, before, ctx, &page); if (e) return e;
        unsigned index = ctx.level ? branches[i] : next;
        if (ctx.level ? index >= page_count(page) : index > page_count(page)) return SFS_INVALID;
        c->frames[c->depth++] = (cursor_frame){ .ref = ref, .before = before, .context = ctx, .index = ctx.level ? index + 1 : index };
        if (!ctx.level) break;
        reference child; if (!child_ref(row_at(page, MAP_NAME, index, r->a.minor), MAP_NAME, &child)) return SFS_CORRUPT;
        before = ref.offset; ref = child; ctx = child_context(page, index, ctx);
    }
    const uint8_t *row = row_at(page, MAP_NAME, next - 1, r->a.minor);
    if (get64(row) != parent) return SFS_INVALID;
    /* Copy before indexed membership reads can reuse cache storage. */
    uint8_t saved[MAX_ROW]; memset(saved, 0, sizeof(saved)); memcpy(saved, row, stride(MAP_NAME, 0, r->a.minor));
    node n; e = node_get(r, ns, get64(saved + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
    if (!e) { key k = row_key(saved, MAP_NAME, 0); e = r->a.minor == 6 ? name_member(r, ns, &n, &k) : (n.e.parent != parent || n.e.name_length != get32(saved + 8) || memcmp(n.e.name, saved + 12, n.e.name_length)) ? SFS_CORRUPT : SFS_OK; }
    return e;
}
enum sfs_status sfs_image_resume_after_position(sfs_image *h, sfs_view view, uint64_t expected_generation, const uint8_t expected_root_digest[32], sfs_inode parent, uint64_t position, sfs_cookie *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e;
    if (!out || !expected_root_digest || !expected_generation) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (expected_generation != h->current.generation || memcmp(expected_root_digest, h->current.root.digest, 32)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns;
    e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent); if (e) return touched_result(&r, e, result_out);
    cursor *c = malloc(sizeof(*c)); if (!c) return touched_result(&r, SFS_NOMEM, result_out);
    e = position_cursor(&r, &ns, parent, position, c);
    if (!e) { sfs_cookie cookie; save_cookie(&cookie, &ns, parent, c); *out = cookie; } free(c); return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_resume_after_name(sfs_image *h, sfs_view view, uint64_t expected_generation, const uint8_t expected_root_digest[32], sfs_inode parent, const void *previous_name, size_t previous_length, sfs_cookie *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e;
    if (!out || !expected_root_digest || !expected_generation || !valid_name(previous_name, previous_length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (h->current.minor != 6) return result(h, SFS_UNSUPPORTED, SFS_PHASE_NONE, 0, result_out);
    if (expected_generation != h->current.generation || memcmp(expected_root_digest, h->current.root.digest, 32)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n; uint8_t row[MAX_ROW]; int found;
    e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent); if (e) return touched_result(&r, e, result_out);
    cursor *c = malloc(sizeof(*c)); if (!c) return touched_result(&r, SFS_NOMEM, result_out);
    key k = name_key(parent, previous_name, previous_length); e = cursor_start(c, &r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k); if (!e) e = cursor_next(c, row, &found);
    if (!e) { key actual = found ? row_key(row, MAP_NAME, 0) : (key){0}; if (!found || keycmp(&actual, &k)) e = SFS_NOT_FOUND; }
    if (!e) { e = node_get(&r, &ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT; }
    if (!e) e = name_member(&r, &ns, &n, &k);
    if (!e) { sfs_cookie cookie; save_cookie(&cookie, &ns, parent, c); *out = cookie; } free(c); return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_resume_after(sfs_image *h, sfs_view view, uint64_t expected_generation,
                                     const uint8_t expected_root_digest[32], sfs_inode parent,
                                     sfs_inode previous, sfs_cookie *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e;
    if (!out || !expected_root_digest || !expected_generation || previous <= SFS_ROOT_INODE) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (expected_generation != h->current.generation || memcmp(expected_root_digest, h->current.root.digest, 32)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n; cursor c; uint8_t row[MAX_ROW]; int found = 0;
    e = selected_namespace(&r, view, &ns);
    if (!e && r.a.minor == 6) {
        e = node_get(&r, &ns, previous, 1, &n); if (e) return touched_result(&r, e, result_out);
        if (n.nlink > 1) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, result_out);
        e = directory_check(&r, &ns, parent); if (e) return touched_result(&r, e, result_out);
        if (n.e.parent != parent) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
        return sfs_image_resume_after_name(h, view, expected_generation, expected_root_digest, parent, n.e.name, n.e.name_length, out, result_out);
    }
    if (!e) e = directory_check(&r, &ns, parent);
    if (!e) e = node_get(&r, &ns, previous, 1, &n);
    if (!e && n.e.parent != parent) e = SFS_INVALID;
    if (!e) { key k = name_key(parent, n.e.name, n.e.name_length); e = cursor_start(&c, &r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k); }
    if (!e) e = cursor_next(&c, row, &found);
    if (!e && (!found || get64(row) != parent || get32(row + 8) != n.e.name_length || memcmp(row + 12, n.e.name, n.e.name_length) || get64(row + 267) != previous)) e = SFS_CORRUPT;
    /* Publish only the checked position; leave successor validation to next. */
    if (!e) { sfs_cookie cookie; save_cookie(&cookie, &ns, parent, &c); memcpy(out, &cookie, sizeof(cookie)); }
    return touched_result(&r, e, result_out);
}
static enum sfs_status next_entry(sfs_image *h, sfs_view view, sfs_inode parent, sfs_cookie *cookie, sfs_entry *out, uint64_t *position, int *found, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!cookie || !out || !found) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *found = 0;
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent); cursor c;
    if (!e) e = cookie_cursor(&r, &ns, parent, cookie, &c); uint8_t row[MAX_ROW]; int exists = 0;
    if (!e) e = cursor_next(&c, row, &exists);
    if (!e && exists && get64(row) != parent) { c.depth = 0; exists = 0; }
    if (!e && exists) { node n; e = node_get(&r, &ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
        if (!e) { key k = row_key(row, MAP_NAME, 0); e = r.a.minor == 6 ? name_member(&r, &ns, &n, &k) : (n.e.parent != parent || n.e.name_length != get32(row + 8) || memcmp(n.e.name, row + 12, n.e.name_length)) ? SFS_CORRUPT : SFS_OK; if (!e) entry_name(&n, row); }
        uint64_t encoded = 0; if (!e && position) e = cursor_position(&c, &encoded);
        if (!e) { *out = n.e; *found = 1; if (position) *position = encoded; }
    }
    if (!e) save_cookie(cookie, &ns, parent, &c); return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_next(sfs_image *h, sfs_view view, sfs_inode parent, sfs_cookie *cookie, sfs_entry *out, int *found, sfs_result *result_out) {
    return next_entry(h, view, parent, cookie, out, NULL, found, result_out);
}
enum sfs_status sfs_image_next_position(sfs_image *h, sfs_view view, sfs_inode parent, sfs_cookie *cookie, sfs_entry *out, uint64_t *position, int *found, sfs_result *result_out) {
    if (!position) { enum sfs_status e = ready(h, 0, 0, result_out); return e ? e : result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); }
    return next_entry(h, view, parent, cookie, out, position, found, result_out);
}
