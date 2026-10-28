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
#include <unistd.h>

#define CELL 4096u
#define ALIGNMENT UINT64_C(4096)
#define DATA_START UINT64_C(8192)
#define REF_SIZE 56u
#define SLOT_HASH 112u
#define PAGE_HEAD 640u
#define MAX_HEIGHT 16u
#define CACHE_COUNT 1000u
#define ARENA_COUNT 1024u
#define NO_CHILD UINT16_MAX
#define ARENA_BYTES (5u * 1024u * 1024u)
_Static_assert(sizeof(off_t) >= 8, "64-bit file offsets required");
_Static_assert(SFS_SNAPSHOT_MAX > 0 && SFS_SNAPSHOT_MAX <= 32, "snapshot limit");
enum { NAMESPACE = 2, ROOT = 4, INDEX = 5, RAW = 6 };
enum { MAP_INODE = 1, MAP_NAME = 2, MAP_EXTENT = 3, MAP_SNAPSHOT = 4 };
typedef struct { uint32_t type; uint64_t offset, length; uint8_t digest[32]; } reference;
typedef struct { uint16_t length; uint8_t bytes[263]; } key;
typedef struct { sfs_entry e; reference extent; } node;
typedef struct { uint64_t count, next_inode; reference inodes, names, ref; } namespace;
typedef struct { uint32_t view, length; uint8_t name[SFS_NAME_MAX]; reference ns; } snapshot;
typedef struct { uint64_t generation, end, capacity; uint8_t uuid[16]; reference root; } anchor;
typedef struct { namespace ns; uint32_t count; snapshot snapshots[SFS_SNAPSHOT_MAX]; reference catalog; } state;
typedef struct { reference ref; uint64_t stamp; uint8_t *bytes; } cache_entry;
typedef struct { cache_entry entries[CACHE_COUNT]; uint64_t clock; unsigned count; } cache;
typedef struct arena arena;
typedef struct tree tree;
typedef struct batch batch;
struct sfs_image {
    int fd, aux_parent, readonly, selected, poisoned, transaction;
    struct stat identity, parent_identity;
    uint64_t eof, epoch, token;
    anchor current, slots[2]; enum sfs_status slot_status[2]; int slot_error[2], slot_observed[2];
    state live, staged; enum sfs_phase phase; cache *cache; batch *batch;
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
typedef struct { unsigned map, level; int root, last; key lower, upper; uint64_t next_inode, eof; } context;
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
static void discard(sfs_image *h);
static void cache_clear(sfs_image *h) { if (!h->cache) return; for (unsigned i = 0; i < h->cache->count; ++i) free(h->cache->entries[i].bytes); free(h->cache); h->cache = NULL; }
static enum sfs_status result(sfs_image *h, enum sfs_status status, enum sfs_phase phase, int error, sfs_result *r) {
    if (r) { memset(r, 0, sizeof(*r)); r->status = status; r->phase = phase; r->system_errno = error;
        if (h) { r->generation = h->current.generation; r->committed_end = h->current.end; r->physical_end = h->eof; r->device = (uint64_t)h->identity.st_dev; r->inode = (uint64_t)h->identity.st_ino; memcpy(r->uuid, h->current.uuid, 16); memcpy(r->root_digest, h->current.root.digest, 32); }
    } return status;
}
static enum sfs_status ready(sfs_image *h, int writing, int tx, sfs_result *r) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (h->poisoned) return result(h, SFS_POISONED, h->phase, 0, r);
    if (!h->selected || (writing && h->readonly) || (tx && !h->transaction)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r); return SFS_OK;
}
static enum sfs_status read_result(sfs_image *h, enum sfs_status code, enum sfs_phase phase, int error, sfs_result *r) {
    if (h && !h->readonly && (code == SFS_IO || code == SFS_CORRUPT || code == SFS_RECOVERY_REQUIRED || code == SFS_UNSUPPORTED)) { h->poisoned = 1; h->phase = phase; discard(h); }
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
static enum sfs_status access_image(const char *directory, const char *name, int creating, int readonly,
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
    int flags = (readonly ? O_RDONLY : O_RDWR) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
    if (creating) flags |= O_CREAT | O_EXCL;
    int fd = openat(p, name, flags, 0600);
    if (fd < 0) { code = errno == EEXIST ? SFS_EXISTS : (errno == ELOOP ? SFS_INVALID : SFS_IO); goto fail; }
    sfs_image *h = calloc(1, sizeof(*h));
    if (!h) { error = ENOMEM; code = SFS_NOMEM; if (close(fd)) error = errno; goto fail_saved; }
    h->fd = fd; h->aux_parent = -1; h->readonly = readonly; h->parent_identity = ps;
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
static void hash_cell(const uint8_t b[CELL], unsigned type, const uint8_t uuid[16], uint8_t out[32]) {
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    if (type == RAW) { uint8_t domain[36] = {0}; memcpy(domain, "SFSDAT02", 8); memcpy(domain + 8, uuid, 16); put32(domain + 24, RAW); put64(domain + 28, CELL); CC_SHA256_Update(&ctx, domain, sizeof(domain)); }
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
    for (unsigned i = 0; i < c->count; ++i) if (same_ref(&c->entries[i].ref, ref)) { c->entries[i].stamp = ++c->clock; *out = c->entries[i].bytes; return SFS_OK; }
    e = charge(r, SFS_INCOMPLETE_METADATA_READ, CELL); if (e) return e;
    e = charge(r, SFS_INCOMPLETE_METADATA_HASH, CELL); if (e) return e;
    unsigned slot = c->count;
    if (slot == CACHE_COUNT) { slot = 0; for (unsigned i = 1; i < c->count; ++i) if (c->entries[i].stamp < c->entries[slot].stamp) slot = i; }
    else { c->entries[slot].bytes = malloc(CELL); if (!c->entries[slot].bytes) return SFS_NOMEM; c->count++; }
    cache_entry *v = &c->entries[slot]; memset(&v->ref, 0, sizeof(v->ref));
    if (read_exact(r->h->fd, v->bytes, CELL, ref->offset)) return io_failure(r, SFS_PHASE_READ);
    uint8_t digest[32]; hash_cell(v->bytes, type, r->a.uuid, digest);
    if (memcmp(digest, ref->digest, 32) || memcmp(v->bytes, "SFSREC02", 8) || get32(v->bytes + 8) != type || get32(v->bytes + 12) || get64(v->bytes + 16) != 4032 || memcmp(v->bytes + 24, r->a.uuid, 16) || !zero(v->bytes + 40, 24)) return SFS_CORRUPT;
    v->ref = *ref; v->stamp = ++c->clock; *out = v->bytes; return SFS_OK;
}
static enum sfs_status raw_read(reader *r, const reference *ref, uint64_t before, unsigned visible, uint8_t *out) {
    enum sfs_status e = bounds(r, ref, RAW, before); if (e) return e;
    if (!visible || visible > CELL) return SFS_CORRUPT;
    uint8_t entry[128]; e = memo(r, ref, entry, 0); if (e) return e;
    if ((get32(entry) & 2) && !out) return get64(entry + 56) <= visible ? SFS_OK : SFS_CORRUPT;
    e = charge(r, SFS_INCOMPLETE_RAW, 1); if (e) return e;
    uint8_t bytes[CELL], digest[32]; if (read_exact(r->h->fd, bytes, CELL, ref->offset)) return io_failure(r, SFS_PHASE_READ);
    hash_cell(bytes, RAW, r->a.uuid, digest); if (memcmp(digest, ref->digest, 32)) return SFS_CORRUPT;
    unsigned nonzero = CELL; while (nonzero && !bytes[nonzero - 1]) nonzero--; if (nonzero > visible) return SFS_CORRUPT;
    memset(entry, 0, sizeof(entry)); put32(entry, 2); put32(entry + 4, RAW); memcpy(entry + 8, ref->digest, 32); put64(entry + 56, nonzero);
    e = memo(r, ref, entry, 1); if (e) return e; if (out) memcpy(out, bytes, CELL); return SFS_OK;
}
static int keycmp(const key *a, const key *b) { size_t n = a->length < b->length ? a->length : b->length; int c = memcmp(a->bytes, b->bytes, n); return c ? c : a->length < b->length ? -1 : a->length > b->length; }
static key number_key(uint64_t v) { key k = { .length = 8 }; big64(k.bytes, v); return k; }
static key name_key(uint64_t parent, const void *name, size_t length) { key k = { .length = (uint16_t)(8 + length) }; big64(k.bytes, parent); if (length) memcpy(k.bytes + 8, name, length); return k; }
static unsigned page_level(const uint8_t *b) { return get16(b + 68); }
static unsigned page_count(const uint8_t *b) { return get16(b + 70); }
static unsigned stride(unsigned map, unsigned level) { return level ? (map == MAP_NAME ? 328 : 72) : map == MAP_INODE ? 352 : map == MAP_NAME ? 280 : map == MAP_EXTENT ? 72 : 328; }
static unsigned minimum(unsigned map, unsigned level) { return level ? (map == MAP_NAME ? 3 : 16) : map == MAP_INODE || map == MAP_SNAPSHOT ? 3 : map == MAP_NAME ? 4 : 16; }
static unsigned maximum(unsigned map, unsigned level) { return 3 * minimum(map, level); }
static const uint8_t *row_at(const uint8_t *b, unsigned map, unsigned i) { return b + PAGE_HEAD + stride(map, page_level(b)) * i; }
static key page_min(const uint8_t *b) { key k = { .length = get16(b + 88) }; if (k.length <= 263) memcpy(k.bytes, b + 112, k.length); return k; }
static key page_max(const uint8_t *b) { key k = { .length = get16(b + 90) }; if (k.length <= 263) memcpy(k.bytes, b + 375, k.length); return k; }
static key row_key(const uint8_t *v, unsigned map, unsigned level) { key k = {0}; if (level) { unsigned length = get32(v); if (length <= 263) { k.length = (uint16_t)length; memcpy(k.bytes, v + 8, k.length); } } else if (map == MAP_NAME) k = name_key(get64(v), v + 12, get32(v + 8) <= 255 ? get32(v + 8) : 0); else k = number_key(map == MAP_SNAPSHOT ? get32(v) : get64(v)); return k; }
static int child_ref(const uint8_t *v, unsigned map, reference *ref) { return decode_ref(v + (map == MAP_NAME ? 271 : 16), ref); }
static void put_child_ref(uint8_t *v, unsigned map, const reference *ref) { encode_ref(v + (map == MAP_NAME ? 271 : 16), ref); }
static context root_context(unsigned map, unsigned level, uint64_t next, uint64_t eof) { context c; memset(&c, 0, sizeof(c)); c.map = map; c.level = level; c.root = 1; c.next_inode = next; c.eof = eof; return c; }
static context child_context(const uint8_t *b, unsigned i, context c) { c.root = 0; c.level--; c.lower = row_key(row_at(b, c.map, i), c.map, c.level + 1); c.last = i + 1 == page_count(b); c.upper = c.last ? page_max(b) : row_key(row_at(b, c.map, i + 1), c.map, c.level + 1); return c; }
static enum sfs_status page_read(reader *r, const reference *ref, uint64_t before, context c, const uint8_t **out) {
    enum sfs_status e = metadata(r, ref, INDEX, before, out); if (e) return e;
    e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
    const uint8_t *b = *out; unsigned n = page_count(b), level = page_level(b); key min = page_min(b), max = page_max(b);
    if (c.map < MAP_INODE || c.map > MAP_SNAPSHOT || get32(b + 64) != c.map || level != c.level || level >= MAX_HEIGHT || !n || n > maximum(c.map, level) || n < (c.root ? (level ? 2 : 1) : minimum(c.map, level)) || !get64(b + 72) || get64(b + 72) > r->a.generation || !zero(b + 80, 8) || !zero(b + 92, 20) || !zero(b + 638, 2)) return SFS_CORRUPT;
    if (min.length < (c.map == MAP_NAME ? 9 : 8) || min.length > (c.map == MAP_NAME ? 263 : 8) || max.length < (c.map == MAP_NAME ? 9 : 8) || max.length > (c.map == MAP_NAME ? 263 : 8) || !zero(b + 112 + min.length, 263 - min.length) || !zero(b + 375 + max.length, 263 - max.length) || keycmp(&min, &max) > 0) return SFS_CORRUPT;
    if (!c.root && (keycmp(&min, &c.lower) || (c.last ? keycmp(&max, &c.upper) != 0 : keycmp(&max, &c.upper) >= 0))) return SFS_CORRUPT;
    unsigned step = stride(c.map, level); if (!zero(b + PAGE_HEAD + step * n, CELL - PAGE_HEAD - step * n)) return SFS_CORRUPT;
    key previous = {0};
    for (unsigned i = 0; i < n; ++i) {
        e = charge(r, SFS_INCOMPLETE_CHECKS, 1); if (e) return e;
        const uint8_t *v = row_at(b, c.map, i); key k = row_key(v, c.map, level);
        if (keycmp(&k, &max) > 0 || (i && keycmp(&previous, &k) >= 0) || (!i && keycmp(&min, &k))) return SFS_CORRUPT; previous = k;
        if (level) { reference child; unsigned len = get32(v), maxlen = c.map == MAP_NAME ? 263 : 8;
            if (len < (c.map == MAP_NAME ? 9u : 8u) || len > maxlen || get32(v + 4) || !zero(v + 8 + len, maxlen - len) || (c.map == MAP_NAME && v[327]) || !child_ref(v, c.map, &child)) return SFS_CORRUPT;
            e = bounds(r, &child, INDEX, ref->offset); if (e) return e;
        } else if (c.map == MAP_EXTENT) { reference data; uint64_t block = get64(v); unsigned visible = get16(v + 64);
            if (!decode_ref(v + 8, &data) || !visible || visible > CELL || !zero(v + 66, 6) || block > UINT64_MAX / CELL || block * CELL >= c.eof || visible > c.eof - block * CELL) return SFS_CORRUPT;
            e = bounds(r, &data, RAW, ref->offset); if (e) return e;
        } else if (c.map == MAP_INODE) { reference ext; uint64_t id = get64(v), parent = get64(v + 8), size = get64(v + 24); unsigned kind = get32(v + 16), len = get32(v + 20);
            if (id < 2 || id >= c.next_inode || !parent || parent >= c.next_inode || (kind != SFS_FILE && kind != SFS_DIRECTORY) || !valid_name(v + 88, len) || !zero(v + 88 + len, 264 - len) || size > SFS_FILE_MAX || !decode_ref(v + 32, &ext) || ((kind == SFS_DIRECTORY || !size) && ext.type) || (kind == SFS_DIRECTORY && size)) return SFS_CORRUPT;
            if (ext.type) { e = bounds(r, &ext, INDEX, ref->offset); if (e) return e; }
        } else if (c.map == MAP_NAME) { uint64_t parent = get64(v), id = get64(v + 267); unsigned len = get32(v + 8);
            if (!parent || parent >= c.next_inode || id < 2 || id >= c.next_inode || !valid_name(v + 12, len) || !zero(v + 12 + len, 255 - len) || !zero(v + 275, 5)) return SFS_CORRUPT;
        } else { reference ns; unsigned id = get32(v), len = get32(v + 64);
            if (!id || id > SFS_SNAPSHOT_MAX || get32(v + 4) || !decode_ref(v + 8, &ns) || !valid_name(v + 68, len) || !zero(v + 68 + len, 260 - len)) return SFS_CORRUPT;
            e = bounds(r, &ns, NAMESPACE, ref->offset); if (e) return e;
        }
    }
    if (!level && keycmp(&previous, &max)) return SFS_CORRUPT; return SFS_OK;
}
static enum sfs_status root_page(reader *r, const reference *ref, unsigned map, uint64_t next, uint64_t eof, const uint8_t **out) {
    const uint8_t *b; enum sfs_status e = metadata(r, ref, INDEX, r->a.end, &b); if (e) return e;
    unsigned level = page_level(b); if (level >= MAX_HEIGHT) return SFS_CORRUPT; return page_read(r, ref, r->a.end, root_context(map, level, next, eof), out);
}

typedef struct { reference ref; uint64_t before; context context; unsigned index; } cursor_frame;
typedef struct { reader *reader; cursor_frame frames[MAX_HEIGHT]; unsigned depth, map; uint64_t next_inode, eof; } cursor;
static enum sfs_status cursor_start(cursor *c, reader *r, reference root, unsigned map, uint64_t next, uint64_t eof, const key *seek) {
    memset(c, 0, sizeof(*c)); c->reader = r; c->map = map; c->next_inode = next; c->eof = eof;
    if (!root.type) return SFS_OK;
    const uint8_t *b; enum sfs_status e = root_page(r, &root, map, next, eof, &b); if (e) return e;
    c->frames[0] = (cursor_frame){ .ref = root, .before = r->a.end, .context = root_context(map, page_level(b), next, eof) }; c->depth = 1;
    if (!seek) return SFS_OK;
    for (;;) {
        cursor_frame *f = &c->frames[c->depth - 1]; e = page_read(r, &f->ref, f->before, f->context, &b); if (e) return e;
        unsigned n = page_count(b), i = 0;
        if (!f->context.level) { while (i < n) { key k = row_key(row_at(b, map, i), map, 0); if (keycmp(&k, seek) >= 0) break; i++; } f->index = i; return SFS_OK; }
        while (i + 1 < n) { key k = row_key(row_at(b, map, i + 1), map, f->context.level); if (keycmp(&k, seek) > 0) break; i++; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, map, i), map, &child)) return SFS_CORRUPT;
        context ctx = child_context(b, i, f->context); f->index = i + 1;
        c->frames[c->depth++] = (cursor_frame){ .ref = child, .before = f->ref.offset, .context = ctx };
    }
}
static enum sfs_status cursor_next(cursor *c, uint8_t out[352], int *found) {
    *found = 0;
    while (c->depth) {
        cursor_frame *f = &c->frames[c->depth - 1]; const uint8_t *b;
        enum sfs_status e = page_read(c->reader, &f->ref, f->before, f->context, &b); if (e) return e;
        unsigned n = page_count(b); if (f->index > n) return SFS_CORRUPT;
        if (f->index == n) { c->depth--; continue; }
        unsigned i = f->index++;
        if (!f->context.level) { memset(out, 0, 352); memcpy(out, row_at(b, c->map, i), stride(c->map, 0)); *found = 1; return SFS_OK; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, c->map, i), c->map, &child)) return SFS_CORRUPT;
        context ctx = child_context(b, i, f->context);
        c->frames[c->depth++] = (cursor_frame){ .ref = child, .before = f->ref.offset, .context = ctx };
    } return SFS_OK;
}
static enum sfs_status index_get(reader *r, reference root, unsigned map, uint64_t next, uint64_t eof, const key *k, uint8_t out[352], int *found) {
    cursor c; enum sfs_status e = cursor_start(&c, r, root, map, next, eof, k); if (e) return e;
    e = cursor_next(&c, out, found); if (!e && *found) { key actual = row_key(out, map, 0); if (keycmp(&actual, k)) *found = 0; } return e;
}
static enum sfs_status namespace_read(reader *r, reference ref, uint64_t before, namespace *ns) {
    const uint8_t *b; enum sfs_status e = metadata(r, &ref, NAMESPACE, before, &b); if (e) return e;
    namespace n = { .ref = ref, .next_inode = get64(b + 176), .count = get64(b + 184) };
    if (!decode_ref(b + 64, &n.inodes) || !decode_ref(b + 120, &n.names) || !zero(b + 192, CELL - 192) || n.next_inode < 2 || n.count > SFS_ENTRY_MAX || n.count > 9 * (r->a.end / CELL) || (!!n.count != !!n.inodes.type) || (!!n.count != !!n.names.type)) return SFS_CORRUPT;
    if (n.count) { e = bounds(r, &n.inodes, INDEX, ref.offset); if (e) return e; e = bounds(r, &n.names, INDEX, ref.offset); if (e) return e;
        e = root_page(r, &n.inodes, MAP_INODE, n.next_inode, UINT64_MAX, &b); if (e) return e;
        e = root_page(r, &n.names, MAP_NAME, n.next_inode, UINT64_MAX, &b); if (e) return e;
    }
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
    uint8_t row[352]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found) {
        if (s->count == SFS_SNAPSHOT_MAX) return SFS_CORRUPT;
        snapshot *snap = &s->snapshots[s->count]; snap->view = get32(row); snap->length = get32(row + 64); memcpy(snap->name, row + 68, snap->length);
        if (!decode_ref(row + 8, &snap->ns)) return SFS_CORRUPT;
        for (unsigned i = 0; i < s->count; ++i) if (s->snapshots[i].length == snap->length && !memcmp(s->snapshots[i].name, snap->name, snap->length)) return SFS_CORRUPT;
        namespace view; e = namespace_read(r, snap->ns, catalog.offset, &view); if (e) return e;
        if (view.next_inode > s->ns.next_inode) return SFS_CORRUPT; s->count++;
    } return e;
}
static void decode_node(const uint8_t row[352], node *n) {
    memset(n, 0, sizeof(*n)); n->e.inode = get64(row); n->e.parent = get64(row + 8); n->e.kind = (enum sfs_kind)get32(row + 16); n->e.name_length = get32(row + 20); n->e.size = get64(row + 24); decode_ref(row + 32, &n->extent); memcpy(n->e.name, row + 88, n->e.name_length);
}
static void encode_node(uint8_t row[352], const node *n) {
    memset(row, 0, 352); put64(row, n->e.inode); put64(row + 8, n->e.parent); put32(row + 16, n->e.kind); put32(row + 20, (uint32_t)n->e.name_length); put64(row + 24, n->e.size); encode_ref(row + 32, &n->extent); memcpy(row + 88, n->e.name, n->e.name_length);
}
static void encode_name(uint8_t row[352], const node *n) { memset(row, 0, 352); put64(row, n->e.parent); put32(row + 8, (uint32_t)n->e.name_length); memcpy(row + 12, n->e.name, n->e.name_length); put64(row + 267, n->e.inode); }
static enum sfs_status node_get(reader *r, const namespace *ns, sfs_inode id, int canonical, node *out) {
    if (id == 1) { memset(out, 0, sizeof(*out)); out->e.inode = out->e.parent = 1; out->e.kind = SFS_DIRECTORY; return SFS_OK; }
    key k = number_key(id); uint8_t row[352]; int found; enum sfs_status e = index_get(r, ns->inodes, MAP_INODE, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e; if (!found) return SFS_NOT_FOUND;
    decode_node(row, out);
    if (canonical) { k = name_key(out->e.parent, out->e.name, out->e.name_length); e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e; if (!found || get64(row + 267) != id) return SFS_CORRUPT; }
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
    uint8_t row[352]; int found; e = cursor_next(&c, row, &found); if (e || !found) return e;
    if (!(old_size % CELL) || get64(row) != old_size / CELL || get16(row + 64) > old_size % CELL) return SFS_CORRUPT;
    e = cursor_next(&c, row, &found); return e ? e : found ? SFS_CORRUPT : SFS_OK;
}

typedef struct { uint8_t bytes[CELL]; reference source; uint64_t owner, token; unsigned map; uint16_t children[48]; int dirty; } overlay_page;
struct arena { overlay_page *pages[ARENA_COUNT]; unsigned used; uint64_t epoch, batch; reference lineage; };
struct tree { arena *arena; reader *reader; reference source; int root; unsigned map; uint64_t owner, next_inode, eof; };
struct batch { arena *arena; tree extent; node inode; uint64_t low, high, number; };
_Static_assert(sizeof(arena) + ARENA_COUNT * sizeof(overlay_page) + 17 * CELL <= ARENA_BYTES, "bounded overlay including merge cells");
static void arena_free(arena *a) { if (!a) return; for (unsigned i = 0; i < a->used; ++i) free(a->pages[i]); free(a); }
static arena *arena_new(sfs_image *h, uint64_t batch_number) { arena *a = calloc(1, sizeof(*a)); if (a) { a->epoch = h->epoch; a->batch = batch_number; a->lineage = h->staged.ns.ref; } return a; }
static void discard(sfs_image *h) { if (h->batch) { arena_free(h->batch->arena); free(h->batch); h->batch = NULL; } memset(&h->staged, 0, sizeof(h->staged)); h->transaction = 0; }
static void envelope(uint8_t b[CELL], unsigned type, const uint8_t uuid[16]) { memset(b, 0, CELL); memcpy(b, "SFSREC02", 8); put32(b + 8, type); put64(b + 16, CELL - 64); memcpy(b + 24, uuid, 16); }
static int arena_add(tree *t, unsigned level) {
    arena *a = t->arena; unsigned i = 0; while (i < a->used && a->pages[i]) i++; if (i == ARENA_COUNT || t->reader->h->token == UINT64_MAX) return -1;
    overlay_page *p = calloc(1, sizeof(*p)); if (!p) return -1;
    for (unsigned j = 0; j < 48; ++j) p->children[j] = NO_CHILD;
    p->map = t->map; p->owner = t->owner; p->token = ++t->reader->h->token; p->dirty = 1;
    envelope(p->bytes, INDEX, t->reader->a.uuid); put32(p->bytes + 64, t->map); put16(p->bytes + 68, level); put64(p->bytes + 72, t->reader->a.generation);
    a->pages[i] = p; if (i == a->used) a->used++; return (int)i;
}
static overlay_page *owned_page(tree *t, unsigned id) { if (id >= t->arena->used) return NULL; overlay_page *p = t->arena->pages[id]; return p && p->token && p->owner == t->owner && p->map == t->map ? p : NULL; }
static enum sfs_status tree_load(tree *t, reference ref, uint64_t before, context ctx, int *id) {
    const uint8_t *b; enum sfs_status e = page_read(t->reader, &ref, before, ctx, &b); if (e) return e;
    int n = arena_add(t, ctx.level); if (n < 0) return SFS_NOMEM;
    overlay_page *p = t->arena->pages[n]; memcpy(p->bytes, b, CELL); p->source = ref; p->dirty = 0;
    /* Check original immediate edges before rows can move during split/borrow/merge. */
    if (ctx.level) for (unsigned i = 0; i < page_count(p->bytes); ++i) { reference child; if (!child_ref(row_at(p->bytes, t->map, i), t->map, &child)) return SFS_CORRUPT;
        e = page_read(t->reader, &child, ref.offset, child_context(p->bytes, i, ctx), &b); if (e) return e;
    }
    *id = n; return SFS_OK;
}
static enum sfs_status tree_root(tree *t) {
    if (t->root >= 0) return SFS_OK;
    if (!t->source.type) { t->root = arena_add(t, 0); return t->root < 0 ? SFS_NOMEM : SFS_OK; }
    const uint8_t *b; enum sfs_status e = root_page(t->reader, &t->source, t->map, t->next_inode, t->eof, &b); if (e) return e;
    return tree_load(t, t->source, t->reader->a.end, root_context(t->map, page_level(b), t->next_inode, t->eof), &t->root);
}
static enum sfs_status shadow_child_mode(tree *t, unsigned parent, unsigned index, unsigned *out, int recomputing_max) {
    overlay_page *p = owned_page(t, parent); if (!p || !page_level(p->bytes) || index >= page_count(p->bytes)) return SFS_CORRUPT;
    if (p->children[index] != NO_CHILD) { if (!owned_page(t, p->children[index])) return SFS_CORRUPT; *out = p->children[index]; return SFS_OK; }
    reference ref; if (!child_ref(row_at(p->bytes, t->map, index), t->map, &ref)) return SFS_CORRUPT;
    const uint8_t *b; context ctx = root_context(t->map, page_level(p->bytes) - 1, t->next_inode, t->eof);
    if (!recomputing_max) ctx = child_context(p->bytes, index, root_context(t->map, page_level(p->bytes), t->next_inode, t->eof));
    enum sfs_status e = page_read(t->reader, &ref, t->reader->a.end, ctx, &b); if (e) return e;
    key min = page_min(b), expected = row_key(row_at(p->bytes, t->map, index), t->map, page_level(p->bytes));
    if (page_count(b) < minimum(t->map, ctx.level) || keycmp(&min, &expected)) return SFS_CORRUPT;
    int id; e = tree_load(t, ref, t->reader->a.end, ctx, &id); if (e) return e;
    p->children[index] = (uint16_t)id; *out = (unsigned)id; return SFS_OK;
}
static enum sfs_status shadow_child(tree *t, unsigned parent, unsigned index, unsigned *out) { return shadow_child_mode(t, parent, index, out, 0); }
static void set_page_range(uint8_t b[CELL], key min, key max) { put16(b + 88, min.length); put16(b + 90, max.length); memset(b + 112, 0, 263); memset(b + 375, 0, 263); memcpy(b + 112, min.bytes, min.length); memcpy(b + 375, max.bytes, max.length); }
static enum sfs_status refresh(tree *t, unsigned id) {
    overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT;
    unsigned n = page_count(p->bytes), level = page_level(p->bytes), step = stride(t->map, level);
    if (!n) { set_page_range(p->bytes, (key){0}, (key){0}); memset(p->bytes + PAGE_HEAD, 0, CELL - PAGE_HEAD); return SFS_OK; }
    key min, max;
    if (!level) { min = row_key(row_at(p->bytes, t->map, 0), t->map, 0); max = row_key(row_at(p->bytes, t->map, n - 1), t->map, 0); }
    else {
        for (unsigned i = 0; i < n; ++i) if (p->children[i] != NO_CHILD) { overlay_page *child = owned_page(t, p->children[i]); if (!child) return SFS_CORRUPT;
            key k = page_min(child->bytes); uint8_t *v = p->bytes + PAGE_HEAD + i * step; reference old; if (!child_ref(v, t->map, &old)) return SFS_CORRUPT;
            memset(v, 0, step); put32(v, k.length); memcpy(v + 8, k.bytes, k.length); put_child_ref(v, t->map, &old);
        }
        min = row_key(row_at(p->bytes, t->map, 0), t->map, level);
        /* The original edge was checked before movement; its new maximum is being computed here. */
        unsigned last; enum sfs_status e = shadow_child_mode(t, id, n - 1, &last, 1); if (e) return e; max = page_max(t->arena->pages[last]->bytes);
    }
    set_page_range(p->bytes, min, max); memset(p->bytes + PAGE_HEAD + n * step, 0, CELL - PAGE_HEAD - n * step); return SFS_OK;
}
static void shift_rows(overlay_page *p, unsigned map, unsigned to, unsigned from, unsigned n) {
    unsigned step = stride(map, page_level(p->bytes)); if (n) { memmove(p->bytes + PAGE_HEAD + to * step, p->bytes + PAGE_HEAD + from * step, n * step); memmove(p->children + to, p->children + from, n * sizeof(uint16_t)); }
}
static enum sfs_status split_child(tree *t, unsigned parent_id, unsigned at) {
    unsigned left_id; enum sfs_status e = shadow_child(t, parent_id, at, &left_id); if (e) return e;
    overlay_page *parent = t->arena->pages[parent_id], *left = t->arena->pages[left_id]; unsigned level = page_level(left->bytes), n = page_count(left->bytes), split = n / 2, step = stride(t->map, level);
    if (n != maximum(t->map, level) || page_count(parent->bytes) >= maximum(t->map, level + 1)) return SFS_CORRUPT;
    int right_id = arena_add(t, level); if (right_id < 0) return SFS_NOMEM; overlay_page *right = t->arena->pages[right_id];
    if (t->reader->h->token == UINT64_MAX) return SFS_LIMIT; left->token = ++t->reader->h->token;
    memcpy(right->bytes + PAGE_HEAD, left->bytes + PAGE_HEAD + split * step, (n - split) * step); memcpy(right->children, left->children + split, (n - split) * sizeof(uint16_t));
    put16(left->bytes + 70, split); put16(right->bytes + 70, n - split); left->dirty = 1;
    for (unsigned i = split; i < 48; ++i) left->children[i] = NO_CHILD;
    unsigned pn = page_count(parent->bytes); shift_rows(parent, t->map, at + 2, at + 1, pn - at - 1); parent->children[at + 1] = (uint16_t)right_id;
    unsigned pstep = stride(t->map, level + 1); memset(parent->bytes + PAGE_HEAD + (at + 1) * pstep, 0, pstep); put16(parent->bytes + 70, pn + 1); parent->dirty = 1;
    e = refresh(t, left_id); if (!e) e = refresh(t, (unsigned)right_id); if (!e) e = refresh(t, parent_id); return e;
}
static enum sfs_status tree_search(tree *t, const key *k, unsigned path[MAX_HEIGHT], unsigned *depth, unsigned *at, int *found) {
    *depth = 0; *found = 0; if (!t->source.type && t->root < 0) return SFS_OK;
    enum sfs_status e = tree_root(t); if (e) return e; unsigned id = (unsigned)t->root;
    for (;;) {
        if (*depth == MAX_HEIGHT) return SFS_CORRUPT; path[(*depth)++] = id;
        overlay_page *p = owned_page(t, id); if (!p) return SFS_CORRUPT; unsigned n = page_count(p->bytes), level = page_level(p->bytes), i = 0;
        if (!level) { while (i < n) { key row = row_key(row_at(p->bytes, t->map, i), t->map, 0); int cmp = keycmp(&row, k); if (cmp >= 0) { *found = !cmp; break; } i++; } *at = i; return SFS_OK; }
        while (i + 1 < n) { key row = row_key(row_at(p->bytes, t->map, i + 1), t->map, level); if (keycmp(&row, k) > 0) break; i++; }
        e = shadow_child(t, id, i, &id); if (e) return e;
    }
}
static enum sfs_status tree_put(tree *t, const uint8_t row[352]) {
    key k = row_key(row, t->map, 0); unsigned path[MAX_HEIGHT], depth, at = 0; int found;
    enum sfs_status e = tree_search(t, &k, path, &depth, &at, &found); if (e) return e;
    if (found) { overlay_page *leaf = t->arena->pages[path[depth - 1]]; memcpy(leaf->bytes + PAGE_HEAD + at * stride(t->map, 0), row, stride(t->map, 0));
        while (depth) { unsigned id = path[--depth]; t->arena->pages[id]->dirty = 1; e = refresh(t, id); if (e) return e; } return SFS_OK;
    }
    e = tree_root(t); if (e) return e;
    overlay_page *root = t->arena->pages[t->root]; unsigned level = page_level(root->bytes);
    if (page_count(root->bytes) == maximum(t->map, level)) {
        if (level + 1 == MAX_HEIGHT) return SFS_LIMIT;
        unsigned old = (unsigned)t->root; int parent = arena_add(t, level + 1); if (parent < 0) return SFS_NOMEM;
        t->root = parent; overlay_page *p = t->arena->pages[parent]; p->children[0] = (uint16_t)old; put16(p->bytes + 70, 1);
        e = split_child(t, (unsigned)parent, 0); if (e) return e;
    }
    unsigned id = (unsigned)t->root; depth = 0;
    for (;;) {
        if (depth == MAX_HEIGHT) return SFS_CORRUPT; path[depth++] = id; overlay_page *p = t->arena->pages[id]; unsigned n = page_count(p->bytes); level = page_level(p->bytes); unsigned i = 0;
        if (!level) { while (i < n) { key v = row_key(row_at(p->bytes, t->map, i), t->map, 0); if (keycmp(&v, &k) > 0) break; i++; }
            shift_rows(p, t->map, i + 1, i, n - i); memcpy(p->bytes + PAGE_HEAD + i * stride(t->map, 0), row, stride(t->map, 0)); p->children[i] = NO_CHILD; put16(p->bytes + 70, n + 1); break;
        }
        while (i + 1 < n) { key v = row_key(row_at(p->bytes, t->map, i + 1), t->map, level); if (keycmp(&v, &k) > 0) break; i++; }
        unsigned child; e = shadow_child(t, id, i, &child); if (e) return e;
        if (page_count(t->arena->pages[child]->bytes) == maximum(t->map, level - 1)) { e = split_child(t, id, i); if (e) return e; key right = page_min(t->arena->pages[p->children[i + 1]]->bytes); if (keycmp(&k, &right) >= 0) i++; child = p->children[i]; }
        id = child;
    }
    while (depth) { id = path[--depth]; t->arena->pages[id]->dirty = 1; e = refresh(t, id); if (e) return e; } return SFS_OK;
}
static enum sfs_status rebalance_child(tree *t, unsigned parent_id, unsigned *at, unsigned *child_id) {
    overlay_page *parent = t->arena->pages[parent_id]; unsigned id; enum sfs_status e = shadow_child(t, parent_id, *at, &id); if (e) return e;
    overlay_page *child = t->arena->pages[id]; unsigned level = page_level(child->bytes), n = page_count(child->bytes), b = minimum(t->map, level), step = stride(t->map, level); *child_id = id;
    if (n > b) return SFS_OK; if (n != b) return SFS_CORRUPT;
    unsigned left = NO_CHILD, right = NO_CHILD;
    if (*at) { e = shadow_child(t, parent_id, *at - 1, &left); if (e) return e; }
    if (*at + 1 < page_count(parent->bytes)) { e = shadow_child(t, parent_id, *at + 1, &right); if (e) return e; }
    if (left != NO_CHILD && page_count(t->arena->pages[left]->bytes) > b) {
        overlay_page *s = t->arena->pages[left]; unsigned sn = page_count(s->bytes); shift_rows(child, t->map, 1, 0, n); memcpy(child->bytes + PAGE_HEAD, row_at(s->bytes, t->map, sn - 1), step); child->children[0] = s->children[sn - 1]; s->children[sn - 1] = NO_CHILD;
        put16(s->bytes + 70, sn - 1); put16(child->bytes + 70, n + 1); s->dirty = child->dirty = parent->dirty = 1; e = refresh(t, left); if (!e) e = refresh(t, id); if (!e) e = refresh(t, parent_id); return e;
    }
    if (right != NO_CHILD && page_count(t->arena->pages[right]->bytes) > b) {
        overlay_page *s = t->arena->pages[right]; unsigned sn = page_count(s->bytes); memcpy(child->bytes + PAGE_HEAD + n * step, s->bytes + PAGE_HEAD, step); child->children[n] = s->children[0]; shift_rows(s, t->map, 0, 1, sn - 1); s->children[sn - 1] = NO_CHILD;
        put16(s->bytes + 70, sn - 1); put16(child->bytes + 70, n + 1); s->dirty = child->dirty = parent->dirty = 1; e = refresh(t, right); if (!e) e = refresh(t, id); if (!e) e = refresh(t, parent_id); return e;
    }
    unsigned first = right != NO_CHILD ? id : left, second = right != NO_CHILD ? right : id, remove = right != NO_CHILD ? *at + 1 : *at;
    if (first == NO_CHILD || second == NO_CHILD) return SFS_CORRUPT;
    overlay_page *l = t->arena->pages[first], *rr = t->arena->pages[second]; unsigned ln = page_count(l->bytes), rn = page_count(rr->bytes);
    if (ln + rn > maximum(t->map, level)) return SFS_CORRUPT;
    if (t->reader->h->token == UINT64_MAX) return SFS_LIMIT; l->token = ++t->reader->h->token;
    memcpy(l->bytes + PAGE_HEAD + ln * step, rr->bytes + PAGE_HEAD, rn * step); memcpy(l->children + ln, rr->children, rn * sizeof(uint16_t)); put16(l->bytes + 70, ln + rn); l->dirty = parent->dirty = 1;
    unsigned pn = page_count(parent->bytes); shift_rows(parent, t->map, remove, remove + 1, pn - remove - 1); parent->children[pn - 1] = NO_CHILD; put16(parent->bytes + 70, pn - 1);
    free(rr); t->arena->pages[second] = NULL; if (right == NO_CHILD) (*at)--; *child_id = first;
    e = refresh(t, first); if (!e) e = refresh(t, parent_id); return e;
}
static enum sfs_status delete_page(tree *t, unsigned id, const key *k) {
    overlay_page *p = t->arena->pages[id]; unsigned level = page_level(p->bytes), n = page_count(p->bytes), i = 0;
    if (!level) {
        while (i < n) { key v = row_key(row_at(p->bytes, t->map, i), t->map, 0); if (!keycmp(&v, k)) break; i++; }
        if (i == n) return SFS_CORRUPT; shift_rows(p, t->map, i, i + 1, n - i - 1); p->children[n - 1] = NO_CHILD; put16(p->bytes + 70, n - 1);
    } else {
        while (i + 1 < n) { key v = row_key(row_at(p->bytes, t->map, i + 1), t->map, level); if (keycmp(&v, k) > 0) break; i++; }
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
static int reserve_cells(sfs_image *h, uint64_t cells) { uint64_t at; return aligned(h->eof < DATA_START ? DATA_START : h->eof, &at) && cells <= UINT64_MAX / CELL && at <= h->current.capacity && cells * CELL <= h->current.capacity - at; }
static enum sfs_status append_prepared(sfs_image *h, unsigned type, const uint8_t b[CELL], reference *out, uint64_t *remaining, const reference *prepared) {
    if (!*remaining || !reserve_cells(h, 1)) return SFS_LIMIT;
    uint64_t at; if (!aligned(h->eof < DATA_START ? DATA_START : h->eof, &at)) return SFS_LIMIT;
    if (stable(h)) return SFS_IO;
    reference ref = { .type = type, .offset = at, .length = CELL }; if (prepared) { if (prepared->type != type || prepared->offset != at || prepared->length != CELL) return SFS_CORRUPT; ref = *prepared; } else hash_cell(b, type, h->current.uuid, ref.digest);
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
    if (level) for (unsigned i = 0; i < page_count(p->bytes); ++i) if (p->children[i] != NO_CHILD) { reference child; enum sfs_status e = seal_page(t, p->children[i], &child, remaining); if (e) return e; put_child_ref(p->bytes + PAGE_HEAD + i * stride(t->map, level), t->map, &child); }
    put64(p->bytes + 72, t->reader->a.generation);
    enum sfs_status e = append_cell(t->reader->h, INDEX, p->bytes, out, remaining); if (!e) { p->source = *out; p->dirty = 0; } return e;
}
static enum sfs_status seal_tree(tree *t, reference *out, uint64_t *remaining) { if (t->root < 0) { *out = t->source; return SFS_OK; } return seal_page(t, (unsigned)t->root, out, remaining); }
static arena *arena_clone(arena *old) {
    arena *a = calloc(1, sizeof(*a)); if (!a) return NULL; a->used = old->used; a->epoch = old->epoch; a->batch = old->batch; a->lineage = old->lineage;
    for (unsigned i = 0; i < old->used; ++i) if (old->pages[i]) { a->pages[i] = malloc(sizeof(overlay_page)); if (!a->pages[i]) { arena_free(a); return NULL; } memcpy(a->pages[i], old->pages[i], sizeof(overlay_page)); } return a;
}
static reader current_reader(sfs_image *h, int staged) { reader r; memset(&r, 0, sizeof(r)); r.h = h; r.a = h->current; r.phase = SFS_PHASE_READ; if (staged) { r.a.end = h->eof; r.a.generation++; } return r; }
static tree make_tree(arena *a, reader *r, reference source, unsigned map, uint64_t owner, uint64_t next, uint64_t eof) { return (tree){ .arena = a, .reader = r, .source = source, .root = -1, .map = map, .owner = owner, .next_inode = next, .eof = eof }; }
static enum sfs_status mutation_failure(sfs_image *h, enum sfs_status e, enum sfs_phase phase, int error, int late, sfs_result *result_out) {
    if (e == SFS_LIMIT || late || e == SFS_IO || e == SFS_CORRUPT || e == SFS_UNSUPPORTED || e == SFS_RECOVERY_REQUIRED) discard(h);
    if (e == SFS_IO || e == SFS_CORRUPT || e == SFS_UNSUPPORTED || e == SFS_RECOVERY_REQUIRED) { h->poisoned = 1; h->phase = phase; }
    return result(h, e, e == SFS_LIMIT ? SFS_PHASE_ADMISSION : phase, e == SFS_IO || e == SFS_RECOVERY_REQUIRED ? error : e == SFS_NOMEM ? ENOMEM : 0, result_out);
}
static enum sfs_status write_namespace(sfs_image *h, namespace *ns, uint64_t *remaining) {
    uint8_t b[CELL]; envelope(b, NAMESPACE, h->current.uuid); encode_ref(b + 64, &ns->inodes); encode_ref(b + 120, &ns->names); put64(b + 176, ns->next_inode); put64(b + 184, ns->count); return append_cell(h, NAMESPACE, b, &ns->ref, remaining);
}

typedef struct { uint64_t count, max_inode, max_end; } summary;
static enum sfs_status intrinsic(reader *r, reference ref, uint64_t before, context ctx, summary *out) {
    const uint8_t *source; enum sfs_status e = page_read(r, &ref, before, ctx, &source); if (e) return e;
    uint8_t entry[128]; e = memo(r, &ref, entry, 0); if (e) return e;
    if (get32(entry) == 1) return SFS_CORRUPT;
    if (get32(entry) & 2) { *out = (summary){ get64(entry + 40), get64(entry + 48), get64(entry + 56) };
        if ((ctx.map == MAP_INODE || ctx.map == MAP_NAME) && out->max_inode >= ctx.next_inode) return SFS_CORRUPT;
        if (ctx.map == MAP_EXTENT && out->max_end > ctx.eof) return SFS_CORRUPT; return SFS_OK;
    }
    memset(entry, 0, sizeof(entry)); put32(entry, 1); put32(entry + 4, INDEX); memcpy(entry + 8, ref.digest, 32); e = memo(r, &ref, entry, 1); if (e) return e;
    uint8_t b[CELL]; memcpy(b, source, CELL); summary s = {0}; unsigned n = page_count(b);
    for (unsigned i = 0; i < n; ++i) {
        const uint8_t *v = row_at(b, ctx.map, i);
        if (ctx.level) { reference child; if (!child_ref(v, ctx.map, &child)) return SFS_CORRUPT; summary cs;
            e = intrinsic(r, child, ref.offset, child_context(b, i, ctx), &cs); if (e) return e;
            if (!add64(s.count, cs.count, &s.count)) return SFS_CORRUPT; if (cs.max_inode > s.max_inode) s.max_inode = cs.max_inode; if (cs.max_end > s.max_end) s.max_end = cs.max_end;
        } else {
            s.count++;
            if (ctx.map == MAP_INODE || ctx.map == MAP_NAME) { uint64_t id = ctx.map == MAP_INODE ? get64(v) : get64(v + 267), parent = get64(v + (ctx.map == MAP_INODE ? 8 : 0)); if (id > s.max_inode) s.max_inode = id; if (parent > s.max_inode) s.max_inode = parent; }
            if (ctx.map == MAP_EXTENT) { reference data; if (!decode_ref(v + 8, &data)) return SFS_CORRUPT; e = raw_read(r, &data, ref.offset, get16(v + 64), NULL); if (e) return e;
                uint64_t end; if (!add64(get64(v) * CELL, get16(v + 64), &end)) return SFS_CORRUPT; if (end > s.max_end) s.max_end = end;
            }
        }
    }
    put32(entry, 2); put64(entry + 40, s.count); put64(entry + 48, s.max_inode); put64(entry + 56, s.max_end); e = memo(r, &ref, entry, 1); if (!e) *out = s; return e;
}
static enum sfs_status intrinsic_root(reader *r, reference ref, unsigned map, uint64_t next, uint64_t eof, summary *out) {
    memset(out, 0, sizeof(*out)); if (!ref.type) return SFS_OK;
    const uint8_t *b; enum sfs_status e = root_page(r, &ref, map, next, eof, &b); if (e) return e;
    return intrinsic(r, ref, r->a.end, root_context(map, page_level(b), next, eof), out);
}
static enum sfs_status full_namespace(reader *r, namespace ns) {
    const uint8_t *b; enum sfs_status e = metadata(r, &ns.ref, NAMESPACE, r->a.end, &b); if (e) return e;
    uint8_t entry[128]; e = memo(r, &ns.ref, entry, 0); if (e) return e; if (get32(entry) & 4) return SFS_OK; if (get32(entry) == 1) return SFS_CORRUPT;
    memset(entry, 0, sizeof(entry)); put32(entry, 1); put32(entry + 4, NAMESPACE); memcpy(entry + 8, ns.ref.digest, 32); e = memo(r, &ns.ref, entry, 1); if (e) return e;
    summary inodes, names; e = intrinsic_root(r, ns.inodes, MAP_INODE, ns.next_inode, UINT64_MAX, &inodes); if (e) return e;
    e = intrinsic_root(r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &names); if (e) return e;
    if (inodes.count != ns.count || names.count != ns.count) return SFS_CORRUPT;
    cursor c; e = cursor_start(&c, r, ns.inodes, MAP_INODE, ns.next_inode, UINT64_MAX, NULL); if (e) return e;
    uint8_t row[352]; int found;
    while (!(e = cursor_next(&c, row, &found)) && found) {
        node n; decode_node(row, &n); key k = name_key(n.e.parent, n.e.name, n.e.name_length); uint8_t name[352]; int matched;
        e = index_get(r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k, name, &matched); if (e) return e; if (!matched || get64(name + 267) != n.e.inode) return SFS_CORRUPT;
        e = parent_chain(r, &ns, n.e.parent, 0); if (e) return e;
        if (n.e.kind == SFS_FILE) { summary ext; e = intrinsic_root(r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &ext); if (e) return e; }
    }
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
    memset(b, 0, CELL); memcpy(b, "SFSIMG01", 8); put32(b + 12, 2); memcpy(b + 24, a->uuid, 16); put64(b + 40, a->generation); encode_ref(b + 48, &a->root); put64(b + 104, a->end); put64(b + 144, a->capacity); hash_cell(b, ROOT, a->uuid, b + SLOT_HASH);
}
static enum sfs_status decode_slot(reader *r, unsigned slot, anchor *a) {
    uint8_t b[CELL], digest[32], expected[32]; if (r->h->eof < (slot + 1) * ALIGNMENT) return SFS_CORRUPT;
    enum sfs_status e = charge(r, SFS_INCOMPLETE_METADATA_READ, CELL); if (e) return e; e = charge(r, SFS_INCOMPLETE_METADATA_HASH, CELL); if (e) return e;
    if (read_exact(r->h->fd, b, CELL, slot * ALIGNMENT)) return io_failure(r, SFS_PHASE_READ);
    memcpy(expected, b + SLOT_HASH, 32); memset(b + SLOT_HASH, 0, 32); hash_cell(b, ROOT, b + 24, digest);
    if (memcmp(b, "SFSIMG01", 8) || memcmp(digest, expected, 32)) return SFS_CORRUPT;
    if (get32(b + 8) || get32(b + 12) != 2 || get64(b + 16)) return SFS_UNSUPPORTED;
    if (!zero(b + 152, CELL - 152) || !decode_ref(b + 48, &a->root)) return SFS_CORRUPT;
    memcpy(a->uuid, b + 24, 16); a->generation = get64(b + 40); a->end = get64(b + 104); a->capacity = get64(b + 144);
    uint64_t end;
    if (zero(a->uuid, 16) || !a->generation || a->capacity < 16384 || a->capacity % CELL || a->capacity > SFS_IMAGE_MAX || a->capacity > (uint64_t)INT64_MAX || a->root.type != ROOT || a->root.offset < DATA_START || a->root.offset % CELL || a->root.length != CELL || !add64(a->root.offset, CELL, &end) || a->end != end || end > r->h->eof || end > a->capacity) return SFS_CORRUPT;
    if (r->h->eof > a->capacity) return SFS_LIMIT;
    /* Pin the first valid observation even if later candidate verification stops. */
    if (!r->h->slot_observed[slot]) { r->h->slots[slot] = *a; r->h->slot_observed[slot] = 1; }
    return SFS_OK;
}
static int same_anchor(const anchor *a, const anchor *b) { return a->generation == b->generation && a->end == b->end && a->capacity == b->capacity && !memcmp(a->uuid, b->uuid, 16) && same_ref(&a->root, &b->root); }
static int pair_valid(const anchor a[2]) {
    if (a[0].capacity != a[1].capacity || memcmp(a[0].uuid, a[1].uuid, 16)) return 0;
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
    if (!r->h->readonly) {
        if (code[0] == SFS_UNSUPPORTED || code[1] == SFS_UNSUPPORTED) return SFS_UNSUPPORTED;
        if (code[0] == SFS_IO || code[1] == SFS_IO) { r->error = errors[0] ? errors[0] : errors[1]; r->phase = SFS_PHASE_READ; return SFS_IO; }
        if ((code[0] && code[0] != SFS_INCOMPLETE) || (code[1] && code[1] != SFS_INCOMPLETE)) return SFS_RECOVERY_REQUIRED;
    }
    if (code[0] == SFS_INCOMPLETE || code[1] == SFS_INCOMPLETE) return SFS_INCOMPLETE;
    if (!r->h->readonly) {
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

enum sfs_status sfs_image_create(const char *directory, const char *name, uint64_t capacity, sfs_image **out, sfs_result *r) {
    if (!out) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r); *out = NULL;
    if (capacity < 16384 || capacity % CELL || capacity > SFS_IMAGE_MAX || capacity > (uint64_t)INT64_MAX) return result(NULL, SFS_INVALID, SFS_PHASE_ADMISSION, 0, r);
    sfs_image *h; int parent; enum sfs_status code = access_image(directory, name, 1, 0, &h, &parent, r); if (code) return code;
    h->current.capacity = capacity; h->live.ns.next_inode = 2; arc4random_buf(h->current.uuid, 16); if (zero(h->current.uuid, 16)) h->current.uuid[0] = 1;
    anchor next = h->current; next.generation = 1; uint64_t remaining = 2; enum sfs_phase phase = SFS_PHASE_RECORDS; int published = 0;
    code = write_namespace(h, &h->live.ns, &remaining); if (code) goto failed;
    uint8_t b[CELL]; envelope(b, ROOT, h->current.uuid); encode_ref(b + 64, &h->live.ns.ref); code = append_cell(h, ROOT, b, &next.root, &remaining); if (code) goto failed; next.end = h->eof;
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
static enum sfs_status open_common(const char *directory, const char *name, int inspection, sfs_image **out, sfs_recovery *report, const sfs_verify_budget *budget, sfs_result *result_out) {
    if (!out || (inspection && (!report || !valid_budget(budget)))) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *out = NULL;
    sfs_image *h; int parent; enum sfs_status e = access_image(directory, name, 0, inspection, &h, &parent, result_out); if (e) return e;
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
enum sfs_status sfs_image_open(const char *directory, const char *name, sfs_image **out, sfs_result *r) { return open_common(directory, name, 0, out, NULL, NULL, r); }
enum sfs_status sfs_image_inspect(const char *directory, const char *name, sfs_image **out, sfs_recovery *report, const sfs_verify_budget *budget, sfs_result *r) { return open_common(directory, name, 1, out, report, budget, r); }
enum sfs_status sfs_image_select(sfs_image *h, unsigned slot, const sfs_verify_budget *budget, sfs_result *out) {
    if (!h || !h->readonly || slot > 1 || !valid_budget(budget)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
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
    int error = 0; if (close(h->fd)) error = errno; if (close(h->aux_parent) && !error) error = errno;
    enum sfs_status e = result(h, error ? SFS_IO : SFS_OK, SFS_PHASE_CLOSE, error, out); discard(h); cache_clear(h); free(h); return e;
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
enum sfs_status sfs_image_lookup(sfs_image *h, sfs_view view, sfs_inode parent, const void *name, size_t length, sfs_entry *out, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!out || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent);
    uint8_t row[352]; int found; key k = name_key(parent, name, length); node n;
    if (!e) { e = index_get(&r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &k, row, &found); if (!e && !found) e = SFS_NOT_FOUND; }
    if (!e) { e = node_get(&r, &ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT; if (!e && (n.e.parent != parent || n.e.name_length != length || memcmp(n.e.name, name, length))) e = SFS_CORRUPT; }
    if (!e) *out = n.e; return touched_result(&r, e, result_out);
}
enum sfs_status sfs_image_read(sfs_image *h, sfs_view view, sfs_inode id, uint64_t offset, void *data, size_t capacity, size_t *read_count, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!read_count || (capacity && !data)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *read_count = 0;
    uint64_t end; if (!add64(offset, capacity, &end)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; node n; e = selected_namespace(&r, view, &ns); if (!e) e = node_get(&r, &ns, id, 1, &n); if (!e && n.e.kind != SFS_FILE) e = SFS_INVALID;
    while (!e && *read_count < capacity && offset + *read_count < n.e.size) {
        uint64_t position = offset + *read_count; size_t amount = CELL - position % CELL; if (amount > capacity - *read_count) amount = capacity - *read_count; if (amount > n.e.size - position) amount = (size_t)(n.e.size - position);
        uint8_t row[352], bytes[CELL] = {0}; int found; key k = number_key(position / CELL);
        e = index_get(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &k, row, &found); if (e) break;
        if (found) { reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; break; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), bytes); if (e) break; }
        memcpy((uint8_t *)data + *read_count, bytes + position % CELL, amount); *read_count += amount;
    }
    return touched_result(&r, e, result_out);
}

static enum sfs_status index_height(reader *r, reference ref, unsigned map, uint64_t next, uint64_t eof, unsigned *height) {
    *height = 0; if (!ref.type) return SFS_OK; const uint8_t *b; enum sfs_status e = root_page(r, &ref, map, next, eof, &b); if (!e) *height = page_level(b) + 1; return e;
}
static enum sfs_status batch_cost(reader *r, uint64_t *cost) {
    *cost = 0; if (!r->h->batch) return SFS_OK; unsigned hi; enum sfs_status e = index_height(r, r->h->staged.ns.inodes, MAP_INODE, r->h->staged.ns.next_inode, UINT64_MAX, &hi); if (e) return e;
    *cost = pending_cells(&r->h->batch->extent) + hi + 1; return SFS_OK;
}
static enum sfs_status flush_batch(reader *r, int *wrote) {
    sfs_image *h = r->h; if (!h->batch) return SFS_OK; batch *b = h->batch;
    uint64_t liability; enum sfs_status e = batch_cost(r, &liability); if (e) return e; if (!reserve_cells(h, liability + 1)) return SFS_LIMIT;
    arena *a = arena_new(h, b->number); if (!a) return SFS_NOMEM;
    tree inodes = make_tree(a, r, h->staged.ns.inodes, MAP_INODE, 0, h->staged.ns.next_inode, UINT64_MAX); uint8_t row[352]; encode_node(row, &b->inode);
    e = tree_put(&inodes, row); if (e) { arena_free(a); return e; }
    uint64_t remaining = pending_cells(&b->extent) + pending_cells(&inodes) + 1;
    if (remaining > liability) { arena_free(a); return SFS_CORRUPT; }
    reference extent; b->extent.reader = r; *wrote = 1; r->phase = SFS_PHASE_RECORDS;
    e = seal_tree(&b->extent, &extent, &remaining);
    if (!e) { b->inode.extent = extent; encode_node(row, &b->inode); e = tree_put(&inodes, row); }
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
    if (h->batch && (h->batch->arena != h->batch->extent.arena || h->batch->arena->epoch != h->epoch || h->batch->arena->batch != h->batch->number || !same_ref(&h->batch->arena->lineage, &h->staged.ns.ref) || h->batch->extent.owner != h->batch->inode.e.inode || h->batch->extent.map != MAP_EXTENT)) return mutation_failure(h, SFS_CORRUPT, SFS_PHASE_VALIDATE, 0, 0, out);
    if (stable(h)) return mutation_failure(h, SFS_IO, SFS_PHASE_IDENTITY, errno, 0, out); return SFS_OK;
}
static enum sfs_status input_name(sfs_image *h, const void *name, size_t length, sfs_result *out) {
    if (length > SFS_NAME_MAX) return mutation_failure(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, 0, out);
    return valid_name(name, length) ? SFS_OK : result(h, SFS_INVALID, SFS_PHASE_NONE, 0, out);
}
static enum sfs_status name_absent(reader *r, const namespace *ns, uint64_t parent, const void *name, size_t length, uint64_t except) {
    uint8_t row[352]; int found; key k = name_key(parent, name, length); enum sfs_status e = index_get(r, ns->names, MAP_NAME, ns->next_inode, UINT64_MAX, &k, row, &found); if (e) return e;
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
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, out);
    if (h->current.generation == UINT64_MAX || h->epoch == UINT64_MAX || !reserve_cells(h, 1)) return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, out);
    h->staged = h->live; h->transaction = 1; h->epoch++; return result(h, SFS_OK, SFS_PHASE_NONE, 0, out);
}
enum sfs_status sfs_image_abort(sfs_image *h, sfs_result *out) { enum sfs_status e = ready(h, 1, 1, out); if (e) return e; discard(h); return result(h, SFS_OK, SFS_PHASE_NONE, 0, out); }
/* Probe the exact metadata edit before a pending batch can consume append space. */
static enum sfs_status probe_metadata(reader *r, unsigned operation, const node *before, const node *after) {
    if (!r->h->batch) return SFS_OK;
    namespace ns = r->h->staged.ns; if (operation == 1) ns.next_inode++;
    arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM;
    tree inodes = make_tree(a, r, ns.inodes, MAP_INODE, 0, ns.next_inode, UINT64_MAX), names = make_tree(a, r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    uint8_t row[352]; enum sfs_status e = SFS_OK;
    if (before) { key nk = name_key(before->e.parent, before->e.name, before->e.name_length); e = tree_delete(&names, &nk); }
    if (!e && operation == 2) { key ik = number_key(before->e.inode); e = tree_delete(&inodes, &ik); }
    if (!e && after) { encode_node(row, after); e = tree_put(&inodes, row); if (!e) { encode_name(row, after); e = tree_put(&names, row); } }
    arena_free(a); return e;
}
enum sfs_status sfs_image_add(sfs_image *h, sfs_inode parent, const void *name, size_t length, enum sfs_kind kind, sfs_inode *out, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    if (!out || (kind != SFS_FILE && kind != SFS_DIRECTORY)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    e = input_name(h, name, length, result_out); if (e) return e;
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; int late = 0;
    e = directory_check(&r, &ns, parent); if (!e) e = parent_chain(&r, &ns, parent, 0); if (!e) e = name_absent(&r, &ns, parent, name, length, 0);
    if (!e && (ns.count >= SFS_ENTRY_MAX || ns.next_inode == UINT64_MAX)) e = SFS_LIMIT;
    if (!e && h->batch) { node proposed = {0}; proposed.e.inode = ns.next_inode; proposed.e.parent = parent; proposed.e.kind = kind; proposed.e.name_length = length; memcpy(proposed.e.name, name, length); e = probe_metadata(&r, 1, NULL, &proposed); }
    if (!e) e = prepare_metadata(&r, 1, 1, 0, &late);
    if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; node n = {0}; n.e.inode = ns.next_inode++; n.e.parent = parent; n.e.kind = kind; n.e.name_length = length; memcpy(n.e.name, name, length); ns.count++;
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, UINT64_MAX), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    uint8_t row[352]; encode_node(row, &n); e = tree_put(&inodes, row); if (!e) { encode_name(row, &n); e = tree_put(&names, row); }
    if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late); int error = r.error; arena_free(a);
    if (e) return mutation_failure(h, e, r.phase, error, late, result_out); *out = n.e.inode; result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_remove(sfs_image *h, sfs_inode id, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; node n; int late = 0; e = node_get(&r, &ns, id, 1, &n);
    if (!e && n.e.kind == SFS_DIRECTORY) { key prefix = name_key(id, NULL, 0); cursor c; e = cursor_start(&c, &r, ns.names, MAP_NAME, ns.next_inode, UINT64_MAX, &prefix); uint8_t row[352]; int found; if (!e) { e = cursor_next(&c, row, &found); if (!e && found && get64(row) == id) e = SFS_STATE; } }
    if (!e) e = probe_metadata(&r, 2, &n, NULL);
    if (!e) e = prepare_metadata(&r, 1, 1, 0, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; e = node_get(&r, &ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out); if (!ns.count) return mutation_failure(h, SFS_CORRUPT, r.phase, 0, late, result_out); ns.count--;
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, UINT64_MAX), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX);
    key ik = number_key(id), nk = name_key(n.e.parent, n.e.name, n.e.name_length); e = tree_delete(&inodes, &ik); if (!e) e = tree_delete(&names, &nk); if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late);
    int error = r.error; arena_free(a); if (e) return mutation_failure(h, e, r.phase, error, late, result_out); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_rename(sfs_image *h, sfs_inode id, sfs_inode parent, const void *name, size_t length, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; e = input_name(h, name, length, result_out); if (e) return e; if (id == 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    reader r = current_reader(h, 1); namespace ns = h->staged.ns; node n; int late = 0;
    e = node_get(&r, &ns, id, 1, &n); if (!e) e = directory_check(&r, &ns, parent); if (!e) e = parent_chain(&r, &ns, parent, id); if (!e) e = name_absent(&r, &ns, parent, name, length, id);
    if (!e && n.e.parent == parent && n.e.name_length == length && !memcmp(n.e.name, name, length)) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out);
    if (!e && h->batch) { node proposed = n; proposed.e.parent = parent; proposed.e.name_length = length; memset(proposed.e.name, 0, sizeof(proposed.e.name)); memcpy(proposed.e.name, name, length); e = probe_metadata(&r, 3, &n, &proposed); }
    if (!e) e = prepare_metadata(&r, 1, 2, 0, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    ns = h->staged.ns; e = node_get(&r, &ns, id, 1, &n); if (e) return mutation_failure(h, e, r.phase, r.error, late, result_out);
    key old = name_key(n.e.parent, n.e.name, n.e.name_length); n.e.parent = parent; n.e.name_length = length; memset(n.e.name, 0, sizeof(n.e.name)); memcpy(n.e.name, name, length);
    arena *a = arena_new(h, 0); if (!a) return mutation_failure(h, SFS_NOMEM, SFS_PHASE_NONE, 0, late, result_out);
    tree inodes = make_tree(a, &r, ns.inodes, MAP_INODE, 0, ns.next_inode, UINT64_MAX), names = make_tree(a, &r, ns.names, MAP_NAME, 0, ns.next_inode, UINT64_MAX); uint8_t row[352];
    e = tree_delete(&names, &old); if (!e) { encode_name(row, &n); e = tree_put(&names, row); } if (!e) { encode_node(row, &n); e = tree_put(&inodes, row); } if (!e) e = write_metadata_trees(&r, &inodes, &names, &ns, &late);
    int error = r.error; arena_free(a); if (e) return mutation_failure(h, e, r.phase, error, late, result_out); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
}
enum sfs_status sfs_image_snapshot(sfs_image *h, const void *name, size_t length, sfs_view *out, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e; if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); e = input_name(h, name, length, result_out); if (e) return e;
    for (unsigned i = 0; i < h->staged.count; ++i) if (h->staged.snapshots[i].length == length && !memcmp(h->staged.snapshots[i].name, name, length)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, result_out);
    if (h->staged.count == SFS_SNAPSHOT_MAX || (h->staged.count && h->staged.snapshots[h->staged.count - 1].view == SFS_SNAPSHOT_MAX)) return mutation_failure(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, 0, result_out);
    reader r = current_reader(h, 1); int late = 0;
    snapshot snap = { .view = h->staged.count ? h->staged.snapshots[h->staged.count - 1].view + 1 : 1, .length = (uint32_t)length, .ns = h->live.ns.ref }; memcpy(snap.name, name, length);
    uint8_t row[352] = {0}; put32(row, snap.view); encode_ref(row + 8, &snap.ns); put32(row + 64, snap.length); memcpy(row + 68, snap.name, length);
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
        if (!q->dirty) { if (tree_dirty(t, child)) return SFS_CORRUPT; put_child_ref(p->bytes + PAGE_HEAD + i * stride(t->map, page_level(p->bytes)), t->map, &q->source); release_clean(t, child); p->children[i] = NO_CHILD; }
        else { enum sfs_status e = prune_clean(t, child); if (e) return e; }
    }
    return SFS_OK;
}
static enum sfs_status tree_get(tree *t, const key *k, uint8_t row[352], int *found) {
    unsigned path[MAX_HEIGHT], depth, at; enum sfs_status e = tree_search(t, k, path, &depth, &at, found); if (e || !*found) return e;
    overlay_page *p = owned_page(t, path[depth - 1]); if (!p) return SFS_CORRUPT; memset(row, 0, 352); memcpy(row, row_at(p->bytes, t->map, at), stride(t->map, 0)); return SFS_OK;
}
static enum sfs_status tree_growth(tree *t, uint64_t old_size) {
    enum sfs_status e = tree_root(t); if (e) return e; overlay_page *p = owned_page(t, (unsigned)t->root); if (!p) return SFS_CORRUPT; if (!page_count(p->bytes)) return SFS_OK;
    key max = page_max(p->bytes); uint64_t last = from_big(max.bytes), boundary = old_size / CELL;
    if (last > boundary || (last == boundary && !(old_size % CELL))) return SFS_CORRUPT;
    if (last == boundary) { uint8_t row[352]; int found; key k = number_key(boundary); e = tree_get(t, &k, row, &found); if (e) return e; if (!found || get16(row + 64) > old_size % CELL) return SFS_CORRUPT; }
    return SFS_OK;
}
enum sfs_status sfs_image_write(sfs_image *h, sfs_inode id, uint64_t offset, const void *data, size_t length, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    if ((length && !data) || length > 65536) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out);
    uint64_t end;
    reader r = current_reader(h, 1); node n; unsigned transition_height = 0; uint64_t transition_bound = 0; int same = h->batch && h->batch->inode.e.inode == id, late = 0; arena *a = NULL; batch *candidate = NULL; uint8_t *merge = NULL; tree ext;
    if (same) n = h->batch->inode; else { e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) goto failed; }
    if (id == 1) { e = SFS_NOT_FOUND; goto failed; } if (n.e.kind != SFS_FILE) { e = SFS_INVALID; goto failed; }
    if (!add64(offset, length, &end) || end > SFS_FILE_MAX) { e = SFS_LIMIT; goto failed; }
    if (!length) return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out);
    uint64_t low = offset / CELL, high = (end - 1) / CELL, next_low = low, next_high = high; unsigned count = (unsigned)(high - low + 1);
    if (same) { if (h->batch->low < next_low) next_low = h->batch->low; if (h->batch->high > next_high) next_high = h->batch->high; a = arena_clone(h->batch->arena); if (!a) { e = SFS_NOMEM; goto failed; } ext = h->batch->extent; ext.arena = a; ext.reader = &r; ext.eof = n.e.size; }
    int rollover = h->batch && (!same || next_high - next_low >= 256);
    if (end > n.e.size) { e = same ? tree_growth(&ext, n.e.size) : extent_growth(&r, n.extent, n.e.size); if (e) goto failed; }
    merge = calloc(count, CELL); if (!merge) { e = SFS_NOMEM; goto failed; }
    uint64_t new_size = end > n.e.size ? end : n.e.size;
    for (unsigned i = 0; i < count; ++i) {
        uint64_t block = low + i, base = block * CELL; uint8_t row[352]; int found = 0; key k = number_key(block);
        if (base < n.e.size) { e = same ? tree_get(&ext, &k, row, &found) : index_get(&r, n.extent, MAP_EXTENT, UINT64_MAX, n.e.size, &k, row, &found); if (e) goto failed; }
        if (found) { reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; goto failed; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), merge + i * CELL); if (e) goto failed; }
        uint64_t begin = offset > base ? offset : base, finish = end < base + CELL ? end : base + CELL;
        memcpy(merge + i * CELL + (size_t)(begin - base), (const uint8_t *)data + (size_t)(begin - offset), (size_t)(finish - begin));
    }
    unsigned hi; e = index_height(&r, h->staged.ns.inodes, MAP_INODE, h->staged.ns.next_inode, UINT64_MAX, &hi); if (e) goto failed;
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
            uint8_t row[352] = {0}; reference provisional = { .type = RAW, .length = CELL }; put64(row, low + i); encode_ref(row + 8, &provisional);
            uint64_t visible = new_size - (low + i) * CELL; put16(row + 64, visible < CELL ? (unsigned)visible : CELL); e = tree_put(&ext, row); if (e) goto failed;
        }
        transition_height = page_level(owned_page(&ext, (unsigned)ext.root)->bytes) + 1;
        arena_free(a); a = NULL; e = flush_batch(&r, &late); if (e) goto failed;
        e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) goto failed; same = 0; next_low = low; next_high = high;
    }
    if (!a) { a = arena_new(h, h->token + 1); if (!a) { e = SFS_NOMEM; goto failed; } ext = make_tree(a, &r, n.extent, MAP_EXTENT, id, UINT64_MAX, n.e.size); }
    candidate = calloc(1, sizeof(*candidate)); if (!candidate) { e = SFS_NOMEM; goto failed; }
    uint64_t at; if (!aligned(h->eof, &at)) { e = SFS_LIMIT; goto failed; } reference refs[17];
    for (unsigned i = 0; i < count; ++i) {
        refs[i] = (reference){ .type = RAW, .offset = at + i * CELL, .length = CELL }; hash_cell(merge + i * CELL, RAW, h->current.uuid, refs[i].digest);
        uint8_t row[352] = {0}; put64(row, low + i); encode_ref(row + 8, &refs[i]); uint64_t visible = new_size - (low + i) * CELL; put16(row + 64, visible < CELL ? (unsigned)visible : CELL);
        e = tree_put(&ext, row); if (e) goto failed;
    }
    ext.eof = new_size; e = prune_clean(&ext, (unsigned)ext.root); if (e) goto failed;
    if (transition_height && (page_level(owned_page(&ext, (unsigned)ext.root)->bytes) + 1 != transition_height || pending_cells(&ext) > transition_bound)) { e = SFS_CORRUPT; goto failed; }
    if (!reserve_cells(h, count + pending_cells(&ext) + hi + 2)) { e = SFS_LIMIT; goto failed; }
    uint64_t remaining = count; late = 1; r.phase = SFS_PHASE_RECORDS;
    for (unsigned i = 0; i < count; ++i) { reference appended; e = append_prepared(h, RAW, merge + i * CELL, &appended, &remaining, &refs[i]); if (e) { if (e == SFS_IO) r.error = errno; goto failed; } }
    n.e.size = new_size; candidate->arena = a; candidate->extent = ext; candidate->extent.reader = NULL; candidate->inode = n; candidate->low = next_low; candidate->high = next_high; candidate->number = a->batch;
    if (h->batch) { arena_free(h->batch->arena); free(h->batch); } h->batch = candidate; free(merge);
    result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed:
    arena_free(a); free(candidate); free(merge); return mutation_failure(h, e, r.phase, r.error, late, result_out);
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
    c->frames[c->depth++] = (extent_frame){ .shadow = shadow, .ref = ref, .before = r->a.end, .context = root_context(MAP_EXTENT, page_level(b), UINT64_MAX, eof) }; return SFS_OK;
}
static enum sfs_status extent_stream_next(extent_stream *c, uint8_t row[352], int *found) {
    *found = 0;
    while (c->depth) {
        extent_frame *f = &c->frames[c->depth - 1]; const uint8_t *b; enum sfs_status e = extent_frame_bytes(c, f, &b); if (e) return e;
        if (f->index >= page_count(b)) { c->depth--; continue; }
        unsigned at = f->index++; if (!f->context.level) { memset(row, 0, 352); memcpy(row, row_at(b, MAP_EXTENT, at), 72); *found = 1; return SFS_OK; }
        if (c->depth == MAX_HEIGHT) return SFS_CORRUPT;
        reference child; if (!child_ref(row_at(b, MAP_EXTENT, at), MAP_EXTENT, &child)) return SFS_CORRUPT;
        int shadow = -1; if (f->shadow >= 0) { overlay_page *p = owned_page(c->overlay, (unsigned)f->shadow); if (p->children[at] != NO_CHILD) shadow = p->children[at]; }
        extent_frame next = { .shadow = shadow, .ref = child, .before = f->shadow >= 0 ? c->reader->a.end : f->ref.offset, .context = child_context(b, at, f->context) }; c->frames[c->depth++] = next;
    } return SFS_OK;
}
typedef struct { uint8_t cells[MAX_HEIGHT][CELL]; uint64_t pages[MAX_HEIGHT], input[MAX_HEIGHT], emitted[MAX_HEIGHT]; unsigned rows[MAX_HEIGHT], levels; sfs_image *h; uint64_t generation; reference root; } prefix_builder;
static enum sfs_status prefix_shape(uint64_t rows, uint64_t pages[MAX_HEIGHT], unsigned *levels, uint64_t *total) {
    *levels = 0; *total = 0; while (rows) { if (*levels == MAX_HEIGHT) return SFS_LIMIT; rows = (rows + 47) / 48; pages[(*levels)++] = rows; if (!add64(*total, rows, total)) return SFS_LIMIT; if (rows == 1) break; } return SFS_OK;
}
static enum sfs_status prefix_feed(prefix_builder *p, unsigned level, const uint8_t *row, key min, key max, uint64_t *remaining) {
    if (level >= p->levels || p->emitted[level] >= p->pages[level]) return SFS_CORRUPT;
    uint8_t *b = p->cells[level]; unsigned n = p->rows[level];
    if (!n) { envelope(b, INDEX, p->h->current.uuid); put32(b + 64, MAP_EXTENT); put16(b + 68, level); put64(b + 72, p->generation); set_page_range(b, min, max); }
    else set_page_range(b, page_min(b), max);
    memcpy(b + PAGE_HEAD + n * 72, row, 72); put16(b + 70, ++n); p->rows[level] = n;
    uint64_t target = p->input[level] / p->pages[level] + (p->emitted[level] < p->input[level] % p->pages[level]);
    if (n < target) return SFS_OK; if (n != target || target > 48 || (p->pages[level] > 1 && target < 16)) return SFS_CORRUPT;
    reference child; enum sfs_status e = append_cell(p->h, INDEX, b, &child, remaining); if (e) return e; min = page_min(b); max = page_max(b); p->rows[level] = 0; p->emitted[level]++;
    if (level + 1 == p->levels) { p->root = child; return SFS_OK; }
    uint8_t parent[72] = {0}; put32(parent, 8); memcpy(parent + 8, min.bytes, 8); encode_ref(parent + 16, &child); return prefix_feed(p, level + 1, parent, min, max, remaining);
}
static enum sfs_status replace_inode(reader *r, node *n, int *late) {
    arena *a = arena_new(r->h, 0); if (!a) return SFS_NOMEM; namespace ns = r->h->staged.ns;
    tree inodes = make_tree(a, r, ns.inodes, MAP_INODE, 0, ns.next_inode, UINT64_MAX); uint8_t row[352]; encode_node(row, n); enum sfs_status e = tree_put(&inodes, row); uint64_t remaining = pending_cells(&inodes) + 1;
    if (!e && !reserve_cells(r->h, remaining + 1)) e = SFS_LIMIT;
    if (!e) { *late = 1; r->phase = SFS_PHASE_RECORDS; e = seal_tree(&inodes, &ns.inodes, &remaining); if (!e) e = write_namespace(r->h, &ns, &remaining); if (e == SFS_IO) r->error = errno; }
    arena_free(a); if (!e && remaining) e = SFS_CORRUPT; if (!e) r->h->staged.ns = ns; return e;
}
enum sfs_status sfs_image_resize(sfs_image *h, sfs_inode id, uint64_t size, sfs_result *result_out) {
    enum sfs_status e = mutation_start(h, result_out); if (e) return e;
    reader r = current_reader(h, 1); node n; int same = h->batch && h->batch->inode.e.inode == id, late = 0; arena *guard = NULL; prefix_builder *builder = NULL;
    if (same) n = h->batch->inode; else { e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) goto failed; }
    if (id == 1) { e = SFS_NOT_FOUND; goto failed; } if (n.e.kind != SFS_FILE) { e = SFS_INVALID; goto failed; } if (size > SFS_FILE_MAX) { e = SFS_LIMIT; goto failed; }
    uint64_t old_size = n.e.size, retained = 0, total = 0, pages[MAX_HEIGHT] = {0}; unsigned levels = 0, boundary = 0; uint8_t boundary_bytes[CELL], boundary_row[352];
    if (size > old_size) {
        if (same) { guard = arena_clone(h->batch->arena); if (!guard) { e = SFS_NOMEM; goto failed; } tree t = h->batch->extent; t.arena = guard; t.reader = &r; t.eof = old_size; e = tree_growth(&t, old_size); arena_free(guard); guard = NULL; }
        else e = extent_growth(&r, n.extent, old_size); if (e) goto failed;
    } else if (size && size < old_size) {
        extent_stream c; e = extent_stream_start(&c, &r, n.extent, same ? &h->batch->extent : NULL, old_size); if (e) goto failed; uint8_t row[352]; int found;
        while (!(e = extent_stream_next(&c, row, &found)) && found) {
            uint64_t block = get64(row); if (block >= (size + CELL - 1) / CELL) break; retained++;
            if (size % CELL && block == size / CELL) { memcpy(boundary_row, row, 352); reference raw; if (!decode_ref(row + 8, &raw)) { e = SFS_CORRUPT; goto failed; } e = raw_read(&r, &raw, r.a.end, get16(row + 64), boundary_bytes); if (e) goto failed; memset(boundary_bytes + size % CELL, 0, CELL - size % CELL); boundary = 1; }
        }
        if (e) goto failed; e = prefix_shape(retained, pages, &levels, &total); if (e) goto failed;
        if (retained) { builder = calloc(1, sizeof(*builder)); if (!builder) { e = SFS_NOMEM; goto failed; } builder->h = h; builder->generation = r.a.generation; builder->levels = levels; memcpy(builder->pages, pages, sizeof(pages)); builder->input[0] = retained; for (unsigned i = 1; i < levels; ++i) builder->input[i] = pages[i - 1]; }
    }
    unsigned hi; e = index_height(&r, h->staged.ns.inodes, MAP_INODE, h->staged.ns.next_inode, UINT64_MAX, &hi); if (e) goto failed;
    uint64_t old; e = batch_cost(&r, &old); if (e) goto failed;
    uint64_t required = old + (size == old_size ? 1 : total + boundary + hi + 2); if (!reserve_cells(h, required)) { e = SFS_LIMIT; goto failed; }
    e = flush_batch(&r, &late); if (e) goto failed; if (size == old_size) { free(builder); return result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); }
    e = node_get(&r, &h->staged.ns, id, 1, &n); if (e) goto failed;
    if (size < old_size) {
        reference new_boundary = {0}; uint64_t remaining = total + boundary; r.phase = SFS_PHASE_RECORDS;
        if (boundary) { late = 1; e = append_cell(h, RAW, boundary_bytes, &new_boundary, &remaining); if (e) { if (e == SFS_IO) r.error = errno; goto failed; } }
        if (retained) {
            cursor c; e = cursor_start(&c, &r, n.extent, MAP_EXTENT, UINT64_MAX, old_size, NULL); if (e) goto failed; uint8_t row[352]; int found;
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
    n.e.size = size; e = replace_inode(&r, &n, &late); if (e) goto failed; free(builder); result(h, SFS_OK, SFS_PHASE_NONE, 0, result_out); if (result_out) result_out->coverage = SFS_COVERAGE_TOUCHED; return SFS_OK;
failed: arena_free(guard); free(builder); return mutation_failure(h, e, r.phase, r.error, late, result_out);
}

enum sfs_status sfs_image_commit(sfs_image *h, sfs_result *out) {
    enum sfs_status e = mutation_start(h, out); if (e) return e;
    reader r = current_reader(h, 0); state fresh; cache_clear(h); e = reconcile(&r, &fresh);
    if (!e && h->staged.ns.next_inode < fresh.ns.next_inode) e = SFS_CORRUPT;
    if (e) return mutation_failure(h, e, r.phase, r.error, 1, out);
    r = current_reader(h, 1); uint64_t pending; e = batch_cost(&r, &pending); if (!e && !reserve_cells(h, pending + 1)) e = SFS_LIMIT;
    if (e) return mutation_failure(h, e, r.phase, r.error, 0, out);
    int late = 0; e = flush_batch(&r, &late); if (e) return mutation_failure(h, e, r.phase, r.error, late, out);
    anchor next = h->current; next.generation++; uint8_t b[CELL]; envelope(b, ROOT, next.uuid); encode_ref(b + 64, &h->staged.ns.ref); encode_ref(b + 120, &h->staged.catalog);
    uint64_t remaining = 1; e = append_cell(h, ROOT, b, &next.root, &remaining); if (e) return mutation_failure(h, e, SFS_PHASE_RECORDS, e == SFS_IO ? errno : 0, 1, out); next.end = h->eof;
    /* Finalize every reachable byte and the slot before the first fence. */
    encode_slot(b, &next); unsigned slot = (unsigned)(next.generation % 2); int published = 0; enum sfs_phase phase = SFS_PHASE_RECORD_BARRIER;
    if (fullsync(h->fd)) goto failed;
    phase = slot ? SFS_PHASE_SLOT1 : SFS_PHASE_SLOT0; published = 1; if (write_exact(h->fd, b, CELL, slot * ALIGNMENT)) goto failed;
    phase = SFS_PHASE_COMMIT_BARRIER; if (fullsync(h->fd)) goto failed;
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
    reference expected = ns->names; uint64_t before = r->a.end; context ctx = root_context(MAP_NAME, page_level(page), ns->next_inode, UINT64_MAX);
    for (unsigned i = 0; i < depth; ++i) {
        const uint8_t *v = b + 48 + i * 64; reference ref; unsigned index = get16(v + 56);
        if (!decode_ref(v, &ref) || !same_ref(&ref, &expected) || get16(v + 58) != ctx.level || !zero(v + 60, 4)) return SFS_INVALID;
        e = page_read(r, &ref, before, ctx, &page); if (e) return e;
        if (index > page_count(page) || (i + 1 < depth && (!index || !ctx.level))) return SFS_INVALID;
        c->frames[c->depth++] = (cursor_frame){ .ref = ref, .before = before, .context = ctx, .index = index };
        if (i + 1 < depth) { if (!child_ref(row_at(page, MAP_NAME, index - 1), MAP_NAME, &expected)) return SFS_CORRUPT; before = ref.offset; ctx = child_context(page, index - 1, ctx); }
    }
    return SFS_OK;
}
static void save_cookie(sfs_cookie *cookie, const namespace *ns, uint64_t parent, const cursor *c) {
    uint8_t *b = cookie->bytes; memset(b, 0, sizeof(cookie->bytes)); memcpy(b, ns->ref.digest, 32); put64(b + 32, parent); put32(b + 40, c->depth); put32(b + 44, c->depth ? 1 : 3);
    for (unsigned i = 0; i < c->depth; ++i) { uint8_t *v = b + 48 + i * 64; encode_ref(v, &c->frames[i].ref); put16(v + 56, c->frames[i].index); put16(v + 58, c->frames[i].context.level); }
}
enum sfs_status sfs_image_next(sfs_image *h, sfs_view view, sfs_inode parent, sfs_cookie *cookie, sfs_entry *out, int *found, sfs_result *result_out) {
    enum sfs_status e = ready(h, 0, 0, result_out); if (e) return e; if (!cookie || !out || !found) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, result_out); *found = 0;
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, result_out);
    reader r = current_reader(h, 0); namespace ns; e = selected_namespace(&r, view, &ns); if (!e) e = directory_check(&r, &ns, parent); cursor c;
    if (!e) e = cookie_cursor(&r, &ns, parent, cookie, &c); uint8_t row[352]; int exists = 0;
    if (!e) e = cursor_next(&c, row, &exists);
    if (!e && exists && get64(row) != parent) { c.depth = 0; exists = 0; }
    if (!e && exists) { node n; e = node_get(&r, &ns, get64(row + 267), 1, &n); if (e == SFS_NOT_FOUND) e = SFS_CORRUPT;
        if (!e && (n.e.parent != parent || n.e.name_length != get32(row + 8) || memcmp(n.e.name, row + 12, n.e.name_length))) e = SFS_CORRUPT;
        if (!e) { *out = n.e; *found = 1; }
    }
    if (!e) save_cookie(cookie, &ns, parent, &c); return touched_result(&r, e, result_out);
}
