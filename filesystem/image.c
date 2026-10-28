#include "image.h"
#include <CommonCrypto/CommonDigest.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ALIGNMENT UINT64_C(4096)
#define DATA_START UINT64_C(8192)
#define HEADER 64u
#define REF_SIZE 56u
#define ENTRY_SIZE 88u
#define SNAP_SIZE 64u
#define SLOT_HASH 112u
_Static_assert(SFS_IMAGE_MAX <= UINT64_C(67108864), "image test bounds may only decrease");
_Static_assert(SFS_FILE_MAX <= UINT64_C(4194304), "file test bounds may only decrease");
_Static_assert(SFS_METADATA_MAX <= UINT64_C(1048576), "metadata test bounds may only decrease");
_Static_assert(SFS_ENTRY_MAX > 0 && SFS_ENTRY_MAX <= 1024, "entry test bounds may only decrease");
_Static_assert(SFS_SNAPSHOT_MAX > 0 && SFS_SNAPSHOT_MAX <= 32, "snapshot test bounds may only decrease");
_Static_assert(sizeof(off_t) >= 8, "64-bit file offsets required");
enum { PAYLOAD = 1, NAMESPACE, CATALOG, ROOT };
typedef struct { uint32_t type; uint64_t offset, length; uint8_t digest[32]; } reference;
typedef struct { sfs_entry e; reference data; uint8_t *bytes; int dirty; } node;
typedef struct { uint32_t count; uint64_t next_inode; node *nodes; reference ref; } namespace;
typedef struct { uint32_t length; uint8_t name[SFS_NAME_MAX]; reference ns; } snapshot;
typedef struct { uint64_t generation, end; uint8_t uuid[16]; reference root; } anchor;
typedef struct {
    namespace ns;
    uint32_t count;
    snapshot snapshots[SFS_SNAPSHOT_MAX];
    reference catalog;
} state;
struct sfs_image {
    int fd, readonly, selected, poisoned, transaction;
    struct stat identity, parent_identity;
    uint64_t eof;
    anchor current, slots[2];
    enum sfs_status slot_status[2];
    int slot_error[2];
    state live, staged;
    enum sfs_phase phase;
};
typedef struct { reference ref; int verified; } verified_record;
typedef struct { sfs_image *image; anchor a; verified_record *seen; size_t count, capacity; } verifier;

static uint32_t get32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static uint64_t get64(const uint8_t *p) { return get32(p) | (uint64_t)get32(p + 4) << 32; }
static void put32(uint8_t *p, uint32_t v) { for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static void put64(uint8_t *p, uint64_t v) { for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(v >> (8 * i)); }
static int add64(uint64_t a, uint64_t b, uint64_t *out) { if (b > UINT64_MAX - a) return 0; *out = a + b; return 1; }
static int aligned(uint64_t n, uint64_t *out) { uint64_t v; if (!add64(n, ALIGNMENT - 1, &v)) return 0; *out = v & ~(ALIGNMENT - 1); return 1; }
static int zero(const void *p, size_t n) { const uint8_t *b = p; for (size_t i = 0; i < n; ++i) if (b[i]) return 0; return 1; }
static void encode_ref(uint8_t *p, const reference *r) {
    memset(p, 0, REF_SIZE); put32(p, r->type); put64(p + 8, r->offset);
    put64(p + 16, r->length); memcpy(p + 24, r->digest, 32);
}
static int decode_ref(const uint8_t *p, reference *r) {
    if (get32(p + 4)) return 0;
    memset(r, 0, sizeof(*r)); r->type = get32(p); r->offset = get64(p + 8);
    r->length = get64(p + 16); memcpy(r->digest, p + 24, 32); return 1;
}
static int same_ref(const reference *a, const reference *b) {
    return a->type == b->type && a->offset == b->offset && a->length == b->length && !memcmp(a->digest, b->digest, 32);
}
static void free_namespace(namespace *ns) {
    if (ns->nodes) for (uint32_t i = 0; i < ns->count; ++i) free(ns->nodes[i].bytes);
    free(ns->nodes); memset(ns, 0, sizeof(*ns));
}
static void free_state(state *s) { free_namespace(&s->ns); memset(s, 0, sizeof(*s)); }
static void discard(sfs_image *h) { free_state(&h->staged); h->transaction = 0; }
static enum sfs_status result(sfs_image *h, enum sfs_status status, enum sfs_phase phase, int error, sfs_result *r) {
    if (r) {
        memset(r, 0, sizeof(*r)); r->status = status; r->phase = phase; r->system_errno = error;
        if (h) {
            r->generation = h->current.generation; r->committed_end = h->current.end; r->physical_end = h->eof;
            r->device = (uint64_t)h->identity.st_dev; r->inode = (uint64_t)h->identity.st_ino;
            memcpy(r->uuid, h->current.uuid, 16); memcpy(r->root_digest, h->current.root.digest, 32);
        }
    }
    return status;
}
static enum sfs_status limit(sfs_image *h, sfs_result *r) { discard(h); return result(h, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, r); }
static enum sfs_status ready(sfs_image *h, int writing, int tx, sfs_result *r) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (h->poisoned) return result(h, SFS_POISONED, h->phase, 0, r);
    if (!h->selected || (writing && h->readonly) || (tx && !h->transaction)) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    return SFS_OK;
}
static enum sfs_status read_result(sfs_image *h, enum sfs_status code, enum sfs_phase phase, int error, sfs_result *r) {
    if (h && !h->readonly && (code == SFS_IO || code == SFS_CORRUPT || code == SFS_RECOVERY_REQUIRED || code == SFS_UNSUPPORTED)) {
        h->poisoned = 1; h->phase = phase; discard(h);
    }
    return result(h, code, phase, error, r);
}
static int read_exact(int fd, void *buffer, size_t n, uint64_t at) {
    uint8_t *p = buffer;
    while (n) {
        ssize_t k = pread(fd, p, n, (off_t)at);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { if (!k) errno = EIO; return -1; }
        if ((size_t)k > n) { errno = EIO; return -1; }
        p += k; n -= (size_t)k; at += (uint64_t)k;
    }
    return 0;
}
static int write_exact(int fd, const void *buffer, size_t n, uint64_t at) {
    const uint8_t *p = buffer;
    while (n) {
        ssize_t k = pwrite(fd, p, n, (off_t)at);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) { if (!k) errno = EIO; return -1; }
        if ((size_t)k > n) { errno = EIO; return -1; }
        p += k; n -= (size_t)k; at += (uint64_t)k;
    }
    return 0;
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
    h->fd = fd; h->readonly = readonly; h->parent_identity = ps;
    phase = SFS_PHASE_LOCK;
    if (flock(fd, LOCK_EX | LOCK_NB)) { code = errno == EWOULDBLOCK ? SFS_BUSY : SFS_IO; goto fail_handle; }
    phase = SFS_PHASE_VALIDATE;
    if (file_stat(fd, &h->identity)) { code = errno == EFBIG ? SFS_LIMIT : SFS_INVALID; goto fail_handle; }
    h->eof = (uint64_t)h->identity.st_size;
    struct statfs fs;
    if (backing(fd, &fs)) { code = errno == ENOTSUP ? SFS_UNSUPPORTED : SFS_IO; goto fail_handle; }
    if (memcmp(&fs.f_fsid, &pf.f_fsid, sizeof(fs.f_fsid)) || h->identity.st_dev != ps.st_dev) { errno = EXDEV; code = SFS_INVALID; goto fail_handle; }
    struct stat named;
    if (fstatat(p, name, &named, AT_SYMLINK_NOFOLLOW) || !same_identity(&named, &h->identity)) { if (!errno) errno = ESTALE; goto fail_handle; }
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

static void encode_slot(uint8_t b[4096], const anchor *a) {
    memset(b, 0, 4096); memcpy(b, "SFSIMG01", 8); put32(b + 12, 1);
    memcpy(b + 24, a->uuid, 16); put64(b + 40, a->generation);
    encode_ref(b + 48, &a->root); put64(b + 104, a->end);
    CC_SHA256(b, 4096, b + SLOT_HASH);
}
static enum sfs_status decode_slot(sfs_image *h, unsigned index, anchor *a) {
    uint8_t b[4096], digest[32], expected[32];
    if (h->eof < (index + 1) * ALIGNMENT) return SFS_CORRUPT;
    if (read_exact(h->fd, b, sizeof(b), index * ALIGNMENT)) return SFS_IO;
    memcpy(expected, b + SLOT_HASH, 32); memset(b + SLOT_HASH, 0, 32); CC_SHA256(b, sizeof(b), digest);
    if (memcmp(b, "SFSIMG01", 8) || memcmp(digest, expected, 32)) return SFS_CORRUPT;
    if (get32(b + 8) || get32(b + 12) != 1 || get64(b + 16)) return SFS_UNSUPPORTED;
    if (!zero(b + 144, sizeof(b) - 144) || !decode_ref(b + 48, &a->root)) return SFS_CORRUPT;
    memcpy(a->uuid, b + 24, 16); a->generation = get64(b + 40); a->end = get64(b + 104);
    uint64_t end, rounded;
    if (zero(a->uuid, 16) || !a->generation || a->root.type != ROOT || a->root.offset < DATA_START || a->root.offset % ALIGNMENT ||
        a->root.length != HEADER + 2 * REF_SIZE || !add64(a->root.offset, a->root.length, &end) || !aligned(end, &rounded) ||
        a->end != rounded || a->end > h->eof || a->end > SFS_IMAGE_MAX) return SFS_CORRUPT;
    return SFS_OK;
}
static int pair_valid(const anchor a[2]) {
    if (memcmp(a[0].uuid, a[1].uuid, 16)) return 0;
    if (a[0].generation == a[1].generation)
        return a[0].generation == 1 && a[0].end == a[1].end && same_ref(&a[0].root, &a[1].root);
    unsigned newest = a[0].generation > a[1].generation ? 0 : 1, old = 1 - newest;
    return a[old].generation != UINT64_MAX && a[newest].generation == a[old].generation + 1 &&
        a[newest].end > a[old].end && a[newest].generation % 2 == newest;
}
static enum sfs_status remember(verifier *v, const reference *r, size_t *index) {
    for (size_t i = 0; i < v->count; ++i) {
        const reference *old = &v->seen[i].ref;
        if (r->offset == old->offset) { if (!same_ref(r, old)) return SFS_CORRUPT; *index = i; return SFS_OK; }
        if (r->offset < old->offset + old->length && old->offset < r->offset + r->length) return SFS_CORRUPT;
    }
    size_t bound = ((size_t)SFS_SNAPSHOT_MAX + 1) * ((size_t)SFS_ENTRY_MAX + 1) + 2;
    if (v->count >= bound) return SFS_CORRUPT;
    if (v->count == v->capacity) {
        size_t capacity = v->capacity ? v->capacity * 2 : 32; if (capacity > bound) capacity = bound;
        if (capacity > SIZE_MAX / sizeof(verified_record)) return SFS_CORRUPT;
        verified_record *p = realloc(v->seen, capacity * sizeof(verified_record)); if (!p) return SFS_NOMEM;
        v->seen = p; v->capacity = capacity;
    }
    *index = v->count; v->seen[v->count++] = (verified_record){ .ref = *r }; return SFS_OK;
}
static enum sfs_status reference_bounds(verifier *v, const reference *r, uint32_t type, uint64_t before) {
    uint64_t end;
    if (r->type != type || r->offset < DATA_START || r->offset % ALIGNMENT || r->length < HEADER ||
        !add64(r->offset, r->length, &end) || end > before || end > v->a.end || end > v->image->eof ||
        (type == PAYLOAD ? r->length - HEADER > SFS_FILE_MAX : r->length > SFS_METADATA_MAX) || r->length > SIZE_MAX) return SFS_CORRUPT;
    return SFS_OK;
}
static enum sfs_status record(verifier *v, const reference *r, uint32_t type, uint64_t before, uint8_t **body) {
    enum sfs_status code = reference_bounds(v, r, type, before); if (code) return code;
    size_t index; code = remember(v, r, &index); if (code) return code;
    if (type == PAYLOAD && !body && v->seen[index].verified) return SFS_OK;
    uint8_t header[HEADER];
    if (read_exact(v->image->fd, header, sizeof(header), r->offset)) return SFS_IO;
    if (memcmp(header, "SFSREC01", 8) || get32(header + 8) != type || get32(header + 12) ||
        get64(header + 16) != r->length - HEADER || memcmp(header + 24, v->a.uuid, 16) || !zero(header + 40, 24)) return SFS_CORRUPT;
    if (body) { *body = malloc((size_t)(r->length - HEADER) + 1); if (!*body) return SFS_NOMEM; }
    CC_SHA256_CTX hash; CC_SHA256_Init(&hash); CC_SHA256_Update(&hash, header, sizeof(header));
    uint8_t scratch[65536]; uint64_t position = HEADER;
    while (position < r->length) {
        size_t n = (size_t)(r->length - position); if (n > sizeof(scratch)) n = sizeof(scratch);
        if (read_exact(v->image->fd, scratch, n, r->offset + position)) { code = SFS_IO; goto fail; }
        CC_SHA256_Update(&hash, scratch, (CC_LONG)n);
        if (body) memcpy(*body + (size_t)(position - HEADER), scratch, n);
        position += n;
    }
    uint8_t digest[32]; CC_SHA256_Final(digest, &hash);
    if (memcmp(digest, r->digest, 32)) { code = SFS_CORRUPT; goto fail; }
    v->seen[index].verified = 1;
    return SFS_OK;
fail:
    if (body) { free(*body); *body = NULL; } return code;
}
static node *find(namespace *ns, sfs_inode id) {
    for (uint32_t i = 0; i < ns->count; ++i) if (ns->nodes[i].e.inode == id) return &ns->nodes[i];
    return NULL;
}
static int directory(namespace *ns, sfs_inode id) { node *n = find(ns, id); return id == SFS_ROOT_INODE || (n && n->e.kind == SFS_DIRECTORY); }
static int duplicate(namespace *ns, sfs_inode parent, const void *name, size_t n, sfs_inode except) {
    for (uint32_t i = 0; i < ns->count; ++i) { sfs_entry *e = &ns->nodes[i].e;
        if (e->inode != except && e->parent == parent && e->name_length == n && !memcmp(e->name, name, n)) return 1;
    } return 0;
}
static enum sfs_status load_namespace(verifier *v, const reference *r, uint64_t before, int payloads, namespace *out) {
    uint8_t *b = NULL; enum sfs_status code = record(v, r, NAMESPACE, before, &b); if (code) return code;
    size_t size = (size_t)r->length - HEADER, pos = 16;
    memset(out, 0, sizeof(*out)); out->ref = *r;
    if (size < 16 || get32(b + 4) || get32(b) > SFS_ENTRY_MAX || get64(b + 8) < 2) { code = SFS_CORRUPT; goto done; }
    out->count = get32(b); out->next_inode = get64(b + 8);
    out->nodes = calloc(out->count ? out->count : 1, sizeof(node)); if (!out->nodes) { code = SFS_NOMEM; goto done; }
    uint64_t previous = 1;
    for (uint32_t i = 0; i < out->count; ++i) {
        if (pos > size || size - pos < ENTRY_SIZE) { code = SFS_CORRUPT; goto done; }
        const uint8_t *p = b + pos; node *n = &out->nodes[i];
        n->e.inode = get64(p); n->e.parent = get64(p + 8); n->e.kind = (enum sfs_kind)get32(p + 16);
        n->e.name_length = get32(p + 20); n->e.size = get64(p + 24);
        if (!decode_ref(p + 32, &n->data) || n->e.inode <= previous || n->e.inode >= out->next_inode ||
            n->e.name_length > size - pos - ENTRY_SIZE || !valid_name(p + ENTRY_SIZE, n->e.name_length) ||
            (n->e.kind != SFS_FILE && n->e.kind != SFS_DIRECTORY)) { code = SFS_CORRUPT; goto done; }
        memcpy(n->e.name, p + ENTRY_SIZE, n->e.name_length); previous = n->e.inode;
        pos += ENTRY_SIZE + n->e.name_length;
        if (n->e.kind == SFS_DIRECTORY) {
            if (n->e.size || !zero(p + 32, REF_SIZE)) { code = SFS_CORRUPT; goto done; }
        } else {
            if (n->e.size > SFS_FILE_MAX || n->data.length != HEADER + n->e.size) { code = SFS_CORRUPT; goto done; }
            if (payloads) code = record(v, &n->data, PAYLOAD, r->offset, NULL);
            else {
                size_t index; code = reference_bounds(v, &n->data, PAYLOAD, r->offset);
                if (!code) code = remember(v, &n->data, &index);
            }
            if (code) goto done;
        }
    }
    if (pos != size) { code = SFS_CORRUPT; goto done; }
    for (uint32_t i = 0; i < out->count; ++i) {
        sfs_entry *e = &out->nodes[i].e;
        if (!directory(out, e->parent) || duplicate(out, e->parent, e->name, e->name_length, e->inode)) { code = SFS_CORRUPT; goto done; }
        uint64_t id = e->parent; uint32_t depth = 0;
        while (id != 1) { node *n = find(out, id); if (!n || ++depth > out->count || id == e->inode) { code = SFS_CORRUPT; goto done; } id = n->e.parent; }
    }
done:
    free(b); if (code) free_namespace(out); return code;
}
static enum sfs_status load_state(sfs_image *h, const anchor *a, state *out) {
    memset(out, 0, sizeof(*out)); verifier v = { .image = h, .a = *a }; uint8_t *root = NULL, *cat = NULL;
    enum sfs_status code = record(&v, &a->root, ROOT, a->end, &root); if (code) goto done;
    reference ns;
    if (!decode_ref(root, &ns) || !decode_ref(root + REF_SIZE, &out->catalog)) { code = SFS_CORRUPT; goto done; }
    code = load_namespace(&v, &ns, a->root.offset, 1, &out->ns); if (code) goto done;
    code = record(&v, &out->catalog, CATALOG, a->root.offset, &cat); if (code) goto done;
    size_t size = (size_t)out->catalog.length - HEADER, pos = 8;
    if (size < 8 || get32(cat + 4) || get32(cat) > SFS_SNAPSHOT_MAX) { code = SFS_CORRUPT; goto done; }
    out->count = get32(cat);
    for (uint32_t i = 0; i < out->count; ++i) {
        snapshot *s = &out->snapshots[i];
        if (pos > size || size - pos < SNAP_SIZE) { code = SFS_CORRUPT; goto done; }
        const uint8_t *p = cat + pos; s->length = get32(p);
        if (get32(p + 4) || !decode_ref(p + 8, &s->ns) || s->length > size - pos - SNAP_SIZE || !valid_name(p + SNAP_SIZE, s->length)) { code = SFS_CORRUPT; goto done; }
        memcpy(s->name, p + SNAP_SIZE, s->length); pos += SNAP_SIZE + s->length;
        for (uint32_t j = 0; j < i; ++j) if (s->length == out->snapshots[j].length && !memcmp(s->name, out->snapshots[j].name, s->length)) { code = SFS_CORRUPT; goto done; }
        namespace historical = {0}; code = load_namespace(&v, &s->ns, out->catalog.offset, 1, &historical);
        if (!code && historical.next_inode > out->ns.next_inode) code = SFS_CORRUPT;
        free_namespace(&historical); if (code) goto done;
    }
    if (pos != size) code = SFS_CORRUPT;
done:
    free(root); free(cat); free(v.seen); if (code) free_state(out); return code;
}

static enum sfs_status predecessor_counter(sfs_image *h, const anchor *previous, uint64_t current) {
    verifier v = { .image = h, .a = *previous }; uint8_t *root = NULL; namespace ns = {0};
    enum sfs_status code = record(&v, &previous->root, ROOT, previous->end, &root);
    if (!code) {
        reference nsref, catalog;
        if (!decode_ref(root, &nsref) || !decode_ref(root + REF_SIZE, &catalog)) code = SFS_CORRUPT;
        else {
            size_t index; code = reference_bounds(&v, &catalog, CATALOG, previous->root.offset);
            if (!code) code = remember(&v, &catalog, &index);
            if (!code) code = load_namespace(&v, &nsref, previous->root.offset, 0, &ns);
            if (!code && current < ns.next_inode) code = SFS_CORRUPT;
        }
    }
    int error = code == SFS_IO ? errno : 0;
    free(root); free_namespace(&ns); free(v.seen); if (error) errno = error; return code;
}

static enum sfs_status close_failed(sfs_image *h, int parent, enum sfs_status code,
                                    enum sfs_phase phase, int error, sfs_result *r) {
    struct stat st;
    if (!fstat(h->fd, &st) && st.st_size >= 0) h->eof = (uint64_t)st.st_size;
    result(h, code, phase, error, r);
    if (parent >= 0 && close(parent)) { error = errno; phase = SFS_PHASE_CLOSE; if (code != SFS_OUTCOME_UNKNOWN) code = SFS_IO; }
    if (close(h->fd)) { error = errno; phase = SFS_PHASE_CLOSE; if (code != SFS_OUTCOME_UNKNOWN) code = SFS_IO; }
    free_state(&h->live); free_state(&h->staged); free(h);
    if (r) { r->status = code; r->phase = phase; r->system_errno = error; }
    return code;
}
static void candidate_result(sfs_image *h, const anchor *a, enum sfs_status code, int error, sfs_result *r) {
    if (!r) return;
    result(h, code, SFS_PHASE_READ, error, r);
    if (a) { r->generation = a->generation; r->committed_end = a->end;
        memcpy(r->uuid, a->uuid, 16); memcpy(r->root_digest, a->root.digest, 32); }
    if (!code) r->coverage = SFS_COVERAGE_FULL_REACHABLE;
}
static enum sfs_status open_common(const char *directory, const char *name, int inspection,
                                   sfs_image **out, sfs_recovery *report, sfs_result *r) {
    if (!out || (inspection && !report)) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    *out = NULL;
    sfs_image *h; int parent;
    enum sfs_status code = access_image(directory, name, 0, inspection, &h, &parent, r); if (code) return code;
    if (close(parent)) return close_failed(h, -1, SFS_IO, SFS_PHASE_CLOSE, errno, r);
    for (unsigned i = 0; i < 2; ++i) {
        h->slot_status[i] = decode_slot(h, i, &h->slots[i]);
        h->slot_error[i] = h->slot_status[i] == SFS_IO ? errno : 0;
    }
    int slot_error = h->slot_error[0] ? h->slot_error[0] : h->slot_error[1];
    int pair = !h->slot_status[0] && !h->slot_status[1] && pair_valid(h->slots);
    if (!inspection) {
        if (h->slot_status[0] == SFS_UNSUPPORTED || h->slot_status[1] == SFS_UNSUPPORTED)
            return close_failed(h, -1, SFS_UNSUPPORTED, SFS_PHASE_READ, slot_error, r);
        if (!pair) return close_failed(h, -1, SFS_RECOVERY_REQUIRED, SFS_PHASE_READ, slot_error, r);
        unsigned index = h->slots[0].generation > h->slots[1].generation ? 0 : 1;
        h->current = h->slots[index];
        code = load_state(h, &h->current, &h->live);
        if (code) return close_failed(h, -1, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
        if (h->slots[1 - index].generation < h->current.generation) {
            code = predecessor_counter(h, &h->slots[1 - index], h->live.ns.next_inode);
            if (code) return close_failed(h, -1, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
        }
        if (stable(h)) return close_failed(h, -1, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
        h->selected = 1; *out = h; candidate_result(h, &h->current, SFS_OK, 0, r); return SFS_OK;
    }
    memset(report, 0, sizeof(*report)); report->pair_valid = pair; report->latest_may_be_unknown = 1;
    int usable = 0;
    for (unsigned i = 0; i < 2; ++i) {
        code = h->slot_status[i];
        if (!code) {
            state candidate = {0}; code = load_state(h, &h->slots[i], &candidate);
            h->slot_error[i] = code == SFS_IO ? errno : 0; free_state(&candidate);
        }
        candidate_result(h, h->slot_status[i] ? NULL : &h->slots[i], code, h->slot_error[i], &report->slots[i]);
        h->slot_status[i] = code; if (!code) ++usable;
    }
    if (stable(h)) return close_failed(h, -1, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    if (!usable) return close_failed(h, -1, SFS_RECOVERY_REQUIRED, SFS_PHASE_READ,
                                     h->slot_error[0] ? h->slot_error[0] : h->slot_error[1], r);
    *out = h; return result(h, SFS_OK, SFS_PHASE_READ, 0, r);
}
enum sfs_status sfs_image_open(const char *directory, const char *name, sfs_image **out, sfs_result *r) {
    return open_common(directory, name, 0, out, NULL, r);
}
enum sfs_status sfs_image_inspect(const char *directory, const char *name, sfs_image **out, sfs_recovery *report, sfs_result *r) {
    return open_common(directory, name, 1, out, report, r);
}
enum sfs_status sfs_image_select(sfs_image *h, unsigned slot, sfs_result *r) {
    if (!h || !h->readonly || slot > 1) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (h->slot_status[slot]) return result(h, h->slot_status[slot], SFS_PHASE_READ, h->slot_error[slot], r);
    if (stable(h)) return result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    anchor fresh = {0}; enum sfs_status code = decode_slot(h, slot, &fresh);
    if (code) return result(h, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
    if (fresh.generation != h->slots[slot].generation || fresh.end != h->slots[slot].end ||
        memcmp(fresh.uuid, h->slots[slot].uuid, 16) || !same_ref(&fresh.root, &h->slots[slot].root))
        return result(h, SFS_CORRUPT, SFS_PHASE_READ, 0, r);
    state selected = {0}; code = load_state(h, &fresh, &selected);
    if (code) return result(h, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
    free_state(&h->live); h->live = selected; h->current = h->slots[slot]; h->selected = 1;
    candidate_result(h, &h->current, SFS_OK, 0, r); return SFS_OK;
}
enum sfs_status sfs_image_close(sfs_image *h, sfs_result *r) {
    if (!h) return result(NULL, SFS_INVALID, SFS_PHASE_CLOSE, 0, r);
    enum sfs_status code = SFS_OK; int error = 0;
    if (close(h->fd)) { code = SFS_IO; error = errno; }
    result(h, code, SFS_PHASE_CLOSE, error, r); free_state(&h->live); free_state(&h->staged); free(h); return code;
}
enum sfs_status sfs_image_verify(sfs_image *h, sfs_result *r) {
    enum sfs_status code = ready(h, 0, 0, r); if (code) return code;
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    /* Re-read both anchors as well as all reachable records; cached state is not evidence. */
    anchor a[2] = {0}; enum sfs_status validity[2];
    for (unsigned i = 0; i < 2; ++i) {
        code = validity[i] = decode_slot(h, i, &a[i]);
        if (code && !h->readonly) return read_result(h, code == SFS_UNSUPPORTED ? code : SFS_RECOVERY_REQUIRED, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
    }
    if (!h->readonly && !pair_valid(a)) return read_result(h, SFS_RECOVERY_REQUIRED, SFS_PHASE_READ, 0, r);
    unsigned index = a[0].generation > a[1].generation ? 0 : 1;
    if (h->readonly) {
        int matched = 0;
        for (unsigned i = 0; i < 2; ++i) if (!validity[i] && a[i].generation == h->current.generation && same_ref(&a[i].root, &h->current.root) && a[i].end == h->current.end && !memcmp(a[i].uuid, h->current.uuid, 16)) matched = 1;
        if (!matched) return result(h, SFS_CORRUPT, SFS_PHASE_READ, 0, r);
    } else if (a[index].generation != h->current.generation || !same_ref(&a[index].root, &h->current.root) || a[index].end != h->current.end || memcmp(a[index].uuid, h->current.uuid, 16))
        return read_result(h, SFS_CORRUPT, SFS_PHASE_READ, 0, r);
    state checked = {0}; code = load_state(h, &h->current, &checked);
    if (!code && !h->readonly && a[1 - index].generation < h->current.generation)
        code = predecessor_counter(h, &a[1 - index], checked.ns.next_inode);
    int error = code == SFS_IO ? errno : 0; free_state(&checked);
    read_result(h, code, SFS_PHASE_READ, error, r);
    if (!code && r) r->coverage = SFS_COVERAGE_FULL_REACHABLE; return code;
}

static int namespace_length(const namespace *ns, uint64_t *out) {
    uint64_t n = HEADER + 16;
    for (uint32_t i = 0; i < ns->count; ++i) if (!add64(n, ENTRY_SIZE + ns->nodes[i].e.name_length, &n)) return 0;
    *out = n; return 1;
}
static int catalog_length(const state *s, uint64_t *out) {
    uint64_t n = HEADER + 8;
    for (uint32_t i = 0; i < s->count; ++i) if (!add64(n, SNAP_SIZE + s->snapshots[i].length, &n)) return 0;
    *out = n; return 1;
}
static int admit(const sfs_image *h, const state *s, uint64_t *end) {
    uint64_t at, n;
    if (!aligned(h->eof < DATA_START ? DATA_START : h->eof, &at) || s->ns.count > SFS_ENTRY_MAX || s->count > SFS_SNAPSHOT_MAX || h->current.generation == UINT64_MAX) return 0;
    for (uint32_t i = 0; i < s->ns.count; ++i) {
        const node *e = &s->ns.nodes[i];
        if (e->e.name_length > SFS_NAME_MAX || e->e.size > SFS_FILE_MAX) return 0;
        if (e->dirty && (!add64(e->e.size, HEADER, &n) || !aligned(n, &n) || !add64(at, n, &at))) return 0;
    }
    if (!namespace_length(&s->ns, &n) || n > SFS_METADATA_MAX || !aligned(n, &n) || !add64(at, n, &at)) return 0;
    if (!catalog_length(s, &n) || n > SFS_METADATA_MAX || !aligned(n, &n) || !add64(at, n, &at)) return 0;
    if (HEADER + 2 * REF_SIZE > SFS_METADATA_MAX || !add64(at, ALIGNMENT, &at) || at > SFS_IMAGE_MAX || at > INT64_MAX) return 0;
    *end = at; return 1;
}
static enum sfs_status admission(sfs_image *h, sfs_result *r) {
    uint64_t end; if (!admit(h, &h->staged, &end)) return limit(h, r); return SFS_OK;
}
static int write_record(sfs_image *h, uint32_t type, const uint8_t *body, uint64_t length,
                        uint64_t *at, reference *out) {
    uint8_t header[HEADER] = {0}; memcpy(header, "SFSREC01", 8); put32(header + 8, type);
    put64(header + 16, length); memcpy(header + 24, h->current.uuid, 16);
    memset(out, 0, sizeof(*out)); out->type = type; out->offset = *at; out->length = HEADER + length;
    CC_SHA256_CTX hash; CC_SHA256_Init(&hash); CC_SHA256_Update(&hash, header, sizeof(header));
    if (length) CC_SHA256_Update(&hash, body, (CC_LONG)length); CC_SHA256_Final(out->digest, &hash);
    if (write_exact(h->fd, header, sizeof(header), *at) || (length && write_exact(h->fd, body, (size_t)length, *at + HEADER))) return -1;
    uint64_t end = *at + out->length, next; if (!aligned(end, &next)) { errno = EOVERFLOW; return -1; }
    uint8_t padding[4096] = {0}; if (next > end && write_exact(h->fd, padding, (size_t)(next - end), end)) return -1;
    *at = next; h->eof = next; return 0;
}
static int write_state(sfs_image *h, state *s, anchor *a) {
    uint64_t at; if (!aligned(h->eof < DATA_START ? DATA_START : h->eof, &at)) { errno = EOVERFLOW; return -1; }
    /* shortcut: whole-file records rewrite a bounded file; replace with ranged records before mounted workload qualification. */
    for (uint32_t i = 0; i < s->ns.count; ++i) {
        node *n = &s->ns.nodes[i]; if (n->dirty && write_record(h, PAYLOAD, n->bytes, n->e.size, &at, &n->data)) return -1;
    }
    uint64_t length;
    /* shortcut: every transaction rewrites the capped manifest; indexed metadata is required before large workloads. */
    if (!namespace_length(&s->ns, &length)) { errno = EOVERFLOW; return -1; }
    uint8_t *b = calloc(1, (size_t)(length - HEADER)); if (!b) { errno = ENOMEM; return -1; }
    put32(b, s->ns.count); put64(b + 8, s->ns.next_inode); size_t pos = 16;
    for (uint32_t i = 0; i < s->ns.count; ++i) {
        node *n = &s->ns.nodes[i]; uint8_t *p = b + pos;
        put64(p, n->e.inode); put64(p + 8, n->e.parent); put32(p + 16, n->e.kind);
        put32(p + 20, (uint32_t)n->e.name_length); put64(p + 24, n->e.size); encode_ref(p + 32, &n->data);
        memcpy(p + ENTRY_SIZE, n->e.name, n->e.name_length); pos += ENTRY_SIZE + n->e.name_length;
    }
    int failed = write_record(h, NAMESPACE, b, length - HEADER, &at, &s->ns.ref); free(b); if (failed) return -1;
    if (!catalog_length(s, &length)) { errno = EOVERFLOW; return -1; }
    b = calloc(1, (size_t)(length - HEADER)); if (!b) { errno = ENOMEM; return -1; }
    put32(b, s->count); pos = 8;
    for (uint32_t i = 0; i < s->count; ++i) {
        snapshot *snap = &s->snapshots[i]; put32(b + pos, snap->length); encode_ref(b + pos + 8, &snap->ns);
        memcpy(b + pos + SNAP_SIZE, snap->name, snap->length); pos += SNAP_SIZE + snap->length;
    }
    failed = write_record(h, CATALOG, b, length - HEADER, &at, &s->catalog); free(b); if (failed) return -1;
    uint8_t root[2 * REF_SIZE]; encode_ref(root, &s->ns.ref); encode_ref(root + REF_SIZE, &s->catalog);
    if (write_record(h, ROOT, root, sizeof(root), &at, &a->root)) return -1;
    a->end = at; return 0;
}
enum sfs_status sfs_image_create(const char *directory, const char *name, sfs_image **out, sfs_result *r) {
    if (!out) return result(NULL, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    *out = NULL; sfs_image *h; int parent;
    enum sfs_status code = access_image(directory, name, 1, 0, &h, &parent, r); if (code) return code;
    h->live.ns.next_inode = 2; arc4random_buf(h->current.uuid, 16);
    if (zero(h->current.uuid, 16)) h->current.uuid[0] = 1;
    uint64_t end;
    if (!admit(h, &h->live, &end)) return close_failed(h, parent, SFS_LIMIT, SFS_PHASE_ADMISSION, 0, r);
    anchor next = h->current; next.generation = 1;
    enum sfs_phase phase = SFS_PHASE_RECORDS; int published = 0;
    if (write_state(h, &h->live, &next)) goto failed;
    phase = SFS_PHASE_RECORD_BARRIER; if (fullsync(h->fd)) goto failed;
    uint8_t slot[4096]; encode_slot(slot, &next);
    phase = SFS_PHASE_SLOT0; published = 1; if (write_exact(h->fd, slot, sizeof(slot), 0)) goto failed;
    phase = SFS_PHASE_SLOT1; if (write_exact(h->fd, slot, sizeof(slot), ALIGNMENT)) goto failed;
    phase = SFS_PHASE_COMMIT_BARRIER; if (fullsync(h->fd)) goto failed;
    phase = SFS_PHASE_PARENT_BARRIER; if (fsync(parent)) goto failed;
    phase = SFS_PHASE_FINAL_BARRIER; if (fullsync(h->fd)) goto failed;
    phase = SFS_PHASE_IDENTITY;
    struct stat ps, named;
    if (fstat(parent, &ps) || !same_identity(&ps, &h->parent_identity) ||
        fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) || !same_identity(&named, &h->identity) || stable(h)) { if (!errno) errno = ESTALE; goto failed; }
    phase = SFS_PHASE_CLOSE;
    if (close(parent)) { parent = -1; goto failed; } parent = -1;
    h->current = next; h->slots[0] = next; h->slots[1] = next; h->selected = 1;
    *out = h; result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
    if (r) r->coverage = SFS_COVERAGE_FULL_REACHABLE; return SFS_OK;
failed:
    return close_failed(h, parent, published ? SFS_OUTCOME_UNKNOWN : SFS_IO, phase, errno, r);
}

enum sfs_status sfs_image_begin(sfs_image *h, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 0, r); if (code) return code;
    if (h->transaction) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    h->staged = h->live; h->staged.ns.nodes = NULL;
    size_t count = h->live.ns.count;
    h->staged.ns.nodes = calloc(count ? count : 1, sizeof(node));
    if (!h->staged.ns.nodes) { memset(&h->staged, 0, sizeof(h->staged)); return result(h, SFS_NOMEM, SFS_PHASE_NONE, ENOMEM, r); }
    if (count) memcpy(h->staged.ns.nodes, h->live.ns.nodes, count * sizeof(node));
    for (uint32_t i = 0; i < count; ++i) { h->staged.ns.nodes[i].bytes = NULL; h->staged.ns.nodes[i].dirty = 0; }
    h->transaction = 1; code = admission(h, r); if (code) return code;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_abort(sfs_image *h, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    discard(h); return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
static enum sfs_status input_name(sfs_image *h, const void *name, size_t length, sfs_result *r) {
    if (length > SFS_NAME_MAX) return limit(h, r);
    if (!valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    return SFS_OK;
}
enum sfs_status sfs_image_add(sfs_image *h, sfs_inode parent, const void *name, size_t length,
                              enum sfs_kind kind, sfs_inode *out, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    if (!out || (kind != SFS_FILE && kind != SFS_DIRECTORY)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    code = input_name(h, name, length, r); if (code) return code;
    namespace *ns = &h->staged.ns;
    if (!directory(ns, parent)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (duplicate(ns, parent, name, length, 0)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, r);
    if (ns->count >= SFS_ENTRY_MAX || ns->next_inode == UINT64_MAX) return limit(h, r);
    size_t count = (size_t)ns->count + 1;
    if (count > SIZE_MAX / sizeof(node)) return limit(h, r);
    node *p = realloc(ns->nodes, count * sizeof(node)); if (!p) return result(h, SFS_NOMEM, SFS_PHASE_NONE, ENOMEM, r);
    ns->nodes = p; node *n = &ns->nodes[ns->count++]; memset(n, 0, sizeof(*n));
    n->e.inode = ns->next_inode++; n->e.parent = parent; n->e.kind = kind; n->e.name_length = length;
    memcpy(n->e.name, name, length); n->dirty = kind == SFS_FILE;
    sfs_inode id = n->e.inode;
    code = admission(h, r); if (code) return code;
    *out = id; return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_remove(sfs_image *h, sfs_inode id, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    namespace *ns = &h->staged.ns; node *n = find(ns, id);
    if (!n) return result(h, id == 1 ? SFS_INVALID : SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
    for (uint32_t i = 0; i < ns->count; ++i) if (ns->nodes[i].e.parent == id) return result(h, SFS_STATE, SFS_PHASE_NONE, 0, r);
    size_t index = (size_t)(n - ns->nodes); free(n->bytes);
    memmove(n, n + 1, (ns->count - index - 1) * sizeof(node)); --ns->count;
    code = admission(h, r); if (code) return code;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_rename(sfs_image *h, sfs_inode id, sfs_inode parent, const void *name, size_t length, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    code = input_name(h, name, length, r); if (code) return code;
    namespace *ns = &h->staged.ns; node *n = find(ns, id);
    if (!n) return result(h, id == 1 ? SFS_INVALID : SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
    if (!directory(ns, parent)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (duplicate(ns, parent, name, length, id)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, r);
    uint64_t p = parent;
    for (uint32_t depth = 0; p != 1; ++depth) {
        if (p == id || depth >= ns->count) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
        node *ancestor = find(ns, p); if (!ancestor) return result(h, SFS_CORRUPT, SFS_PHASE_NONE, 0, r); p = ancestor->e.parent;
    }
    n->e.parent = parent; n->e.name_length = length; memcpy(n->e.name, name, length);
    code = admission(h, r); if (code) return code;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
static enum sfs_status materialize(sfs_image *h, node *n, uint64_t size, sfs_result *r) {
    uint64_t old_size = n->e.size; int was_dirty = n->dirty;
    n->e.size = size; n->dirty = 1;
    enum sfs_status code = admission(h, r); if (code) return code;
    uint8_t *bytes = calloc(1, (size_t)(size ? size : 1));
    if (!bytes) { n->e.size = old_size; n->dirty = was_dirty; return result(h, SFS_NOMEM, SFS_PHASE_NONE, ENOMEM, r); }
    uint64_t keep = size < old_size ? size : old_size;
    if (was_dirty) { if (keep) memcpy(bytes, n->bytes, (size_t)keep); }
    else {
        verifier v = { .image = h, .a = h->current };
        code = record(&v, &n->data, PAYLOAD, h->live.ns.ref.offset, NULL); free(v.seen);
        if (!code && keep && read_exact(h->fd, bytes, (size_t)keep, n->data.offset + HEADER)) code = SFS_IO;
        if (code) { free(bytes); discard(h); h->poisoned = 1; h->phase = SFS_PHASE_READ; return result(h, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r); }
    }
    free(n->bytes); n->bytes = bytes; return SFS_OK;
}
enum sfs_status sfs_image_write(sfs_image *h, sfs_inode id, uint64_t offset, const void *data, size_t length, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    if (length && !data) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    node *n = find(&h->staged.ns, id);
    if (!n) return result(h, SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
    if (n->e.kind != SFS_FILE) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    uint64_t end;
    if (!add64(offset, length, &end) || end > SFS_FILE_MAX) return limit(h, r);
    if (!length) return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
    uint64_t size = n->e.size > end ? n->e.size : end;
    code = materialize(h, n, size, r); if (code) return code;
    memcpy(n->bytes + (size_t)offset, data, length); return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_resize(sfs_image *h, sfs_inode id, uint64_t size, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    node *n = find(&h->staged.ns, id);
    if (!n) return result(h, SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
    if (n->e.kind != SFS_FILE) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    if (size > SFS_FILE_MAX) return limit(h, r);
    if (size == n->e.size) return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
    code = materialize(h, n, size, r); if (code) return code;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_snapshot(sfs_image *h, const void *name, size_t length, sfs_view *out, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    code = input_name(h, name, length, r); if (code) return code;
    state *s = &h->staged;
    for (uint32_t i = 0; i < s->count; ++i) if (s->snapshots[i].length == length && !memcmp(s->snapshots[i].name, name, length)) return result(h, SFS_EXISTS, SFS_PHASE_NONE, 0, r);
    if (s->count >= SFS_SNAPSHOT_MAX) return limit(h, r);
    snapshot *snap = &s->snapshots[s->count++]; snap->length = (uint32_t)length;
    memcpy(snap->name, name, length); snap->ns = h->live.ns.ref; sfs_view view = s->count;
    code = admission(h, r); if (code) return code;
    *out = view; return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_commit(sfs_image *h, sfs_result *r) {
    enum sfs_status code = ready(h, 1, 1, r); if (code) return code;
    code = admission(h, r); if (code) return code;
    if (stable(h)) { int error = errno; discard(h); h->poisoned = 1; h->phase = SFS_PHASE_IDENTITY; return result(h, SFS_IO, h->phase, error, r); }
    /* Catch observable modification before preserving any cached references. */
    code = sfs_image_verify(h, r);
    if (code) { discard(h); h->poisoned = 1; h->phase = SFS_PHASE_READ; return code; }
    anchor next = h->current; ++next.generation;
    int published = 0; enum sfs_phase phase = SFS_PHASE_RECORDS;
    if (write_state(h, &h->staged, &next)) goto failed;
    phase = SFS_PHASE_RECORD_BARRIER; if (fullsync(h->fd)) goto failed;
    unsigned index = (unsigned)(next.generation % 2); uint8_t slot[4096]; encode_slot(slot, &next);
    phase = index ? SFS_PHASE_SLOT1 : SFS_PHASE_SLOT0; published = 1;
    if (write_exact(h->fd, slot, sizeof(slot), index * ALIGNMENT)) goto failed;
    phase = SFS_PHASE_COMMIT_BARRIER; if (fullsync(h->fd)) goto failed;
    free_state(&h->live); h->live = h->staged; memset(&h->staged, 0, sizeof(h->staged)); h->transaction = 0;
    for (uint32_t i = 0; i < h->live.ns.count; ++i) { free(h->live.ns.nodes[i].bytes); h->live.ns.nodes[i].bytes = NULL; h->live.ns.nodes[i].dirty = 0; }
    h->current = next; h->slots[index] = next;
    return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
failed: {
    int error = errno; discard(h); h->poisoned = 1; h->phase = phase;
    return result(h, published ? SFS_OUTCOME_UNKNOWN : SFS_IO, phase, error, r);
}
}

static enum sfs_status selected_namespace(sfs_image *h, sfs_view view, namespace **out, namespace *temporary, sfs_result *r) {
    enum sfs_status code = ready(h, 0, 0, r); if (code) return code;
    if (stable(h)) return read_result(h, SFS_IO, SFS_PHASE_IDENTITY, errno, r);
    if (!view) { *out = &h->live.ns; return SFS_OK; }
    if (view > h->live.count) return result(h, SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
    verifier v = { .image = h, .a = h->current };
    code = load_namespace(&v, &h->live.snapshots[view - 1].ns, h->live.catalog.offset, 1, temporary); free(v.seen);
    if (code) return read_result(h, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
    *out = temporary; return SFS_OK;
}
enum sfs_status sfs_image_snapshot_view(sfs_image *h, const void *name, size_t length, sfs_view *out, sfs_result *r) {
    enum sfs_status code = ready(h, 0, 0, r); if (code) return code;
    if (!out || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    for (uint32_t i = 0; i < h->live.count; ++i) if (h->live.snapshots[i].length == length && !memcmp(h->live.snapshots[i].name, name, length)) {
        *out = i + 1; return result(h, SFS_OK, SFS_PHASE_NONE, 0, r);
    }
    return result(h, SFS_NOT_FOUND, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_lookup(sfs_image *h, sfs_view view, sfs_inode parent, const void *name, size_t length, sfs_entry *out, sfs_result *r) {
    if (!out || !valid_name(name, length)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    namespace *ns, temporary = {0}; enum sfs_status code = selected_namespace(h, view, &ns, &temporary, r); if (code) return code;
    code = SFS_NOT_FOUND;
    if (!directory(ns, parent)) code = SFS_INVALID;
    else for (uint32_t i = 0; i < ns->count; ++i) if (ns->nodes[i].e.parent == parent && ns->nodes[i].e.name_length == length && !memcmp(ns->nodes[i].e.name, name, length)) { *out = ns->nodes[i].e; code = SFS_OK; break; }
    free_namespace(&temporary); return result(h, code, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_stat(sfs_image *h, sfs_view view, sfs_inode id, sfs_entry *out, sfs_result *r) {
    if (!out) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    namespace *ns, temporary = {0}; enum sfs_status code = selected_namespace(h, view, &ns, &temporary, r); if (code) return code;
    node *n = find(ns, id); code = SFS_NOT_FOUND;
    if (id == 1) { memset(out, 0, sizeof(*out)); out->inode = 1; out->kind = SFS_DIRECTORY; code = SFS_OK; }
    else if (n) { *out = n->e; code = SFS_OK; }
    free_namespace(&temporary); return result(h, code, SFS_PHASE_NONE, 0, r);
}
enum sfs_status sfs_image_read(sfs_image *h, sfs_view view, sfs_inode id, uint64_t offset, void *data, size_t capacity, size_t *read_count, sfs_result *r) {
    if (!read_count || (capacity && !data)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    *read_count = 0; uint64_t end;
    if (!add64(offset, capacity, &end)) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    namespace *ns, temporary = {0}; enum sfs_status code = selected_namespace(h, view, &ns, &temporary, r); if (code) return code;
    node *n = find(ns, id);
    if (!n) code = SFS_NOT_FOUND;
    else if (n->e.kind != SFS_FILE) code = SFS_INVALID;
    else {
        verifier v = { .image = h, .a = h->current }; code = record(&v, &n->data, PAYLOAD, ns->ref.offset, NULL); free(v.seen);
        if (!code && offset < n->e.size) {
            size_t count = (size_t)(n->e.size - offset); if (count > capacity) count = capacity;
            if (count && read_exact(h->fd, data, count, n->data.offset + HEADER + offset)) code = SFS_IO;
            if (!code) *read_count = count;
        }
    }
    free_namespace(&temporary); return read_result(h, code, SFS_PHASE_READ, code == SFS_IO ? errno : 0, r);
}
enum sfs_status sfs_image_next(sfs_image *h, sfs_view view, sfs_inode parent, sfs_cookie *cookie, sfs_entry *out, int *found, sfs_result *r) {
    if (!cookie || !out || !found) return result(h, SFS_INVALID, SFS_PHASE_NONE, 0, r);
    *found = 0; namespace *ns, temporary = {0}; enum sfs_status code = selected_namespace(h, view, &ns, &temporary, r); if (code) return code;
    if (!directory(ns, parent)) code = SFS_INVALID;
    else if (cookie->started && (memcmp(cookie->namespace_digest, ns->ref.digest, 32) || cookie->next > ns->count)) code = SFS_STATE;
    else {
        if (!cookie->started) { memcpy(cookie->namespace_digest, ns->ref.digest, 32); cookie->next = 0; cookie->started = 1; }
        while (cookie->next < ns->count) { node *n = &ns->nodes[cookie->next++]; if (n->e.parent == parent) { *out = n->e; *found = 1; break; } }
    }
    free_namespace(&temporary); return result(h, code, SFS_PHASE_NONE, 0, r);
}
