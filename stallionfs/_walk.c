#include "_tree.h"
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct scan {
    struct stallion_scan_stats *stats;
    dev_t device;
    int bulk, error;
    stallion_cancel_fn cancel;
    void *context;
    char *error_path;
    size_t error_capacity;
};

static int fail(struct scan *s, int error, const char *path) {
    if (!s->error) {
        s->error = error ? error : EIO;
        if (s->error_path && s->error_capacity)
            snprintf(s->error_path, s->error_capacity, "%s", path);
    }
    return -1;
}

static int cancelled(struct scan *s, const char *path) {
    return s->cancel && s->cancel(s->context) ? fail(s, EINTR, path) : 0;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s);

static int visit(int fd, const char *path, const char *name, unsigned type,
                 off_t size, unsigned depth, struct scan *s) {
    if (type == VREG) {
        if (size < 0 || UINT64_MAX - s->stats->logical_bytes < (uint64_t)size)
            return fail(s, EOVERFLOW, path);
        s->stats->files++;
        s->stats->logical_bytes += size;
    } else if (type == VLNK) s->stats->symlinks++;
    else if (type != VDIR) s->stats->other++;
    else {
        s->stats->directories++;
        char *child_path = NULL;
        if (asprintf(&child_path, "%s/%s", path, name) < 0)
            return fail(s, ENOMEM, path);
        int child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        int result = 0;
        if (child < 0) result = fail(s, errno, child_path);
        else {
            struct stat st;
            if (fstat(child, &st)) {
                result = fail(s, errno, child_path);
                close(child);
            } else if (st.st_dev != s->device) {
                s->stats->skipped_mounts++;
                if (close(child)) result = fail(s, errno, child_path);
            } else result = walk(child, child_path, depth + 1, s);
        }
        free(child_path);
        return result;
    }
    return 0;
}

// getattrlist fields use 4-byte alignment. File length is omitted for directories.
struct __attribute__((packed, aligned(4))) attributes {
    uint32_t length;
    attribute_set_t returned;
    uint32_t error;
    attrreference_t name;
    fsobj_type_t type;
};

static int walk_bulk(int fd, const char *path, unsigned depth, struct scan *s) {
    const size_t capacity = 65536;
    unsigned char *buffer = malloc(capacity);
    if (!buffer) return fail(s, ENOMEM, path);
    struct attrlist requested = {0};
    requested.bitmapcount = ATTR_BIT_MAP_COUNT;
    requested.commonattr = ATTR_CMN_RETURNED_ATTRS | ATTR_CMN_ERROR | ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
    requested.fileattr = ATTR_FILE_DATALENGTH;
    int result = 0;
    for (;;) {
        if (cancelled(s, path)) { result = -1; break; }
        int count = getattrlistbulk(fd, &requested, buffer, capacity, FSOPT_PACK_INVAL_ATTRS);
        if (count < 0) { result = fail(s, errno, path); break; }
        if (!count) break;
        size_t offset = 0;
        for (int i = 0; i < count; i++) {
            struct attributes a;
            off_t size = 0;
            if (offset > capacity - sizeof(a)) goto invalid;
            memcpy(&a, buffer + offset, sizeof(a));
            if (a.length < sizeof(a) || a.length > capacity - offset) goto invalid;
            if (a.error) { result = fail(s, a.error, path); goto done; }
            unsigned required = ATTR_CMN_NAME | ATTR_CMN_OBJTYPE;
            if ((a.returned.commonattr & required) != required) goto invalid;
            size_t fixed = sizeof(a);
            if (a.returned.fileattr & ATTR_FILE_DATALENGTH) {
                fixed += sizeof(size);
                if (a.length < fixed) goto invalid;
                memcpy(&size, buffer + offset + sizeof(a), sizeof(size));
            } else if (a.type == VREG) goto invalid;
            int64_t start = (int64_t)offsetof(struct attributes, name) + a.name.attr_dataoffset;
            if (start < (int64_t)fixed || start >= a.length || !a.name.attr_length ||
                a.name.attr_length > a.length - start) goto invalid;
            const char *name = (const char *)(buffer + offset + start);
            if (name[a.name.attr_length - 1] || !name[0] ||
                memchr(name, '/', a.name.attr_length - 1) ||
                memchr(name, 0, a.name.attr_length - 1) ||
                !strcmp(name, ".") || !strcmp(name, "..")) goto invalid;
            if (visit(fd, path, name, a.type, size, depth, s)) { result = -1; goto done; }
            offset += a.length;
        }
    }
    goto done;
invalid:
    result = fail(s, EIO, path);
done:
    free(buffer);
    return result;
}

// Private reference implementation for correctness and performance comparisons.
static int walk_posix(int fd, const char *path, unsigned depth, struct scan *s) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return fail(s, errno, path);
    DIR *directory = fdopendir(copy);
    if (!directory) { int error = errno; close(copy); return fail(s, error, path); }
    int result = 0;
    unsigned checked = 0;
    for (;;) {
        if (!(checked++ % 256) && cancelled(s, path)) { result = -1; break; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = fail(s, errno, path); break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
            result = fail(s, errno, path);
            break;
        }
        unsigned type = S_ISREG(st.st_mode) ? VREG : S_ISDIR(st.st_mode) ? VDIR : S_ISLNK(st.st_mode) ? VLNK : VNON;
        if (visit(fd, path, entry->d_name, type, st.st_size, depth, s)) { result = -1; break; }
    }
    if (closedir(directory) && !result) result = fail(s, errno, path);
    return result;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s) {
    // Bounded recursion; use an explicit traversal stack if 512 levels are needed.
    int result = depth >= 512 ? fail(s, ELOOP, path) :
        s->bulk ? walk_bulk(fd, path, depth, s) : walk_posix(fd, path, depth, s);
    if (close(fd) && !result) result = fail(s, errno, path);
    return result;
}

int stallion_scan(const char *path, int bulk, struct stallion_scan_stats *stats,
                   stallion_cancel_fn cancel, void *context,
                   char *error_path, size_t error_capacity) {
    if (error_path && error_capacity) error_path[0] = 0;
    if (!path || !stats) { errno = EINVAL; return -1; }
    *stats = (struct stallion_scan_stats){0};
    struct scan s = {.stats = stats, .bulk = bulk, .cancel = cancel, .context = context,
                     .error_path = error_path, .error_capacity = error_capacity};
    int result = -1;
    if (!cancelled(&s, path)) {
        char *trimmed = NULL;
        size_t length = strlen(path);
        if (length > 1 && path[length - 1] == '/') {
            /* A trailing slash must not bypass final-component O_NOFOLLOW. */
            trimmed = strdup(path);
            if (!trimmed) fail(&s, ENOMEM, path);
            else while (length > 1 && trimmed[length - 1] == '/') trimmed[--length] = 0;
        }
        if (!s.error) {
            int fd = open(trimmed ? trimmed : path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) fail(&s, errno, path);
            else {
                struct stat st;
                if (fstat(fd, &st)) { fail(&s, errno, path); close(fd); }
                else { s.device = st.st_dev; result = walk(fd, path, 0, &s); }
            }
        }
        free(trimmed);
    }
    if (!result && cancelled(&s, path)) result = -1;
    errno = s.error;
    return result;
}
