#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <copyfile.h>
#include <sys/attr.h>
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct scan {
    uint64_t files, directories, symlinks, other, logical_bytes, skipped_mounts;
    dev_t device;
    int bulk, error, cancelled;
    char *error_path;
};

static int fail(struct scan *s, int error, const char *path) {
    if (!s->error && !s->cancelled) {
        s->error = error;
        s->error_path = strdup(path);
    }
    return -1;
}

static int cancelled(struct scan *s) {
    PyGILState_STATE state = PyGILState_Ensure();
    s->cancelled = PyErr_CheckSignals() < 0;
    PyGILState_Release(state);
    return s->cancelled;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s);

static int visit(int fd, const char *path, const char *name, unsigned type,
                 off_t size, unsigned depth, struct scan *s) {
    if (type == VREG) {
        if (size < 0 || UINT64_MAX - s->logical_bytes < (uint64_t)size)
            return fail(s, EOVERFLOW, path);
        s->files++;
        s->logical_bytes += size;
    } else if (type == VLNK) s->symlinks++;
    else if (type != VDIR) s->other++;
    else {
        s->directories++;
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
                s->skipped_mounts++;
                close(child);
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
        if (cancelled(s)) { result = -1; break; }
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
    int copy = dup(fd);
    if (copy < 0) return fail(s, errno, path);
    DIR *directory = fdopendir(copy);
    if (!directory) { int error = errno; close(copy); return fail(s, error, path); }
    int result = 0;
    unsigned checked = 0;
    for (;;) {
        if (!(checked++ % 256) && cancelled(s)) { result = -1; break; }
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
    closedir(directory);
    return result;
}

static int walk(int fd, const char *path, unsigned depth, struct scan *s) {
    // Bounded recursion; use an explicit traversal stack if 512 levels are needed.
    int result = depth >= 512 ? fail(s, ELOOP, path) :
        s->bulk ? walk_bulk(fd, path, depth, s) : walk_posix(fd, path, depth, s);
    if (close(fd) && !result) result = fail(s, errno, path);
    return result;
}

static PyObject *scan_tree(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *names[] = {"path", "bulk", NULL};
    PyObject *path;
    struct scan s = {0};
    s.bulk = 1;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|p", names, PyUnicode_FSConverter, &path, &s.bulk)) return NULL;
    const char *name = PyBytes_AS_STRING(path);
    if ((Py_ssize_t)strlen(name) != PyBytes_GET_SIZE(path)) {
        Py_DECREF(path);
        PyErr_SetString(PyExc_ValueError, "Path contains a null byte");
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    int fd = open(name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail(&s, errno, name);
    else {
        struct stat st;
        if (fstat(fd, &st)) { fail(&s, errno, name); close(fd); }
        else { s.device = st.st_dev; walk(fd, name, 0, &s); }
    }
    Py_END_ALLOW_THREADS
    PyObject *result = NULL;
    if (s.error) {
        errno = s.error;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, s.error_path ? s.error_path : name);
    } else if (!s.cancelled) {
        result = Py_BuildValue("{s:K,s:K,s:K,s:K,s:K,s:K}",
            "files", (unsigned long long)s.files, "directories", (unsigned long long)s.directories,
            "symlinks", (unsigned long long)s.symlinks, "other", (unsigned long long)s.other,
            "logical_bytes", (unsigned long long)s.logical_bytes, "skipped_mounts", (unsigned long long)s.skipped_mounts);
    }
    free(s.error_path);
    Py_DECREF(path);
    return result;
}

static int clone_walk(int source, int destination, const char *path, unsigned depth, struct scan *s) {
    if (depth >= 512) return fail(s, ELOOP, path);
    int copy = dup(source);
    if (copy < 0) return fail(s, errno, path);
    DIR *directory = fdopendir(copy);
    if (!directory) { int error = errno; close(copy); return fail(s, error, path); }
    int result = 0;
    unsigned checked = 0;
    for (;;) {
        if (!(checked++ % 256) && cancelled(s)) { result = -1; break; }
        errno = 0;
        struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) result = fail(s, errno, path); break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        unsigned type = entry->d_type;
        if (type == DT_UNKNOWN) {
            struct stat st;
            if (fstatat(source, name, &st, AT_SYMLINK_NOFOLLOW)) { result = fail(s, errno, path); break; }
            type = S_ISDIR(st.st_mode) ? DT_DIR : S_ISREG(st.st_mode) ? DT_REG : S_ISLNK(st.st_mode) ? DT_LNK : DT_UNKNOWN;
        }
        if (type == DT_DIR) {
            char *child_path = NULL;
            if (asprintf(&child_path, "%s/%s", path, name) < 0) { result = fail(s, ENOMEM, path); break; }
            int child = openat(source, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            int target = -1;
            struct stat st;
            if (child < 0) result = fail(s, errno, child_path);
            else if (fstat(child, &st)) result = fail(s, errno, child_path);
            else if (st.st_dev != s->device) result = fail(s, EXDEV, child_path);
            else if (mkdirat(destination, name, 0700)) result = fail(s, errno, child_path);
            else if ((target = openat(destination, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0)
                result = fail(s, errno, child_path);
            else result = clone_walk(child, target, child_path, depth + 1, s);
            if (child >= 0 && close(child) && !result) result = fail(s, errno, child_path);
            if (target >= 0 && close(target) && !result) result = fail(s, errno, child_path);
            free(child_path);
        } else if (type == DT_REG || type == DT_LNK) {
            // The syscall either clones or fails; byte-copy fallback is impossible.
            if (clonefileat(source, name, destination, name, CLONE_NOFOLLOW | CLONE_ACL))
                result = fail(s, errno, path);
        } else result = fail(s, ENOTSUP, path);
        if (result) break;
    }
    if (closedir(directory) && !result) result = fail(s, errno, path);
    // Apply directory permissions last so read-only prepared directories can be populated.
    if (!result && fcopyfile(source, destination, NULL, COPYFILE_METADATA)) result = fail(s, errno, path);
    return result;
}

static PyObject *clone_tree(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source, *destination;
    if (!PyArg_ParseTuple(args, "O&O&", PyUnicode_FSConverter, &source, PyUnicode_FSConverter, &destination)) return NULL;
    const char *from = PyBytes_AS_STRING(source), *to = PyBytes_AS_STRING(destination);
    if ((Py_ssize_t)strlen(from) != PyBytes_GET_SIZE(source) || (Py_ssize_t)strlen(to) != PyBytes_GET_SIZE(destination)) {
        Py_DECREF(source); Py_DECREF(destination);
        PyErr_SetString(PyExc_ValueError, "Path contains a null byte");
        return NULL;
    }
    struct scan s = {0};
    Py_BEGIN_ALLOW_THREADS
    int src = open(from, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int dst = -1;
    struct stat st;
    if (src < 0) fail(&s, errno, from);
    else if (fstat(src, &st)) fail(&s, errno, from);
    else if (mkdir(to, 0700)) fail(&s, errno, to);
    else if ((dst = open(to, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) fail(&s, errno, to);
    else { s.device = st.st_dev; clone_walk(src, dst, from, 0, &s); }
    if (src >= 0 && close(src) && !s.error) fail(&s, errno, from);
    if (dst >= 0 && close(dst) && !s.error) fail(&s, errno, to);
    Py_END_ALLOW_THREADS
    PyObject *result = NULL;
    if (s.error) {
        errno = s.error;
        PyErr_SetFromErrnoWithFilename(PyExc_OSError, s.error_path ? s.error_path : from);
    } else if (!s.cancelled) result = Py_NewRef(Py_None);
    free(s.error_path);
    Py_DECREF(source); Py_DECREF(destination);
    return result;
}

static PyObject *mount_records(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    struct statfs *mounts;
    // Keep the GIL until the static getmntinfo buffer has been copied.
    errno = 0;
    int count = getmntinfo(&mounts, MNT_NOWAIT);
    if (!count) {
        if (!errno) errno = EIO;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyObject *result = PyList_New(count);
    if (!result) return NULL;
    for (int i = 0; i < count; i++) {
        PyObject *path = PyUnicode_DecodeFSDefault(mounts[i].f_mntonname);
        PyObject *device = PyUnicode_DecodeFSDefault(mounts[i].f_mntfromname);
        PyObject *filesystem = PyUnicode_DecodeFSDefault(mounts[i].f_fstypename);
        if (!path || !device || !filesystem) {
            Py_XDECREF(path); Py_XDECREF(device); Py_XDECREF(filesystem);
            Py_DECREF(result);
            return NULL;
        }
        PyObject *record = Py_BuildValue("{s:O,s:O,s:O,s:O,s:O,s:I}",
            "path", path, "device", device, "filesystem", filesystem,
            "readonly", mounts[i].f_flags & MNT_RDONLY ? Py_True : Py_False,
            "ignore_ownership", mounts[i].f_flags & MNT_IGNORE_OWNERSHIP ? Py_True : Py_False,
            "owner", (unsigned int)mounts[i].f_owner);
        Py_DECREF(path); Py_DECREF(device); Py_DECREF(filesystem);
        if (!record) { Py_DECREF(result); return NULL; }
        PyList_SET_ITEM(result, i, record);
    }
    return result;
}

static PyMethodDef methods[] = {
    {"scan", (PyCFunction)(void(*)(void))scan_tree, METH_VARARGS | METH_KEYWORDS, "Count directory entries and regular-file logical bytes without following symlinks."},
    {"clone", clone_tree, METH_VARARGS, "Clone a tree with independent metadata and copy-on-write file data."},
    {"mounts", mount_records, METH_NOARGS, "Read cached mount identities and flags without walking their contents."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_scan", NULL, -1, methods, NULL, NULL, NULL, NULL};
PyMODINIT_FUNC PyInit__scan(void) { return PyModule_Create(&module); }
