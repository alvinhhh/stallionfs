#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/attr.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "_tree.h"

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
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
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

static int check_cancel(void *unused) {
    (void)unused;
    PyGILState_STATE state = PyGILState_Ensure();
    int interrupted = PyErr_CheckSignals() < 0;
    PyGILState_Release(state);
    return interrupted;
}

static int valid_path(PyObject *value) {
    if ((Py_ssize_t)strlen(PyBytes_AS_STRING(value)) == PyBytes_GET_SIZE(value)) return 1;
    PyErr_SetString(PyExc_ValueError, "Path contains a null byte");
    return 0;
}

static PyObject *operation_result(int result, int error, const char *path) {
    // Workers have joined before this check, including when a syscall returned EINTR.
    if (PyErr_Occurred() || PyErr_CheckSignals() < 0) return NULL;
    if (!result) Py_RETURN_NONE;
    errno = error;
    return PyErr_SetFromErrnoWithFilename(PyExc_OSError, path);
}

static PyObject *clone_operation(PyObject *self, PyObject *args, PyObject *kwargs, int tree_only) {
    (void)self;
    static char *names[] = {"source", "destination", "jobs", NULL};
    PyObject *source, *destination;
    int jobs = 4;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O&|i", names,
            PyUnicode_FSConverter, &source, PyUnicode_FSConverter, &destination, &jobs)) return NULL;
    if (jobs < 1 || jobs > 4) {
        Py_DECREF(source); Py_DECREF(destination);
        PyErr_SetString(PyExc_ValueError, "jobs must be between 1 and 4");
        return NULL;
    }
    if (!valid_path(source) || !valid_path(destination)) {
        Py_DECREF(source); Py_DECREF(destination); return NULL;
    }
    char error_path[PATH_MAX] = {0};
    int result, error;
    Py_BEGIN_ALLOW_THREADS
    result = (tree_only ? stallion_clone_tree : stallion_clone)(PyBytes_AS_STRING(source), PyBytes_AS_STRING(destination), jobs,
                           check_cancel, NULL, error_path, sizeof(error_path));
    error = errno;
    Py_END_ALLOW_THREADS
    PyObject *value = operation_result(result, error,
        error_path[0] ? error_path : PyBytes_AS_STRING(destination));
    Py_DECREF(source); Py_DECREF(destination);
    return value;
}

static PyObject *clone_path(PyObject *self, PyObject *args, PyObject *kwargs) {
    return clone_operation(self, args, kwargs, 0);
}

static PyObject *clone_tree(PyObject *self, PyObject *args, PyObject *kwargs) {
    return clone_operation(self, args, kwargs, 1);
}

static PyObject *delete_path(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *names[] = {"path", "recursive", "missing_ok", "jobs", NULL};
    PyObject *path;
    int recursive = 0, missing_ok = 0;
    int jobs = 4;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|ppi", names,
            PyUnicode_FSConverter, &path, &recursive, &missing_ok, &jobs)) return NULL;
    if (jobs < 1 || jobs > 4) {
        Py_DECREF(path);
        PyErr_SetString(PyExc_ValueError, "jobs must be between 1 and 4");
        return NULL;
    }
    if (!valid_path(path)) { Py_DECREF(path); return NULL; }
    char error_path[PATH_MAX] = {0};
    int result, error;
    Py_BEGIN_ALLOW_THREADS
    result = stallion_delete(PyBytes_AS_STRING(path), recursive, missing_ok, jobs,
                            check_cancel, NULL, error_path, sizeof(error_path));
    error = errno;
    Py_END_ALLOW_THREADS
    PyObject *value = operation_result(result, error, error_path[0] ? error_path : PyBytes_AS_STRING(path));
    Py_DECREF(path);
    return value;
}

static PyObject *move_path(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *names[] = {"source", "destination", "replace", "exchange", NULL};
    PyObject *source, *destination;
    int replace = 0, exchange = 0;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&O&|pp", names,
            PyUnicode_FSConverter, &source, PyUnicode_FSConverter, &destination, &replace, &exchange)) return NULL;
    if (!valid_path(source) || !valid_path(destination) || (replace && exchange)) {
        if (replace && exchange) PyErr_SetString(PyExc_ValueError, "Choose replace or exchange, not both");
        Py_DECREF(source); Py_DECREF(destination); return NULL;
    }
    int result, error;
    Py_BEGIN_ALLOW_THREADS
    result = renamex_np(PyBytes_AS_STRING(source), PyBytes_AS_STRING(destination),
                        exchange ? RENAME_SWAP : replace ? 0 : RENAME_EXCL);
    error = errno;
    Py_END_ALLOW_THREADS
    PyObject *value = NULL;
    if (!PyErr_Occurred() && PyErr_CheckSignals() >= 0) {
        if (result) {
            errno = error;
            value = PyErr_SetFromErrnoWithFilenameObjects(PyExc_OSError, source, destination);
        } else value = Py_NewRef(Py_None);
    }
    Py_DECREF(source); Py_DECREF(destination);
    return value;
}

static PyObject *mount_records(PyObject *self, PyObject *unused) {
    (void)self; (void)unused;
    struct statfs *mounts = NULL;
    errno = 0;
    int count = getmntinfo_r_np(&mounts, MNT_NOWAIT);
    if (!count) {
        if (!errno) errno = EIO;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyObject *result = PyList_New(count);
    if (!result) { free(mounts); return NULL; }
    for (int i = 0; i < count; i++) {
        PyObject *path = PyUnicode_DecodeFSDefault(mounts[i].f_mntonname);
        PyObject *device = PyUnicode_DecodeFSDefault(mounts[i].f_mntfromname);
        PyObject *filesystem = PyUnicode_DecodeFSDefault(mounts[i].f_fstypename);
        if (!path || !device || !filesystem) {
            Py_XDECREF(path); Py_XDECREF(device); Py_XDECREF(filesystem);
            Py_DECREF(result);
            free(mounts);
            return NULL;
        }
        PyObject *record = Py_BuildValue("{s:O,s:O,s:O,s:O,s:O,s:I}",
            "path", path, "device", device, "filesystem", filesystem,
            "readonly", mounts[i].f_flags & MNT_RDONLY ? Py_True : Py_False,
            "ignore_ownership", mounts[i].f_flags & MNT_IGNORE_OWNERSHIP ? Py_True : Py_False,
            "owner", (unsigned int)mounts[i].f_owner);
        Py_DECREF(path); Py_DECREF(device); Py_DECREF(filesystem);
        if (!record) { Py_DECREF(result); free(mounts); return NULL; }
        PyList_SET_ITEM(result, i, record);
    }
    free(mounts);
    return result;
}

static PyMethodDef methods[] = {
    {"scan", (PyCFunction)(void(*)(void))scan_tree, METH_VARARGS | METH_KEYWORDS, "Count directory entries and regular-file logical bytes without following symlinks."},
    {"clone", (PyCFunction)(void(*)(void))clone_path, METH_VARARGS | METH_KEYWORDS, "Clone to an exact new path without byte-copy fallback."},
    {"_clone_tree", (PyCFunction)(void(*)(void))clone_tree, METH_VARARGS | METH_KEYWORDS, "Clone a prepared directory; reject root symlinks."},
    {"delete", (PyCFunction)(void(*)(void))delete_path, METH_VARARGS | METH_KEYWORDS, "Delete a path; directories require recursive=True and mounts are refused."},
    {"move", (PyCFunction)(void(*)(void))move_path, METH_VARARGS | METH_KEYWORDS, "Rename an exact path atomically; default is no overwrite, with optional replace or exchange."},
    {"mounts", mount_records, METH_NOARGS, "Read cached mount identities and flags without walking their contents."},
    {NULL, NULL, 0, NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT, "_scan", NULL, -1, methods, NULL, NULL, NULL, NULL};
PyMODINIT_FUNC PyInit__scan(void) { return PyModule_Create(&module); }
