#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <sys/mount.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "_tree.h"

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

static PyObject *scan_tree(PyObject *self, PyObject *args, PyObject *kwargs) {
    (void)self;
    static char *names[] = {"path", "bulk", "jobs", NULL};
    PyObject *path;
    int bulk = 1, jobs = 4;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "O&|pi", names, PyUnicode_FSConverter, &path, &bulk, &jobs)) return NULL;
    if (jobs < 1 || jobs > 4) {
        Py_DECREF(path);
        PyErr_SetString(PyExc_ValueError, "jobs must be between 1 and 4");
        return NULL;
    }
    if (!valid_path(path)) { Py_DECREF(path); return NULL; }
    struct stallion_scan_stats stats;
    char error_path[4096] = {0};
    int result, error;
    Py_BEGIN_ALLOW_THREADS
    result = stallion_scan(PyBytes_AS_STRING(path), bulk, (unsigned)jobs, &stats, check_cancel, NULL,
                           error_path, sizeof(error_path));
    error = errno;
    Py_END_ALLOW_THREADS
    PyObject *value;
    if (result || PyErr_Occurred() || PyErr_CheckSignals() < 0) {
        value = operation_result(result, error, error_path[0] ? error_path : PyBytes_AS_STRING(path));
    } else {
        value = Py_BuildValue("{s:K,s:K,s:K,s:K,s:K,s:K}",
            "files", (unsigned long long)stats.files, "directories", (unsigned long long)stats.directories,
            "symlinks", (unsigned long long)stats.symlinks, "other", (unsigned long long)stats.other,
            "logical_bytes", (unsigned long long)stats.logical_bytes, "skipped_mounts", (unsigned long long)stats.skipped_mounts);
    }
    Py_DECREF(path);
    return value;
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

static PyObject *private_directory(PyObject *self, PyObject *argument) {
    (void)self;
    PyObject *path;
    if (!PyUnicode_FSConverter(argument, &path)) return NULL;
    if (!valid_path(path)) { Py_DECREF(path); return NULL; }
    int result, error;
    Py_BEGIN_ALLOW_THREADS
    result = stallion_private_directory(PyBytes_AS_STRING(path));
    error = errno;
    Py_END_ALLOW_THREADS
    PyObject *value = operation_result(result, error, PyBytes_AS_STRING(path));
    Py_DECREF(path);
    return value;
}

static PyMethodDef methods[] = {
    {"_private_directory", private_directory, METH_O, "Validate private directory ownership, mode and ACLs without changing them."},
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
