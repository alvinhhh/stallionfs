#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include "image.h"
#include "_native_import.h"
#include <math.h>

/* Ordinary core only. Each call owns one handle until its consumed close;
 * Python holds the managed lease and validates the canonical parent's ACL. */
enum operation { INSPECT, SNAPSHOT, LIST, RESTORE };
typedef struct {
    double deadline;
    int expired, clock_error;
    PyObject *signal_type, *signal_value, *signal_traceback;
    PyObject *carrier, *fallback;
} cancellation;

/* The fixed numeric/hex receipt schema fits below 8 KiB even at uint64 limits.
 * Names live separately in the preallocated Python carrier, never in this JSON. */
typedef struct { char *bytes; size_t used, capacity; int failed; } fixed_json;
static void append_json(fixed_json *output, const char *format, ...) {
    if (output->failed) return;
    va_list args; va_start(args,format);
    int n = vsnprintf(output->bytes + output->used,output->capacity - output->used,format,args);
    va_end(args);
    if (n < 0 || (size_t)n >= output->capacity - output->used) { output->failed = 1; return; }
    output->used += (size_t)n;
}
static void raw_hex(const uint8_t *bytes, size_t length, char *text) {
    const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < length; ++i) { text[i*2] = digits[bytes[i] >> 4]; text[i*2+1] = digits[bytes[i] & 15]; }
    text[length*2] = 0;
}
static void append_receipt(fixed_json *output, const sfs_result *r) {
    if (!r) { append_json(output,"null"); return; }
    char uuid[33], root[65]; raw_hex(r->uuid,16,uuid); raw_hex(r->root_digest,32,root);
    append_json(output,"{\"status\":%d,\"phase\":%d,\"system_errno\":%d,\"generation\":%" PRIu64
        ",\"committed_end\":%" PRIu64 ",\"physical_end\":%" PRIu64 ",\"device\":%" PRIu64 ",\"inode\":%" PRIu64
        ",\"uuid\":\"%s\",\"root_digest\":\"%s\",\"coverage\":%d,\"incomplete_reason\":%d,\"limit_reason\":%d,"
        "\"fence_attempted\":%u,\"fence_succeeded\":%u,\"transaction_active\":%s,\"poisoned\":%s}",
        (int)r->status,(int)r->phase,r->system_errno,r->generation,r->committed_end,r->physical_end,r->device,r->inode,
        uuid,root,(int)r->coverage,(int)r->incomplete_reason,(int)r->limit_reason,r->fence_attempted,r->fence_succeeded,
        r->transaction_active ? "true" : "false",r->poisoned ? "true" : "false");
}

static double monotonic_time(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return -1;
    return (double)now.tv_sec + (double)now.tv_nsec / 1000000000.0;
}

/* All callers retain the GIL. Never close a handle from a signal handler. */
static int take_signal(cancellation *context) {
    if (context->signal_type) return 1;
    if (PyErr_CheckSignals() < 0) {
        PyErr_Fetch(&context->signal_type, &context->signal_value, &context->signal_traceback);
        PyErr_NormalizeException(&context->signal_type, &context->signal_value, &context->signal_traceback);
        if (context->signal_value && context->carrier &&
            PyObject_SetAttrString(context->signal_value,"native_image_carrier",context->carrier) < 0) {
            PyErr_Clear();
            /* Exception context slots do not need a new instance dictionary. */
            if (context->fallback && PyExceptionInstance_Check(context->signal_value)) {
                PyException_SetContext(context->fallback,PyException_GetContext(context->signal_value));
                PyException_SetContext(context->signal_value,Py_NewRef(context->fallback));
            }
        }
        return 1;
    }
    return 0;
}
static int cancelled(void *opaque) {
    cancellation *context = opaque;
    if (take_signal(context) || context->expired || context->clock_error) return 1;
    double now = monotonic_time();
    if (now < 0) { context->clock_error = errno ? errno : EIO; return 1; }
    if (now >= context->deadline) { context->expired = 1; return 1; }
    return 0;
}

static int set_owned(PyObject *dictionary, const char *key, PyObject *value) {
    if (!value) return -1;
    int status = PyDict_SetItemString(dictionary, key, value);
    Py_DECREF(value);
    return status;
}
#define PUT_U(d,k,v) set_owned((d),(k),PyLong_FromUnsignedLongLong((unsigned long long)(v)))
#define PUT_I(d,k,v) set_owned((d),(k),PyLong_FromLongLong((long long)(v)))
#define PUT_B(d,k,v) set_owned((d),(k),PyBool_FromLong(!!(v)))
#define PUT_S(d,k,v) set_owned((d),(k),PyUnicode_FromString(v))

static PyObject *hex_bytes(const uint8_t *bytes, size_t length) {
    const char digits[] = "0123456789abcdef";
    char text[65];
    if (length > 32) { PyErr_SetString(PyExc_ValueError, "Invalid digest length"); return NULL; }
    for (size_t i = 0; i < length; ++i) { text[i * 2] = digits[bytes[i] >> 4]; text[i * 2 + 1] = digits[bytes[i] & 15]; }
    return PyUnicode_FromStringAndSize(text, (Py_ssize_t)(length * 2));
}

static PyObject *receipt(const sfs_result *r) {
    PyObject *value = PyDict_New();
    if (!value) return NULL;
    if (PUT_I(value,"status",r->status) || PUT_I(value,"phase",r->phase) || PUT_I(value,"system_errno",r->system_errno) ||
        PUT_U(value,"generation",r->generation) || PUT_U(value,"committed_end",r->committed_end) ||
        PUT_U(value,"physical_end",r->physical_end) || PUT_U(value,"device",r->device) || PUT_U(value,"inode",r->inode) ||
        set_owned(value,"uuid",hex_bytes(r->uuid,16)) || set_owned(value,"root_digest",hex_bytes(r->root_digest,32)) ||
        PUT_I(value,"coverage",r->coverage) || PUT_I(value,"incomplete_reason",r->incomplete_reason) ||
        PUT_I(value,"limit_reason",r->limit_reason) || PUT_U(value,"fence_attempted",r->fence_attempted) ||
        PUT_U(value,"fence_succeeded",r->fence_succeeded) || PUT_B(value,"transaction_active",r->transaction_active) ||
        PUT_B(value,"poisoned",r->poisoned)) { Py_DECREF(value); return NULL; }
    return value;
}

static int pair_value(PyObject *dictionary, const char *key, uint64_t pair[2], int optional) {
    PyObject *value = PyDict_GetItemString(dictionary,key);
    if (optional && value == Py_None) return 0;
    if (!value) { PyErr_SetString(PyExc_ValueError,"Missing image identity"); return -1; }
    PyObject *sequence = PySequence_Fast(value,"Identity must be a pair");
    if (!sequence) return -1;
    if (PySequence_Fast_GET_SIZE(sequence) != 2) { Py_DECREF(sequence); PyErr_SetString(PyExc_ValueError,"Identity must be a pair"); return -1; }
    for (int i = 0; i < 2; ++i) {
        PyObject *item = PySequence_Fast_GET_ITEM(sequence,i);
        if (!PyLong_CheckExact(item)) { Py_DECREF(sequence); PyErr_SetString(PyExc_ValueError,"Identity must contain integers"); return -1; }
        pair[i] = PyLong_AsUnsignedLongLong(item);
        if (PyErr_Occurred()) { Py_DECREF(sequence); return -1; }
    }
    Py_DECREF(sequence); return 1;
}

static PyObject *path_bytes(PyObject *value) {
    PyObject *bytes = NULL;
    if (!value) { PyErr_SetString(PyExc_ValueError,"Missing image path"); return NULL; }
    if (!PyUnicode_FSConverter(value,&bytes)) return NULL;
    Py_ssize_t length = PyBytes_GET_SIZE(bytes);
    if (length < 1 || length >= PATH_MAX || memchr(PyBytes_AS_STRING(bytes),0,(size_t)length)) {
        Py_DECREF(bytes); PyErr_SetString(PyExc_ValueError,"Invalid image path or name"); return NULL;
    }
    return bytes;
}

static int same_parent(const char *path, int descriptor, const uint64_t expected[2]) {
    struct stat held, named;
    if (fstat(descriptor,&held) || lstat(path,&named)) return -1;
    if (!S_ISDIR(held.st_mode) || !S_ISDIR(named.st_mode) || held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        (uint64_t)held.st_dev != expected[0] || (uint64_t)held.st_ino != expected[1]) { errno = ESTALE; return -1; }
    return 0;
}

static int identity_matches(const sfs_result *r, const uint64_t expected[2], PyObject *uuid) {
    if (r->device != expected[0] || r->inode != expected[1] || !uuid || !PyUnicode_Check(uuid)) return 0;
    Py_ssize_t count; const char *text = PyUnicode_AsUTF8AndSize(uuid,&count);
    if (!text) return -1;
    if (count != 32) return 0;
    const char digits[] = "0123456789abcdef";
    for (int i = 0; i < 16; ++i) if (text[i*2] != digits[r->uuid[i] >> 4] || text[i*2+1] != digits[r->uuid[i] & 15]) return 0;
    return 1;
}

static int error_code(enum sfs_status status, const sfs_result *r) {
    switch (status) {
        case SFS_OK: return 0;
        case SFS_BUSY: return EBUSY;
        case SFS_INVALID: return EINVAL;
        case SFS_NOT_FOUND: return ENOENT;
        case SFS_EXISTS: return EEXIST;
        case SFS_UNSUPPORTED: return ENOTSUP;
        case SFS_NOMEM: return ENOMEM;
        case SFS_INCOMPLETE: return ECANCELED;
        case SFS_LIMIT: return r->limit_reason == SFS_LIMIT_APPEND_CAPACITY ? ENOSPC : EOVERFLOW;
        default: return r->system_errno > 0 ? r->system_errno : EIO;
    }
}

static int durable_commit(const sfs_result *before, const sfs_result *after) {
    return before->generation != UINT64_MAX && after->generation == before->generation + 1 &&
        before->device == after->device && before->inode == after->inode && !memcmp(before->uuid,after->uuid,16) &&
        after->committed_end > before->committed_end && after->physical_end >= after->committed_end &&
        !after->transaction_active && !after->poisoned && after->fence_attempted == 3 && after->fence_succeeded == 3;
}

static PyObject *invoke(PyObject *target, PyObject *name, PyObject *recovery_name, enum operation operation) {
    PyObject *directory = NULL, *component = NULL, *snapshot_name = NULL, *recovery = NULL;
    PyObject *listing = NULL, *result = NULL, *allocation_error = NULL, *carrier = NULL, *carrier_buffer = NULL;
    uint64_t parent[2], expected[2];
    sfs_image *handle = NULL;
    sfs_result opened = {0}, original = {0}, staged = {0}, aborted = {0}, closed = {0};
    enum sfs_status status = SFS_OK, close_status = SFS_OK, abort_status = SFS_OK;
    sfs_view view = 0, recovery_view = 0;
    int guard = -1, have_expected, local_error = 0, guard_close_error = 0;
    int owned_transaction = 0, abort_attempted = 0, close_attempted = 0, commit_attempted = 0, committed = 0;
    int core_attempted = 0, stage_attempted = 0;
    cancellation context = {0};
    double entered = monotonic_time();
    if (entered < 0) return PyErr_SetFromErrno(PyExc_OSError);
    context.deadline = entered + 30.0;
    if (!PyDict_Check(target)) { PyErr_SetString(PyExc_TypeError,"Image target must be a dictionary"); return NULL; }
    int parsed = pair_value(target,"parent",parent,0);
    if (parsed < 0) goto finish;
    have_expected = pair_value(target,"file",expected,operation == INSPECT);
    if (have_expected < 0) goto finish;
    if (operation != INSPECT && !have_expected) { PyErr_SetString(PyExc_ValueError,"Registered image identity required"); goto finish; }
    directory = path_bytes(PyDict_GetItemString(target,"directory"));
    component = path_bytes(PyDict_GetItemString(target,"component"));
    if (!directory || !component) goto finish;
    if (name && !(snapshot_name = path_bytes(name))) goto finish;
    if (recovery_name && !(recovery = path_bytes(recovery_name))) goto finish;
    listing = PyList_New(0); result = PyDict_New();
    carrier = PyDict_New(); carrier_buffer = PyByteArray_FromStringAndSize(NULL,8192);
    allocation_error = PyObject_CallFunction(PyExc_MemoryError,"s","Native image response allocation failed; inspect the preserved operation result before retrying.");
    if (!listing || !result || !allocation_error || !carrier || !carrier_buffer) goto finish;
    memset(PyByteArray_AS_STRING(carrier_buffer),0,8192);
    memcpy(PyByteArray_AS_STRING(carrier_buffer),"{}",2);
    if (PyDict_SetItemString(carrier,"data",carrier_buffer) ||
        set_owned(carrier,"snapshot",snapshot_name ? PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(snapshot_name),PyBytes_GET_SIZE(snapshot_name)) : Py_NewRef(Py_None)) ||
        set_owned(carrier,"recovery",recovery ? PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(recovery),PyBytes_GET_SIZE(recovery)) : Py_NewRef(Py_None)) ||
        PyObject_SetAttrString(allocation_error,"native_image_carrier",carrier)) goto finish;
    context.carrier = carrier; context.fallback = allocation_error;
    if (cancelled(&context)) goto cleanup;
    guard = open(PyBytes_AS_STRING(directory),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (guard < 0) { local_error = errno; goto cleanup; }
    if (same_parent(PyBytes_AS_STRING(directory),guard,parent)) { local_error = errno; goto cleanup; }
    const char *dir = PyBytes_AS_STRING(directory), *file = PyBytes_AS_STRING(component);
    core_attempted = 1;
    status = operation == SNAPSHOT || operation == RESTORE ? sfs_image_open(dir,file,&handle,&original) : sfs_image_open_readonly(dir,file,&handle,&original);
    opened = original;
    if (status != SFS_OK) goto cleanup;
    if (have_expected) {
        int matches = identity_matches(&opened,expected,PyDict_GetItemString(target,"uuid"));
        if (matches < 0) goto cleanup;
        if (!matches) { local_error = ESTALE; goto cleanup; }
    }
    if (same_parent(dir,guard,parent)) { local_error = errno; goto cleanup; }
    if (cancelled(&context)) goto cleanup;
    if (operation == LIST) {
        for (uint32_t index = 0; index <= SFS_SNAPSHOT_MAX; ++index) {
            sfs_snapshot_entry entry; int found = 0;
            status = sfs_image_snapshot_at(handle,index,&entry,&found,&original);
            if (status != SFS_OK || !found) break;
            PyObject *row = PyDict_New();
            if (!row) goto cleanup;
            int failed = set_owned(row,"id",PyUnicode_DecodeFSDefaultAndSize((const char *)entry.name,(Py_ssize_t)entry.name_length)) ||
                set_owned(row,"name",PyUnicode_DecodeFSDefaultAndSize((const char *)entry.name,(Py_ssize_t)entry.name_length)) ||
                PUT_U(row,"view",entry.view) || PUT_S(row,"backend","native-image") || PyList_Append(listing,row);
            Py_DECREF(row);
            if (failed || cancelled(&context)) goto cleanup;
        }
    } else if (operation == SNAPSHOT) {
        stage_attempted = 1;
        status = sfs_image_begin(handle,&original);
        if (status != SFS_OK) goto cleanup;
        owned_transaction = 1;
        if (cancelled(&context)) goto cleanup;
        status = sfs_image_snapshot(handle,PyBytes_AS_STRING(snapshot_name),(size_t)PyBytes_GET_SIZE(snapshot_name),&view,&original);
    } else if (operation == RESTORE) {
        status = sfs_image_snapshot_view(handle,PyBytes_AS_STRING(snapshot_name),(size_t)PyBytes_GET_SIZE(snapshot_name),&view,&original);
        if (status != SFS_OK || cancelled(&context)) goto cleanup;
        stage_attempted = 1;
        sfs_verify_budget budget = {1,UINT64_C(536870912),UINT64_C(536870912),UINT64_C(50000000),1,1,cancelled,&context};
        status = sfs_image_prepare_restore(handle,view,PyBytes_AS_STRING(recovery),(size_t)PyBytes_GET_SIZE(recovery),&budget,&recovery_view,&original);
        owned_transaction = status == SFS_OK;
    }
    if (status != SFS_OK) goto cleanup;
    staged = original;
    if (operation == SNAPSHOT || operation == RESTORE) {
        if (cancelled(&context)) goto cleanup;
        commit_attempted = 1;
        status = sfs_image_commit(handle,&original);
        committed = status == SFS_OK;
        if (committed && !durable_commit(&opened,&original)) local_error = EIO;
    }
cleanup:
    /* Save original before cleanup: close consumes even when it reports error. */
    if (stage_attempted && !commit_attempted) staged = original;
    if (handle && owned_transaction && original.transaction_active && !original.poisoned && !committed) {
        abort_attempted = 1; abort_status = sfs_image_abort(handle,&aborted);
    }
    if (guard >= 0 && directory && same_parent(PyBytes_AS_STRING(directory),guard,parent) && !local_error) local_error = errno;
    if (handle) {
        close_attempted = 1; close_status = sfs_image_close(handle,&closed); handle = NULL;
    }
    if (guard >= 0) { if (close(guard)) guard_close_error = errno; guard = -1; }
    /* Commit and consumed close finish before a pending signal is delivered. */
    if (!context.signal_type && !PyErr_Occurred()) {
        if (commit_attempted) (void)take_signal(&context);
        else (void)cancelled(&context);
    }
    int interrupted = context.signal_type != NULL;
    int code = status != SFS_OK ? error_code(status,&original) : local_error ? local_error :
        context.clock_error ? context.clock_error : context.expired ? ETIMEDOUT : 0;
    if (!code && abort_attempted && abort_status != SFS_OK) code = error_code(abort_status,&aborted);
    if (!code && close_attempted && close_status != SFS_OK) code = error_code(close_status,&closed);
    if (!code && guard_close_error) code = guard_close_error;
    if (!code && interrupted) code = EINTR;
    int unknown = status == SFS_OUTCOME_UNKNOWN || (commit_attempted && committed && local_error);
    int ok = !code && !interrupted && status == SFS_OK;
    const char *operation_names[] = {"inspect","snapshot","snapshots","restore"};
    fixed_json fallback = {PyByteArray_AS_STRING(carrier_buffer),0,8192,0};
    append_json(&fallback,"{\"ok\":false,\"response_complete\":false,\"operation\":\"%s\",\"error_code\":%d,\"committed\":%s,\"commit_attempted\":%s,"
        "\"outcome\":\"%s\",\"deadline_expired\":%s,\"interrupted\":%s,\"path_errno\":%d,\"guard_close_errno\":%d,"
        "\"abort_attempted\":%s,\"close_attempted\":%s,\"view\":%u,\"recovery_view\":%u,\"receipt\":",
        operation_names[operation],code,committed ? "true" : "false",commit_attempted ? "true" : "false",
        unknown ? "unknown" : committed ? "committed" : "not_committed",context.expired ? "true" : "false",interrupted ? "true" : "false",
        local_error,guard_close_error,abort_attempted ? "true" : "false",close_attempted ? "true" : "false",view,recovery_view);
    append_receipt(&fallback,core_attempted ? &original : NULL);
    append_json(&fallback,",\"opened_receipt\":"); append_receipt(&fallback,core_attempted ? &opened : NULL);
    append_json(&fallback,",\"staged_receipt\":"); append_receipt(&fallback,stage_attempted ? &staged : NULL);
    append_json(&fallback,",\"abort_receipt\":"); append_receipt(&fallback,abort_attempted ? &aborted : NULL);
    append_json(&fallback,",\"close_receipt\":"); append_receipt(&fallback,close_attempted ? &closed : NULL);
    append_json(&fallback,"}");
    if (PyErr_Occurred()) goto finish;
    if (PUT_B(result,"ok",ok) || PUT_S(result,"operation",operation_names[operation]) || PUT_I(result,"error_code",code) ||
        PUT_B(result,"committed",committed) || PUT_B(result,"commit_attempted",commit_attempted) ||
        PUT_S(result,"outcome",unknown ? "unknown" : committed ? "committed" : "not_committed") ||
        set_owned(result,"receipt",core_attempted ? receipt(&original) : Py_NewRef(Py_None)) ||
        set_owned(result,"opened_receipt",core_attempted ? receipt(&opened) : Py_NewRef(Py_None)) ||
        set_owned(result,"staged_receipt",stage_attempted ? receipt(&staged) : Py_NewRef(Py_None)) || PUT_B(result,"abort_attempted",abort_attempted) ||
        set_owned(result,"abort_receipt",abort_attempted ? receipt(&aborted) : Py_NewRef(Py_None)) ||
        PUT_B(result,"close_attempted",close_attempted) || set_owned(result,"close_receipt",close_attempted ? receipt(&closed) : Py_NewRef(Py_None)) ||
        PUT_I(result,"guard_close_errno",guard_close_error) || PUT_I(result,"path_errno",local_error) ||
        PUT_B(result,"deadline_expired",context.expired) || PUT_B(result,"interrupted",interrupted) ||
        PUT_U(result,"view",view) || PUT_U(result,"recovery_view",recovery_view) ||
        set_owned(result,"snapshot",snapshot_name ? PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(snapshot_name),PyBytes_GET_SIZE(snapshot_name)) : Py_NewRef(Py_None)) ||
        set_owned(result,"recovery",recovery ? PyUnicode_DecodeFSDefaultAndSize(PyBytes_AS_STRING(recovery),PyBytes_GET_SIZE(recovery)) : Py_NewRef(Py_None)) ||
        PyDict_SetItemString(result,"snapshots",listing)) goto finish;
    PyObject *identity = PyDict_New();
    if (!identity) goto finish;
    int identity_error = set_owned(identity,"file",Py_BuildValue("[KK]",(unsigned long long)opened.device,(unsigned long long)opened.inode)) ||
        set_owned(identity,"uuid",hex_bytes(opened.uuid,16));
    if (!identity_error) identity_error = PyDict_SetItemString(result,"identity",identity);
    Py_DECREF(identity);
    if (identity_error) goto finish;
    if (interrupted) {
        if (context.signal_value && PyObject_SetAttrString(context.signal_value,"native_image_result",result) < 0) PyErr_Clear();
        PyErr_Restore(context.signal_type,context.signal_value,context.signal_traceback);
        context.signal_type = context.signal_value = context.signal_traceback = NULL;
        goto finish;
    }
finish:
    if (handle) { sfs_result ignored; (void)sfs_image_close(handle,&ignored); }
    if (guard >= 0) (void)close(guard);
    Py_XDECREF(directory); Py_XDECREF(component); Py_XDECREF(snapshot_name); Py_XDECREF(recovery); Py_XDECREF(listing);
    if (context.signal_type) {
        /* Result allocation cannot replace a captured signal or its carrier. */
        PyErr_Clear();
        PyErr_Restore(context.signal_type,context.signal_value,context.signal_traceback);
        context.signal_type = context.signal_value = context.signal_traceback = NULL;
    }
    if (PyErr_Occurred()) {
        if (allocation_error && PyErr_ExceptionMatches(PyExc_MemoryError)) PyErr_SetObject(PyExc_MemoryError,allocation_error);
        Py_XDECREF(result); result = NULL;
    }
    Py_XDECREF(allocation_error);
    Py_XDECREF(carrier); Py_XDECREF(carrier_buffer);
    return result;
}

static PyObject *inspect_image(PyObject *self, PyObject *target) { (void)self; return invoke(target,NULL,NULL,INSPECT); }
static PyObject *list_images(PyObject *self, PyObject *target) { (void)self; return invoke(target,NULL,NULL,LIST); }
static PyObject *snapshot_image(PyObject *self, PyObject *args) {
    (void)self; PyObject *target, *name;
    if (!PyArg_ParseTuple(args,"OO:snapshot",&target,&name)) return NULL;
    return invoke(target,name,NULL,SNAPSHOT);
}
static PyObject *restore_image(PyObject *self, PyObject *args) {
    (void)self; PyObject *target, *name, *recovery;
    if (!PyArg_ParseTuple(args,"OOO:restore",&target,&name,&recovery)) return NULL;
    return invoke(target,name,recovery,RESTORE);
}

/* Private synchronous exclusion scope. Callbacks must not fork, exec, transfer
 * ownership or retain a verifier for later use. flock is cooperative exclusion;
 * inherited descriptors can prolong it after an unsupported fork. */
typedef struct {
    PyObject_HEAD
    pid_t owner;
    unsigned long thread;
    int active, consumed, parent_close_errno;
    sfs_result opened, closed;
} backing_verifier;

static int verifier_owner(backing_verifier *self) {
    if (self->owner != getpid() || self->thread != PyThread_get_thread_ident()) {
        PyErr_SetString(PyExc_RuntimeError,"Backing guard belongs to another process or thread"); return -1;
    }
    return 0;
}
static PyObject *verifier_close_result(backing_verifier *self, void *closure) {
    (void)closure;
    if (verifier_owner(self)) return NULL;
    if (!self->consumed && !self->parent_close_errno) Py_RETURN_NONE;
    PyObject *value = self->consumed ? receipt(&self->closed) : PyDict_New();
    if (value && (PUT_B(value,"core_consumed",self->consumed) ||
                  PUT_I(value,"parent_close_errno",self->parent_close_errno) ||
                  (!self->consumed && set_owned(value,"core_receipt",Py_NewRef(Py_None))))) {
        Py_DECREF(value); return NULL;
    }
    return value;
}
static int guard_target(PyObject *target, PyObject **directory, PyObject **component, uint64_t parent[2], uint64_t file[2]) {
    if (!PyDict_Check(target)) { PyErr_SetString(PyExc_TypeError,"Image target must be a dictionary"); return -1; }
    if (pair_value(target,"parent",parent,0) < 0 || pair_value(target,"file",file,0) < 0) return -1;
    *directory = path_bytes(PyDict_GetItemString(target,"directory"));
    *component = path_bytes(PyDict_GetItemString(target,"component"));
    if (!*directory || !*component) return -1;
    const char *name = PyBytes_AS_STRING(*component);
    if (strchr(name,'/') || !strcmp(name,".") || !strcmp(name,"..")) {
        PyErr_SetString(PyExc_ValueError,"Expected one backing filename component"); return -1;
    }
    return 0;
}
static int guard_location(const char *directory, const char *name, int parent_fd,
                          const uint64_t parent[2], const sfs_result *opened) {
    struct stat ps, named;
    if (same_parent(directory,parent_fd,parent) || fstat(parent_fd,&ps) ||
        fstatat(parent_fd,name,&named,AT_SYMLINK_NOFOLLOW)) return -1;
    if (ps.st_uid != geteuid() || (ps.st_mode & 0777) != 0700 ||
        !S_ISREG(named.st_mode) || named.st_uid != geteuid() || named.st_nlink != 1 ||
        (named.st_mode & 0077) || (named.st_mode & 0600) != 0600 ||
        (uint64_t)named.st_dev != opened->device || (uint64_t)named.st_ino != opened->inode) {
        errno = ESTALE; return -1;
    }
    return same_parent(directory,parent_fd,parent);
}
static PyObject *verifier_verify(backing_verifier *self, PyObject *target) {
    if (verifier_owner(self)) return NULL;
    if (!self->active) { PyErr_SetString(PyExc_RuntimeError,"Backing guard is no longer active"); return NULL; }
    PyObject *directory = NULL, *component = NULL, *result = NULL;
    uint64_t parent[2], file[2]; int fd = -1;
    if (guard_target(target,&directory,&component,parent,file)) goto done;
    int matches = identity_matches(&self->opened,file,PyDict_GetItemString(target,"uuid"));
    if (matches < 0) goto done;
    if (!matches) { errno = ESTALE; PyErr_SetFromErrno(PyExc_OSError); goto done; }
    fd = open(PyBytes_AS_STRING(directory),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0 || guard_location(PyBytes_AS_STRING(directory),PyBytes_AS_STRING(component),fd,parent,&self->opened)) {
        PyErr_SetFromErrno(PyExc_OSError); goto done;
    }
    result = Py_NewRef(Py_None);
done:
    if (fd >= 0 && close(fd) && !PyErr_Occurred()) { Py_CLEAR(result); PyErr_SetFromErrno(PyExc_OSError); }
    Py_XDECREF(directory); Py_XDECREF(component);
    return result;
}
static PyMethodDef verifier_methods[] = {
    {"verify",(PyCFunction)verifier_verify,METH_O,"Verify a location names the guarded inode; does not grant deletion authority."},
    {NULL,NULL,0,NULL}
};
static PyGetSetDef verifier_properties[] = {
    {"close_result",(getter)verifier_close_result,NULL,"Consumed close disposition, available after the callback.",NULL},
    {NULL,NULL,NULL,NULL,NULL}
};
static PyObject *verifier_new(PyTypeObject *type, PyObject *args, PyObject *keywords) {
    (void)type; (void)args; (void)keywords;
    PyErr_SetString(PyExc_TypeError,"Backing verifiers are created only inside a guarded callback"); return NULL;
}
static PyTypeObject verifier_type = {
    PyVarObject_HEAD_INIT(NULL,0)
    .tp_name = "stallionfs._image._BackingVerifier",
    .tp_basicsize = sizeof(backing_verifier),
    .tp_flags = Py_TPFLAGS_DEFAULT,
    .tp_methods = verifier_methods,
    .tp_getset = verifier_properties,
    .tp_new = verifier_new,
};
static PyObject *with_backing_guard(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *target, *callback, *directory = NULL, *component = NULL, *value = NULL;
    PyObject *error_type = NULL, *error_value = NULL, *error_trace = NULL, *fallback = NULL;
    uint64_t parent[2], file[2]; int fd = -1;
    sfs_image *handle = NULL;
    backing_verifier *token = NULL;
    if (!PyArg_ParseTuple(args,"OO:with_backing_guard",&target,&callback)) return NULL;
    if (!PyCallable_Check(callback)) { PyErr_SetString(PyExc_TypeError,"Expected a synchronous callback"); return NULL; }
    if (guard_target(target,&directory,&component,parent,file)) goto done;
    token = PyObject_New(backing_verifier,&verifier_type);
    if (!token) goto done;
    token->owner = getpid(); token->thread = PyThread_get_thread_ident();
    token->active = token->consumed = token->parent_close_errno = 0;
    memset(&token->opened,0,sizeof(token->opened)); memset(&token->closed,0,sizeof(token->closed));
    fallback = PyObject_CallFunction(PyExc_RuntimeError,"s","Backing guard consumed-close disposition");
    if (!fallback || PyObject_SetAttrString(fallback,"native_backing_guard",(PyObject *)token)) goto done;
    if (PyErr_CheckSignals() < 0) goto done;
    fd = open(PyBytes_AS_STRING(directory),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0 || same_parent(PyBytes_AS_STRING(directory),fd,parent)) { PyErr_SetFromErrno(PyExc_OSError); goto done; }
    enum sfs_status status = sfs_image_open_readonly(PyBytes_AS_STRING(directory),PyBytes_AS_STRING(component),&handle,&token->opened);
    if (status != SFS_OK) { errno = error_code(status,&token->opened); PyErr_SetFromErrno(PyExc_OSError); goto done; }
    int matches = identity_matches(&token->opened,file,PyDict_GetItemString(target,"uuid"));
    if (matches < 0) goto done;
    if (!matches) { errno = ESTALE; PyErr_SetFromErrno(PyExc_OSError); goto done; }
    if (guard_location(PyBytes_AS_STRING(directory),PyBytes_AS_STRING(component),fd,parent,&token->opened)) {
        PyErr_SetFromErrno(PyExc_OSError); goto done;
    }
    if (PyErr_CheckSignals() < 0) goto done;
    token->active = 1;
    value = PyObject_CallOneArg(callback,(PyObject *)token);
done:
    if (token) token->active = 0;
    /* A foreign fork cannot consume the parent's logical scope. Do not touch
     * the inherited core; the unsupported child's descriptors live until exit. */
    if (token && token->owner != getpid()) {
        Py_CLEAR(value); PyErr_Clear();
        PyErr_SetString(PyExc_RuntimeError,"Forking while a backing guard is active is unsupported");
        handle = NULL; fd = -1;
    }
    PyErr_Fetch(&error_type,&error_value,&error_trace);
    if (handle) {
        (void)sfs_image_close(handle,&token->closed); handle = NULL; token->consumed = 1;
    }
    if (fd >= 0) { if (close(fd) && token) token->parent_close_errno = errno; fd = -1; }
    if (!error_type && token && (token->closed.status != SFS_OK || token->parent_close_errno)) {
        errno = token->closed.status != SFS_OK ? error_code(token->closed.status,&token->closed) : token->parent_close_errno;
        PyErr_SetFromErrno(PyExc_OSError);
        PyErr_Fetch(&error_type,&error_value,&error_trace);
    }
    if (!error_type && PyErr_CheckSignals() < 0) PyErr_Fetch(&error_type,&error_value,&error_trace);
    if (error_type) {
        PyErr_NormalizeException(&error_type,&error_value,&error_trace);
        if (token && error_value && PyObject_SetAttrString(error_value,"native_backing_guard",(PyObject *)token)) {
            PyErr_Clear();
            if (fallback && PyExceptionInstance_Check(error_value)) {
                PyException_SetContext(fallback,PyException_GetContext(error_value));
                PyException_SetContext(error_value,Py_NewRef(fallback));
            }
        }
        Py_CLEAR(value); PyErr_Restore(error_type,error_value,error_trace);
    }
    Py_XDECREF(fallback); Py_XDECREF(token); Py_XDECREF(directory); Py_XDECREF(component);
    return value;
}

typedef struct { cancellation cancel; PyObject *before_create; } import_context;
static int import_cancelled(void *opaque) { return cancelled(&((import_context *)opaque)->cancel); }
static int import_before_create(void *opaque) {
    import_context *context = opaque;
    if (import_cancelled(opaque)) return -1;
    PyObject *value = PyObject_CallNoArgs(context->before_create);
    if (value) { Py_DECREF(value); return 0; }
    PyErr_Fetch(&context->cancel.signal_type,&context->cancel.signal_value,&context->cancel.signal_traceback);
    PyErr_NormalizeException(&context->cancel.signal_type,&context->cancel.signal_value,&context->cancel.signal_traceback);
    return -1;
}
static void import_json(fixed_json *json, const sfs_import_report *r) {
    const char *outcome = r->candidate_complete ? "candidate-created" :
        r->creation_attempted ? "retained-incomplete" : "not-created";
    const char *disposition = !r->creation_attempted ? "not_attempted" : r->created ? "known_created" : r->existing ? "known_existing" : "unknown";
    const sfs_result *failed = &r->original;
    const sfs_result *operations[] = {&r->creation,&r->commit,&r->verify,&r->close,&r->reopen,&r->reopen_close};
    for (size_t i=0;i<sizeof(operations)/sizeof(*operations);i++) if (operations[i]->status != SFS_OK) { failed=operations[i]; break; }
    int code=r->local_error ? r->local_error : r->cleanup_error ? r->cleanup_error : error_code(failed->status,failed);
    if (!r->candidate_complete && !code) code=EIO;
    append_json(json,"{\"ok\":%s,\"candidate_complete\":%s,\"creation_attempted\":%s,\"creation_disposition\":\"%s\","
        "\"import_committed\":%s,\"verified\":%s,\"outcome\":\"%s\",\"reason\":\"%s\",\"error_code\":%d,"
        "\"local_error\":%d,\"descriptor_close_error\":%d,\"failed_record\":%" PRIu64 ",\"observed_file\":",
        r->candidate_complete ? "true" : "false",r->candidate_complete ? "true" : "false",
        r->creation_attempted ? "true" : "false",disposition,r->import_committed ? "true" : "false",r->verified ? "true" : "false",
        outcome,r->reason ? r->reason : "none",code,r->local_error,r->cleanup_error,r->failed_record);
    if (r->observed) append_json(json,"[%" PRIu64 ",%" PRIu64 "]",r->observed_identity[0],r->observed_identity[1]);
    else append_json(json,"null");
    append_json(json,",\"identity\":");
    if (r->created) { char uuid[33]; raw_hex(r->creation.uuid,16,uuid);
        append_json(json,"{\"file\":[%" PRIu64 ",%" PRIu64 "],\"uuid\":\"%s\"}",r->creation.device,r->creation.inode,uuid);
    } else append_json(json,"null");
    append_json(json,",\"anchor\":");
    if (r->import_committed) { char digest[65]; raw_hex(r->commit.root_digest,32,digest);
        append_json(json,"{\"generation\":%" PRIu64 ",\"root_digest\":\"%s\",\"committed_end\":%" PRIu64 "}",r->commit.generation,digest,r->commit.committed_end);
    } else append_json(json,"null");
    append_json(json,",\"resources\":{\"entries\":%" PRIu64 ",\"scratch_bytes\":%" PRIu64 ",\"xattr_memory_high_water\":%" PRIu64
        ",\"policy\":\"finite-traversal-v2\",\"budget\":{\"raw_cells\":%" PRIu64 ",\"metadata_read_bytes\":%" PRIu64
        ",\"metadata_hash_bytes\":%" PRIu64 ",\"checks\":%" PRIu64 ",\"auxiliary_bytes\":%" PRIu64 ",\"auxiliary_io_bytes\":%" PRIu64 "}},",
        r->entries,r->scratch_bytes,r->xattr_memory_high_water,r->budget.raw_cells,r->budget.metadata_read_bytes,r->budget.metadata_hash_bytes,
        r->budget.checks,r->budget.auxiliary_bytes,r->budget.auxiliary_io_bytes);
    append_json(json,"\"budget_explicit\":%s,\"budget_saturated\":%s,\"parent_steps\":%" PRIu64 ",",r->budget_explicit ? "true" : "false",r->budget_saturated ? "true" : "false",r->parent_steps);
    append_json(json,"\"creation\":"); append_receipt(json,r->creation_attempted ? &r->creation : NULL);
    append_json(json,",\"original\":"); append_receipt(json,&r->original);
    append_json(json,",\"commit\":"); append_receipt(json,r->commit.generation ? &r->commit : NULL);
    append_json(json,",\"abort\":"); append_receipt(json,r->abort_attempted ? &r->abort : NULL);
    append_json(json,",\"verify\":"); append_receipt(json,r->verify.generation ? &r->verify : NULL);
    append_json(json,",\"close\":"); append_receipt(json,r->close_attempted ? &r->close : NULL);
    append_json(json,",\"reopen\":"); append_receipt(json,r->reopen_attempted ? &r->reopen : NULL);
    append_json(json,",\"reopen_close\":"); append_receipt(json,r->reopen_close_attempted ? &r->reopen_close : NULL);
    append_json(json,",\"failure_path_error\":%d,\"xattr_names_scratch_high_water\":%" PRIu64 "}",r->failure_path_error,r->xattr_names_scratch_high_water);
}
static PyObject *create_from_tree(PyObject *self, PyObject *args) {
    (void)self;
    PyObject *source,*destination,*capacity,*budget_arg=Py_None,*source_path=NULL,*destination_path=NULL;
    PyObject *carrier=NULL,*buffer=NULL,*fallback=NULL,*json_module=NULL,*loads=NULL,*result=NULL;
    sfs_import_options options={0}; sfs_import_report report={0}; import_context context={0}; sfs_verify_budget supplied={0};
    if (!PyArg_ParseTuple(args,"OOO|O:create_from_tree",&source,&destination,&capacity,&budget_arg)) return NULL;
    if (!PyDict_Check(source) || !PyDict_Check(destination) || !PyLong_CheckExact(capacity)) {
        PyErr_SetString(PyExc_TypeError,"Source and destination must be dictionaries; capacity must be an integer"); return NULL;
    }
    if (PyDict_GetItemString(destination,"file") || PyDict_GetItemString(destination,"uuid")) {
        PyErr_SetString(PyExc_ValueError,"Native creation cannot adopt an existing backing identity"); return NULL;
    }
    PyObject *component=PyDict_GetItemString(destination,"component");
    context.before_create=PyDict_GetItemString(destination,"before_create");
    if (!component || !PyUnicode_Check(component) || PyUnicode_CompareWithASCIIString(component,"image.sfs") ||
        !context.before_create || !PyCallable_Check(context.before_create)) {
        PyErr_SetString(PyExc_ValueError,"Native creation requires image.sfs and a durable precreate callback"); return NULL;
    }
    context.before_create=Py_NewRef(context.before_create);
    if (pair_value(source,"root",options.source_identity,0)<0 || pair_value(destination,"parent",options.destination_identity,0)<0) goto finish;
    options.capacity=PyLong_AsUnsignedLongLong(capacity); if (PyErr_Occurred()) goto finish;
    if (budget_arg != Py_None) {
        const char *names[] = {"raw_cells","metadata_read_bytes","metadata_hash_bytes","checks","auxiliary_bytes","auxiliary_io_bytes"};
        uint64_t *values[] = {&supplied.raw_cells,&supplied.metadata_read_bytes,&supplied.metadata_hash_bytes,
            &supplied.checks,&supplied.auxiliary_bytes,&supplied.auxiliary_io_bytes};
        if (!PyDict_Check(budget_arg) || PyDict_Size(budget_arg)!=6) {
            PyErr_SetString(PyExc_ValueError,"Verification budget requires all six positive uint64 dimensions"); goto finish;
        }
        for (unsigned i=0;i<6;i++) {
            PyObject *value=PyDict_GetItemString(budget_arg,names[i]);
            if (!value || !PyLong_CheckExact(value)) { PyErr_SetString(PyExc_ValueError,"Verification budget dimensions must be exact integers"); goto finish; }
            *values[i]=PyLong_AsUnsignedLongLong(value);
            if (PyErr_Occurred()) goto finish;
            if (!*values[i]) { PyErr_SetString(PyExc_ValueError,"Verification budget dimensions must be positive"); goto finish; }
        }
        options.verification_budget=&supplied;
    }
    source_path=path_bytes(PyDict_GetItemString(source,"directory"));
    destination_path=path_bytes(PyDict_GetItemString(destination,"directory"));
    if (!source_path || !destination_path) goto finish;
    carrier=PyDict_New(); buffer=PyByteArray_FromStringAndSize(NULL,16384);
    fallback=PyObject_CallFunction(PyExc_MemoryError,"s","Native candidate response unavailable; inspect retained intent and receipt before retrying");
    json_module=PyImport_ImportModule("json"); if (json_module) loads=PyObject_GetAttrString(json_module,"loads");
    if (!carrier || !buffer || !fallback || !loads) goto finish;
    memset(PyByteArray_AS_STRING(buffer),0,16384); memcpy(PyByteArray_AS_STRING(buffer),"{}",2);
    if (PyDict_SetItemString(carrier,"data",buffer) || PyDict_SetItemString(carrier,"snapshot",Py_None) ||
        PyDict_SetItemString(carrier,"recovery",Py_None) || PyObject_SetAttrString(fallback,"native_image_carrier",carrier)) goto finish;
    context.cancel.carrier=carrier; context.cancel.fallback=fallback; context.cancel.deadline=INFINITY;
    options.source=PyBytes_AS_STRING(source_path); options.destination=PyBytes_AS_STRING(destination_path);
    options.cancelled=import_cancelled; options.before_create=import_before_create; options.context=&context;
    sfs_native_import(&options,&report);
    fixed_json json={.bytes=PyByteArray_AS_STRING(buffer),.capacity=16384}; import_json(&json,&report);
    if (json.failed) { PyErr_SetString(PyExc_RuntimeError,"Native creation receipt exceeded its fixed carrier"); goto retained_error; }
    if (context.cancel.signal_type) {
        if (context.cancel.signal_value && PyObject_SetAttrString(context.cancel.signal_value,"native_image_carrier",carrier)<0) {
            PyErr_Clear(); PyException_SetContext(context.cancel.signal_value,Py_NewRef(fallback));
        }
        PyErr_Restore(context.cancel.signal_type,context.cancel.signal_value,context.cancel.signal_traceback);
        context.cancel.signal_type=context.cancel.signal_value=context.cancel.signal_traceback=NULL; goto finish;
    }
    PyObject *text=PyUnicode_FromStringAndSize(json.bytes,(Py_ssize_t)json.used);
    if (text) { result=PyObject_CallOneArg(loads,text); Py_DECREF(text); }
    if (result) {
        PyObject *path=report.failure_path ? PyUnicode_DecodeFSDefaultAndSize(report.failure_path,(Py_ssize_t)report.failure_path_length) : Py_NewRef(Py_None);
        if (path && !PyDict_SetItemString(result,"failure_path",path) && !PyDict_SetItemString(carrier,"failure_path",path)) {
            Py_DECREF(path); goto finish;
        }
        Py_XDECREF(path); Py_CLEAR(result);
    }
retained_error:
    PyErr_Clear(); PyErr_SetObject(PyExc_MemoryError,fallback);
finish:
    Py_XDECREF(source_path); Py_XDECREF(destination_path); Py_XDECREF(carrier); Py_XDECREF(buffer);
    Py_XDECREF(context.before_create);
    free(report.failure_path);
    Py_XDECREF(fallback); Py_XDECREF(json_module); Py_XDECREF(loads);
    return result;
}
static PyMethodDef methods[] = {
    {"create_from_tree",create_from_tree,METH_VARARGS,"Produce a retained native candidate from a private prepared tree."},
    {"with_backing_guard",with_backing_guard,METH_VARARGS,"Run synchronous nonforking work while holding a readonly backing lock."},
    {"inspect",inspect_image,METH_O,"Check a closed native image and report its opened identity."},
    {"snapshot",snapshot_image,METH_VARARGS,"Commit a named snapshot of a closed native image."},
    {"snapshots",list_images,METH_O,"List committed snapshot names under one core handle."},
    {"restore",restore_image,METH_VARARGS,"Restore a named snapshot and atomically retain prior current."},
    {NULL,NULL,0,NULL}
};
static struct PyModuleDef module = {PyModuleDef_HEAD_INIT,"_image",NULL,-1,methods,NULL,NULL,NULL,NULL};
PyMODINIT_FUNC PyInit__image(void) {
    if (PyType_Ready(&verifier_type) < 0) return NULL;
    return PyModule_Create(&module);
}
