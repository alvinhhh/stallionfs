/* Diagnostic linkage only; ordinary installed modules export none of these. */
#include "native_image_bridge_hooks.h"
#include <assert.h>
#include <signal.h>
#include "fskit_write_hooks.c"
static int bridge_flags, deadline_tick, ticks, preparing;
void sfs_bridge_test_configure(int fault_kind, int ordinal, int flags, int deadline) {
    sfs_diag_fault(fault_kind,ordinal); bridge_flags = flags; deadline_tick = deadline; ticks = preparing = 0;
}
int sfs_bridge_test_clock(clockid_t clock, struct timespec *out) {
    int status = clock_gettime(clock,out);
    if (!status && clock == CLOCK_MONOTONIC && ++ticks == deadline_tick) out->tv_sec += 31;
    return status;
}
int sfs_bridge_test_close(int fd) {
    int status = close(fd);
    if (!status && (bridge_flags & 1) && sfs_diag_fences() >= 2) { bridge_flags &= ~1; errno = EIO; return -1; }
    return status;
}
int sfs_bridge_test_fcntl(int fd, int command, ...) {
    if (command == F_DUPFD_CLOEXEC) {
        va_list args; va_start(args,command); int minimum = va_arg(args,int); va_end(args);
        return sfs_diag_fcntl(fd,command,minimum);
    }
    int status = sfs_diag_fcntl(fd,command);
    if (!status && command == F_FULLFSYNC && (bridge_flags & 2) && sfs_diag_fences() == 2) { bridge_flags &= ~2; raise(SIGINT); }
    return status;
}
ssize_t sfs_bridge_test_pread(int fd, void *bytes, size_t count, off_t offset) {
    ssize_t status = sfs_diag_pread(fd,bytes,count,offset);
    if (status >= 0 && preparing && (bridge_flags & 8)) { bridge_flags &= ~8; raise(SIGINT); }
    return status;
}
enum sfs_status sfs_bridge_test_snapshot(sfs_image *h, const void *name, size_t length, sfs_view *view, sfs_result *result) {
    enum sfs_status status = sfs_image_snapshot(h,name,length,view,result);
    if (status == SFS_OK && (bridge_flags & 4)) { bridge_flags &= ~4; raise(SIGINT); }
    return status;
}
enum sfs_status sfs_bridge_test_restore(sfs_image *h, sfs_view view, const void *name, size_t length,
                                       const sfs_verify_budget *budget, sfs_view *recovery, sfs_result *result) {
    assert(budget && budget->raw_cells == 1 && budget->auxiliary_bytes == 1 && budget->auxiliary_io_bytes == 1);
    assert(budget->metadata_read_bytes == 536870912 && budget->metadata_hash_bytes == 536870912 && budget->checks == 50000000);
    sfs_verify_budget actual = *budget;
    if (bridge_flags & 16) actual.metadata_read_bytes = 1;
    preparing = 1;
    enum sfs_status status = sfs_image_prepare_restore(h,view,name,length,&actual,recovery,result);
    preparing = 0; return status;
}
PyObject *sfs_bridge_test_signed(long long value) {
    if ((bridge_flags & 64) || ((bridge_flags & 32) && sfs_diag_fences() >= 2)) { bridge_flags &= ~(32|64); return PyErr_NoMemory(); }
    return PyLong_FromLongLong(value);
}
PyObject *sfs_bridge_test_unsigned(unsigned long long value) {
    if ((bridge_flags & 64) || ((bridge_flags & 32) && sfs_diag_fences() >= 2)) { bridge_flags &= ~(32|64); return PyErr_NoMemory(); }
    return PyLong_FromUnsignedLongLong(value);
}
