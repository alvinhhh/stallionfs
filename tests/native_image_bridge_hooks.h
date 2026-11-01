#define _DARWIN_C_SOURCE 1
#include <Python.h>
#include "image.h"
#include "fskit_write_hooks.h"
int sfs_bridge_test_fcntl(int, int, ...);
int sfs_bridge_test_close(int);
ssize_t sfs_bridge_test_pread(int, void *, size_t, off_t);
int sfs_bridge_test_clock(clockid_t, struct timespec *);
PyObject *sfs_bridge_test_signed(long long);
PyObject *sfs_bridge_test_unsigned(unsigned long long);
enum sfs_status sfs_bridge_test_snapshot(sfs_image *, const void *, size_t, sfs_view *, sfs_result *);
enum sfs_status sfs_bridge_test_restore(sfs_image *, sfs_view, const void *, size_t, const sfs_verify_budget *, sfs_view *, sfs_result *);
