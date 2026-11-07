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

PyObject *sfs_bridge_test_text(const char *, Py_ssize_t);
enum sfs_status sfs_bridge_test_import_verify(sfs_image *, const sfs_verify_budget *, sfs_result *);
enum sfs_status sfs_bridge_test_import_open(const char *, const char *, sfs_image **, sfs_result *);
enum sfs_status sfs_bridge_test_import_close(sfs_image *, sfs_result *);
enum sfs_status sfs_bridge_test_import_write(sfs_image *, sfs_inode, uint64_t, const void *, size_t, sfs_result *);
void *sfs_bridge_test_import_malloc(size_t);
ssize_t sfs_bridge_test_import_pwrite(int, const void *, size_t, off_t);

int sfs_bridge_test_parent_close(int);
enum sfs_status sfs_bridge_test_guard_open(const char *, const char *, sfs_image **, sfs_result *);
