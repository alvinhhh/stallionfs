#include <stddef.h>
#include <sys/types.h>
#include <time.h>
ssize_t sfs_diag_pwrite(int, const void *, size_t, off_t);
ssize_t sfs_diag_pread(int, void *, size_t, off_t);
int sfs_diag_fcntl(int, int, ...);
int sfs_diag_clock_gettime(clockid_t, struct timespec *);
void *sfs_diag_malloc(size_t);
void *sfs_diag_calloc(size_t, size_t);
