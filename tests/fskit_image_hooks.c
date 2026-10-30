/* Linked only with the offline harness's separately compiled real core. */
#define _DARWIN_C_SOURCE 1
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
static uint64_t reads, writes, closes;
static int fail_read, fail_close;
static int fixture_writes;
/* Only the direct core producer in the offline test enables this gate. */
void sfs_hooks_fixture_writes(int allowed) { fixture_writes = allowed; }
void sfs_hooks_reset(void) { reads = writes = closes = 0; fail_read = fail_close = 0; }
uint64_t sfs_hooks_reads(void) { return reads; }
uint64_t sfs_hooks_writes(void) { return writes; }
uint64_t sfs_hooks_closes(void) { return closes; }
void sfs_hooks_fail_read(void) { fail_read = 1; }
void sfs_hooks_fail_close(void) { fail_close = 1; }
ssize_t sfs_hooks_pread(int fd, void *p, size_t n, off_t offset) {
    ++reads; if (fail_read) { fail_read = 0; errno = EIO; return -1; }
    return pread(fd, p, n, offset);
}
ssize_t sfs_hooks_pwrite(int fd, const void *p, size_t n, off_t offset) {
    if (fixture_writes) { ++writes; return pwrite(fd, p, n, offset); }
    (void)fd; (void)p; (void)n; (void)offset; ++writes; errno = EROFS; return -1;
}
int sfs_hooks_ftruncate(int fd, off_t length) { ++writes; if (fixture_writes) return ftruncate(fd, length); errno = EROFS; return -1; }
int sfs_hooks_fsync(int fd) { ++writes; if (fixture_writes) return fsync(fd); errno = EROFS; return -1; }
int sfs_hooks_close(int fd) {
    ++closes; int result = close(fd);
    if (fail_close) { fail_close = 0; errno = EIO; return -1; }
    return result;
}
