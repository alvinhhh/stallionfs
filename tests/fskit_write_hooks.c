/* Only linked to the private disposable-image helper. Compile this file without
 * the syscall substitutions applied to image.c. Successful I/O stays real. */
#define _DARWIN_C_SOURCE 1
#include "fskit_write_hooks.h"
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
static int kind, target, writes, slots, fences, clocks, allocations, reads, hit;
void sfs_diag_fault(int k, int n) {
    kind = k; target = n; writes = slots = fences = clocks = allocations = reads = hit = 0;
}
int sfs_diag_hit(void) { return hit; }
int sfs_diag_fences(void) { return fences; }
ssize_t sfs_diag_pwrite(int fd, const void *p, size_t n, off_t at) {
    ++writes; if (at < 8192) ++slots;
    if ((kind == 1 && writes == target) || (kind == 5 && at < 8192 && slots == target)) {
        ++hit; errno = ENOSPC; return -1;
    }
    if (kind == 2 && writes == target) {
        ++hit; return pwrite(fd, p, n > 19 ? 19 : n, at);
    }
    if (kind == 2 && writes == target + 1) { ++hit; errno = ENOSPC; return -1; }
    if (kind == 3 && writes == target) { ++hit; return 0; }
    if (kind == 9 && n > 17) { ++hit; n = 17; }
    return pwrite(fd, p, n, at);
}
ssize_t sfs_diag_pread(int fd, void *p, size_t n, off_t at) {
    if (++reads == target && kind == 8) { ++hit; errno = EIO; return -1; }
    ssize_t result = pread(fd, p, n, at);
    if (kind == 10 && reads == target && at < 8192 && result == 4096) {
        /* A checked but unsupported header observed by commit reconciliation.
         * Only the returned buffer changes; the owned image stays untouched. */
        unsigned char *b = p; b[8] = 1; memset(b + 112, 0, 32);
        unsigned char digest[32]; CC_SHA256(b, 4096, digest); memcpy(b + 112, digest, 32); ++hit;
    }
    return result;
}
int sfs_diag_fcntl(int fd, int command, ...) {
    if (command == F_DUPFD_CLOEXEC) {
        va_list ap; va_start(ap, command); int minimum = va_arg(ap, int); va_end(ap);
        return fcntl(fd, command, minimum);
    }
    if (command != F_FULLFSYNC) { errno = EINVAL; return -1; }
    if (++fences == target && kind == 4) { ++hit; errno = ENOSPC; return -1; }
    return fcntl(fd, command);
}
int sfs_diag_clock_gettime(clockid_t clock, struct timespec *out) {
    if (++clocks == target && kind == 6) { ++hit; errno = ENXIO; return -1; }
    return clock_gettime(clock, out);
}
void *sfs_diag_malloc(size_t n) {
    if (++allocations == target && kind == 7) { ++hit; errno = ENOMEM; return NULL; }
    return malloc(n);
}
void *sfs_diag_calloc(size_t n, size_t size) {
    if (++allocations == target && kind == 7) { ++hit; errno = ENOMEM; return NULL; }
    return calloc(n, size);
}
