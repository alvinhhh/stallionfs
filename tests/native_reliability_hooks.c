/* Private linkage for disposable-image syscall failures and interruption cuts. */
#define _DARWIN_C_SOURCE 1
#include <signal.h>
#include <stdio.h>
#include "fskit_write_hooks.c"

static const char *fault = "none";
static unsigned ordinal, cut_point, records, campaign_slot_calls, campaign_fence_calls, hits;
static int delegated;
void campaign_configure(const char *name, unsigned nth, unsigned cut) {
    fault = name; ordinal = nth; cut_point = cut;
    records = campaign_slot_calls = campaign_fence_calls = hits = 0; delegated = 0; sfs_diag_fault(0, 0);
}
unsigned campaign_hits(void) { return hits; }
unsigned campaign_records(void) { return records; }
unsigned campaign_slots(void) { return campaign_slot_calls; }
unsigned campaign_fences(void) { return campaign_fence_calls; }
static void pause_at(unsigned point) {
    if (cut_point != point) return;
    printf("{\"event\":\"cut\",\"point\":%u}\n", point); fflush(stdout);
    raise(SIGSTOP);
    for (;;) pause();
}
ssize_t campaign_pwrite(int fd, const void *data, size_t count, off_t offset) {
    int slot = offset < 8192;
    unsigned position = slot ? ++campaign_slot_calls : ++records;
    if (slot && cut_point == 3) {
        size_t prefix = count < 73 ? count : 73;
        ssize_t done = pwrite(fd, data, prefix, offset);
        if (done != (ssize_t)prefix) return done;
        pause_at(3);
    }
    if (!delegated && position == ordinal &&
        !strncmp(fault, slot ? "slot_" : "record_", slot ? 5 : 7)) {
        const char *kind = fault + (slot ? 5 : 7); ++hits;
        if (!strcmp(kind, "eio")) { errno = EIO; return -1; }
        if (!strcmp(kind, "enospc")) { sfs_diag_fault(1, 1); delegated = 1; }
        else if (!strcmp(kind, "zero")) { sfs_diag_fault(3, 1); delegated = 1; }
        else if (!strcmp(kind, "partial")) { sfs_diag_fault(2, 1); delegated = 1; }
        else if (!strncmp(kind, "torn", 4)) {
            size_t prefix = !strcmp(kind, "torn73") ? 73 : 4095;
            if (prefix > count) prefix = count;
            ssize_t done = pwrite(fd, data, prefix, offset);
            if (done != (ssize_t)prefix) return done;
            errno = ENOSPC; return -1;
        }
    }
    ssize_t done = delegated ? sfs_diag_pwrite(fd, data, count, offset) : pwrite(fd, data, count, offset);
    if (!slot && records == 1 && done > 0) pause_at(1);
    return done;
}
int campaign_fcntl(int fd, int command, ...) {
    if (command == F_DUPFD_CLOEXEC) {
        va_list args; va_start(args, command); int minimum = va_arg(args, int); va_end(args);
        return fcntl(fd, command, minimum);
    }
    if (command != F_FULLFSYNC) { errno = EINVAL; return -1; }
    ++campaign_fence_calls;
    if (campaign_fence_calls == ordinal && !strncmp(fault, "fence_", 6)) {
        ++hits;
        if (!strcmp(fault, "fence_enospc")) { sfs_diag_fault(4, 1); return sfs_diag_fcntl(fd, command); }
        errno = EIO; return -1;
    }
    int status = fcntl(fd, command);
    if (!status) pause_at(campaign_fence_calls == 1 ? 2 : 4);
    return status;
}
