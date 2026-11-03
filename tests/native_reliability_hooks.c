/* Private linkage for disposable-image syscall failures and interruption cuts. */
#define _DARWIN_C_SOURCE 1
#include <signal.h>
#include <stdio.h>
#include "fskit_write_hooks.c"

#ifdef CAMPAIGN_GAPS
#include <inttypes.h>
#include <sys/stat.h>
static struct {
    unsigned mode, expected_ordinal, matches, write_hits, proof_error;
    uint64_t device, inode, parent_device, parent_inode, expected_offset, offset;
    unsigned write_ordinal, requested, caller_unchanged;
    int fd, closing, inject_close, image_closes, parent_closes, close_hits, parent_identity;
    int image_real, image_errno, image_returned, image_return_errno, parent_result, parent_errno;
    ssize_t written, returned;
    unsigned char original_hash[32], replacement_hash[32];
} gap;
static struct {
    uint64_t generation;
    unsigned char uuid[16], original[4096];
    unsigned fences, first_fence_ok, before_write_fences, original_checksum_valid;
    int first_fence_fd;
} gap_anchor;
void campaign_gap_configure(unsigned mode, uint64_t device, uint64_t inode,
    uint64_t parent_device, uint64_t parent_inode, uint64_t offset, unsigned nth) {
    memset(&gap,0,sizeof(gap)); gap.mode=mode; gap.device=device; gap.inode=inode;
    gap.parent_device=parent_device; gap.parent_inode=parent_inode;
    gap.expected_offset=offset; gap.expected_ordinal=nth; gap.fd=-1;
    gap.written=gap.returned=-2; gap.image_real=gap.image_returned=gap.parent_result=-2;
    memset(&gap_anchor,0,sizeof(gap_anchor)); gap_anchor.first_fence_fd=-1;
}
void campaign_gap_anchor(uint64_t generation, const unsigned char uuid[16]) {
    gap_anchor.generation=generation; memcpy(gap_anchor.uuid,uuid,16);
}
static uint64_t gap_u64(const unsigned char *p) {
    uint64_t value=0; for (unsigned i=0;i<8;++i) value|=(uint64_t)p[i]<<(8*i); return value;
}
static unsigned gap_u32(const unsigned char *p) {
    unsigned value=0; for (unsigned i=0;i<4;++i) value|=(unsigned)p[i]<<(8*i); return value;
}
static int gap_identity(int fd, uint64_t device, uint64_t inode, int directory) {
    struct stat st;
    return !fstat(fd,&st) && (uint64_t)st.st_dev==device && (uint64_t)st.st_ino==inode &&
           (directory ? S_ISDIR(st.st_mode) : S_ISREG(st.st_mode));
}
static ssize_t gap_write(int fd, const void *data, size_t count, off_t offset, unsigned nth) {
    /* RAW is a whole payload page, with no in-cell tag. Match the known B page;
     * the controller independently binds its external reference chain. */
    unsigned char expected[4096], replacement[4096];
    for (size_t i=0;i<sizeof(expected);++i) expected[i]=(unsigned char)(67+31+i*17+(i>>8));
    if (count!=sizeof(expected) || memcmp(data,expected,sizeof(expected))) return pwrite(fd,data,count,offset);
    ++gap.matches;
    if (gap.matches!=1 || offset<8192 || offset%4096 || offset>4*1024*1024-4096 ||
        !gap_identity(fd,gap.device,gap.inode,0) ||
        (gap.mode!=1 && ((uint64_t)offset!=gap.expected_offset || nth!=gap.expected_ordinal))) {
        gap.proof_error=1; return pwrite(fd,data,count,offset);
    }
    gap.fd=fd; gap.offset=(uint64_t)offset; gap.write_ordinal=nth; gap.requested=(unsigned)count;
    CC_SHA256(data,(CC_LONG)count,gap.original_hash);
    memcpy(replacement,data,count);
    if (gap.mode==2) replacement[17]^=1;
    CC_SHA256(replacement,(CC_LONG)count,gap.replacement_hash);
    gap.written=pwrite(fd,replacement,count,offset); int saved=errno;
    gap.returned=gap.written; gap.caller_unchanged=!memcmp(data,expected,count);
    if (gap.mode==2 && gap.written==(ssize_t)count) ++gap.write_hits;
    errno=saved; return gap.returned;
}
static ssize_t gap_slot_write(int fd, const void *data, size_t count, off_t offset, unsigned nth) {
    unsigned char checked[4096], replacement[4096], digest[32], caller_after[32];
    const unsigned char *b=data;
    ++gap.matches;
    if (count!=4096 || gap.matches!=1 || nth!=1 || nth!=gap.expected_ordinal ||
        (uint64_t)offset!=gap.expected_offset || offset!=(off_t)(gap_anchor.generation%2)*4096 ||
        !gap_identity(fd,gap.device,gap.inode,0) || gap_anchor.fences!=1 ||
        !gap_anchor.first_fence_ok || gap_anchor.first_fence_fd!=fd ||
        memcmp(b,"SFSIMG01",8) || gap_u32(b+12)!=6 ||
        memcmp(b+24,gap_anchor.uuid,16) || gap_u64(b+40)!=gap_anchor.generation ||
        gap_u32(b+48)!=4 || gap_u64(b+64)!=4096 || gap_u64(b+56)<8192 ||
        gap_u64(b+56)%4096 || gap_u64(b+56)>4*1024*1024-4096 ||
        gap_u64(b+104)!=gap_u64(b+56)+4096 || gap_u64(b+144)!=4*1024*1024) {
        gap.proof_error=1; return pwrite(fd,data,count,offset);
    }
    memcpy(checked,b,4096); memset(checked+112,0,32); CC_SHA256(checked,4096,digest);
    if (memcmp(digest,b+112,32)) { gap.proof_error=1; return pwrite(fd,data,count,offset); }
    gap_anchor.original_checksum_valid=1; gap_anchor.before_write_fences=gap_anchor.fences;
    memcpy(gap_anchor.original,b,4096);
    gap.fd=fd; gap.offset=(uint64_t)offset; gap.write_ordinal=nth; gap.requested=(unsigned)count;
    CC_SHA256(b,4096,gap.original_hash); memcpy(replacement,b,4096);
    if (gap.mode==5) replacement[72]^=1;
    CC_SHA256(replacement,4096,gap.replacement_hash);
    gap.written=pwrite(fd,replacement,count,offset); int saved=errno;
    gap.returned=gap.written; CC_SHA256(data,4096,caller_after);
    gap.caller_unchanged=!memcmp(caller_after,gap.original_hash,32);
    if (gap.mode==5 && gap.written==4096) ++gap.write_hits;
    errno=saved; return gap.returned;
}
int campaign_gap_begin_close(int inject) {
    if (gap.closing || gap.fd<0 || !gap_identity(gap.fd,gap.device,gap.inode,0)) {
        gap.proof_error=1; return 0;
    }
    gap.closing=1; gap.inject_close=inject; return 1;
}
int campaign_close(int fd) {
    if (!gap.closing) return close(fd);
    if (fd==gap.fd) {
        if (++gap.image_closes!=1) { gap.proof_error=1; errno=EBADF; return -1; }
        if (!gap_identity(fd,gap.device,gap.inode,0)) gap.proof_error=1;
        int inject=gap.inject_close; gap.inject_close=0;
        gap.image_real=close(fd); gap.image_errno=gap.image_real ? errno : 0;
        gap.image_returned=gap.image_real; gap.image_return_errno=gap.image_errno;
        if (!gap.image_real && inject && !gap.proof_error) {
            ++gap.close_hits; gap.image_returned=-1; gap.image_return_errno=EIO;
        }
        if (gap.image_returned) errno=gap.image_return_errno;
        return gap.image_returned;
    }
    ++gap.parent_closes;
    gap.parent_identity=gap_identity(fd,gap.parent_device,gap.parent_inode,1);
    if (!gap.parent_identity || gap.parent_closes!=1) gap.proof_error=1;
    gap.parent_result=close(fd); gap.parent_errno=gap.parent_result ? errno : 0;
    if (gap.parent_result) errno=gap.parent_errno;
    return gap.parent_result;
}
void campaign_gap_report(void) {
    printf("{\"event\":\"injection\",\"mode\":%u,\"device\":%" PRIu64 ",\"inode\":%" PRIu64
           ",\"target_matches\":%u,\"write_hits\":%u,\"proof_error\":%u,\"fd\":%d,"
           "\"offset\":%" PRIu64 ",\"ordinal\":%u,\"requested_count\":%u,\"real_write_count\":%zd,"
           "\"returned_count\":%zd,\"caller_unchanged\":%u,\"source_sha256\":\"",
           gap.mode,gap.device,gap.inode,gap.matches,gap.write_hits,gap.proof_error,gap.fd,
           gap.offset,gap.write_ordinal,gap.requested,gap.written,gap.returned,gap.caller_unchanged);
    for (unsigned i=0;i<32;++i) printf("%02x",gap.original_hash[i]);
    printf("\",\"replacement_sha256\":\"");
    for (unsigned i=0;i<32;++i) printf("%02x",gap.replacement_hash[i]);
    if (gap.mode>=4) {
        const unsigned char *b=gap_anchor.original;
        printf("\",\"first_fence_succeeded\":%u,\"first_fence_fd\":%d,\"fences_before_write\":%u,"
               "\"original_checksum_valid\":%u,\"anchor_generation\":%" PRIu64 ",\"anchor_uuid\":\"",
               gap_anchor.first_fence_ok,gap_anchor.first_fence_fd,gap_anchor.before_write_fences,
               gap_anchor.original_checksum_valid,gap_u64(b+40));
        for (unsigned i=24;i<40;++i) printf("%02x",b[i]);
        printf("\",\"anchor_root_type\":%u,\"anchor_root_offset\":%" PRIu64 ",\"anchor_root_length\":%" PRIu64
               ",\"anchor_end\":%" PRIu64 ",\"anchor_capacity\":%" PRIu64 ",\"anchor_root_digest\":\"",
               gap_u32(b+48),gap_u64(b+56),gap_u64(b+64),gap_u64(b+104),gap_u64(b+144));
        for (unsigned i=72;i<104;++i) printf("%02x",b[i]);
        printf("\",\"anchor_slot_checksum\":\"");
        for (unsigned i=112;i<144;++i) printf("%02x",b[i]);
    }
    printf("\",\"close_armed\":%d,\"image_close_attempts\":%d,\"real_image_close_result\":%d,"
           "\"real_image_close_errno\":%d,\"returned_image_close_result\":%d,\"returned_image_close_errno\":%d,"
           "\"close_hits\":%d,\"parent_close_attempts\":%d,\"parent_close_identity_ok\":%d,"
           "\"parent_close_result\":%d,\"parent_close_errno\":%d}\n",
           gap.closing,gap.image_closes,gap.image_real,gap.image_errno,gap.image_returned,gap.image_return_errno,
           gap.close_hits,gap.parent_closes,gap.parent_identity,gap.parent_result,gap.parent_errno);
    fflush(stdout);
}
#endif

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
#ifdef CAMPAIGN_GAPS
    if (gap.mode>=4 && slot) return gap_slot_write(fd,data,count,offset,position);
    if (gap.mode && gap.mode<=3 && !slot) return gap_write(fd,data,count,offset,position);
#endif
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
#ifdef CAMPAIGN_GAPS
    int anchor_errno=errno;
    if (gap.mode>=4) {
        ++gap_anchor.fences;
        if (gap_anchor.fences==1 && !status && gap_identity(fd,gap.device,gap.inode,0)) {
            gap_anchor.first_fence_ok=1; gap_anchor.first_fence_fd=fd;
        }
    }
#endif
    if (!status) pause_at(campaign_fence_calls == 1 ? 2 : 4);
#ifdef CAMPAIGN_GAPS
    if (gap.mode>=4) errno=anchor_errno;
#endif
    return status;
}
