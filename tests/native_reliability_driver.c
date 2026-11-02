/* Closed-image producer and non-mutating reader for durability-oracle checks. */
#define _DARWIN_C_SOURCE 1
#include "image.h"
#include <CommonCrypto/CommonDigest.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#ifdef CAMPAIGN_GAPS
#include <errno.h>
void campaign_gap_configure(unsigned, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, unsigned);
int campaign_gap_begin_close(int);
void campaign_gap_report(void);
#endif

#ifdef CAMPAIGN_FAULTS
void campaign_configure(const char *, unsigned, unsigned);
unsigned campaign_hits(void), campaign_records(void), campaign_slots(void), campaign_fences(void);
#else
static void campaign_configure(const char *a, unsigned b, unsigned c) { (void)a; (void)b; (void)c; }
static unsigned campaign_hits(void) { return 0; }
static unsigned campaign_records(void) { return 0; }
static unsigned campaign_slots(void) { return 0; }
static unsigned campaign_fences(void) { return 0; }
#endif
static sfs_result receipt;
static sfs_image *image;
static const sfs_verify_budget budget = {131072,536870912,536870912,50000000,33554432,1073741824,NULL,NULL};
static const char *attrs[] = {"org.campaign/value", "com.apple.ResourceFork"};
static void hex(const unsigned char *bytes, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", bytes[i]);
}
static void result(const char *event, enum sfs_status status) {
    printf("{\"event\":\"%s\",\"status\":%d,\"generation\":%" PRIu64 ",\"committed_end\":%" PRIu64
           ",\"phase\":%d,\"errno\":%d,\"coverage\":%d,\"fence_attempted\":%u,\"fence_succeeded\":%u,"
           "\"poisoned\":%d,\"transaction_active\":%d,\"hits\":%u,\"record_calls\":%u,\"slot_calls\":%u,\"fence_calls\":%u,\"root_digest\":\"",
           event,status,receipt.generation,receipt.committed_end,receipt.phase,receipt.system_errno,receipt.coverage,
           receipt.fence_attempted,receipt.fence_succeeded,receipt.poisoned,receipt.transaction_active,
           campaign_hits(),campaign_records(),campaign_slots(),campaign_fences());
    hex(receipt.root_digest,32); puts("\"}"); fflush(stdout);
}
static sfs_metadata_initial initial(unsigned mode) {
    sfs_metadata_initial value = {0}; value.mode = mode; value.uid = geteuid(); value.gid = getegid();
    value.restore = SFS_RESTORE_BIRTH | SFS_RESTORE_ACCESS | SFS_RESTORE_MODIFICATION;
    value.birth.seconds=10; value.access.seconds=20; value.modification.seconds=30; return value;
}
static void pattern(unsigned char *out, size_t count, unsigned state, unsigned kind) {
    for (size_t i=0;i<count;++i) out[i]=(unsigned char)(state*67+kind*31+i*17+(i>>8));
}
static enum sfs_status find(sfs_view view, const char *name, sfs_entry *entry) {
    return sfs_image_lookup(image,view,1,name,strlen(name),entry,&receipt);
}
static enum sfs_status contents(unsigned state, sfs_inode file_id, sfs_inode companion_id) {
    unsigned char data[12288]; sfs_entry file, companion;
    enum sfs_status status=SFS_OK;
    if (file_id && companion_id) { file.inode=file_id; companion.inode=companion_id; }
    else { status=find(0,"file",&file); if (!status) status=find(0,"companion",&companion); }
    if (!status) { pattern(data,sizeof(data),state,1); status=sfs_image_write(image,file.inode,0,data,sizeof(data),&receipt); }
    if (!status) { pattern(data,8192,state,2); status=sfs_image_write(image,companion.inode,0,data,8192,&receipt); }
    for (unsigned i=0;i<2&&!status;++i) {
        pattern(data,8192,state,3+i);
        status=sfs_image_set_xattr(image,file.inode,attrs[i],strlen(attrs[i]),data,8192,&receipt);
    }
    return status;
}
static int seed(const char *directory, unsigned parity) {
    sfs_metadata_initial root=initial(S_IFDIR|0700), file=initial(S_IFREG|0640), other=initial(S_IFREG|0600), link=initial(S_IFLNK|0700);
    sfs_inode id=0, file_id=0, companion_id=0; sfs_view view;
    enum sfs_status status=sfs_image_create_metadata_version(directory,"image.sfs",4*1024*1024,6,&root,&image,&receipt);
    if (!status) status=sfs_image_begin(image,&receipt);
    if (!status) status=sfs_image_add_metadata(image,1,"file",4,SFS_FILE,&file,&id,&receipt);
    file_id=id;
    if (!status) status=sfs_image_link(image,id,1,"alias",5,&receipt);
    if (!status) status=sfs_image_add_metadata(image,1,"companion",9,SFS_FILE,&other,&id,&receipt);
    companion_id=id;
    if (!status) status=sfs_image_symlink_metadata(image,1,"link",4,"file",4,&link,&id,&receipt);
    if (!status) status=contents(0,file_id,companion_id);
    if (!status) status=sfs_image_commit(image,&receipt);
    if (!status) status=sfs_image_begin(image,&receipt);
    if (!status) status=sfs_image_snapshot(image,"baseline",8,&view,&receipt);
    if (!status) status=sfs_image_commit(image,&receipt);
    if (!status && parity) { status=sfs_image_begin(image,&receipt); if (!status) status=sfs_image_commit(image,&receipt); }
    result(status ? "result" : "ack",status);
    if (image) sfs_image_close(image,NULL);
    return status ? 1 : 0;
}
static void object(const char *label, sfs_view view, const char *name, int attribute, int *first) {
    sfs_entry entry={0}; size_t count=0; uint64_t length=0; unsigned char data[65536], digest[32];
    enum sfs_status lookup_status=find(view,name,&entry), size_status=SFS_STATE, read_status=SFS_STATE;
    enum sfs_status status=lookup_status; length=entry.size;
    int size_attempted=!status&&attribute>=0, read_attempted=0;
    if (size_attempted) status=size_status=sfs_image_xattr_size(image,view,entry.inode,attrs[attribute],strlen(attrs[attribute]),&length,&receipt);
    if (!status && length<=sizeof(data)) {
        read_attempted=1;
        status=read_status=attribute<0 ? sfs_image_read(image,view,entry.inode,0,data,(size_t)length,&count,&receipt)
                                   : sfs_image_read_xattr(image,view,entry.inode,attrs[attribute],strlen(attrs[attribute]),0,data,(size_t)length,&count,&receipt);
    }
    int invalid=count>length || length>sizeof(data) || count>sizeof(data);
    CC_SHA256(data,(CC_LONG)(invalid?0:count),digest);
    printf("%s{\"name\":\"%s\",\"status\":%d,\"length\":%" PRIu64 ",\"count\":%zu,\"sha256\":\"",*first?"":",",label,status,length,count);
    hex(digest,32);
    printf("\",\"invalid_count\":%s,\"lookup_status\":%d,\"lookup_size\":%" PRIu64
           ",\"lookup_is_file\":%s,\"size_attempted\":%s,\"size_status\":%d,\"size_value\":%" PRIu64
           ",\"read_attempted\":%s,\"read_status\":%d}",invalid?"true":"false",lookup_status,entry.size,
           entry.kind==SFS_FILE?"true":"false",size_attempted?"true":"false",size_status,length,
           read_attempted?"true":"false",read_status); *first=0;
}
static void namespace_entries(sfs_view view, const char *label) {
    sfs_cookie cookie={0}; sfs_entry entry; int found=0, first=1; unsigned seen=0;
    enum sfs_status status=SFS_OK;
    printf("{\"view\":\"%s\",\"entries\":[",label);
    do {
        status=sfs_image_next(image,view,1,&cookie,&entry,&found,&receipt);
        if (status || !found) break;
        sfs_metadata_entry metadata; enum sfs_status ms=sfs_image_stat_metadata(image,view,entry.inode,&metadata,&receipt);
        printf("%s{\"name_hex\":\"",first?"":","); hex(entry.name,entry.name_length<=sizeof(entry.name)?entry.name_length:0);
        printf("\",\"invalid_name_length\":%s,\"is_file\":%s,\"size\":%" PRIu64 ",\"metadata_status\":%d,\"mode\":%u,\"links\":%" PRIu64 "}",
               entry.name_length>sizeof(entry.name)?"true":"false",entry.kind==SFS_FILE?"true":"false",entry.size,ms,ms?0:metadata.mode&07777,ms?UINT64_C(0):metadata.link_count);
        first=0;
        if (++seen>16) { status=SFS_LIMIT; break; }
    } while (found);
    printf("],\"status\":%d}",status);
}
static int read_image(const char *directory) {
    enum sfs_status status=sfs_image_open_readonly(directory,"image.sfs",&image,&receipt);
    int opened=!status; sfs_view views[3]={0}; int selected_status[3]={SFS_OK,SFS_NOT_FOUND,SFS_NOT_FOUND};
    printf("{\"event\":\"read\",\"open_status\":%d,\"generation\":%" PRIu64 ",\"open_coverage\":%d,\"root_digest\":\"",
           status,receipt.generation,receipt.coverage);
    hex(receipt.root_digest,32); printf("\",\"objects\":[");
    int first=1, baseline_status=-1, recovery_status=-1;
    const char *names[]={"file","alias","companion","link","root"};
    sfs_entry entries[5]={{0}}; sfs_metadata_entry metadata[5]={{0}};
    enum sfs_status ls[5]={SFS_STATE,SFS_STATE,SFS_STATE,SFS_STATE,SFS_STATE};
    enum sfs_status ms[5]={SFS_STATE,SFS_STATE,SFS_STATE,SFS_STATE,SFS_STATE};
    unsigned char target[4]={0}; size_t got=0; enum sfs_status link_status=SFS_STATE;
    if (!status) {
        const char *prefixes[]={"current","baseline","recovery"};
        for (unsigned i=0;i<3;++i) {
            sfs_view view=0; enum sfs_status selected=SFS_OK;
            if (i) selected=sfs_image_snapshot_view(image,i==1?"baseline":"recovery",8,&view,&receipt);
            views[i]=view; selected_status[i]=selected;
            if (i==1) baseline_status=selected;
            if (i==2) recovery_status=selected;
            if (selected) continue;
            char label[64];
            for (unsigned j=0;j<4;++j) {
                snprintf(label,sizeof(label),"%s/%s",prefixes[i],j==0?"file":j==1?"companion":j==2?"xattr":"resource");
                object(label,view,j==1?"companion":"file",j<2?-1:(int)j-2,&first);
            }
        }
        for (unsigned i=0;i<5;++i) {
            ls[i]=i==4?sfs_image_stat(image,0,1,&entries[i],&receipt):find(0,names[i],&entries[i]);
            if (!ls[i]) ms[i]=sfs_image_stat_metadata(image,0,entries[i].inode,&metadata[i],&receipt);
        }
        if (!ls[3]) link_status=sfs_image_readlink(image,0,entries[3].inode,target,sizeof(target),&got,&receipt);
        status=sfs_image_verify(image,&budget,&receipt);
    }
    int full=!status&&receipt.coverage==SFS_COVERAGE_FULL_REACHABLE;
    printf("],\"namespaces\":[");
    if (opened) { int comma=0; const char *labels[]={"current","baseline","recovery"};
        for (unsigned i=0;i<3;++i) if (!selected_status[i]) { if (comma++) printf(","); namespace_entries(views[i],labels[i]); } }
    printf("],\"catalog\":{\"names_hex\":[");
    enum sfs_status catalog_status=opened?SFS_OK:SFS_STATE; int found=0, comma=0, invalid_name=0;
    if (opened) for (unsigned i=0;i<=32;++i) { sfs_snapshot_entry entry;
        catalog_status=sfs_image_snapshot_at(image,i,&entry,&found,&receipt); if (catalog_status || !found) break;
        if (entry.name_length>sizeof(entry.name)) { invalid_name=1; break; }
        if (comma++) printf(","); printf("\""); hex(entry.name,entry.name_length); printf("\""); }
    printf("],\"status\":%d,\"invalid_name_length\":%s},\"verify_status\":%d,\"full_reachable\":%s,\"baseline_status\":%d,\"recovery_status\":%d,\"metadata\":[",
           catalog_status,invalid_name?"true":"false",status,full?"true":"false",baseline_status,recovery_status);
    for (unsigned i=0;i<5;++i) {
        printf("%s{\"name\":\"%s\",\"lookup_status\":%d,\"metadata_attempted\":%s,\"metadata_status\":%d,\"size\":%" PRIu64 ",\"is_file\":%s,\"mode\":%u,\"links\":%" PRIu64 "}",
               i?",":"",names[i],ls[i],!ls[i]?"true":"false",ms[i],entries[i].size,entries[i].kind==SFS_FILE?"true":"false",
               ms[i]?0:metadata[i].mode&07777,ms[i]?UINT64_C(0):metadata[i].link_count);
    }
    printf("],\"alias_comparison_attempted\":%s,\"alias_equal\":%s,\"symlink\":{\"attempted\":%s,\"status\":%d,\"count\":%zu,\"capacity\":%zu,\"invalid_count\":%s,\"target_hex\":\"",
           !ls[0]&&!ls[1]?"true":"false",!ls[0]&&!ls[1]&&entries[0].inode==entries[1].inode?"true":"false",
           !ls[3]?"true":"false",link_status,got,sizeof(target),got>sizeof(target)?"true":"false");
    hex(target,got<=sizeof(target)?got:0); puts("\"}}");
    if (image) sfs_image_close(image,NULL);
    return 0;
}
static int inspect_image(const char *directory) {
    sfs_recovery recovery={0};
    enum sfs_status status=sfs_image_inspect(directory,"image.sfs",&image,&recovery,&budget,&receipt);
    printf("{\"event\":\"inspection\",\"status\":%d,\"pair_valid\":%s,\"latest_may_be_unknown\":%s,\"slots\":[",
           status,recovery.pair_valid?"true":"false",recovery.latest_may_be_unknown?"true":"false");
    for (unsigned i=0;i<2;++i) printf("%s{\"slot\":%u,\"status\":%d,\"generation\":%" PRIu64 ",\"full_reachable\":%s}",
        i?",":"",i,recovery.slots[i].status,recovery.slots[i].generation,
        recovery.slots[i].status==SFS_OK&&recovery.slots[i].coverage==SFS_COVERAGE_FULL_REACHABLE?"true":"false");
    puts("]}");
    if (image) sfs_image_close(image,NULL);
    return 0;
}
static int verify_image(const char *directory) {
    enum sfs_status opened=sfs_image_open_readonly(directory,"image.sfs",&image,&receipt);
    uint64_t generation=receipt.generation;
    unsigned char opened_root[32]; memcpy(opened_root,receipt.root_digest,32);
    enum sfs_coverage open_coverage=receipt.coverage;
    enum sfs_status verified=SFS_STATE;
    if (!opened) verified=sfs_image_verify(image,&budget,&receipt);
    int full=!opened&&!verified&&receipt.coverage==SFS_COVERAGE_FULL_REACHABLE;
    printf("{\"event\":\"verification\",\"open_status\":%d,\"generation\":%" PRIu64
           ",\"open_coverage\":%d,\"verify_attempted\":%s,\"verify_status\":%d,\"full_reachable\":%s,\"root_digest\":\"",
           opened,generation,open_coverage,!opened?"true":"false",verified,full?"true":"false");
    hex(opened_root,32); puts("\"}");
    if (image) sfs_image_close(image,NULL);
    return 0;
}
#ifdef CAMPAIGN_GAPS
static int gap_write_image(char **argv) {
    char *end=NULL; errno=0; unsigned long mode=strtoul(argv[3],&end,10);
    if (errno || !*argv[3] || *end || mode<1 || mode>3) return 2;
    errno=0; uint64_t offset=strtoull(argv[4],&end,10);
    if (errno || !*argv[4] || *end || offset>4*1024*1024-4096) return 2;
    errno=0; unsigned long ordinal=strtoul(argv[5],&end,10);
    if (errno || !*argv[5] || *end || ordinal>1024 ||
        (mode==1 ? offset || ordinal : offset<8192 || offset%4096 || !ordinal)) return 2;
    enum sfs_status status=sfs_image_open(argv[2],"image.sfs",&image,&receipt);
    if (status) { result("result",status); return 0; }
    struct stat parent;
    if (lstat(argv[2],&parent) || !S_ISDIR(parent.st_mode)) {
        sfs_image_close(image,NULL); image=NULL; return 2;
    }
    campaign_configure("none",0,0);
    campaign_gap_configure((unsigned)mode,receipt.device,receipt.inode,
        (uint64_t)parent.st_dev,(uint64_t)parent.st_ino,offset,(unsigned)ordinal);
    status=sfs_image_begin(image,&receipt); result("begin",status);
    if (!status) { status=contents(1,0,0); result("write",status); }
    if (!status) status=sfs_image_commit(image,&receipt);
    result(status?"result":"ack",status);
    /* The ACK receipt is already flushed. Closing consumes the handle even
     * when it reports EIO; its receipt never replaces the earlier ACK. */
    (void)campaign_gap_begin_close(mode==3 && status==SFS_OK);
    enum sfs_status closed=sfs_image_close(image,&receipt); image=NULL;
    result("close",closed); campaign_gap_report();
    return 0;
}
#endif
int main(int argc,char **argv) {
    if (argc<3) return 2;
    if (!strcmp(argv[1],"seed") && argc==4) return seed(argv[2],(unsigned)atoi(argv[3]));
    if (!strcmp(argv[1],"read") && argc==3) return read_image(argv[2]);
    if (!strcmp(argv[1],"verify") && argc==3) return verify_image(argv[2]);
    if (!strcmp(argv[1],"inspect") && argc==3) return inspect_image(argv[2]);
#ifdef CAMPAIGN_GAPS
    if (!strcmp(argv[1],"gap") && argc==6) return gap_write_image(argv);
#endif
    if (argc!=7 || (strcmp(argv[1],"write") && strcmp(argv[1],"restore"))) return 2;
    enum sfs_status status=sfs_image_open(argv[2],"image.sfs",&image,&receipt);
    if (status) { result("result",status); return 1; }
    campaign_configure(argv[3],(unsigned)atoi(argv[4]),(unsigned)atoi(argv[5]));
    if (!strcmp(argv[1],"write")) { status=sfs_image_begin(image,&receipt); if (!status) status=contents(1,0,0); }
    else { sfs_view target, recovery; status=sfs_image_snapshot_view(image,"baseline",8,&target,&receipt);
        if (!status) status=sfs_image_prepare_restore(image,target,"recovery",8,&budget,&recovery,&receipt); }
    if (!status) status=sfs_image_commit(image,&receipt);
    result(status?"result":"ack",status);
    if (!status && atoi(argv[6])) { raise(SIGSTOP); for (;;) pause(); }
    if (image) sfs_image_close(image,NULL);
    return 0;
}
