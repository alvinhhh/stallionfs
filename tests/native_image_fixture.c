/* Owned fixture producer/checker; snapshot and restore run through installed sfs. */
#define _DARWIN_C_SOURCE 1
#include "image.h"
#include <CommonCrypto/CommonDigest.h>
#include <inttypes.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OK(call) assert((call) == SFS_OK)
static sfs_result receipt;
static sfs_image *image;
static sfs_metadata_initial initial(unsigned mode) {
    sfs_metadata_initial m = {0};
    m.mode = mode; m.uid = geteuid(); m.gid = getegid();
    m.restore = SFS_RESTORE_BIRTH | SFS_RESTORE_ACCESS | SFS_RESTORE_MODIFICATION;
    m.birth.seconds = 10; m.access.seconds = 20; m.modification.seconds = 30;
    return m;
}
static sfs_entry lookup(sfs_view view, const char *name) {
    sfs_entry e; OK(sfs_image_lookup(image,view,1,name,strlen(name),&e,&receipt)); return e;
}
static void same_time(sfs_timestamp a, sfs_timestamp b) { assert(a.seconds == b.seconds && a.nanoseconds == b.nanoseconds); }
static void same_metadata(sfs_view view, sfs_inode inode) {
    sfs_metadata_entry a, b;
    OK(sfs_image_stat_metadata(image,view,inode,&a,&receipt));
    OK(sfs_image_stat_metadata(image,0,inode,&b,&receipt));
    assert(a.entry.inode == b.entry.inode && a.entry.parent == b.entry.parent && a.entry.kind == b.entry.kind && a.entry.size == b.entry.size);
    assert(a.entry.name_length == b.entry.name_length && !memcmp(a.entry.name,b.entry.name,a.entry.name_length));
    assert(a.uid == b.uid && a.gid == b.gid && a.mode == b.mode && a.flags == b.flags && a.link_count == b.link_count && a.referenced_data_bytes == b.referenced_data_bytes);
    same_time(a.birth,b.birth); same_time(a.access,b.access); same_time(a.modification,b.modification); same_time(a.change,b.change);
}
static void hex(const unsigned char *p,size_t n) { for (size_t i=0;i<n;i++) printf("%02x",p[i]); }
static sfs_inode path_inode(const char *path) {
    sfs_inode inode=1; char *copy=strdup(path),*rest=copy,*name;
    assert(copy);
    while ((name=strsep(&rest,"/"))) {
        if (!*name || !strcmp(name,".")) continue;
        sfs_entry entry; OK(sfs_image_lookup(image,0,inode,name,strlen(name),&entry,&receipt)); inode=entry.inode;
    }
    free(copy); return inode;
}
static void describe(const char *path) {
    sfs_inode inode = path_inode(path);
    sfs_metadata_entry m; OK(sfs_image_stat_metadata(image,0,inode,&m,&receipt));
    sfs_result anchor=receipt;
    printf("{\"inode\":%" PRIu64 ",\"kind\":%d,\"size\":%" PRIu64 ",\"mode\":%u,\"uid\":%u,\"gid\":%u,\"flags\":%u,\"links\":%" PRIu64 ",\"mapped_bytes\":%" PRIu64,
        inode,m.entry.kind,m.entry.size,m.mode,m.uid,m.gid,m.flags,m.link_count,m.referenced_data_bytes);
    printf(",\"birth\":[%" PRId64 ",%u],\"access\":[%" PRId64 ",%u],\"modification\":[%" PRId64 ",%u]",
        m.birth.seconds,m.birth.nanoseconds,m.access.seconds,m.access.nanoseconds,m.modification.seconds,m.modification.nanoseconds);
    if (m.entry.kind==SFS_FILE) {
        unsigned char bytes[65536],digest[32]; CC_SHA256_CTX hash; CC_SHA256_Init(&hash);
        for (uint64_t at=0;at<m.entry.size;) { size_t n=m.entry.size-at>sizeof(bytes) ? sizeof(bytes) : (size_t)(m.entry.size-at),got;
            OK(sfs_image_read(image,0,inode,at,bytes,n,&got,&receipt)); assert(got==n); CC_SHA256_Update(&hash,bytes,(CC_LONG)n); at+=n; }
        CC_SHA256_Final(digest,&hash); printf(",\"sha256\":\""); hex(digest,32); printf("\",\"mapped\":[");
        sfs_verify_budget budget={UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,UINT64_MAX,NULL,NULL};
        uint64_t seek=0,block; int found,first=1;
        for (;;) { OK(sfs_image_next_mapped_block(image,0,anchor.generation,anchor.root_digest,inode,seek,&budget,&block,&found,&receipt)); if (!found) break;
            printf("%s%" PRIu64,first ? "" : ",",block); first=0; seek=block+1; }
        printf("]");
    } else if (m.entry.kind==SFS_SYMLINK) {
        unsigned char bytes[4096]; size_t got; OK(sfs_image_readlink(image,0,inode,bytes,sizeof(bytes),&got,&receipt));
        printf(",\"target\":\""); hex(bytes,got); printf("\"");
    } else {
        sfs_cookie cookie={0}; sfs_entry entry; int found,first=1; printf(",\"children\":[");
        for (;;) { OK(sfs_image_next(image,0,inode,&cookie,&entry,&found,&receipt)); if (!found) break;
            printf("%s\"",first ? "" : ","); hex(entry.name,entry.name_length); printf("\""); first=0; }
        printf("]");
    }
    unsigned char after[255]; size_t length=0; int first=1; printf(",\"xattrs\":{");
    for (;;) {
        sfs_xattr_entry entry; int found; OK(sfs_image_next_xattr(image,0,anchor.generation,anchor.root_digest,inode,length ? after : NULL,length,&entry,&found,&receipt)); if (!found) break;
        unsigned char bytes[65536],digest[32]; CC_SHA256_CTX hash; CC_SHA256_Init(&hash);
        for (uint64_t at=0;at<entry.size;) { size_t n=entry.size-at>sizeof(bytes) ? sizeof(bytes) : (size_t)(entry.size-at),got;
            OK(sfs_image_read_xattr(image,0,inode,entry.name,entry.name_length,at,bytes,n,&got,&receipt)); assert(got==n); CC_SHA256_Update(&hash,bytes,(CC_LONG)n); at+=n; }
        CC_SHA256_Final(digest,&hash); printf("%s\"",first ? "" : ","); hex(entry.name,entry.name_length);
        printf("\":{\"size\":%" PRIu64 ",\"sha256\":\"",entry.size); hex(digest,32); printf("\"}");
        memcpy(after,entry.name,entry.name_length); length=entry.name_length; first=0;
    }
    printf("}}\n");
}
int main(int argc, char **argv) {
    assert(argc >= 3);
    if (!strcmp(argv[1],"host-times")) {
        assert(argc==3); struct stat st; assert(!lstat(argv[2],&st));
        printf("{\"birth\":[%lld,%ld],\"access\":[%lld,%ld],\"modification\":[%lld,%ld]}\n",
            (long long)st.st_birthtimespec.tv_sec,st.st_birthtimespec.tv_nsec,
            (long long)st.st_atimespec.tv_sec,st.st_atimespec.tv_nsec,
            (long long)st.st_mtimespec.tv_sec,st.st_mtimespec.tv_nsec); return 0;
    }
    if (!strcmp(argv[1],"describe")) {
        assert(argc==4); OK(sfs_image_open_readonly(argv[2],"image.sfs",&image,&receipt));
        describe(argv[3]); OK(sfs_image_close(image,&receipt)); return 0;
    }
    if (!strcmp(argv[1],"seed")) {
        sfs_metadata_initial root = initial(S_IFDIR|0700), file = initial(S_IFREG|0640), link = initial(S_IFLNK|0700);
        sfs_inode id, symlink;
        OK(sfs_image_create_metadata_version(argv[2],"image.sfs",4*1024*1024,6,&root,&image,&receipt));
        OK(sfs_image_begin(image,&receipt));
        OK(sfs_image_add_metadata(image,1,"file",4,SFS_FILE,&file,&id,&receipt));
        OK(sfs_image_link(image,id,1,"alias",5,&receipt));
        OK(sfs_image_write(image,id,0,"original",8,&receipt));
        OK(sfs_image_write(image,id,8192,"TAIL",4,&receipt));
        const unsigned char value[] = {0,255,3,0,128};
        OK(sfs_image_set_xattr(image,id,"org.example/test",16,value,sizeof(value),&receipt));
        OK(sfs_image_set_xattr(image,id,"com.apple.ResourceFork",22,value,sizeof(value),&receipt));
        OK(sfs_image_symlink_metadata(image,1,"link",4,"file",4,&link,&symlink,&receipt));
        OK(sfs_image_commit(image,&receipt));
    } else {
        OK(sfs_image_open(argv[2],"image.sfs",&image,&receipt));
        if (!strcmp(argv[1],"write-path")) {
            assert(argc == 5); sfs_inode inode = path_inode(argv[3]);
            OK(sfs_image_begin(image,&receipt));
            OK(sfs_image_write(image,inode,0,argv[4],strlen(argv[4]),&receipt));
            OK(sfs_image_resize(image,inode,strlen(argv[4]),&receipt));
            OK(sfs_image_commit(image,&receipt));
        } else if (!strcmp(argv[1],"edit")) {
            sfs_inode id = lookup(0,"file").inode, newer;
            sfs_metadata_initial file = initial(S_IFREG|0600);
            OK(sfs_image_begin(image,&receipt));
            OK(sfs_image_write(image,id,0,"modified",8,&receipt));
            OK(sfs_image_resize(image,id,16384,&receipt));
            OK(sfs_image_set_xattr(image,id,"org.example/test",16,"new",3,&receipt));
            OK(sfs_image_add_metadata(image,1,"newer",5,SFS_FILE,&file,&newer,&receipt));
            OK(sfs_image_unlink_expected(image,1,"newer",5,newer,&receipt));
            OK(sfs_image_commit(image,&receipt));
            printf("%llu\n",(unsigned long long)newer);
        } else if (!strcmp(argv[1],"verify")) {
            assert(argc == 5); sfs_view target;
            OK(sfs_image_snapshot_view(image,argv[3],strlen(argv[3]),&target,&receipt));
            sfs_inode id = lookup(target,"file").inode;
            assert(lookup(0,"file").inode == id && lookup(0,"alias").inode == id && lookup(target,"alias").inode == id);
            same_metadata(target,1); same_metadata(target,id);
            sfs_inode link = lookup(target,"link").inode; assert(lookup(0,"link").inode == link); same_metadata(target,link);
            unsigned char a[8196], b[8196]; size_t count;
            OK(sfs_image_read(image,target,id,0,a,sizeof(a),&count,&receipt)); assert(count == sizeof(a));
            OK(sfs_image_read(image,0,id,0,b,sizeof(b),&count,&receipt)); assert(count == sizeof(b) && !memcmp(a,b,sizeof(a)));
            assert(!memcmp(b,"original",8) && !memcmp(b+8192,"TAIL",4));
            for (unsigned i = 8; i < 8192; ++i) assert(!b[i]);
            const char *names[] = {"org.example/test","com.apple.ResourceFork"};
            for (unsigned i = 0; i < 2; ++i) {
                uint64_t length; OK(sfs_image_xattr_size(image,0,id,names[i],strlen(names[i]),&length,&receipt)); assert(length == 5);
                OK(sfs_image_read_xattr(image,target,id,names[i],strlen(names[i]),0,a,5,&count,&receipt)); assert(count == 5);
                OK(sfs_image_read_xattr(image,0,id,names[i],strlen(names[i]),0,b,5,&count,&receipt)); assert(count == 5 && !memcmp(a,b,5));
            }
            OK(sfs_image_readlink(image,0,link,b,sizeof(b),&count,&receipt)); assert(count == 4 && !memcmp(b,"file",4));
            sfs_inode after; sfs_metadata_initial file = initial(S_IFREG|0600);
            OK(sfs_image_begin(image,&receipt));
            OK(sfs_image_add_metadata(image,1,"after",5,SFS_FILE,&file,&after,&receipt));
            assert(after > strtoull(argv[4],NULL,10)); OK(sfs_image_commit(image,&receipt));
            sfs_verify_budget budget = {131072,536870912,536870912,50000000,33554432,1073741824,NULL,NULL};
            OK(sfs_image_verify(image,&budget,&receipt)); assert(receipt.coverage == SFS_COVERAGE_FULL_REACHABLE);
        } else if (!strcmp(argv[1],"verify-edited")) {
            assert(argc == 4); sfs_view view; unsigned char bytes[8]; size_t count;
            OK(sfs_image_snapshot_view(image,argv[3],strlen(argv[3]),&view,&receipt));
            sfs_entry e = lookup(view,"file"); assert(e.size == 16384);
            OK(sfs_image_read(image,view,e.inode,0,bytes,sizeof(bytes),&count,&receipt));
            assert(count == sizeof(bytes) && !memcmp(bytes,"modified",8));
        } else assert(0);
    }
    OK(sfs_image_close(image,&receipt)); return 0;
}
