/* Compile only _tree.c with linkat/fchflags symbol substitutions. */
#include "_tree.h"
#include <assert.h>
#include <copyfile.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/attr.h>
#include <sys/unistd.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mode, copying;
static atomic_int copied_inodes;
static atomic_int clears, restores, links, metadata_calls;
static pthread_t caller;
static int cancel_after_metadata(void *context) {
    (void)context; assert(pthread_equal(pthread_self(),caller));
    return mode==10 && atomic_load(&metadata_calls)>0;
}
int stallion_test_fcopyfile(int from,int to,copyfile_state_t state,copyfile_flags_t flags) {
    int result=fcopyfile(from,to,state,flags);
    if(!result) {
        struct stat info; assert(fstat(from,&info)==0);
        if(!copying || S_ISDIR(info.st_mode)) metadata_calls++;
        if(copying && !S_ISDIR(info.st_mode)) copied_inodes++;
    }
    return result;
}
static struct stat source_identity;
int stallion_test_fstat(int fd, struct stat *st) __DARWIN_INODE64(stallion_test_fstat);
int stallion_test_fstat(int fd, struct stat *st) {
    int result = fstat(fd, st);
    if (!result && links && (S_ISREG(st->st_mode) || S_ISLNK(st->st_mode))) {
        int source = st->st_dev == source_identity.st_dev && st->st_ino == source_identity.st_ino;
        if (mode == 5 && source) st->st_size ^= 1; /* Simulated source change after link. */
        if (mode == 6 && !source) st->st_ino ^= 1; /* Simulated replaced destination. */
    }
    return result;
}
int stallion_test_linkat(int from, const char *name, int to, const char *alias, int flags) {
    links++;
    if (mode == 1 || mode == 4) { errno = ENOSPC; return -1; }
    return linkat(from, name, to, alias, flags);
}
int stallion_test_fchflags(int fd, unsigned flags) {
    if (flags & (UF_IMMUTABLE | UF_APPEND)) {
        restores++;
        if (mode == 3 || mode == 4) { errno = EIO; return -1; }
    } else {
        clears++;
        if (mode == 2) { errno = EACCES; return -1; }
    }
    return fchflags(fd, flags);
}
/* Simulate another same-UID actor replacing the destination leaf. This test
 * owns both names and changes flags only to construct that race deterministically. */
static void replace_leaf(int parent, const char *name) {
    struct stat info; assert(fstatat(parent,name,&info,AT_SYMLINK_NOFOLLOW)==0);
    int fd=openat(parent,name,O_RDONLY|O_CLOEXEC|(S_ISLNK(info.st_mode)?O_SYMLINK:O_NOFOLLOW)); assert(fd>=0);
    assert(fchflags(fd,info.st_flags & ~(UF_IMMUTABLE|UF_APPEND))==0);
    assert(renameat(parent,name,parent,"retained-original")==0);
    assert(fchflags(fd,info.st_flags)==0); assert(close(fd)==0);
    if(S_ISLNK(info.st_mode)) assert(symlinkat("replacement-target",parent,name)==0);
    else { fd=openat(parent,name,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(fd>=0); assert(write(fd,"replacement",11)==11); assert(close(fd)==0); }
}
int stallion_test_openat(int parent,const char *name,int flags,...) {
    mode_t permissions=0;
    if(flags & O_CREAT) { va_list args; va_start(args,flags); permissions=(mode_t)va_arg(args,int); va_end(args); }
    int fd=openat(parent,name,flags,permissions);
    struct stat info;
    if(fd>=0 && (!copying || copied_inodes) && mode>=7 && mode<=9 && fstat(fd,&info)==0 && (S_ISREG(info.st_mode)||S_ISLNK(info.st_mode)) &&
       !(info.st_dev==source_identity.st_dev && info.st_ino==source_identity.st_ino)) {
        assert(close(fd)==0);
        if(mode==8) replace_leaf(parent,name);
        errno=EACCES; return -1;
    }
    return fd;
}
int stallion_test_setattrlistat(int parent,const char *name,void *attributes,void *buffer,size_t size,uint32_t options) {
    struct attrlist *attrs=attributes;
    assert(size==sizeof(uint32_t) && attrs->commonattr==ATTR_CMN_FLAGS && options==FSOPT_NOFOLLOW);
    uint32_t flags; memcpy(&flags,buffer,sizeof(flags));
    if(flags & (UF_IMMUTABLE|UF_APPEND)) restores++; else clears++;
    int result=setattrlistat(parent,name,attrs,buffer,size,options);
    if(!result && mode==9 && !(flags & (UF_IMMUTABLE|UF_APPEND))) replace_leaf(parent,name);
    return result;
}
static int descriptor_count(void) {
    int count=0;
    for(int fd=0;fd<1024;fd++) if(fcntl(fd,F_GETFD)>=0) count++;
    return count;
}
static int leaf_open(const char *path, int symlink) {
    return open(path,O_RDONLY|O_NONBLOCK|O_CLOEXEC|(symlink?O_SYMLINK:O_NOFOLLOW));
}
static void clear_owned(const char *path, int symlink) {
    int fd=leaf_open(path,symlink);
    if(fd<0) { assert(errno==ENOENT); return; }
    struct stat st; assert(fstat(fd,&st)==0);
    assert(fchflags(fd,st.st_flags & ~(UF_IMMUTABLE|UF_APPEND))==0);
    assert(close(fd)==0);
}
int main(int argc, char **argv) {
    assert(argc==2);
    unsigned sequence=0;
    int operations=1;
    if (__builtin_available(macOS 13.0, *)) operations=2;
    for(copying=0;copying<operations;copying++) for(int symlink=0;symlink<2;symlink++) for(int append=0;append<2;append++)
    for(unsigned workers=1;workers<=4;workers+=3) for(mode=0;mode<11;mode++) {
        char source[PATH_MAX],target[PATH_MAX],a[PATH_MAX],b[PATH_MAX],first[PATH_MAX],second[PATH_MAX],error_path[PATH_MAX];
        assert(snprintf(source,sizeof(source),"%s/hardlink-source-%u",argv[1],sequence)<(int)sizeof(source));
        assert(snprintf(target,sizeof(target),"%s/hardlink-target-%u",argv[1],sequence++)<(int)sizeof(target));
        assert(mkdir(source,0700)==0);
        assert(snprintf(a,sizeof(a),"%s/a",source)<(int)sizeof(a)); assert(mkdir(a,0700)==0);
        assert(snprintf(b,sizeof(b),"%s/b",source)<(int)sizeof(b)); assert(mkdir(b,0700)==0);
        assert(snprintf(first,sizeof(first),"%s/leaf",a)<(int)sizeof(first));
        assert(snprintf(second,sizeof(second),"%s/leaf",b)<(int)sizeof(second));
        if(symlink) assert(symlinkat("absent-target",AT_FDCWD,first)==0);
        else { int fd=open(first,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600); assert(fd>=0); assert(write(fd,"payload",7)==7); assert(close(fd)==0); }
        assert(linkat(AT_FDCWD,first,AT_FDCWD,second,0)==0);
        int fd=leaf_open(first,symlink); assert(fd>=0);
        unsigned flags=append?UF_APPEND:UF_IMMUTABLE;
        assert(fchflags(fd,flags)==0); struct stat original,after; assert(fstat(fd,&original)==0); assert(close(fd)==0);
        source_identity=original;
        int descriptors=descriptor_count(); clears=restores=links=metadata_calls=copied_inodes=0; caller=pthread_self();
        int result=(copying?stallion_copy:stallion_clone)(source,target,workers,cancel_after_metadata,NULL,error_path,sizeof(error_path)); int error=errno;
        assert(descriptor_count()==descriptors);
        assert(lstat(first,&after)==0 && after.st_ino==original.st_ino && after.st_flags==flags && after.st_nlink==2);
        if(mode==0 || mode==7) { assert(result==0 && clears==1 && restores==1 && links==1); }
        else {
            assert(result==-1);
            assert(error==(mode==2?EACCES:mode==3?EIO:mode==10?EINTR:mode>=5?ESTALE:ENOSPC));
            assert(clears==(mode==8?0:1) && restores==((mode==2 || mode==8 || mode==9)?0:1));
            if(mode==3 || mode==4) assert(strstr(error_path,"destination flag restoration failed: errno 5"));
            if(mode==9) assert(strstr(error_path,"destination flag restoration failed: errno 70"));
            if(mode==8 || mode==9) assert(links==0);
            if(mode==10) assert(metadata_calls==1 && links==1);
        }
        char copy_a[PATH_MAX],copy_b[PATH_MAX];
        assert(snprintf(copy_a,sizeof(copy_a),"%s/a/leaf",target)<(int)sizeof(copy_a));
        assert(snprintf(copy_b,sizeof(copy_b),"%s/b/leaf",target)<(int)sizeof(copy_b));
        for(int i=0;i<2;i++) {
            struct stat st;
            if(lstat(i?copy_b:copy_a,&st)==0) {
                assert(st.st_ino!=original.st_ino);
                assert(st.st_flags==((mode==3 || mode==4 || mode==8 || mode==9)?0:flags));
            } else assert(errno==ENOENT);
        }
        if(mode==0 || mode==7) { struct stat x,y; assert(lstat(copy_a,&x)==0 && lstat(copy_b,&y)==0 && x.st_ino==y.st_ino); }
        if(mode==8 || mode==9) {
            unsigned found=0;
            for(int i=0;i<2;i++) {
                char retained[PATH_MAX]; assert(snprintf(retained,sizeof(retained),"%s/%s/retained-original",target,i?"b":"a")<(int)sizeof(retained));
                struct stat st;
                if(lstat(retained,&st)==0) { found++; assert(st.st_flags==(mode==8?flags:0)); clear_owned(retained,symlink); }
                else assert(errno==ENOENT);
            }
            assert(found==1);
        }
        clear_owned(first,symlink); clear_owned(copy_a,symlink); clear_owned(copy_b,symlink);
        assert(stallion_delete(source,1,0,workers,NULL,NULL,error_path,sizeof(error_path))==0);
        assert(stallion_delete(target,1,0,workers,NULL,NULL,error_path,sizeof(error_path))==0);
        assert(descriptor_count()==descriptors);
    }
    return 0;
}
