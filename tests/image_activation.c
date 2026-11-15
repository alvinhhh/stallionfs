/* Fresh offline fixtures; syscall substitutions apply only to the core below. */
#include <CommonCrypto/CommonDigest.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include <stdatomic.h>
static int deny_writes, writes, fail_dup, fail_read, fail_alloc, fail_close;
static int close_order[16], close_count;
static ssize_t hooked_pread(int fd, void *p, size_t n, off_t at) {
    if (fail_read) { fail_read = 0; errno = EIO; return -1; } return pread(fd, p, n, at);
}
static ssize_t hooked_pwrite(int fd, const void *p, size_t n, off_t at) {
    writes++; assert(!deny_writes); return pwrite(fd, p, n, at);
}
static int hooked_ftruncate(int fd, off_t n) { writes++; assert(!deny_writes); return ftruncate(fd, n); }
static int hooked_openat(int fd, const char *p, int flags, ...) {
    mode_t mode = 0; if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); writes++; assert(!deny_writes); }
    return openat(fd, p, flags, mode);
}
static int hooked_fcntl(int fd, int cmd, ...) {
    int arg = 0; if (cmd == F_DUPFD_CLOEXEC) { va_list a; va_start(a, cmd); arg = va_arg(a, int); va_end(a);
        if (fail_dup) { fail_dup = 0; errno = EMFILE; return -1; } }
    if (cmd == F_FULLFSYNC) { writes++; assert(!deny_writes); }
    return fcntl(fd, cmd, arg);
}
static void *hooked_calloc(size_t n, size_t m) { if (fail_alloc) { fail_alloc=0; return NULL; } return calloc(n,m); }
static int hooked_close(int fd) {
    if (close_count < 16) close_order[close_count++] = fd;
    int r=close(fd); if (fail_close) { fail_close=0; errno=EIO; return -1; } return r;
}
#define pread hooked_pread
#define pwrite hooked_pwrite
#define ftruncate hooked_ftruncate
#define openat hooked_openat
#define fcntl hooked_fcntl
#define calloc hooked_calloc
#define close hooked_close
#include "../filesystem/image.c"
#undef pread
#undef pwrite
#undef ftruncate
#undef openat
#undef fcntl
#undef calloc
#undef close
extern char **environ;
static const char *executable;
static char image_path[4096];
static void competitor(int busy) {
    char *args[]={(char *)executable,"--compete",image_path,busy?"busy":"free",NULL};
    pid_t pid; assert(posix_spawn(&pid,executable,NULL,NULL,args,environ)==0);
    int status; assert(waitpid(pid,&status,0)==pid && WIFEXITED(status) && WEXITSTATUS(status)==0);
}
static sfs_image *fresh(const char *directory, unsigned index, sfs_result *anchor_out) {
    char name[32]; snprintf(name,sizeof(name),"image-%u",index);
    snprintf(image_path,sizeof(image_path),"%s/%s",directory,name);
    sfs_metadata_initial initial={0}; initial.mode=S_IFDIR|0700; initial.uid=geteuid(); initial.gid=getegid();
    sfs_image *h=NULL; sfs_result r;
    deny_writes=0; assert(sfs_image_create_metadata_version(directory,name,1048576,6,&initial,&h,&r)==SFS_OK);
    assert(sfs_image_close(h,&r)==SFS_OK); deny_writes=1; writes=0;
    assert(sfs_image_open_pending(directory,name,&h,anchor_out)==SFS_OK); return h;
}
static void denied(sfs_image *h) {
    sfs_result r; sfs_inode inode; sfs_view view; sfs_verify_budget b=sfs_image_seek_budget();
#define DENY(call) assert((call)==SFS_STATE)
    DENY(sfs_image_begin(h,&r)); DENY(sfs_image_abort(h,&r)); DENY(sfs_image_commit(h,&r));
    DENY(sfs_image_add(h,1,"x",1,SFS_FILE,&inode,&r)); DENY(sfs_image_remove(h,2,&r));
    DENY(sfs_image_rename(h,2,1,"y",1,&r)); DENY(sfs_image_write(h,2,0,"x",1,&r));
    DENY(sfs_image_resize(h,2,0,&r)); DENY(sfs_image_snapshot(h,"s",1,&view,&r));
    DENY(sfs_image_prepare_restore(h,1,"s",1,&b,&view,&r));
    DENY(sfs_image_pin_configure(h,4,65536,&r)); DENY(sfs_image_verify(h,&b,&r));
#undef DENY
    assert(!writes);
}
int main(int argc,char **argv) {
    if(argc==4 && !strcmp(argv[1],"--compete")) {
        int fd=open(argv[2],O_RDONLY|O_CLOEXEC); assert(fd>=0);
        int r=flock(fd,LOCK_EX|LOCK_NB); if(!strcmp(argv[3],"busy")) assert(r<0 && errno==EWOULDBLOCK); else assert(!r);
        assert(!close(fd)); return 0;
    }
    assert(argc==2); executable=argv[0]; const char *directory=argv[1];
    int parent=open(directory,O_RDONLY|O_DIRECTORY|O_CLOEXEC); assert(parent>=0);
    for(unsigned test=0;test<14;test++) {
        sfs_result anchor,r; sfs_image *h=fresh(directory,test,&anchor); denied(h); competitor(1);
        int candidate=open(image_path,O_RDWR|O_CLOEXEC); assert(candidate>=0);
        int cleanup=0; enum sfs_status status;
        if(test==1) anchor.generation++;
        if(test==2) { assert(!close(candidate)); candidate=open(image_path,O_RDONLY|O_CLOEXEC); }
        if(test==3) assert(!fchmod(candidate,0644));
        if(test==4) assert(!ftruncate(candidate,(off_t)anchor.physical_end+4096));
        if(test==5) fail_dup=1;
        if(test==6) fail_read=1;
        if(test==7 || test==8) fail_alloc=1;
        if(test==8) fail_close=1;
        if(test==9) { unsigned char byte; assert(pread(candidate,&byte,1,128)==1); byte^=1; assert(pwrite(candidate,&byte,1,128)==1); }
        if(test==10) h->poisoned=1;
        if(test==11) h->transaction=1;
        if(test==12 || test==13) {
            assert(sfs_image_close(h,&r)==SFS_OK);
            const char *name=strrchr(image_path,'/')+1;
            assert((test==12 ? sfs_image_open_readonly(directory,name,&h,&r) : sfs_image_open(directory,name,&h,&r))==SFS_OK);
        }
        status=sfs_image_activate_pending(h,parent,candidate,&anchor,&cleanup,&r);
        if(test==0) {
            assert(status==SFS_OK); assert(!writes); assert(h->lock_fd>=0); competitor(1);
            assert(!close(candidate)); candidate=-1; competitor(1);
            assert(sfs_image_activate_pending(h,parent,h->fd,&anchor,&cleanup,&r)==SFS_STATE);
            deny_writes=0; assert(sfs_image_begin(h,&r)==SFS_OK); sfs_inode inode;
            assert(sfs_image_add(h,1,"file",4,SFS_FILE,&inode,&r)==SFS_OK);
            assert(sfs_image_write(h,inode,0,"value",5,&r)==SFS_OK); assert(sfs_image_commit(h,&r)==SFS_OK); competitor(1);
        } else {
            assert(status!=SFS_OK && !writes); competitor(1);
            if(test==7 || test==8) assert(status==SFS_NOMEM && r.system_errno==ENOMEM);
            if(test==8) { assert(cleanup==EIO && h->phase==SFS_PHASE_CLOSE); assert(sfs_image_begin(h,&r)==SFS_POISONED && r.phase==SFS_PHASE_CLOSE); }
        }
        if(candidate>=0) assert(!close(candidate)); competitor(1);
        int lock_owner=h->lock_fd>=0?h->lock_fd:h->fd; close_count=0;
        assert(sfs_image_close(h,&r)==SFS_OK); if(test<12) assert(close_order[close_count-1]==lock_owner); competitor(0);
    }
    assert(!close(parent)); puts("PASS pending activation, descriptor lifetime, refusal and cleanup"); return 0;
}
