#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>

static int ready_fd=-1, release_fd=-1, hold_controller=1;
static pid_t fixture_child=-1;
static struct timespec frozen_monotonic;
static int clock_frozen;
static ssize_t fixture_write(int, const void *, size_t);
static pid_t fixture_fork(void);
static int fixture_clock_gettime(clockid_t, struct timespec *);
#define write fixture_write
#define fork fixture_fork
#define clock_gettime fixture_clock_gettime
#define main original_main
#define SFS_TEST_FAULT 6
#define SFS_DEADLINE_MS 100
#include "../filesystem/fskit/maintenance_native.c"
#undef write
#undef fork
#undef main
#undef clock_gettime

static int fixture_clock_gettime(clockid_t which,struct timespec *value) {
    int result=clock_gettime(which,value);
    if(!result && which==CLOCK_MONOTONIC && hold_controller) {
        if(!clock_frozen) { frozen_monotonic=*value; clock_frozen=1; }
        *value=frozen_monotonic;
    }
    return result;
}

static int exact(pid_t pid, struct kinfo_proc *info) {
    int mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,pid}; size_t bytes=sizeof *info;
    memset(info,0,sizeof *info);
    if(sysctl(mib,4,info,&bytes,NULL,0)) return -1;
    return bytes==sizeof *info && info->kp_proc.p_pid==pid;
}
static pid_t fixture_fork(void) { pid_t pid=fork(); if(pid>0) fixture_child=pid; return pid; }
static ssize_t fixture_write(int fd,const void *data,size_t bytes) {
    if(fd==1 && bytes==11 && !memcmp(data,"{\"partial\":",11)) {
        if(fcntl(ready_fd,F_GETFD)!=-1 || errno!=EBADF ||
           fcntl(release_fd,F_GETFD)!=-1 || errno!=EBADF) _exit(126);
    }
    ssize_t result=write(fd,data,bytes);
    if(fd>=3 && bytes==11 && result==11 && !memcmp(data,"{\"partial\":",11)) {
        struct kinfo_proc info;
        if(exact(fixture_child,&info)!=1 || info.kp_eproc.e_ppid!=getpid() ||
           info.kp_eproc.e_ucred.cr_uid!=getuid() || info.kp_proc.p_stat==SZOMB) _exit(122);
        char record[512];
        int n=snprintf(record,sizeof record,"{\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"start_sec\":%lld,\"start_usec\":%d,\"status\":%d}\n",
            fixture_child,getpid(),getuid(),(long long)info.kp_proc.p_starttime.tv_sec,
            info.kp_proc.p_starttime.tv_usec,info.kp_proc.p_stat);
        if(n<=0 || n>=(int)sizeof record || write(ready_fd,record,(size_t)n)!=n) _exit(122);
        if(hold_controller) {
            struct pollfd wait={release_fd,POLLIN|POLLHUP,0};
            int polled=poll(&wait,1,800); char release=0;
            if(polled==0) _exit(123);
            if(polled<0) _exit(122);
            ssize_t got=read(release_fd,&release,1);
            if(got==0) _exit(124);
            if(got!=1 || release!='R') _exit(125);
            hold_controller=0;
        }
    }
    return result;
}
static int number(const char *text,int minimum) {
    if(!text || !*text || strlen(text)>10) return -1;
    for(const char *p=text;*p;p++) if(*p<'0' || *p>'9') return -1;
    char *end; errno=0; long value=strtol(text,&end,10);
    return errno || *end || value<minimum || value>INT_MAX ? -1 : (int)value;
}
int main(int argc,char **argv) {
    if(argc==3 && !strcmp(argv[1],"exact")) {
        int selected=number(argv[2],2);
        if(selected<0) return 2;
        struct kinfo_proc info; int found=exact((pid_t)selected,&info);
        if(found<0) return 2;
        if(!found) { puts("null"); return 0; }
        printf("{\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"start_sec\":%lld,\"start_usec\":%d,\"status\":%d}\n",
            info.kp_proc.p_pid,info.kp_eproc.e_ppid,info.kp_eproc.e_ucred.cr_uid,
            (long long)info.kp_proc.p_starttime.tv_sec,info.kp_proc.p_starttime.tv_usec,info.kp_proc.p_stat);
        return 0;
    }
    if(argc!=5) return 2;
    ready_fd=number(argv[1],3); release_fd=number(argv[2],3);
    if(ready_fd<0 || release_fd<0 || ready_fd==release_fd ||
       (fcntl(ready_fd,F_GETFL)&O_ACCMODE)!=O_WRONLY ||
       (fcntl(release_fd,F_GETFL)&O_ACCMODE)!=O_RDONLY) return 2;
    return original_main(argc-2,argv+2);
}
