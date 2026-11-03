#include "_native_import.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/xattr.h>
#include <unistd.h>

#define CELL UINT64_C(4096)
#define NONE UINT64_MAX
/* These are private scratch records, never an image or recovery format. A
 * sequential inventory bounds memory independently of entry/link counts. */
typedef struct {
    struct stat captured;
    uint64_t parent, depth, first, inode, attributes, attributes_end, ranges, range_count;
    uint32_t length;
    char name[256];
} record;
typedef struct { uint64_t start, end; } range;
typedef struct { uint64_t length; uint32_t name_length; } attribute;
typedef struct {
    const sfs_import_options *options;
    sfs_import_report *report;
    int root, destination, stage, inventory, values, ranges, names;
    uint64_t count, value_end, range_end, current;
    sfs_image *image;
} importer;

static int fail(importer *c, const char *reason, int error) {
    if (!c->report->reason) { c->report->reason = reason; c->report->local_error = error; c->report->failed_record = c->current; }
    return -1;
}
static int poll(importer *c) {
    return c->options->cancelled && c->options->cancelled(c->options->context)
        ? fail(c, "verification-incomplete", ECANCELED) : 0;
}
static int add_size(importer *c, uint64_t a, uint64_t b, uint64_t *out) {
    if (a > INT64_MAX || b > (uint64_t)INT64_MAX - a) return fail(c, "representation-limit", EOVERFLOW);
    *out = a + b; return 0;
}
static int transfer(importer *c, int fd, void *data, size_t size, uint64_t offset, int writing) {
    uint64_t end; if (add_size(c, offset, size, &end)) return -1;
    size_t done = 0;
    while (done < size) {
        if (poll(c)) return -1;
        ssize_t n = writing ? pwrite(fd, (char *)data + done, size - done, (off_t)(offset + done))
                            : pread(fd, (char *)data + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return fail(c, "io", n < 0 ? errno : EIO);
        done += (size_t)n;
    }
    return 0;
}
static int get_record(importer *c, uint64_t index, record *r) {
    if (index >= c->count || index > INT64_MAX / sizeof(*r)) return fail(c, "source-changed", EINVAL);
    return transfer(c, c->inventory, r, sizeof(*r), index * sizeof(*r), 0);
}
static int put_record(importer *c, uint64_t index, record *r) {
    if (index > INT64_MAX / sizeof(*r)) return fail(c, "representation-limit", EOVERFLOW);
    return transfer(c, c->inventory, r, sizeof(*r), index * sizeof(*r), 1);
}
static int same_time(struct timespec a, struct timespec b) { return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec; }
static int stable_stat(const struct stat *a, const struct stat *b) {
    /* Reading this private input may update atime. Preserve its pre-read value,
     * but do not misclassify that expected access as source mutation. */
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_flags == b->st_flags &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        same_time(a->st_birthtimespec,b->st_birthtimespec) && same_time(a->st_mtimespec,b->st_mtimespec) &&
        same_time(a->st_ctimespec,b->st_ctimespec);
}
static int close_fd(importer *c, int fd) {
    if (fd < 0 || !close(fd)) return 0;
    int error = errno; if (!c->report->cleanup_error) c->report->cleanup_error = error;
    return fail(c, "io", error);
}
static int check_fd(importer *c, int fd, const record *r) {
    struct stat st;
    if (fstat(fd, &st)) return fail(c, "io", errno);
    if (!stable_stat(&r->captured, &st)) return fail(c, "source-changed", ESTALE);
    return 0;
}
static int open_absolute(importer *c, const char *path) {
    if (!path || path[0] != '/') { fail(c, "unsafe-path", EINVAL); return -1; }
    int fd = open("/", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (fd < 0) { fail(c, "io", errno); return -1; }
    const char *p = path + 1;
    while (*p) {
        const char *end = strchr(p, '/'); size_t n = end ? (size_t)(end-p) : strlen(p);
        if (!n || n > 255 || (n == 1 && *p == '.') || (n == 2 && p[0] == '.' && p[1] == '.')) {
            fail(c,"unsafe-path",EINVAL); close_fd(c,fd); return -1;
        }
        char name[256]; memcpy(name,p,n); name[n]=0;
        int next = openat(fd,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
        if (next < 0) { fail(c,"unsafe-path",errno); close_fd(c,fd); return -1; }
        if (close_fd(c,fd)) { close_fd(c,next); return -1; }
        fd=next; p = end ? end+1 : p+n;
    }
    return fd;
}
static int identity_fd(importer *c, int fd, const uint64_t pair[2], int private) {
    struct stat st;
    if (fstat(fd,&st)) return fail(c,"io",errno);
    if (!S_ISDIR(st.st_mode) || (uint64_t)st.st_dev != pair[0] || (uint64_t)st.st_ino != pair[1] ||
        (private && (st.st_uid != geteuid() || (st.st_mode & 0777) != 0700))) return fail(c,"unsafe-path",ESTALE);
    return 0;
}
/* Reopen one path using record-parent offsets and one held directory at a time.
 * No depth-sized path allocation, unbounded descriptor stack, or followed link. */
static int open_record(importer *c, uint64_t target) {
    int fd = fcntl(c->root,F_DUPFD_CLOEXEC,0);
    if (fd < 0) { fail(c,"io",errno); return -1; }
    record r;
    if (get_record(c,0,&r) || check_fd(c,fd,&r)) goto failed;
    uint64_t current=0;
    while (current != target) {
        uint64_t child=target, steps=0;
        for (;;) {
            if (get_record(c,child,&r)) goto failed;
            if (r.parent == current) break;
            if (r.parent >= child || ++steps > c->count) { fail(c,"source-changed",ESTALE); goto failed; }
            child=r.parent;
        }
        struct stat named;
        if (fstatat(fd,r.name,&named,AT_SYMLINK_NOFOLLOW)) { fail(c,"io",errno); goto failed; }
        if (!stable_stat(&r.captured,&named)) { fail(c,"source-changed",ESTALE); goto failed; }
        int flags=O_RDONLY|O_CLOEXEC|O_NONBLOCK;
        flags|=S_ISLNK(r.captured.st_mode) ? O_SYMLINK : O_NOFOLLOW;
        if (S_ISDIR(r.captured.st_mode)) flags|=O_DIRECTORY;
        int next=openat(fd,r.name,flags);
        if (next < 0) { fail(c,"io",errno); goto failed; }
        int failed=check_fd(c,next,&r);
        if (close_fd(c,fd)) failed=1;
        if (failed) { close_fd(c,next); return -1; }
        fd=next; current=child;
    }
    return fd;
failed:
    close_fd(c,fd); return -1;
}
static int supported_stat(importer *c, const struct stat *st) {
    if (!(S_ISREG(st->st_mode)||S_ISDIR(st->st_mode)||S_ISLNK(st->st_mode))) return fail(c,"unsupported-kind",ENOTSUP);
    if ((uint64_t)st->st_dev != c->options->source_identity[0]) return fail(c,"unsafe-path",EXDEV);
    if (st->st_flags & ~SFS_FLAGS_SUPPORTED) return fail(c,"unsupported-metadata",ENOTSUP);
    if (st->st_size < 0 || (S_ISREG(st->st_mode) && (uint64_t)st->st_size > SFS_FILE_MAX)) return fail(c,"representation-limit",EOVERFLOW);
    if ((st->st_mode & ~(S_IFMT|07777)) || st->st_birthtimespec.tv_nsec < 0 || st->st_birthtimespec.tv_nsec >= 1000000000 ||
        st->st_atimespec.tv_nsec < 0 || st->st_atimespec.tv_nsec >= 1000000000 ||
        st->st_mtimespec.tv_nsec < 0 || st->st_mtimespec.tv_nsec >= 1000000000) return fail(c,"unsupported-metadata",EINVAL);
    return 0;
}
static int empty_acl(importer *c,int fd) {
    errno=0; acl_t acl=acl_get_fd_np(fd,ACL_TYPE_EXTENDED);
    if (!acl && errno==ENOENT) acl=acl_init(0);
    if (!acl) return fail(c,"unsupported-acl",errno ? errno : EIO);
    acl_entry_t entry; int error=0,empty=0;
    if (acl_valid(acl)) error=errno ? errno : EIO;
    if (!error) { errno=0; if (acl_get_entry(acl,ACL_FIRST_ENTRY,&entry)) {
        if (errno==EINVAL) empty=1; else error=errno ? errno : EIO;
    } }
    if (acl_free(acl) && !error) error=errno ? errno : EIO;
    if (error) return fail(c,"unsupported-acl",error);
    return empty ? 0 : fail(c,"unsupported-acl",ENOTSUP);
}
/* Darwin enumerates all names in one call. Back that address range with a
 * retained scratch mapping, not an in-memory whole-tree/name inventory.
 * Values remain one allocation at a time; mapping/address-space and paging
 * failures are operational failures, never a new supported-size class. */
static int names_digest(importer *c,const char *names,size_t length,unsigned char out[32]) {
    CC_SHA256_CTX hash; CC_SHA256_Init(&hash);
    while (length) { if (poll(c)) return -1; CC_LONG n=length>65536 ? 65536 : (CC_LONG)length; CC_SHA256_Update(&hash,names,n); names+=n; length-=n; }
    CC_SHA256_Final(out,&hash); return 0;
}
static int attributes(importer *c,int fd,record *r,int capture,int importing) {
    ssize_t length=flistxattr(fd,NULL,0,XATTR_SHOWCOMPRESSION);
    if (length < 0) return fail(c,"io",errno);
    size_t mapped=length ? (size_t)length : 1;
    if (ftruncate(c->names,(off_t)mapped)) return fail(c,"io",errno);
    char *names=mmap(NULL,mapped,PROT_READ|PROT_WRITE,MAP_SHARED,c->names,0);
    if (names==MAP_FAILED) return fail(c,"io",errno);
    if (mapped>c->report->xattr_names_scratch_high_water) c->report->xattr_names_scratch_high_water=mapped;
    int failed=0;
    if (flistxattr(fd,names,(size_t)length,XATTR_SHOWCOMPRESSION)!=length) { fail(c,"source-changed",errno ? errno : ESTALE); failed=1; goto done; }
    uint64_t offset=capture ? c->value_end : r->attributes;
    if (capture) r->attributes=offset;
    for (size_t at=0; at<(size_t)length;) {
        char *name=names+at; size_t n=strnlen(name,(size_t)length-at);
        if (!n || n>255 || n==(size_t)length-at) { fail(c,"representation-limit",EOVERFLOW); failed=1; break; }
        if (!strcmp(name,"com.apple.decmpfs")) {
            fail(c,"unsupported-metadata",ENOTSUP); failed=1; break;
        }
        ssize_t size=fgetxattr(fd,name,NULL,0,0,XATTR_SHOWCOMPRESSION);
        if (size<0) { fail(c,"io",errno); failed=1; break; }
        if ((uint64_t)size>SFS_FILE_MAX || (uint64_t)size>SIZE_MAX || (uint64_t)size>SSIZE_MAX) { fail(c,"representation-limit",EOVERFLOW); failed=1; break; }
        void *value=malloc(size ? (size_t)size : 1);
        if (!value) { fail(c,"io",ENOMEM); failed=1; break; }
        if ((uint64_t)size>c->report->xattr_memory_high_water) c->report->xattr_memory_high_water=(uint64_t)size;
        if (fgetxattr(fd,name,value,(size_t)size,0,XATTR_SHOWCOMPRESSION)!=size) { fail(c,"source-changed",errno ? errno : ESTALE); failed=1; }
        attribute a={.length=(uint64_t)size,.name_length=(uint32_t)n};
        if (!failed && capture) {
            if (transfer(c,c->values,&a,sizeof(a),offset,1) || add_size(c,offset,sizeof(a),&offset) ||
                transfer(c,c->values,name,n,offset,1) || add_size(c,offset,n,&offset) ||
                transfer(c,c->values,value,(size_t)size,offset,1) || add_size(c,offset,(uint64_t)size,&offset)) failed=1;
        } else if (!failed) {
            attribute saved; char saved_name[256];
            if (transfer(c,c->values,&saved,sizeof(saved),offset,0) || add_size(c,offset,sizeof(saved),&offset) ||
                saved.name_length!=n || saved.length!=(uint64_t)size || transfer(c,c->values,saved_name,n,offset,0) ||
                memcmp(name,saved_name,n) || add_size(c,offset,n,&offset)) { fail(c,"source-changed",ESTALE); failed=1; }
            unsigned char block[65536]; uint64_t pos=0;
            while (!failed && pos<(uint64_t)size) {
                size_t take=(uint64_t)size-pos>sizeof(block) ? sizeof(block) : (size_t)((uint64_t)size-pos);
                if (transfer(c,c->values,block,take,offset+pos,0) || memcmp(block,(char *)value+pos,take)) { fail(c,"source-changed",ESTALE); failed=1; }
                pos+=take;
            }
            if (!failed && add_size(c,offset,(uint64_t)size,&offset)) failed=1;
        }
        if (!failed && importing && sfs_image_set_xattr(c->image,r->inode,name,n,value,(size_t)size,&c->report->original)!=SFS_OK) { fail(c,"core",0); failed=1; }
        free(value); if (failed) break; at+=n+1;
    }
    if (!failed && capture) { c->value_end=offset; r->attributes_end=offset; }
    if (!failed && !capture && offset!=r->attributes_end) { fail(c,"source-changed",ESTALE); failed=1; }
    if (!failed) {
        unsigned char before[32],after[32];
        if (names_digest(c,names,(size_t)length,before)) { failed=1; goto done; }
        if (flistxattr(fd,names,(size_t)length,XATTR_SHOWCOMPRESSION)!=length) { fail(c,"source-changed",errno ? errno : ESTALE); failed=1; }
        else { if (names_digest(c,names,(size_t)length,after)) { failed=1; goto done; } if (memcmp(before,after,32)) { fail(c,"source-changed",ESTALE); failed=1; } }
    }
done:
    if (munmap(names,mapped)) { if (!c->report->cleanup_error) c->report->cleanup_error=errno; fail(c,"io",errno); failed=1; }
    return failed ? -1 : 0;
}
static int sparse_ranges(importer *c,int fd,record *r,int capture) {
    uint64_t pos=0,count=0,offset=capture ? c->range_end : r->ranges, size=(uint64_t)r->captured.st_size;
    if (capture) r->ranges=offset;
    while (pos<size) {
        if (poll(c)) return -1;
        errno=0; off_t data=lseek(fd,(off_t)pos,SEEK_DATA);
        if (data<0 && errno==ENXIO) break;
        if (data<0) return fail(c,"unsupported-sparse-layout",errno);
        off_t hole=lseek(fd,data,SEEK_HOLE);
        if (hole<0) return fail(c,"unsupported-sparse-layout",errno);
        if ((uint64_t)data<pos || (uint64_t)data>=size || hole<=data || (uint64_t)hole>size ||
            (uint64_t)data % CELL || ((uint64_t)hole!=size && (uint64_t)hole % CELL)) return fail(c,"unsupported-sparse-layout",ENOTSUP);
        range now={(uint64_t)data,(uint64_t)hole},saved;
        if (capture) { if (transfer(c,c->ranges,&now,sizeof(now),offset,1)) return -1; }
        else if (count>=r->range_count || transfer(c,c->ranges,&saved,sizeof(saved),offset,0) || saved.start!=now.start || saved.end!=now.end) return fail(c,"source-changed",ESTALE);
        if (add_size(c,offset,sizeof(now),&offset)) return -1;
        count++; pos=(uint64_t)hole;
    }
    if (capture) { c->range_end=offset; r->range_count=count; }
    else if (count!=r->range_count) return fail(c,"source-changed",ESTALE);
    return 0;
}
/* A repeated directory scan selects one exact raw-byte name at a time. It uses
 * constant memory even for a very wide directory; membership is rechecked. */
static int next_name(importer *c,int fd,const char *after,char out[256],int *found) {
    int duplicate=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (duplicate<0) return fail(c,"io",errno);
    DIR *dir=fdopendir(duplicate);
    if (!dir) { int error=errno; close_fd(c,duplicate); return fail(c,"io",error); }
    *found=0; errno=0; struct dirent *entry;
    while ((entry=readdir(dir))) {
        if (poll(c)) break;
        const char *name=entry->d_name;
        if (!strcmp(name,".") || !strcmp(name,"..")) continue;
        size_t n=strlen(name);
        if (!n || n>255 || strchr(name,'/')) { fail(c,"representation-limit",EOVERFLOW); break; }
        if ((!after || strcmp(name,after)>0) && (!*found || strcmp(name,out)<0)) { memcpy(out,name,n+1); *found=1; }
        errno=0;
    }
    int error=errno;
    if (closedir(dir)) { if (!error) error=errno; if (!c->report->cleanup_error) c->report->cleanup_error=errno; }
    if (error) fail(c,"io",error);
    return c->report->reason ? -1 : 0;
}
static int read_target(importer *,const record *,char [4097],size_t *);
static int inventory(importer *c) {
    record root={.parent=NONE,.first=0};
    if (fstat(c->root,&root.captured)) return fail(c,"io",errno);
    if (supported_stat(c,&root.captured) || put_record(c,0,&root)) return -1;
    c->count=1;
    for (uint64_t i=0;i<c->count;i++) {
        c->current=i; record r; if (get_record(c,i,&r)) return -1;
        int fd=open_record(c,i); if (fd<0) return -1;
        int failed=empty_acl(c,fd) || attributes(c,fd,&r,1,0);
        if (!failed && S_ISREG(r.captured.st_mode)) failed=sparse_ranges(c,fd,&r,1);
        if (!failed && S_ISLNK(r.captured.st_mode)) {
            char target[4097]; size_t n=0;
            failed=read_target(c,&r,target,&n);
            /* Preserve exact target bytes; validate resolution after inventory. */
            if (!failed) { uint64_t end; r.ranges=c->value_end; r.range_count=(uint64_t)n;
                failed=transfer(c,c->values,target,(size_t)n,c->value_end,1) || add_size(c,c->value_end,(uint64_t)n,&end);
                if (!failed) c->value_end=end;
            }
        }
        if (!failed) failed=put_record(c,i,&r);
        if (!failed && S_ISDIR(r.captured.st_mode)) {
            char previous[256]={0},name[256]; int found;
            while (!(failed=next_name(c,fd,previous,name,&found)) && found) {
                if (i && !strcmp(name,".git")) { failed=fail(c,"unsafe-path",EINVAL); break; }
                record child={.parent=i,.depth=r.depth+1,.first=c->count,.length=(uint32_t)strlen(name)};
                memcpy(child.name,name,child.length+1);
                if (fstatat(fd,name,&child.captured,AT_SYMLINK_NOFOLLOW)) { failed=fail(c,"io",errno); break; }
                if (put_record(c,c->count,&child)) { failed=1; break; }
                uint64_t child_index=c->count++; c->current=child_index;
                if (supported_stat(c,&child.captured)) { failed=1; break; }
                for (uint64_t j=0;j<child_index;j++) {
                    record seen; if (get_record(c,j,&seen)) { failed=1; break; }
                    if (seen.captured.st_dev==child.captured.st_dev && seen.captured.st_ino==child.captured.st_ino) {
                        if (S_ISDIR(child.captured.st_mode) || !stable_stat(&seen.captured,&child.captured)) { failed=fail(c,"source-changed",ESTALE); break; }
                        child.first=seen.first; child.captured.st_atimespec=seen.captured.st_atimespec; break;
                    }
                }
                if (failed || put_record(c,child_index,&child)) { failed=1; break; }
                c->current=i; memcpy(previous,name,child.length+1);
            }
        }
        if (!failed) failed=check_fd(c,fd,&r);
        if (close_fd(c,fd)) failed=1;
        if (failed) return -1;
    }
    for (uint64_t i=0;i<c->count;i++) {
        c->current=i; record r; if (get_record(c,i,&r)) return -1;
        c->report->parent_steps=sfs_import_budget_add(c->report->parent_steps,r.depth,&c->report->budget_saturated);
        if (S_ISDIR(r.captured.st_mode)) continue;
        uint64_t links=0;
        for (uint64_t j=0;j<c->count;j++) { record other; if (get_record(c,j,&other)) return -1; if (other.first==r.first) links++; }
        if (links!=(uint64_t)r.captured.st_nlink) return fail(c,"external-hardlink",ENOTSUP);
    }
    c->report->entries=c->count;
    uint64_t bytes;
    if (add_size(c,c->count*sizeof(record),c->value_end,&bytes) || add_size(c,bytes,c->range_end,&bytes) || add_size(c,bytes,c->report->xattr_names_scratch_high_water,&bytes)) return -1;
    c->report->scratch_bytes=bytes;
    return 0;
}
/* Resolve relative link targets in the captured namespace. No target is opened
 * through the host filesystem, and every intermediate component must be an
 * inventoried directory or link while present. Missing components remain
 * lexical, matching Store validation of contained dangling targets. */
static int validate_link(importer *c,const record *link) {
    long limit=sysconf(_SC_SYMLOOP_MAX);
    if (limit<=0) return fail(c,"unsupported-metadata",errno ? errno : ENOTSUP);
    size_t length=(size_t)link->range_count;
    char *pending=malloc(length+1);
    if (!pending) return fail(c,"io",ENOMEM);
    if (transfer(c,c->values,pending,length,link->ranges,0)) { free(pending); return -1; }
    pending[length]=0; uint64_t parent=link->parent, missing_depth=0; long followed=1; int failed=0;
    while (*pending && !failed) {
        char *slash=strchr(pending,'/'); size_t n=slash ? (size_t)(slash-pending) : strlen(pending);
        char *rest=slash ? slash+1 : pending+n;
        if (!n || (n==1 && pending[0]=='.')) { memmove(pending,rest,strlen(rest)+1); continue; }
        if (n==2 && pending[0]=='.' && pending[1]=='.') {
            if (missing_depth) { missing_depth--; memmove(pending,rest,strlen(rest)+1); continue; }
            record node;
            if (!parent || get_record(c,parent,&node)) { failed=fail(c,"unsafe-path",EINVAL); break; }
            parent=node.parent; memmove(pending,rest,strlen(rest)+1); continue;
        }
        if (missing_depth) {
            if (missing_depth==UINT64_MAX) { failed=fail(c,"representation-limit",EOVERFLOW); break; }
            missing_depth++; memmove(pending,rest,strlen(rest)+1); continue;
        }
        uint64_t child=NONE; record node;
        for (uint64_t i=1;i<c->count;i++) {
            if (get_record(c,i,&node)) { failed=1; break; }
            if (node.parent==parent && node.length==n && !memcmp(node.name,pending,n)) { child=i; break; }
        }
        if (failed) break;
        if (child==NONE) { missing_depth=1; memmove(pending,rest,strlen(rest)+1); continue; }
        if (S_ISLNK(node.captured.st_mode)) {
            if (followed++>=limit) { failed=fail(c,"unsafe-path",ELOOP); break; }
            size_t tail=strlen(rest);
            if (node.range_count>SIZE_MAX-tail-2) { failed=fail(c,"representation-limit",EOVERFLOW); break; }
            size_t total=(size_t)node.range_count+(tail ? tail+1 : 0);
            char *next=malloc(total+1);
            if (!next) { failed=fail(c,"io",ENOMEM); break; }
            if (transfer(c,c->values,next,(size_t)node.range_count,node.ranges,0)) { free(next); failed=1; break; }
            size_t end=(size_t)node.range_count;
            if (tail) { next[end++]='/'; memcpy(next+end,rest,tail); end+=tail; }
            next[end]=0; free(pending); pending=next;
        } else {
            if (*rest && !S_ISDIR(node.captured.st_mode)) missing_depth=1;
            else parent=child;
            memmove(pending,rest,strlen(rest)+1);
        }
    }
    free(pending); return failed ? -1 : 0;
}
static int validate_links(importer *c) {
    for (uint64_t i=0;i<c->count;i++) {
        c->current=i; record r; if (get_record(c,i,&r)) return -1;
        if (S_ISLNK(r.captured.st_mode) && validate_link(c,&r)) return -1;
    }
    return 0;
}
static int named_directories(importer *c) {
    int source=open_absolute(c,c->options->source);
    if (source<0) return -1;
    int destination=open_absolute(c,c->options->destination),failed=destination<0;
    if (!failed) failed=identity_fd(c,source,c->options->source_identity,0) || identity_fd(c,destination,c->options->destination_identity,1);
    if (close_fd(c,source)) failed=1;
    if (close_fd(c,destination)) failed=1;
    return failed ? -1 : 0;
}
static sfs_timestamp timestamp(struct timespec t) { return (sfs_timestamp){.seconds=t.tv_sec,.nanoseconds=(uint32_t)t.tv_nsec}; }
static sfs_metadata_initial initial(const record *r) {
    return (sfs_metadata_initial){.mode=r->captured.st_mode,.uid=r->captured.st_uid,.gid=r->captured.st_gid,
        .flags=r->captured.st_flags,.restore=7,.birth=timestamp(r->captured.st_birthtimespec),
        .access=timestamp(r->captured.st_atimespec),.modification=timestamp(r->captured.st_mtimespec)};
}
static int core(importer *c,enum sfs_status status) { return status==SFS_OK ? 0 : fail(c,status==SFS_INCOMPLETE ? "verification-incomplete" : status==SFS_LIMIT ? "capacity" : "core",0); }
static int populate(importer *c) {
    if (core(c,sfs_image_begin(c->image,&c->report->original))) return -1;
    for (uint64_t i=0;i<c->count;i++) {
        c->current=i; if (poll(c)) return -1;
        record r,parent; if (get_record(c,i,&r)) return -1;
        if (i && get_record(c,r.parent,&parent)) return -1;
        int fd=open_record(c,i); if (fd<0) return -1;
        int failed=0;
        sfs_inode parent_inode=i ? parent.inode : SFS_ROOT_INODE;
        const char *name=i ? r.name : "repo"; size_t length=i ? r.length : 4;
        if (r.first!=i) {
            record first;
            if (get_record(c,r.first,&first)) failed=1;
            else { r.inode=first.inode; failed=core(c,sfs_image_link(c->image,r.inode,parent_inode,name,length,&c->report->original)); }
        } else {
            sfs_metadata_initial metadata=initial(&r);
            if (S_ISLNK(r.captured.st_mode)) {
                char target[4096];
                failed=transfer(c,c->values,target,(size_t)r.range_count,r.ranges,0);
                if (!failed) failed=core(c,sfs_image_symlink_metadata(c->image,parent_inode,name,length,target,(size_t)r.range_count,&metadata,&r.inode,&c->report->original));
            } else failed=core(c,sfs_image_add_metadata(c->image,parent_inode,name,length,S_ISDIR(r.captured.st_mode) ? SFS_DIRECTORY : SFS_FILE,&metadata,&r.inode,&c->report->original));
            if (!failed && S_ISREG(r.captured.st_mode)) {
                failed=core(c,sfs_image_resize(c->image,r.inode,(uint64_t)r.captured.st_size,&c->report->original));
                unsigned char bytes[65536];
                for (uint64_t j=0;!failed && j<r.range_count;j++) {
                    range area={0}; failed=transfer(c,c->ranges,&area,sizeof(area),r.ranges+j*sizeof(area),0);
                    for (uint64_t at=area.start;!failed && at<area.end;) {
                        size_t n=area.end-at>sizeof(bytes) ? sizeof(bytes) : (size_t)(area.end-at);
                        failed=transfer(c,fd,bytes,n,at,0) || core(c,sfs_image_write(c->image,r.inode,at,bytes,n,&c->report->original)); at+=n;
                    }
                }
            }
            if (!failed) failed=attributes(c,fd,&r,0,1);
        }
        if (!failed) failed=check_fd(c,fd,&r) || put_record(c,i,&r);
        if (close_fd(c,fd)) failed=1;
        if (failed) return -1;
    }
    /* Children and all aliases now exist. Restore every supported timestamp and
     * metadata field bottom-up; only one update per shared inode. */
    for (uint64_t i=c->count;i--;) {
        c->current=i; record r; if (get_record(c,i,&r)) return -1;
        if (r.first!=i) continue;
        sfs_metadata_initial m=initial(&r);
        sfs_metadata_update u={.fields=127,.mode=m.mode,.uid=m.uid,.gid=m.gid,.flags=m.flags,
            .birth=m.birth,.access=m.access,.modification=m.modification};
        if (core(c,sfs_image_set_metadata(c->image,r.inode,&u,&c->report->original))) return -1;
    }
    sfs_metadata_update root={.fields=SFS_META_MODE|SFS_META_UID|SFS_META_GID|SFS_META_FLAGS,
        .mode=S_IFDIR|0700,.uid=geteuid(),.gid=getegid()};
    if (core(c,sfs_image_set_metadata(c->image,SFS_ROOT_INODE,&root,&c->report->original))) return -1;
    enum sfs_status status=sfs_image_commit(c->image,&c->report->commit);
    c->report->original=c->report->commit;
    if (core(c,status)) return -1;
    c->report->import_committed=1; return 0;
}
static int verification_budget(importer *c) {
    if (c->options->verification_budget) {
        c->report->budget=*c->options->verification_budget;
        c->report->budget_explicit=1;
    } else {
        c->report->budget=sfs_import_default_budget(c->report->commit.physical_end,
            c->count,c->report->parent_steps,&c->report->budget_saturated);
    }
    c->report->budget.cancelled=c->options->cancelled;
    c->report->budget.context=c->options->context;
    return 0;
}
static int equal_time(sfs_timestamp a,struct timespec b) { return a.seconds==b.tv_sec && a.nanoseconds==(uint32_t)b.tv_nsec; }
static int verify_attributes(importer *c,const record *r) {
    unsigned char after[255]; size_t after_length=0; uint64_t seen=0,expected=0;
    for (uint64_t offset=r->attributes;offset<r->attributes_end;) {
        attribute a; if (transfer(c,c->values,&a,sizeof(a),offset,0)) return -1;
        if (add_size(c,offset,sizeof(a)+a.name_length,&offset) || add_size(c,offset,a.length,&offset)) return -1;
        expected++;
    }
    for (;;) {
        sfs_xattr_entry entry; int found=0;
        if (core(c,sfs_image_next_xattr(c->image,0,c->report->commit.generation,c->report->commit.root_digest,r->inode,
            after_length ? after : NULL,after_length,&entry,&found,&c->report->original))) return -1;
        if (!found) break;
        uint64_t value_offset=0; int matched=0;
        for (uint64_t offset=r->attributes;offset<r->attributes_end;) {
            attribute a; char name[255];
            if (transfer(c,c->values,&a,sizeof(a),offset,0) || add_size(c,offset,sizeof(a),&offset) ||
                a.name_length>sizeof(name) || transfer(c,c->values,name,a.name_length,offset,0) || add_size(c,offset,a.name_length,&offset)) return fail(c,"source-changed",ESTALE);
            if (a.name_length==entry.name_length && !memcmp(name,entry.name,a.name_length)) {
                if (a.length!=entry.size) return fail(c,"verification-mismatch",EIO);
                value_offset=offset; matched=1; break;
            }
            if (add_size(c,offset,a.length,&offset)) return -1;
        }
        if (!matched) return fail(c,"verification-mismatch",EIO);
        unsigned char original[65536],stored[65536];
        for (uint64_t pos=0;pos<entry.size;) {
            size_t size=entry.size-pos>sizeof(original) ? sizeof(original) : (size_t)(entry.size-pos),got=0;
            if (transfer(c,c->values,original,size,value_offset+pos,0) ||
                core(c,sfs_image_read_xattr(c->image,0,r->inode,entry.name,entry.name_length,pos,stored,size,&got,&c->report->original))) return -1;
            if (got!=size || memcmp(original,stored,size)) return fail(c,"verification-mismatch",EIO);
            pos+=size;
        }
        memcpy(after,entry.name,entry.name_length); after_length=entry.name_length; seen++;
    }
    return seen==expected ? 0 : fail(c,"verification-mismatch",EIO);
}
static int verify_directory(importer *c,uint64_t index,int fd,const record *r) {
    uint64_t expected=0,seen=0; record child;
    for (uint64_t i=1;i<c->count;i++) { if (get_record(c,i,&child)) return -1; if (child.parent==index) expected++; }
    char after[256]={0},name[256]; int found;
    while (!next_name(c,fd,after,name,&found) && found) {
        int matched=0;
        for (uint64_t i=1;i<c->count;i++) {
            if (get_record(c,i,&child)) return -1;
            if (child.parent==index && !strcmp(child.name,name)) { matched=1; break; }
        }
        if (!matched) return fail(c,"source-changed",ESTALE);
        struct stat st;
        if (fstatat(fd,name,&st,AT_SYMLINK_NOFOLLOW)) return fail(c,"io",errno);
        if (!stable_stat(&child.captured,&st)) return fail(c,"source-changed",ESTALE);
        strcpy(after,name); seen++;
    }
    if (c->report->reason) return -1;
    if (seen!=expected) return fail(c,"source-changed",ESTALE);
    seen=0; sfs_cookie cookie={0}; sfs_entry entry;
    for (;;) {
        if (core(c,sfs_image_next(c->image,0,r->inode,&cookie,&entry,&found,&c->report->original))) return -1;
        if (!found) break;
        int matched=0;
        for (uint64_t i=1;i<c->count;i++) {
            if (get_record(c,i,&child)) return -1;
            if (child.parent==index && child.length==entry.name_length && !memcmp(child.name,entry.name,child.length) && child.inode==entry.inode) { matched=1; break; }
        }
        if (!matched) return fail(c,"verification-mismatch",EIO);
        seen++;
    }
    return seen==expected ? 0 : fail(c,"verification-mismatch",EIO);
}
static int read_target(importer *c,const record *r,char target[4097],size_t *length) {
    int parent=open_record(c,r->parent);
    if (parent<0) return -1;
    struct stat before,after; int failed=0;
    if (fstatat(parent,r->name,&before,AT_SYMLINK_NOFOLLOW)) failed=fail(c,"io",errno);
    if (!failed && !stable_stat(&r->captured,&before)) failed=fail(c,"source-changed",ESTALE);
    ssize_t n=-1;
    if (!failed) { n=readlinkat(parent,r->name,target,4097); if (n<0) failed=fail(c,"io",errno); }
    if (!failed && (fstatat(parent,r->name,&after,AT_SYMLINK_NOFOLLOW) || !stable_stat(&r->captured,&after))) failed=fail(c,"source-changed",ESTALE);
    if (!failed && (!n || n>4096 || target[0]=='/' || memchr(target,0,(size_t)n))) failed=fail(c,"unsafe-path",EINVAL);
    if (close_fd(c,parent)) failed=1;
    if (!failed) *length=(size_t)n;
    return failed ? -1 : 0;
}
static int verify_file(importer *c,int fd,const record *r) {
    if (sparse_ranges(c,fd,(record *)r,0)) return -1;
    unsigned char host[65536],stored[65536];
    for (uint64_t at=0;at<(uint64_t)r->captured.st_size;) {
        size_t n=(uint64_t)r->captured.st_size-at>sizeof(host) ? sizeof(host) : (size_t)((uint64_t)r->captured.st_size-at),got=0;
        if (transfer(c,fd,host,n,at,0) || core(c,sfs_image_read(c->image,0,r->inode,at,stored,n,&got,&c->report->original))) return -1;
        if (got!=n || memcmp(host,stored,n)) return fail(c,"verification-mismatch",EIO);
        at+=n;
    }
    uint64_t seek=0,actual=0;
    for (uint64_t i=0;i<r->range_count;i++) {
        range area; if (transfer(c,c->ranges,&area,sizeof(area),r->ranges+i*sizeof(area),0)) return -1;
        for (uint64_t block=area.start/CELL;block<(area.end/CELL+!!(area.end%CELL));block++) {
            int found=0;
            if (core(c,sfs_image_next_mapped_block(c->image,0,c->report->commit.generation,c->report->commit.root_digest,
                r->inode,seek,&c->report->budget,&actual,&found,&c->report->original))) return -1;
            if (!found || actual!=block) return fail(c,"verification-mismatch",EIO);
            seek=actual+1;
        }
    }
    int found=0;
    if (core(c,sfs_image_next_mapped_block(c->image,0,c->report->commit.generation,c->report->commit.root_digest,
        r->inode,seek,&c->report->budget,&actual,&found,&c->report->original))) return -1;
    return found ? fail(c,"verification-mismatch",EIO) : 0;
}
static int compare(importer *c) {
    for (uint64_t i=0;i<c->count;i++) {
        c->current=i; if (poll(c)) return -1;
        record r,parent; if (get_record(c,i,&r) || (i && get_record(c,r.parent,&parent))) return -1;
        int fd=open_record(c,i); if (fd<0) return -1;
        sfs_entry entry; sfs_metadata_entry m;
        int failed=core(c,sfs_image_lookup(c->image,0,i ? parent.inode : SFS_ROOT_INODE,i ? r.name : "repo",i ? r.length : 4,&entry,&c->report->original));
        if (!failed && entry.inode!=r.inode) failed=fail(c,"verification-mismatch",EIO);
        if (!failed) failed=core(c,sfs_image_stat_metadata(c->image,0,r.inode,&m,&c->report->original));
        if (!failed && (m.mode!=(uint32_t)r.captured.st_mode || m.uid!=r.captured.st_uid || m.gid!=r.captured.st_gid ||
            m.flags!=r.captured.st_flags || !equal_time(m.birth,r.captured.st_birthtimespec) ||
            !equal_time(m.access,r.captured.st_atimespec) || !equal_time(m.modification,r.captured.st_mtimespec) ||
            m.link_count!=(S_ISDIR(r.captured.st_mode) ? 1 : (uint64_t)r.captured.st_nlink) ||
            (!S_ISDIR(r.captured.st_mode) && m.entry.size!=(uint64_t)r.captured.st_size))) failed=fail(c,"verification-mismatch",EIO);
        if (!failed) failed=empty_acl(c,fd) || attributes(c,fd,&r,0,0) || verify_attributes(c,&r);
        if (!failed && S_ISREG(r.captured.st_mode)) {
            uint64_t mapped=0;
            for (uint64_t j=0;j<r.range_count;j++) {
                range area;
                if (transfer(c,c->ranges,&area,sizeof(area),r.ranges+j*sizeof(area),0)) { failed=1; break; }
                uint64_t blocks=area.end/CELL+!!(area.end%CELL)-area.start/CELL;
                if (blocks>UINT64_MAX/CELL || mapped>UINT64_MAX-blocks*CELL) { failed=fail(c,"representation-limit",EOVERFLOW); break; }
                mapped+=blocks*CELL;
            }
            if (!failed && mapped!=m.referenced_data_bytes) failed=fail(c,"verification-mismatch",EIO);
            if (!failed) failed=verify_file(c,fd,&r);
        }
        if (!failed && S_ISDIR(r.captured.st_mode)) failed=verify_directory(c,i,fd,&r);
        if (!failed && S_ISLNK(r.captured.st_mode)) {
            char target[4097],original[4096],stored[4096]; size_t length=0,got=0;
            failed=read_target(c,&r,target,&length) || transfer(c,c->values,original,(size_t)r.range_count,r.ranges,0) ||
                core(c,sfs_image_readlink(c->image,0,r.inode,stored,sizeof(stored),&got,&c->report->original));
            if (!failed && (length!=r.range_count || got!=length || memcmp(target,original,length) || memcmp(target,stored,length))) failed=fail(c,"verification-mismatch",EIO);
        }
        if (!failed) failed=check_fd(c,fd,&r);
        if (close_fd(c,fd)) failed=1;
        if (failed) return -1;
    }
    /* The synthetic root has exactly one child; it is not copied source data. */
    sfs_cookie cookie={0}; sfs_entry entry; int found=0; sfs_metadata_entry root;
    if (core(c,sfs_image_stat_metadata(c->image,0,SFS_ROOT_INODE,&root,&c->report->original)) ||
        root.mode!=(S_IFDIR|0700) || root.uid!=geteuid() || root.gid!=getegid() || root.flags ||
        core(c,sfs_image_next(c->image,0,SFS_ROOT_INODE,&cookie,&entry,&found,&c->report->original)) ||
        !found || entry.name_length!=4 || memcmp(entry.name,"repo",4) ||
        core(c,sfs_image_next(c->image,0,SFS_ROOT_INODE,&cookie,&entry,&found,&c->report->original)) || found)
        return fail(c,"verification-mismatch",EIO);
    return 0;
}
static int setup(importer *c) {
    c->root=open_absolute(c,c->options->source); if (c->root<0) return -1;
    c->destination=open_absolute(c,c->options->destination); if (c->destination<0) return -1;
    if (identity_fd(c,c->root,c->options->source_identity,0) || identity_fd(c,c->destination,c->options->destination_identity,1)) return -1;
    c->stage=openat(c->destination,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (c->stage<0) return fail(c,"io",errno);
    int source_parent=openat(c->root,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (source_parent<0) return fail(c,"io",errno);
    int source_stage=openat(source_parent,"..",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (source_stage<0) { fail(c,"io",errno); close_fd(c,source_parent); return -1; }
    struct stat a,b,input,source,destination;
    int failed=fstat(c->stage,&a) || fstat(source_stage,&b) || fstat(source_parent,&input) || fstat(c->root,&source) || fstat(c->destination,&destination);
    if (failed) fail(c,"io",errno);
    else if (a.st_dev!=b.st_dev || a.st_ino!=b.st_ino || input.st_ino==destination.st_ino || source.st_ino==destination.st_ino ||
        a.st_uid!=geteuid() || (a.st_mode&0777)!=0700 || input.st_uid!=geteuid() || (input.st_mode&0777)!=0700)
        failed=fail(c,"unsafe-path",EINVAL);
    if (close_fd(c,source_stage)) failed=1;
    if (close_fd(c,source_parent)) failed=1;
    if (failed) return -1;
    c->inventory=openat(c->stage,"native-inventory",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (c->inventory<0) return fail(c,"io",errno);
    c->values=openat(c->stage,"native-values",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (c->values<0) return fail(c,"io",errno);
    c->ranges=openat(c->stage,"native-ranges",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (c->ranges<0) return fail(c,"io",errno);
    c->names=openat(c->stage,"native-xattr-names",O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    return c->names<0 ? fail(c,"io",errno) : 0;
}
static void observe(importer *c) {
    struct stat st;
    if (!fstatat(c->destination,"image.sfs",&st,AT_SYMLINK_NOFOLLOW)) {
        c->report->observed=1; c->report->observed_identity[0]=(uint64_t)st.st_dev; c->report->observed_identity[1]=(uint64_t)st.st_ino;
    }
}
static int path_record(importer *c,uint64_t index,record *r) {
    if (index>=c->count || index>INT64_MAX/sizeof(*r)) return EINVAL;
    size_t got=0;
    while (got<sizeof(*r)) {
        ssize_t n=pread(c->inventory,(char *)r+got,sizeof(*r)-got,(off_t)(index*sizeof(*r)+got));
        if (n<0 && errno==EINTR) continue;
        if (n<=0) return n<0 ? errno : EIO;
        got+=(size_t)n;
    }
    return 0;
}
/* Best-effort presentation only. The fixed carrier always keeps failed_record
 * and the retained inventory even when allocation of this path fails. */
static void failure_path(importer *c) {
    uint64_t index=c->report->failed_record;
    if (index==NONE || c->inventory<0 || index>=c->count) return;
    size_t length=0; int error=0; record r;
    for (uint64_t at=index;at;) {
        if ((error=path_record(c,at,&r))) break;
        if (r.parent>=at || r.length>255 || length>SIZE_MAX-r.length-1) { error=EOVERFLOW; break; }
        length+=r.length+1; at=r.parent;
    }
    if (error) { c->report->failure_path_error=error; return; }
    if (!length) length=1; else length--;
    char *path=malloc(length+1);
    if (!path) { c->report->failure_path_error=ENOMEM; return; }
    path[length]=0; size_t position=length;
    if (!index) path[0]='.';
    for (uint64_t at=index;at;) {
        if ((error=path_record(c,at,&r))) break;
        if (r.length>position) { error=EINVAL; break; }
        position-=r.length; memcpy(path+position,r.name,r.length); at=r.parent;
        if (at) { if (!position) { error=EINVAL; break; } path[--position]='/'; }
    }
    if (error) { free(path); c->report->failure_path_error=error; return; }
    c->report->failure_path=path; c->report->failure_path_length=length;
}
void sfs_native_import(const sfs_import_options *options,sfs_import_report *report) {
    memset(report,0,sizeof(*report)); report->failed_record=NONE;
    importer c={.options=options,.report=report,.root=-1,.destination=-1,.stage=-1,.inventory=-1,.values=-1,.ranges=-1,.names=-1,.current=NONE};
    if (options->verification_budget && (!options->verification_budget->raw_cells ||
        !options->verification_budget->metadata_read_bytes || !options->verification_budget->metadata_hash_bytes ||
        !options->verification_budget->checks || !options->verification_budget->auxiliary_bytes ||
        !options->verification_budget->auxiliary_io_bytes)) { fail(&c,"verification-incomplete",EINVAL); goto done; }
    if (options->capacity<16384 || options->capacity%CELL || options->capacity>SFS_IMAGE_MAX || options->capacity>INT64_MAX) { fail(&c,"capacity",EINVAL); goto done; }
    if (setup(&c) || inventory(&c) || validate_links(&c) || named_directories(&c) || poll(&c)) goto done;
    if (!options->before_create || options->before_create(options->context)) { fail(&c,"publication-unknown",EIO); goto done; }
    if (named_directories(&c)) goto done;
    report->creation_attempted=1;
    sfs_metadata_initial root={.mode=S_IFDIR|0700,.uid=geteuid(),.gid=getegid()};
    enum sfs_status status=sfs_image_create_metadata_version(options->destination,"image.sfs",options->capacity,6,&root,&c.image,&report->creation);
    report->original=report->creation; observe(&c);
    if (status!=SFS_OK) { report->existing=status==SFS_EXISTS; core(&c,status); goto done; }
    report->created=1;
    if (named_directories(&c)) goto done;
    if (!report->observed || report->observed_identity[0]!=report->creation.device || report->observed_identity[1]!=report->creation.inode) {
        fail(&c,"publication-unknown",ESTALE); goto done;
    }
    if (populate(&c) || verification_budget(&c) || compare(&c)) goto done;
    if (core(&c,sfs_image_verify(c.image,&report->budget,&report->verify))) goto done;
    if (report->verify.coverage!=SFS_COVERAGE_FULL_REACHABLE) { fail(&c,"verification-incomplete",EIO); goto done; }
    if (named_directories(&c) || compare(&c)) goto done;
    report->verified=1;
    report->close_attempted=1;
    status=sfs_image_close(c.image,&report->close); c.image=NULL;
    if (core(&c,status)) goto done;
    report->reopen_attempted=1;
    status=sfs_image_open_readonly(options->destination,"image.sfs",&c.image,&report->reopen);
    if (core(&c,status)) goto done;
    if (report->reopen.device!=report->commit.device || report->reopen.inode!=report->commit.inode ||
        report->reopen.generation!=report->commit.generation || memcmp(report->reopen.uuid,report->commit.uuid,16) ||
        memcmp(report->reopen.root_digest,report->commit.root_digest,32)) { fail(&c,"publication-unknown",ESTALE); goto done; }
    report->reopen_close_attempted=1;
    status=sfs_image_close(c.image,&report->reopen_close); c.image=NULL;
    if (core(&c,status)) goto done;
    report->candidate_complete=1;
done:
    if (c.image) {
        if (report->original.transaction_active && !report->original.poisoned && !report->import_committed &&
            report->commit.status!=SFS_OUTCOME_UNKNOWN) {
            report->abort_attempted=1; sfs_image_abort(c.image,&report->abort);
        }
        if (report->reopen_attempted) { report->reopen_close_attempted=1; sfs_image_close(c.image,&report->reopen_close); }
        else { report->close_attempted=1; sfs_image_close(c.image,&report->close); }
        c.image=NULL;
    }
    if (c.destination>=0 && report->creation_attempted) observe(&c);
    failure_path(&c);
    close_fd(&c,c.inventory); close_fd(&c,c.values); close_fd(&c,c.ranges); close_fd(&c,c.names);
    close_fd(&c,c.root); close_fd(&c,c.destination); close_fd(&c,c.stage);
    if (report->reason || report->cleanup_error) report->candidate_complete=0;
}
