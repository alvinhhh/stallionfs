/* Standalone read-only acquisition. Retain mode owns only the child it forks. */
#include <CommonCrypto/CommonDigest.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/proc.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/acl.h>
#include <libproc.h>
#include <utmpx.h>
#include <pwd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#ifndef SFS_PROCESS_CAP
#define SFS_PROCESS_CAP 16384
#endif
#ifndef SFS_MOUNT_CAP
#define SFS_MOUNT_CAP 4096
#endif
#ifndef SFS_SESSION_CAP
#define SFS_SESSION_CAP 256
#endif
#ifndef SFS_OUTPUT_CAP
#define SFS_OUTPUT_CAP (16 * 1024 * 1024)
#endif
#ifndef SFS_DEADLINE_MS
#define SFS_DEADLINE_MS 5000
#endif
/* Faults are build-only inputs; production has no environment or argument hook. */
#ifndef SFS_TEST_FAULT
#define SFS_TEST_FAULT 0
#endif

struct output { char *data; size_t used; int overflow; };
static struct output out;
static const char *uncertain[64];
static unsigned uncertainties;
static volatile sig_atomic_t interrupted;
static pid_t owned_controller;
static struct kinfo_proc owned_controller_info;
static int owned_controller_valid;
static char owned_executable[PROC_PIDPATHINFO_MAXSIZE];
static size_t activity_helpers, activity_descendants, activity_mounts, activity_other_sessions;
static int synthetic(void) { return SFS_TEST_FAULT >= 17 && SFS_TEST_FAULT <= 21; }
static int relevant_path(const char *path) {
    const char *base = strrchr(path,'/'); base = base ? base+1 : path;
    return strcasestr(path,"stallionfs") != NULL || !strcmp(base,"sfs");
}

static uint64_t clock_ns(clockid_t clock) {
    struct timespec t;
    if (clock_gettime(clock, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000000000ULL + (uint64_t)t.tv_nsec;
}
static void uncertainty(const char *value) {
    for (unsigned i = 0; i < uncertainties; i++) if (!strcmp(uncertain[i], value)) return;
    if (uncertainties < sizeof uncertain / sizeof *uncertain) uncertain[uncertainties++] = value;
}
static void append(const char *format, ...) {
    if (out.overflow) return;
    va_list args; va_start(args, format);
    int n = vsnprintf(out.data + out.used, SFS_OUTPUT_CAP - out.used, format, args);
    va_end(args);
    if (n < 0 || (size_t)n >= SFS_OUTPUT_CAP - out.used) { out.overflow = 1; return; }
    out.used += (size_t)n;
}
static int valid_utf8(const char *data, size_t size) {
    for (size_t i = 0; i < size;) {
        unsigned char c = (unsigned char)data[i++];
        if (c < 0x80) continue;
        unsigned need = c >= 0xc2 && c <= 0xdf ? 1 : c >= 0xe0 && c <= 0xef ? 2 : c >= 0xf0 && c <= 0xf4 ? 3 : 0;
        if (!need || size - i < need) return 0;
        unsigned char first = (unsigned char)data[i];
        if ((c == 0xe0 && first < 0xa0) || (c == 0xed && first >= 0xa0) ||
            (c == 0xf0 && first < 0x90) || (c == 0xf4 && first >= 0x90)) return 0;
        for (unsigned j = 0; j < need; j++) if (((unsigned char)data[i++] & 0xc0) != 0x80) return 0;
    }
    return 1;
}
static void string(const char *data, size_t size) {
    int utf8 = valid_utf8(data, size);
    if (!utf8) uncertainty("invalid-native-utf8");
    append("\"");
    for (size_t i = 0; i < size; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c == '"' || c == '\\') append("\\%c", c);
        else if (c < 0x20 || (!utf8 && c >= 0x7f)) append("\\u%04x", c);
        else append("%c", c);
    }
    append("\"");
}
static int field(const char *data, size_t capacity) {
    const char *end = memchr(data, 0, capacity);
    if (!end) { string(data, capacity); uncertainty("unterminated-native-string"); return 0; }
    string(data, (size_t)(end - data)); return 1;
}
static int write_all(int fd, const void *data, size_t size) {
    const char *p = data;
    while (size) {
        ssize_t n = write(fd, p, size);
        if (n < 0 && errno == EINTR && !interrupted) continue;
        if (n <= 0) return -1;
        p += n; size -= (size_t)n;
    }
    return 0;
}

static struct kinfo_proc *processes(size_t *count) {
    int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
    size_t size = 0, cap = SFS_PROCESS_CAP * sizeof(struct kinfo_proc);
    *count = 0;
    if (synthetic()) {
        *count = SFS_TEST_FAULT == 18 ? 5 : 3;
        struct kinfo_proc *fixture = calloc(*count,sizeof *fixture);
        if (!fixture) { uncertainty("process-allocation"); *count=0; return NULL; }
        for (size_t i=0;i<*count;i++) {
            fixture[i].kp_proc.p_pid = i==0 ? 0 : i==1 ? getpid() : i==2 ? getppid() : i==3 ? 1500000000 : 1500000001;
            fixture[i].kp_eproc.e_ppid = i==1 ? getppid() : i==4 ? 1500000000 : 0;
            fixture[i].kp_eproc.e_ucred.cr_uid = getuid();
            fixture[i].kp_proc.p_starttime.tv_sec = i ? 1 : 0;
            fixture[i].kp_proc.p_stat = SRUN;
        }
        fixture[0].kp_proc.p_flag=P_SYSTEM;
        return fixture;
    }
    if (SFS_TEST_FAULT == 2 || sysctl(mib, 4, NULL, &size, NULL, 0)) {
        uncertainty("process-enumeration-denied"); return NULL;
    }
    if (size > cap || cap - size < sizeof(struct kinfo_proc)) {
        uncertainty("process-capacity-or-truncation"); return NULL;
    }
    struct kinfo_proc *rows = calloc(1, cap);
    if (!rows) { uncertainty("process-allocation"); return NULL; }
    size = cap;
    if (sysctl(mib, 4, rows, &size, NULL, 0) || size > cap || size == cap ||
        size % sizeof *rows || SFS_TEST_FAULT == 9) {
        uncertainty("process-enumeration-truncated-or-changed"); free(rows); return NULL;
    }
    *count = size / sizeof *rows;
    if (!*count) uncertainty("process-enumeration-empty");
    return rows;
}
static int identity_equal(const struct kinfo_proc *a, const struct kinfo_proc *b) {
    return a->kp_proc.p_pid == b->kp_proc.p_pid &&
        a->kp_proc.p_starttime.tv_sec == b->kp_proc.p_starttime.tv_sec &&
        a->kp_proc.p_starttime.tv_usec == b->kp_proc.p_starttime.tv_usec &&
        a->kp_eproc.e_ucred.cr_uid == b->kp_eproc.e_ucred.cr_uid &&
        a->kp_eproc.e_ppid == b->kp_eproc.e_ppid;
}
static int process_path(pid_t pid, char *path, uint32_t capacity) {
    if (synthetic()) {
        if (pid==0 || (SFS_TEST_FAULT==20 && pid==getpid())) { errno=ENOENT; return 0; }
        const char *value = pid==1500000000 ? "/Applications/StallionFS.app/Contents/MacOS/StallionFS" :
            pid==1500000001 ? "/bin/sleep" : "/external/stallionfs-maintenance";
        return snprintf(path,capacity,"%s",value);
    }
    return proc_pidpath(pid,path,capacity);
}
static void acquire_owned_path(void) {
    memset(owned_executable,0,sizeof owned_executable);
    int n=process_path(getpid(),owned_executable,sizeof owned_executable);
    if (n<=0 || n>=(int)sizeof owned_executable || !memchr(owned_executable,0,sizeof owned_executable)) {
        owned_executable[0]=0; uncertainty("observer-path-unavailable-or-truncated");
    }
}
static void collect_processes(void) {
    size_t count = 0; struct kinfo_proc *rows = processes(&count);
    unsigned char *active = calloc(count ? count : 1,1);
    if (!active) { uncertainty("activity-allocation"); count=0; }
    append(",\"processes\":[");
    for (size_t i = 0; i < count; i++) {
        struct kinfo_proc *k = rows + i, after = {0};
        char path[PROC_PIDPATHINFO_MAXSIZE] = {0}; errno = 0;
        int n = SFS_TEST_FAULT == 4 ? 0 : process_path(k->kp_proc.p_pid, path, sizeof path);
        int path_errno = n > 0 ? 0 : errno ? errno : ENOENT;
        if (n > 0 && (n >= (int)sizeof path || !memchr(path, 0, sizeof path))) {
            n = 0; path_errno = EOVERFLOW;
        }
        int mib[] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, k->kp_proc.p_pid};
        size_t bytes = sizeof after; errno = 0;
        int result;
        if (synthetic()) { after=*k; result=0; }
        else result = sysctl(mib, 4, &after, &bytes, NULL, 0);
        int requery_errno = result ? errno : bytes != sizeof after ? ESRCH : 0;
        char second_path[PROC_PIDPATHINFO_MAXSIZE] = {0}; errno = 0;
        int second_n = SFS_TEST_FAULT == 4 ? 0 : process_path(k->kp_proc.p_pid, second_path, sizeof second_path);
        int second_errno = second_n > 0 ? 0 : errno ? errno : ENOENT;
        if (second_n >= (int)sizeof second_path || (second_n > 0 && !memchr(second_path, 0, sizeof second_path))) {
            second_n = 0; second_errno = EOVERFLOW;
        }
        int same_path = n > 0 && second_n > 0 ? !strcmp(path, second_path) : n <= 0 && second_n <= 0 && path_errno == second_errno;
        int stable = !requery_errno && identity_equal(k, &after) && same_path && SFS_TEST_FAULT != 3;
        int kernel = k->kp_proc.p_pid == 0 && k->kp_eproc.e_ppid == 0 &&
            (k->kp_proc.p_flag & P_SYSTEM);
        if (!stable) uncertainty("process-identity-changed-or-unavailable");
        if (!n && !kernel && k->kp_proc.p_stat != SZOMB)
            uncertainty("live-process-path-unavailable");
        int owned = n > 0 && stable && owned_executable[0] && !strcmp(path,owned_executable) &&
            k->kp_eproc.e_ucred.cr_uid==getuid() &&
            ((k->kp_proc.p_pid==getpid() && (!owned_controller || k->kp_eproc.e_ppid==owned_controller)) ||
             (owned_controller_valid && k->kp_proc.p_pid==owned_controller && identity_equal(k,&owned_controller_info)));
        if (owned) active[i]=3;
        else if (n > 0 && relevant_path(path)) active[i]=1;
        if (!kernel && k->kp_proc.p_starttime.tv_sec <= 0)
            uncertainty("process-start-unavailable");
        append("%s{\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"start_sec\":%lld,\"start_usec\":%d,\"path\":",
            i ? "," : "", k->kp_proc.p_pid, k->kp_eproc.e_ppid,
            k->kp_eproc.e_ucred.cr_uid, (long long)k->kp_proc.p_starttime.tv_sec,
            k->kp_proc.p_starttime.tv_usec);
        if (n > 0) field(path, sizeof path); else append("null");
        append(",\"path_errno\":%d,\"postquery_errno\":%d,\"stable\":%s,\"status\":%d,\"kernel\":%s}",
            path_errno, requery_errno, stable ? "true" : "false", k->kp_proc.p_stat,
            kernel ? "true" : "false");
    }
    append("]");
    int changed;
    do {
        changed=0;
        for (size_t i=0;i<count;i++) if (active[i]==1 || active[i]==2)
            for (size_t j=0;j<count;j++) if (!active[j] && rows[j].kp_eproc.e_ppid==rows[i].kp_proc.p_pid) { active[j]=2; changed=1; }
    } while (changed);
    for (size_t i=0;i<count;i++) { if (active[i]==1) activity_helpers++; else if (active[i]==2) activity_descendants++; }
    free(active);
    size_t second_count = 0; struct kinfo_proc *second = processes(&second_count);
    if (!rows || !second || count != second_count) uncertainty("process-snapshot-changed");
    else {
        /* Kernel order is not an identity contract. Every original member must survive. */
        for (size_t i = 0; i < count; i++) {
            size_t j = 0;
            for (; j < second_count; j++) if (identity_equal(rows + i, second + j)) break;
            if (j == second_count) { uncertainty("process-snapshot-changed"); break; }
        }
    }
    free(second); free(rows);
}
static int mount_equal(const struct statfs *a, const struct statfs *b) {
    return !memcmp(&a->f_fsid, &b->f_fsid, sizeof a->f_fsid) &&
        !memcmp(a->f_mntonname, b->f_mntonname, sizeof a->f_mntonname) &&
        !memcmp(a->f_mntfromname, b->f_mntfromname, sizeof a->f_mntfromname) &&
        !memcmp(a->f_fstypename, b->f_fstypename, sizeof a->f_fstypename) &&
        a->f_owner == b->f_owner && a->f_flags == b->f_flags && a->f_flags_ext == b->f_flags_ext;
}
static void collect_mounts(void) {
    append(",\"mounts\":[");
    if (synthetic()) {
        if (SFS_TEST_FAULT==19) { append("{\"source\":\"owned\",\"target\":\"/fixture/mount\",\"type\":\"stallionfs\",\"owner\":%u,\"flags\":0,\"extended_flags\":0}",getuid()); activity_mounts++; }
        append("]"); return;
    }
    int count = SFS_TEST_FAULT == 1 ? -1 : getfsstat(NULL, 0, MNT_NOWAIT);
    if (count < 0 || count >= SFS_MOUNT_CAP) {
        uncertainty(count < 0 ? "mount-enumeration-denied" : "mount-capacity-or-truncation");
        append("]"); return;
    }
    size_t capacity = ((size_t)count + 1) * sizeof(struct statfs);
    struct statfs *rows = calloc(1, capacity), *after = calloc(1, capacity);
    if (!rows || !after) { uncertainty("mount-allocation"); goto finish; }
    int actual = getfsstat(rows, (int)capacity, MNT_NOWAIT);
    if (actual < 0 || actual > count) { uncertainty("mount-enumeration-truncated-or-changed"); goto finish; }
    for (int i = 0; i < actual; i++) {
        int terminated = memchr(rows[i].f_fstypename,0,sizeof rows[i].f_fstypename) &&
            memchr(rows[i].f_mntfromname,0,sizeof rows[i].f_mntfromname) && memchr(rows[i].f_mntonname,0,sizeof rows[i].f_mntonname);
        if (!terminated) uncertainty("unterminated-native-mount");
        else if (!strcmp(rows[i].f_fstypename,"stallionfs") || !strcmp(rows[i].f_fstypename,"sfsro27") ||
            relevant_path(rows[i].f_mntfromname) || relevant_path(rows[i].f_mntonname)) activity_mounts++;
        else if (!strcasecmp(rows[i].f_fstypename,"fskit") || !strcasecmp(rows[i].f_fstypename,"fskitfs")) uncertainty("unattributed-fskit-mount");
        append("%s{\"source\":", i ? "," : ""); field(rows[i].f_mntfromname, sizeof rows[i].f_mntfromname);
        append(",\"target\":"); field(rows[i].f_mntonname, sizeof rows[i].f_mntonname);
        append(",\"type\":"); field(rows[i].f_fstypename, sizeof rows[i].f_fstypename);
        append(",\"owner\":%u,\"flags\":%u,\"extended_flags\":%u}", rows[i].f_owner, rows[i].f_flags, rows[i].f_flags_ext);
    }
    int second = getfsstat(after, (int)capacity, MNT_NOWAIT);
    if (second != actual) uncertainty("mount-snapshot-changed");
    else for (int i = 0; i < actual; i++) if (!mount_equal(rows + i, after + i)) {
        uncertainty("mount-snapshot-changed"); break;
    }
finish:
    append("]"); free(rows); free(after);
}
static int session_stat_equal(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static void collect_sessions(void) {
    struct stat before = {0}, after = {0};
    append(",\"sessions\":[");
    if (synthetic()) {
        append("{\"user\":\"fixture-user\",\"line\":\"fixture\",\"host\":\"\",\"uid\":%u}",getuid()+(SFS_TEST_FAULT==21));
        if (SFS_TEST_FAULT==21) activity_other_sessions++;
        append("]"); return;
    }
    if (SFS_TEST_FAULT == 5 || stat(_PATH_UTMPX, &before) || !S_ISREG(before.st_mode)) {
        uncertainty("session-enumeration-unavailable"); append("]"); return;
    }
    unsigned count = 0; struct utmpx *u; setutxent();
    for (;;) {
        errno = 0; u = getutxent();
        if (!u) { if (errno) uncertainty("session-enumeration-error"); break; }
        if (u->ut_type != USER_PROCESS) continue;
        if (count >= SFS_SESSION_CAP) { uncertainty("session-capacity-or-truncation"); break; }
        append("%s{\"user\":", count++ ? "," : ""); field(u->ut_user, sizeof u->ut_user);
        append(",\"line\":"); field(u->ut_line, sizeof u->ut_line);
        append(",\"host\":"); field(u->ut_host, sizeof u->ut_host);
        char user[sizeof u->ut_user+1]; memcpy(user,u->ut_user,sizeof u->ut_user); user[sizeof u->ut_user]=0;
        struct passwd record, *found=NULL; char account[65536];
        int lookup=getpwnam_r(user,&record,account,sizeof account,&found);
        if (lookup || !found) { uncertainty("session-account-lookup-unavailable"); append(",\"uid\":null}"); }
        else { append(",\"uid\":%u}",record.pw_uid); if (record.pw_uid!=getuid()) activity_other_sessions++; }
    }
    endutxent();
    if (stat(_PATH_UTMPX, &after) || !session_stat_equal(&before, &after)) uncertainty("session-snapshot-changed");
    append("]");
}
static int observe(void) {
    uint64_t started = clock_ns(CLOCK_REALTIME);
    if (!owned_executable[0]) acquire_owned_path();
    out.data = calloc(1, SFS_OUTPUT_CAP);
    if (!out.data) return 1;
    char boot[128] = {0}; size_t boot_size = sizeof boot;
    if (sysctlbyname("kern.bootsessionuuid", boot, &boot_size, NULL, 0) ||
        boot_size < 2 || boot_size > sizeof boot || !memchr(boot, 0, boot_size))
        uncertainty("boot-identity-unavailable");
    append("{\"schema\":1,\"scope\":\"global-kernel-snapshot\",\"boot_id\":"); field(boot, sizeof boot);
    append(",\"started_ns\":%llu", (unsigned long long)started);
    collect_mounts(); collect_processes(); collect_sessions();
    uint64_t finished = clock_ns(CLOCK_REALTIME);
    if (!started || !finished || finished < started) uncertainty("wall-clock-unavailable-or-changed");
    append(",\"activity\":{\"scope\":\"global-cooperative-snapshot\",\"helpers\":%zu,\"descendants\":%zu,\"mounts\":%zu,\"other_user_sessions\":%zu,\"clear_at_observation\":%s}",
        activity_helpers,activity_descendants,activity_mounts,activity_other_sessions,
        !uncertainties && !activity_helpers && !activity_descendants && !activity_mounts && !activity_other_sessions ? "true" : "false");
    append(",\"finished_ns\":%llu,\"complete\":%s,\"uncertainties\":[",
        (unsigned long long)finished, uncertainties ? "false" : "true");
    for (unsigned i = 0; i < uncertainties; i++) {
        append("%s", i ? "," : ""); string(uncertain[i], strlen(uncertain[i]));
    }
    append("]}\n");
    int result = uncertainties ? 1 : 0;
    if (out.overflow) {
        const char *failed = "{\"schema\":1,\"scope\":\"global-kernel-snapshot\",\"complete\":false,\"uncertainties\":[\"output-capacity\"]}\n";
        result = write_all(STDOUT_FILENO, failed, strlen(failed)) ? 1 : 1;
    } else if (write_all(STDOUT_FILENO, out.data, out.used)) result = 1;
    free(out.data); return result;
}
static void stop(int number) { interrupted = number; }
static int no_acl(int fd) {
    errno = 0; acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
    if (!acl) return errno == ENOENT;
    acl_entry_t entry; errno = 0;
    int valid = acl_valid(acl), result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry), error = errno;
    int empty = !valid && result == -1 && error == EINVAL;
    if (acl_free(acl)) return 0;
    return empty;
}
static int same_file(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink;
}
static int app_overlap(const char *literal) {
    const char *app = "/Applications/StallionFS.app";
    const char *data = "/System/Volumes/Data";
    size_t data_length = strlen(data);
    if (!strncasecmp(literal,data,data_length) && literal[data_length] == '/') literal += data_length;
    size_t length = strlen(app);
    return !strncasecmp(literal, app, length) && (!literal[length] || literal[length] == '/');
}
static int private_directory(const char *literal) {
    if (strstr(literal, "//") || literal[0] != '/' || literal[1] == '/' || strlen(literal) >= PATH_MAX || literal[strlen(literal)-1] == '/') return -1;
    struct stat app_info; int app_known = !stat("/Applications/StallionFS.app",&app_info);
    if (!app_known && errno != ENOENT && errno != ENOTDIR) return -1;
    if (SFS_TEST_FAULT == 16) {
        char parent[PATH_MAX]; strcpy(parent,literal); char *last = strrchr(parent,'/');
        if (!last || last == parent) return -1;
        *last = 0; app_known = !stat(parent,&app_info);
    }
    char path[PATH_MAX]; strcpy(path, literal);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    char *save = NULL, *part = strtok_r(path + 1, "/", &save);
    while (part) {
        if (!strcmp(part, ".") || !strcmp(part, "..")) { close(fd); return -1; }
        int next = openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        if (close(fd) || next < 0) { if (next >= 0) close(next); return -1; }
        fd = next;
        struct stat opened;
        if (fstat(fd,&opened) || (app_known && opened.st_dev == app_info.st_dev && opened.st_ino == app_info.st_ino)) {
            close(fd); return -1;
        }
        part = strtok_r(NULL, "/", &save);
    }
    struct stat info;
    if (fstat(fd, &info) || info.st_uid != getuid() || (info.st_mode & 07777) != 0700 || !no_acl(fd)) {
        close(fd); return -1;
    }
    int duplicate = dup(fd); if (duplicate < 0) { close(fd); return -1; }
    DIR *directory = fdopendir(duplicate);
    if (!directory) { close(duplicate); close(fd); return -1; }
    int empty = 1; struct dirent *entry;
    errno = 0;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) { empty = 0; break; }
    int scan_error = errno;
    int closed = closedir(directory);
    if (scan_error || closed || !empty) { close(fd); return -1; }
    return fd;
}
static int bound(int directory, const char *name, int fd, const struct stat *initial) {
    struct stat held, named;
    return !fstat(fd, &held) && !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) &&
        same_file(initial, &held) && same_file(&held, &named) && held.st_uid == getuid() &&
        S_ISREG(held.st_mode) && (held.st_mode & 07777) == 0600 && held.st_nlink == 1 && no_acl(fd);
}
static int content_equal(const struct stat *a, const struct stat *b) {
    return same_file(a,b) && a->st_size == b->st_size &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec && a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec && a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int readback(int directory, const char *name, int fd, size_t bytes, const unsigned char *expected) {
    struct stat before, after, named;
    if (fstat(fd,&before) || before.st_size < 0 || (uint64_t)before.st_size != bytes) return 0;
    CC_SHA256_CTX hash; unsigned char actual[CC_SHA256_DIGEST_LENGTH];
    if (!CC_SHA256_Init(&hash)) return 0;
    char block[65536]; size_t offset = 0;
    while (offset < bytes) {
        size_t count = bytes-offset < sizeof block ? bytes-offset : sizeof block;
        ssize_t n = pread(fd,block,count,(off_t)offset);
        if (n <= 0 || !CC_SHA256_Update(&hash,block,(CC_LONG)n)) return 0;
        offset += (size_t)n;
    }
    if (pread(fd,block,1,(off_t)bytes) != 0 || !CC_SHA256_Final(actual,&hash) ||
        memcmp(actual,expected,CC_SHA256_DIGEST_LENGTH) || fstat(fd,&after) ||
        fstatat(directory,name,&named,AT_SYMLINK_NOFOLLOW) ||
        !content_equal(&before,&after) || !content_equal(&after,&named)) return 0;
    return 1;
}
static int directory_bound(int directory, const char *literal, const struct stat *initial) {
    struct stat named, held;
    if (lstat(literal, &named) || fstat(directory, &held) ||
        initial->st_dev != held.st_dev || initial->st_ino != held.st_ino ||
        initial->st_uid != held.st_uid || initial->st_gid != held.st_gid || initial->st_mode != held.st_mode ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino || held.st_uid != named.st_uid ||
        held.st_gid != named.st_gid || held.st_mode != named.st_mode || !no_acl(directory)) return 0;
    int duplicate = dup(directory); if (duplicate < 0) return 0;
    DIR *scan = fdopendir(duplicate); if (!scan) { close(duplicate); return 0; }
    rewinddir(scan); unsigned outputs = 0; int valid = 1; struct dirent *entry;
    for (;;) {
        errno = 0; entry = readdir(scan);
        if (!entry) { if (errno) valid = 0; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!strcmp(entry->d_name, "native.json") || !strcmp(entry->d_name, "native-completion.json")) outputs++;
        else { valid = 0; break; }
    }
    if (closedir(scan)) valid = 0;
    return valid && outputs == 2;
}
static int retain(const char *literal) {
    if (app_overlap(literal)) return 2;
    uint64_t started = clock_ns(CLOCK_REALTIME), monotonic = clock_ns(CLOCK_MONOTONIC);
    int directory = private_directory(literal); if (directory < 0) return 2;
    struct stat dir_initial, output_initial, receipt_initial;
    if (fstat(directory, &dir_initial)) { close(directory); return 2; }
    int output = openat(directory, "native.json", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    int receipt = openat(directory, "native-completion.json", O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (output < 0 || receipt < 0 || fstat(output, &output_initial) || fstat(receipt, &receipt_initial) ||
        !bound(directory, "native.json", output, &output_initial) ||
        !bound(directory, "native-completion.json", receipt, &receipt_initial) ||
        !directory_bound(directory, literal, &dir_initial) || fsync(directory)) {
        if (output >= 0) close(output); if (receipt >= 0) close(receipt); close(directory); return 2;
    }
    struct sigaction action = {0}, original_int, original_term;
    action.sa_handler = stop; sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, &original_int) || sigaction(SIGTERM, &action, &original_term)) {
        close(output); close(receipt); close(directory); return 2;
    }
    int pipes[2] = {-1, -1}; pid_t child = -1;
    const char *outcome = "not-launched";
    int reaped = 0, status = 0, eof = 0, durable = 0, cleanup = 0, io_error = 0, close_error = 0;
    CC_SHA256_CTX output_hash; CC_SHA256_Init(&output_hash);
    size_t bytes = 0; uint64_t deadline = monotonic + (uint64_t)SFS_DEADLINE_MS * 1000000ULL;
    if (!monotonic || pipe(pipes) || fcntl(pipes[0], F_SETFL, O_NONBLOCK)) goto finish;
    acquire_owned_path();
    int controller_mib[]={CTL_KERN,KERN_PROC,KERN_PROC_PID,getpid()}; size_t controller_size=sizeof owned_controller_info;
    if (synthetic()) {
        memset(&owned_controller_info,0,sizeof owned_controller_info);
        owned_controller_info.kp_proc.p_pid=getpid(); owned_controller_info.kp_proc.p_starttime.tv_sec=1;
        owned_controller_info.kp_eproc.e_ucred.cr_uid=getuid(); owned_controller_valid=1;
    } else owned_controller_valid=!sysctl(controller_mib,4,&owned_controller_info,&controller_size,NULL,0) && controller_size==sizeof owned_controller_info;
    if (!owned_controller_valid) uncertainty("owned-controller-identity-unavailable");
    child = fork();
    if (child == 0) {
        owned_controller=getppid();
        signal(SIGINT, SIG_DFL); signal(SIGTERM, SIG_DFL); signal(SIGALRM, SIG_DFL);
        alarm((SFS_DEADLINE_MS + 999) / 1000 + 1);
        if (dup2(pipes[1], STDOUT_FILENO) < 0 || dup2(pipes[1], STDERR_FILENO) < 0) _exit(127);
        int nullfd = open("/dev/null", O_RDONLY | O_NOFOLLOW);
        if (nullfd < 0 || dup2(nullfd, STDIN_FILENO) < 0) _exit(127);
        size_t fd_cap = 65536 * sizeof(struct proc_fdinfo);
        struct proc_fdinfo *fds = calloc(1, fd_cap);
        if (!fds) _exit(127);
        int fd_bytes = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fds, (int)fd_cap);
        if (fd_bytes <= 0 || (size_t)fd_bytes >= fd_cap || fd_bytes % sizeof *fds) _exit(127);
        for (size_t i = 0; i < (size_t)fd_bytes / sizeof *fds; i++)
            if (fds[i].proc_fd >= 3 && close(fds[i].proc_fd)) _exit(127);
        free(fds);
#if SFS_TEST_FAULT == 11
        if (fcntl(42, F_GETFD) != -1 || errno != EBADF) _exit(126);
#endif
        if (SFS_TEST_FAULT == 6) { write_all(1, "{\"partial\":", 11); for (;;) pause(); }
        if (SFS_TEST_FAULT == 7) { char block[4096]; memset(block, 'x', sizeof block); for (;;) if (write_all(1, block, sizeof block)) _exit(1); }
        _exit(observe());
    }
    close(pipes[1]); pipes[1] = -1;
    if (child < 0) goto finish;
    outcome = "running";
    int term_sent = 0, kill_sent = 0; uint64_t stop_at = 0;
    for (;;) {
        uint64_t now = clock_ns(CLOCK_MONOTONIC);
        if ((!now || now >= deadline || interrupted || io_error) && !term_sent) {
            outcome = io_error ? "io-error" : interrupted ? "interrupted" : "timeout";
            stop_at = now; term_sent = 1;
            /* An unreaped direct child cannot have its PID recycled. Never use saved PIDs. */
            if (!reaped && kill(child, SIGTERM) && errno != ESRCH) io_error = 1;
        }
        if (term_sent && !kill_sent && (!now || now - stop_at >= 200000000ULL)) {
            kill_sent = 1;
            if (!reaped && kill(child, SIGKILL) && errno != ESRCH) io_error = 1;
        }
        char buffer[65536];
        for (int reads = 0; reads < 16 && !eof; reads++) {
            ssize_t n = read(pipes[0], buffer, sizeof buffer);
            if (n > 0) {
                size_t keep = (size_t)n <= SFS_OUTPUT_CAP - bytes ? (size_t)n : SFS_OUTPUT_CAP - bytes;
                if (keep && write_all(output, buffer, keep)) io_error = 1;
                if (keep && !CC_SHA256_Update(&output_hash,buffer,(CC_LONG)keep)) io_error = 1;
                bytes += keep;
                if (keep != (size_t)n) {
                    outcome = "output-limit"; io_error = 1;
                    if (!term_sent) { term_sent = 1; stop_at = now; if (!reaped && kill(child, SIGTERM) && errno != ESRCH) io_error = 1; }
                }
            } else if (!n) eof = 1;
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) { io_error = 1; break; }
            else break;
        }
        if (!reaped) {
            pid_t waited = waitpid(child, &status, WNOHANG);
            if (waited == child) reaped = 1;
            else if (waited < 0 && errno != EINTR) { io_error = 1; break; }
        }
        if (reaped && eof) break;
        if (term_sent && (!now || now - stop_at >= 700000000ULL)) break;
        struct pollfd pollfd = {pipes[0], POLLIN | POLLHUP, 0};
        if (poll(&pollfd, 1, 20) < 0 && errno != EINTR) io_error = 1;
    }
    if (!strcmp(outcome, "running")) outcome = io_error ? "io-error" : WIFEXITED(status) && WEXITSTATUS(status) == 0 ? "success" : "error";
finish:
    if (pipes[0] >= 0 && close(pipes[0])) io_error = close_error = 1;
    if (pipes[1] >= 0 && close(pipes[1])) io_error = close_error = 1;
    unsigned char output_digest[CC_SHA256_DIGEST_LENGTH];
    if (!CC_SHA256_Final(output_digest,&output_hash)) io_error = 1;
    char output_sha256[CC_SHA256_DIGEST_LENGTH*2+1];
    for (size_t i=0;i<sizeof output_digest;i++) snprintf(output_sha256+i*2,3,"%02x",output_digest[i]);
    if (SFS_TEST_FAULT == 13 && ftruncate(output,0)) io_error = 1;
    if (SFS_TEST_FAULT == 14 && pwrite(output,"X",1,0) != 1) io_error = 1;
    durable = !fsync(output);
    int output_readback = durable && readback(directory,"native.json",output,bytes,output_digest);
    if (!output_readback) io_error = 1;
    int dir_bound = directory_bound(directory, literal, &dir_initial);
    int output_bound = bound(directory, "native.json", output, &output_initial);
    int receipt_bound = bound(directory, "native-completion.json", receipt, &receipt_initial);
    if (close(output)) { io_error = close_error = 1; durable = 0; }
    if (SFS_TEST_FAULT == 12) { io_error = close_error = 1; outcome = "io-error"; }
    cleanup = child > 0 && reaped && eof && !close_error;
    int complete = cleanup && durable && output_readback && dir_bound && output_bound && receipt_bound && !io_error &&
        (!strcmp(outcome, "success") || !strcmp(outcome, "error"));
    int returncode = reaped && WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    char value[2048];
    int length = snprintf(value, sizeof value,
        "{\"schema\":1,\"worker_pid\":%d,\"started_ns\":%llu,\"finished_ns\":%llu,\"deadline_ms\":%d,\"output_cap\":%d,\"reaped\":%s,\"returncode\":%d,\"wait_status\":%d,\"outcome\":\"%s\",\"streams_eof\":%s,\"output_bytes\":%zu,\"output_sha256\":\"%s\",\"output_readback\":%s,\"output_durable\":%s,\"directory_bound\":%s,\"output_bound\":%s,\"cleanup_complete\":%s,\"io_error\":%s,\"close_errors\":%s,\"complete\":%s}\n",
        child, (unsigned long long)started, (unsigned long long)clock_ns(CLOCK_REALTIME),
        SFS_DEADLINE_MS, SFS_OUTPUT_CAP, reaped ? "true" : "false", returncode, status, outcome,
        eof ? "true" : "false", bytes, output_sha256, output_readback ? "true" : "false", durable ? "true" : "false", dir_bound ? "true" : "false",
        output_bound ? "true" : "false", cleanup ? "true" : "false", io_error ? "true" : "false",
        close_error ? "true" : "false", complete ? "true" : "false");
    if (length < 0 || (size_t)length >= sizeof value || !receipt_bound ||
        write_all(receipt, value, (size_t)length) || fsync(receipt)) complete = 0;
    if (SFS_TEST_FAULT == 15 && ftruncate(receipt,0)) complete = 0;
    unsigned char receipt_digest[CC_SHA256_DIGEST_LENGTH];
    if (length < 0 || (size_t)length >= sizeof value ||
        !CC_SHA256(value,(CC_LONG)length,receipt_digest) ||
        !readback(directory,"native-completion.json",receipt,(size_t)length,receipt_digest) ||
        !bound(directory,"native-completion.json",receipt,&receipt_initial) ||
        !directory_bound(directory,literal,&dir_initial)) complete = 0;
    if (close(receipt)) complete = 0;
    if (fsync(directory)) complete = 0;
    if (close(directory)) complete = 0;
    sigaction(SIGINT, &original_int, NULL); sigaction(SIGTERM, &original_term, NULL);
    return complete ? 0 : 1;
}
int main(int argc, char **argv) {
    umask(077);
    if (argc == 2 && !strcmp(argv[1], "observe")) return observe();
    if (argc == 3 && !strcmp(argv[1], "retain")) return retain(argv[2]);
    return 2;
}
