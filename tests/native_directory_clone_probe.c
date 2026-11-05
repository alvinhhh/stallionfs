/* Hosted, synthetic-fixture feasibility probe. Never a production backend. */
#include <inttypes.h>
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU)
#error "Directory feasibility requires an ordinary source build"
#endif
/* Keep root admission identical to the existing implementation. */
#include "../stallionfs/_tree.c"
#ifdef STALLIONFS_DIRECTORY_PREFLIGHT_TEST_HEADER
#include STALLIONFS_DIRECTORY_PREFLIGHT_TEST_HEADER
#endif

static int component(const char *value) {
    return value && *value && strcmp(value, ".") && strcmp(value, "..") &&
        !strchr(value, '/') && strlen(value) <= NAME_MAX;
}

static int number(const char *value, uintmax_t *result) {
    if (!value || !*value) return -1;
    for (const char *p = value; *p; p++) if (*p < '0' || *p > '9') return -1;
    char *end; errno = 0; *result = strtoumax(value, &end, 10);
    return errno || *end ? -1 : 0;
}

static int pinned(int fd, uintmax_t device, uintmax_t inode, struct stat *value) {
    if (fstat(fd, value)) return -1;
    if (!S_ISDIR(value->st_mode) || (uintmax_t)value->st_dev != device ||
        (uintmax_t)value->st_ino != inode || value->st_uid != geteuid()) {
        errno = ESTALE; return -1;
    }
    return 0;
}

/* Current private small recipes only; document admission is not increased. */
enum { PROBE_ENTRY_LIMIT = 18, PROBE_DEPTH_LIMIT = 2 };

/* Consumes owned_fd even on failure; ancestors remain borrowed and held. */
static int source_types(int owned_fd, int named_parent, const char *name,
                        const struct stat *expected, dev_t device, unsigned depth,
                        unsigned *visited, int *close_error) {
    DIR *entries = fdopendir(owned_fd);
    if (!entries) {
        int error = errno ? errno : EIO;
        if (close(owned_fd) && !*close_error) *close_error = errno ? errno : EIO;
        errno = error;
        return -1;
    }
    int fd = dirfd(entries), error = 0;
    struct stat held, named;
    if (fd < 0 || fstat(fd, &held)) error = errno ? errno : EIO;
    else if (held.st_dev != device) error = EXDEV;
    else if (!S_ISDIR(held.st_mode) || !same_object(&held, expected)) error = ESTALE;
    while (!error) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) error = errno; break; }
        const char *child_name = entry->d_name;
        if (!strcmp(child_name, ".") || !strcmp(child_name, "..")) continue;
        if (!component(child_name)) { error = EINVAL; break; }
        if (++*visited > PROBE_ENTRY_LIMIT) { error = E2BIG; break; }
        /* Stat every name: d_type may be unknown, stale or unsupported. */
        if (fstatat(fd, child_name, &named, AT_SYMLINK_NOFOLLOW)) { error = errno ? errno : EIO; break; }
        if (named.st_dev != device) { error = EXDEV; break; }
        if (entry->d_ino && named.st_ino != entry->d_ino) { error = ESTALE; break; }
        if (!S_ISDIR(named.st_mode) && !S_ISREG(named.st_mode) && !S_ISLNK(named.st_mode)) {
            error = ENOTSUP; break;
        }
        if (S_ISDIR(named.st_mode)) {
            if (depth >= PROBE_DEPTH_LIMIT) { error = ELOOP; break; }
            int child = openat(fd, child_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { error = errno ? errno : EIO; break; }
            if (source_types(child, fd, child_name, &named, device, depth + 1, visited, close_error))
                error = errno ? errno : EIO;
        }
    }
    if (!error) {
        if (fstat(fd, &held)) error = errno ? errno : EIO;
        else if (held.st_dev != device) error = EXDEV;
        else if (!same_object(&held, expected)) error = ESTALE;
        else if (fstatat(named_parent, name, &named, AT_SYMLINK_NOFOLLOW)) error = errno ? errno : EIO;
        else if (!same_object(&held, &named)) error = ESTALE;
    }
    if (closedir(entries)) {
        int failed_close = errno ? errno : EIO;
        if (!*close_error) *close_error = failed_close;
        if (!error) error = failed_close;
    }
    errno = error;
    return error ? -1 : 0;
}

/* Shared with the fake-C behavior tests; main retains the earlier refusals. */
static int probe_clone_admitted(int root, int source, int parent,
                               const char *source_name, const char *parent_name, const char *destination,
                               const struct stat *source_info, const struct stat *parent_info,
                               int *calls, int *close_error) {
    if (no_mounts(source)) return -1;
    int copy = fcntl(source, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) return -1;
    unsigned visited = 1;
    if (source_types(copy, root, source_name, source_info, source_info->st_dev, 0, &visited, close_error)) return -1;
    if (no_mounts(source)) return -1;
    struct stat named;
    if (fstatat(root, source_name, &named, AT_SYMLINK_NOFOLLOW)) return -1;
    if (!same_object(&named, source_info)) { errno = ESTALE; return -1; }
    if (fstatat(root, parent_name, &named, AT_SYMLINK_NOFOLLOW)) return -1;
    if (!same_object(&named, parent_info)) { errno = ESTALE; return -1; }
    if (!fstatat(parent, destination, &named, AT_SYMLINK_NOFOLLOW)) { errno = EEXIST; return -1; }
    if (errno != ENOENT) return -1;
    *calls = 1;
    return fclonefileat(source, parent, destination, CLONE_NOFOLLOW | CLONE_ACL);
}

int main(int argc, char **argv) {
    const char *hosted = getenv("STALLIONFS_DIRECTORY_FEASIBILITY_HOSTED");
    const char *actions = getenv("GITHUB_ACTIONS"), *temporary = getenv("RUNNER_TEMP");
    uintmax_t values[6];
    if (argc != 11 || !hosted || strcmp(hosted, "1") || !actions || strcmp(actions, "true") ||
        !temporary || temporary[0] != '/' || strlen(temporary) >= PATH_MAX || strlen(argv[1]) >= PATH_MAX ||
        strncmp(argv[1], temporary, strlen(temporary)) || argv[1][strlen(temporary)] != '/' ||
        !component(argv[4]) || !component(argv[5]) || !component(argv[6])) return 2;
    char canonical[PATH_MAX];
    if (!realpath(argv[1], canonical) || strcmp(canonical, argv[1])) return 2;
    const int indices[] = {2, 3, 7, 8, 9, 10};
    for (int i = 0; i < 6; i++) if (number(argv[indices[i]], &values[i])) return 2;
    int root = -1, source = -1, parent = -1, result = -1, error = 0, calls = 0, close_error = 0;
    struct stat root_info, source_info, parent_info, named;
    root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) error = errno;
    if (!error && pinned(root, values[0], values[1], &root_info)) error = errno;
    if (!error && (root_info.st_mode & 0777) != 0700) error = EPERM;
    if (!error && stallion_protected_directory_fd(root, 1)) error = errno;
    if (!error && (source = openat(root, argv[4], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) error = errno;
    if (!error && pinned(source, values[2], values[3], &source_info)) error = errno;
    if (!error && (parent = openat(root, argv[5], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) < 0) error = errno;
    if (!error && pinned(parent, values[4], values[5], &parent_info)) error = errno;
    /* A recursive syscall cannot rely on the ordinary private staging tree. */
    if (!error && protected_parent(parent, source_info.st_dev, CLONING, 1)) error = errno;
    if (!error && outside_source(parent, &source_info)) error = errno;
    if (!error) {
        if (!fstatat(parent, argv[6], &named, AT_SYMLINK_NOFOLLOW)) error = EEXIST;
        else if (errno != ENOENT) error = errno;
    }
    if (!error && fstatat(root, argv[4], &named, AT_SYMLINK_NOFOLLOW)) error = errno;
    if (!error && !same_object(&named, &source_info)) error = ESTALE;
    if (!error && fstatat(root, argv[5], &named, AT_SYMLINK_NOFOLLOW)) error = errno;
    if (!error && !same_object(&named, &parent_info)) error = ESTALE;
    if (!error) {
        result = probe_clone_admitted(root, source, parent, argv[4], argv[5], argv[6],
                                      &source_info, &parent_info, &calls, &close_error);
        error = result ? errno : 0;
    }
    if (parent >= 0 && close(parent) && !close_error) close_error = errno;
    if (source >= 0 && close(source) && !close_error) close_error = errno;
    if (root >= 0 && close(root) && !close_error) close_error = errno;
    /* Exit success denotes a completed transport, including ordinary refusal. */
    char native[96];
    if (calls) snprintf(native, sizeof(native), "\"native_return\":%d,\"native_errno\":%d", result, error);
    else strcpy(native, "\"native_return\":null,\"native_errno\":null");
    if (printf("{\"schema\":1,\"marker\":\"directory-clone-feasibility-v1\",%s,"
        "\"admission_errno\":%d,\"clone_calls\":%d,\"close_error\":%d}\n",
        native, calls ? 0 : error, calls, close_error) < 0 || fflush(stdout)) return 3;
    return 0;
}
