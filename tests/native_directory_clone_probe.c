/* Hosted, synthetic-fixture feasibility probe. Never a production backend. */
#include <inttypes.h>
#if defined(STALLIONFS_DIAGNOSTIC_THREAD_CPU)
#error "Directory feasibility requires an ordinary source build"
#endif
/* Keep root admission identical to the existing implementation. */
#include "../stallionfs/_tree.c"

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
        calls = 1;
        result = fclonefileat(source, parent, argv[6], CLONE_NOFOLLOW | CLONE_ACL);
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
