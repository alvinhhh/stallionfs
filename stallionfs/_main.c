#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/clonefile.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include "_tree.h"

static volatile sig_atomic_t interrupted;
static void interrupt(int value) { interrupted = value; }
static int cancelled(void *unused) { (void)unused; return interrupted != 0; }

static int python(int argc, char **argv) {
    uint32_t size = 0;
    _NSGetExecutablePath(NULL, &size);
    char *raw = malloc(size);
    if (!raw) return -1;
    if (_NSGetExecutablePath(raw, &size)) { free(raw); errno = ENAMETOOLONG; return -1; }
    char *path = realpath(raw, NULL);
    free(raw);
    if (!path) return -1;
    char *slash = strrchr(path, '/');
    if (!slash) { free(path); errno = EINVAL; return -1; }
    *slash = 0;
    char *helper = NULL;
    if (asprintf(&helper, "%s/stallionfs-python", path) < 0) { free(path); errno = ENOMEM; return -1; }
    free(path);
    char **arguments = calloc((size_t)argc + 1, sizeof(*arguments));
    if (!arguments) { free(helper); return -1; }
    arguments[0] = helper;
    for (int i = 1; i < argc; i++) arguments[i] = argv[i];
    execv(helper, arguments);
    int error = errno;
    free(arguments); free(helper); errno = error;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 2 || (strcmp(argv[1], "clone") && strcmp(argv[1], "delete") &&
                    strcmp(argv[1], "move") && strcmp(argv[1], "volumes"))) {
        python(argc, argv);
        fprintf(stderr, "stallionfs: cannot run installed Python helper: %s\n", strerror(errno));
        return 1;
    }
    /* Let the common parser render help and structured output. */
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--")) break;
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            python(argc, argv);
            fprintf(stderr, "stallionfs: cannot run installed Python helper: %s\n", strerror(errno));
            return 1;
        }
    }
    unsigned workers = 4;
    int recursive = 0, missing_ok = 0, move_flags = RENAME_EXCL, end_options = 0;
    char *paths[2] = {0};
    int count = 0;
    for (int i = 2; i < argc; i++) {
        const char *arg = argv[i];
        if (!end_options && !strcmp(arg, "--")) { end_options = 1; continue; }
        if (!end_options && !strcmp(arg, "--jobs") && strcmp(argv[1], "move") && strcmp(argv[1], "volumes")) {
            if (++i >= argc || argv[i][0] < '1' || argv[i][0] > '4' || argv[i][1]) goto usage;
            workers = (unsigned)(argv[i][0] - '0');
        } else if (!end_options && !strcmp(argv[1], "delete") && (!strcmp(arg, "--recursive") || !strcmp(arg, "-r"))) recursive = 1;
        else if (!end_options && !strcmp(argv[1], "delete") && !strcmp(arg, "--missing-ok")) missing_ok = 1;
        else if (!end_options && !strcmp(argv[1], "move") && !strcmp(arg, "--replace")) {
            if (move_flags != RENAME_EXCL) goto usage;
            move_flags = 0;
        } else if (!end_options && !strcmp(argv[1], "move") && !strcmp(arg, "--exchange")) {
            if (move_flags != RENAME_EXCL) goto usage;
            move_flags = RENAME_SWAP;
        } else if ((!end_options && arg[0] == '-') || count == 2) goto usage;
        else paths[count++] = argv[i];
    }
    if (!strcmp(argv[1], "volumes")) {
        if (count) goto usage;
        struct statfs *mounts = NULL;
        int length = getmntinfo_r_np(&mounts, MNT_NOWAIT);
        if (!length) { if (!errno) errno = EIO; goto failed; }
        for (int i = 0; i < length; i++)
            printf("%s\t%s\t%s\n", mounts[i].f_fstypename,
                   mounts[i].f_flags & MNT_RDONLY ? "read-only" : "writable", mounts[i].f_mntonname);
        free(mounts);
        if (fflush(stdout) == EOF || ferror(stdout)) { errno = EIO; goto failed; }
        return 0;
    }
    if (count != (!strcmp(argv[1], "delete") ? 1 : 2)) goto usage;
    struct sigaction action = {0};
    action.sa_handler = interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) goto failed;
    char error_path[PATH_MAX] = {0};
    int result;
    if (!strcmp(argv[1], "move")) result = renamex_np(paths[0], paths[1], (unsigned)move_flags);
    else if (!strcmp(argv[1], "clone"))
        result = stallion_clone(paths[0], paths[1], workers, cancelled, NULL, error_path, sizeof(error_path));
    else result = stallion_delete(paths[0], recursive, missing_ok, workers,
                                 cancelled, NULL, error_path, sizeof(error_path));
    if (!result) return 0;
    fprintf(stderr, "stallionfs: %s: %s\n", error_path[0] ? error_path : paths[0], strerror(errno));
    return interrupted ? 128 + interrupted : 1;
usage:
    fprintf(stderr, "stallionfs: invalid arguments; use stallionfs %s --help\n", argv[1]);
    return 2;
failed:
    fprintf(stderr, "stallionfs: %s\n", strerror(errno));
    return 1;
}
