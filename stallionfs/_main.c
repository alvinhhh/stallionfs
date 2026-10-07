#include <errno.h>
#include <inttypes.h>
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

/* Escape UTF-8 and preserve invalid filesystem bytes as Python surrogate escapes. */
static void json_text(FILE *stream, const char *text) {
    const unsigned char *p = (const unsigned char *)text;
    while (*p) {
        uint32_t code = *p;
        unsigned length = 1;
        if (code >= 0x80) {
            unsigned wanted = code >= 0xc2 && code <= 0xdf ? 2 :
                              code >= 0xe0 && code <= 0xef ? 3 :
                              code >= 0xf0 && code <= 0xf4 ? 4 : 0;
            uint32_t value = code & (wanted == 2 ? 0x1f : wanted == 3 ? 0x0f : 0x07);
            unsigned i = 1;
            for (; i < wanted && (p[i] & 0xc0) == 0x80; i++) value = (value << 6) | (p[i] & 0x3f);
            if (wanted && i == wanted && value >= (wanted == 2 ? 0x80u : wanted == 3 ? 0x800u : 0x10000u) &&
                value <= 0x10ffff && !(value >= 0xd800 && value <= 0xdfff)) {
                code = value; length = wanted;
            } else code = 0xdc00 + *p;
        }
        if (code == '"' || code == '\\') fprintf(stream, "\\%c", (int)code);
        else if (code < 0x20 || code >= 0x7f) {
            if (code > 0xffff) {
                code -= 0x10000;
                fprintf(stream, "\\u%04x\\u%04x", (unsigned)(0xd800 + (code >> 10)), (unsigned)(0xdc00 + (code & 0x3ff)));
            } else fprintf(stream, "\\u%04x", (unsigned)code);
        } else fputc((int)code, stream);
        p += length;
    }
}
static void json_string(FILE *stream, const char *text) {
    fputc('"', stream); json_text(stream, text); fputc('"', stream);
}
static int report_error(int json, const char *path, int error) {
    if (json) {
        fputs("{\"error\":\"", stderr);
        if (path && *path) { json_text(stderr, path); fputs(": ", stderr); }
        json_text(stderr, strerror(error));
        fputs("\"}\n", stderr);
    } else fprintf(stderr, "stallionfs: %s%s%s\n", path ? path : "", path && *path ? ": " : "", strerror(error));
    return interrupted ? 128 + interrupted : 1;
}

int main(int argc, char **argv) {
    int json = 0, command = 1;
    while (command < argc) {
        if (!strcmp(argv[command], "--json")) { json = 1; command++; }
        else if (!strncmp(argv[command], "--root=", 7)) command++;
        else if (!strcmp(argv[command], "--root") && command + 1 < argc && argv[command + 1][0] != '-') command += 2;
        else break;
    }
    if (command >= argc) goto helper;
    const char *name = argv[command];
    int cloning = !strcmp(name, "clone"), deleting = !strcmp(name, "delete"), moving = !strcmp(name, "move");
    int scanning = !strcmp(name, "scan"), volumes = !strcmp(name, "volumes");
    if (!cloning && !deleting && !moving && !scanning && !volumes) goto helper;
    /* Keep help and workspace commands on the shared Python parser. */
    for (int i = command + 1; i < argc; i++) {
        if (!strcmp(argv[i], "--")) break;
        if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) goto helper;
    }
    unsigned workers = 4;
    int recursive = 0, missing_ok = 0, move_flags = RENAME_EXCL, end_options = 0;
    char *paths[2] = {0};
    int count = 0;
    for (int i = command + 1; i < argc; i++) {
        const char *arg = argv[i];
        if (!end_options && !strcmp(arg, "--")) { end_options = 1; continue; }
        if (!end_options && (cloning || deleting) && (!strcmp(arg, "--jobs") || !strncmp(arg, "--jobs=", 7))) {
            const char *value = arg + 7;
            if (!strcmp(arg, "--jobs")) { if (++i >= argc) goto usage; value = argv[i]; }
            if (value[0] < '1' || value[0] > '4' || value[1]) goto usage;
            workers = (unsigned)(value[0] - '0');
        } else if (!end_options && deleting && (!strcmp(arg, "--recursive") || !strcmp(arg, "-r"))) recursive = 1;
        else if (!end_options && deleting && !strcmp(arg, "--missing-ok")) missing_ok = 1;
        else if (!end_options && moving && !strcmp(arg, "--replace")) {
            if (move_flags != RENAME_EXCL) goto usage;
            move_flags = 0;
        } else if (!end_options && moving && !strcmp(arg, "--exchange")) {
            if (move_flags != RENAME_EXCL) goto usage;
            move_flags = RENAME_SWAP;
        } else if ((!end_options && arg[0] == '-') || count == 2) goto usage;
        else paths[count++] = argv[i];
    }
    if (count != (volumes ? 0 : scanning || deleting ? 1 : 2)) goto usage;
    /* Python preserves expanduser's HOME, named-user and missing-user behavior. */
    if (scanning && paths[0][0] == '~') goto helper;
    struct sigaction action = {0};
    action.sa_handler = interrupt;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGINT, &action, NULL) || sigaction(SIGTERM, &action, NULL)) goto failed;
    if (interrupted) { errno = EINTR; goto failed; }
    if (volumes) {
        struct statfs *mounts = NULL;
        errno = 0;
        int length = getmntinfo_r_np(&mounts, MNT_NOWAIT);
        if (!length) { if (!errno) errno = EIO; goto failed; }
        if (json) fputc('[', stdout);
        for (int i = 0; i < length; i++) {
            if (json) {
                if (i) fputc(',', stdout);
                fputs("{\"path\":", stdout); json_string(stdout, mounts[i].f_mntonname);
                fputs(",\"device\":", stdout); json_string(stdout, mounts[i].f_mntfromname);
                fputs(",\"filesystem\":", stdout); json_string(stdout, mounts[i].f_fstypename);
                printf(",\"readonly\":%s,\"ignore_ownership\":%s,\"owner\":%u}",
                       mounts[i].f_flags & MNT_RDONLY ? "true" : "false",
                       mounts[i].f_flags & MNT_IGNORE_OWNERSHIP ? "true" : "false", (unsigned)mounts[i].f_owner);
            } else printf("%s\t%s\t%s\n", mounts[i].f_fstypename,
                          mounts[i].f_flags & MNT_RDONLY ? "read-only" : "writable", mounts[i].f_mntonname);
        }
        if (json) fputs("]\n", stdout);
        free(mounts);
    } else {
        char error_path[4096] = {0};
        struct stallion_scan_stats stats;
        int result;
        if (scanning) result = stallion_scan(paths[0], 1, &stats, cancelled, NULL, error_path, sizeof(error_path));
        else if (moving) result = renamex_np(paths[0], paths[1], (unsigned)move_flags);
        else if (cloning) result = stallion_clone(paths[0], paths[1], workers, cancelled, NULL, error_path, sizeof(error_path));
        else result = stallion_delete(paths[0], recursive, missing_ok, workers, cancelled, NULL, error_path, sizeof(error_path));
        if (result) return report_error(json, error_path[0] ? error_path : paths[0], errno);
        if (scanning) {
            if (json) printf("{\"files\":%" PRIu64 ",\"directories\":%" PRIu64 ",\"symlinks\":%" PRIu64 ",\"other\":%" PRIu64
                             ",\"logical_bytes\":%" PRIu64 ",\"skipped_mounts\":%" PRIu64 "}\n",
                             stats.files, stats.directories, stats.symlinks, stats.other, stats.logical_bytes, stats.skipped_mounts);
            else printf("%" PRIu64 " files, %" PRIu64 " directories, %" PRIu64 " symlinks, %" PRIu64 " other entries\n"
                        "%" PRIu64 " logical bytes; %" PRIu64 " nested volumes skipped\n",
                        stats.files, stats.directories, stats.symlinks, stats.other, stats.logical_bytes, stats.skipped_mounts);
        } else if (json) {
            fputs(deleting ? "{\"path\":" : "{\"source\":", stdout); json_string(stdout, paths[0]);
            if (!deleting) { fputs(",\"destination\":", stdout); json_string(stdout, paths[1]); }
            fputs("}\n", stdout);
        } else return 0;
    }
    if (fflush(stdout) == EOF || ferror(stdout)) { errno = EIO; goto failed; }
    return 0;
usage:
    fprintf(stderr, "stallionfs: invalid arguments; use stallionfs %s --help\n", name);
    return 2;
failed:
    return report_error(json, NULL, errno);
helper:
    python(argc, argv);
    fprintf(stderr, "stallionfs: cannot run installed Python helper: %s\n", strerror(errno));
    return 1;
}
