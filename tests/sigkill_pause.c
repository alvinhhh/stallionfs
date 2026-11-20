#define _DARWIN_C_SOURCE
#include <copyfile.h>
#include <sys/clonefile.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_uint hits;

static void cut(const char *kind) {
    int saved = errno;
    const char *parent = getenv("STALLIONFS_TEST_CUT_PARENT");
    if (parent && getppid() != (pid_t)strtol(parent, NULL, 10)) {
        errno = saved;
        return;
    }
    const char *selected = getenv("STALLIONFS_TEST_CUT_KIND");
    if (selected && !strcmp(selected, kind)) {
        const char *count = getenv("STALLIONFS_TEST_CUT_COUNT");
        unsigned target = count ? (unsigned)strtoul(count, NULL, 10) : 1;
        if (atomic_fetch_add(&hits, 1) + 1 == target) {
            const char *descriptor = getenv("STALLIONFS_TEST_CUT_FD");
            if (!descriptor || write(atoi(descriptor), "R", 1) != 1) _exit(90);
            raise(SIGSTOP);
            _exit(91);
        }
    }
    errno = saved;
}

static int stopped_copy(int source, int destination, copyfile_state_t state, copyfile_flags_t flags) {
    int result = fcopyfile(source, destination, state, flags);
    if (!result) cut("copy");
    return result;
}

static int stopped_clone(int source, int parent, const char *name, int flags) {
    int result = fclonefileat(source, parent, name, flags);
    if (!result) cut("clone");
    return result;
}

static int stopped_move(const char *source, const char *destination, unsigned flags) {
    cut("move-before");
    int result = renamex_np(source, destination, flags);
    if (!result) cut("move-after");
    return result;
}

static int selected_path(const char *path) {
    const char *prefix = getenv("STALLIONFS_TEST_CUT_PATH");
    return !prefix || !strncmp(path, prefix, strlen(prefix));
}

static int stopped_rename(const char *source, const char *destination) {
    if (selected_path(destination)) cut("rename-before");
    int result = rename(source, destination);
    if (!result && selected_path(destination)) cut("rename-after");
    return result;
}

static int stopped_renameat(int source_parent, const char *source, int destination_parent, const char *destination) {
    if (selected_path(destination)) cut("rename-before");
    int result = renameat(source_parent, source, destination_parent, destination);
    if (!result && selected_path(destination)) cut("rename-after");
    return result;
}

static int stopped_unlinkat(int parent, const char *name, int flags) {
    int result = unlinkat(parent, name, flags);
    if (!result) cut("unlink-after");
    return result;
}

static int stopped_open(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = (mode_t)va_arg(args, int);
        va_end(args);
    }
    int result = open(path, flags, mode);
    if (result >= 0 && selected_path(path)) cut("image-ready");
    return result;
}

static ssize_t stopped_write(int descriptor, const void *buffer, size_t size) {
    static const char marker[] = "\"unmounted\"";
    if (descriptor == STDOUT_FILENO && memmem(buffer, size, marker, sizeof(marker) - 1))
        cut("unmount-result");
    return write(descriptor, buffer, size);
}

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { \
        const void *new_function; const void *old_function; \
    } binding_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&replacement, (const void *)&original \
    }

INTERPOSE(stopped_copy, fcopyfile);
INTERPOSE(stopped_clone, fclonefileat);
INTERPOSE(stopped_move, renamex_np);
INTERPOSE(stopped_rename, rename);
INTERPOSE(stopped_renameat, renameat);
INTERPOSE(stopped_unlinkat, unlinkat);
INTERPOSE(stopped_open, open);
INTERPOSE(stopped_write, write);
