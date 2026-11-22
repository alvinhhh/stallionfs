#define _DARWIN_C_SOURCE
#include <copyfile.h>
#include <sys/clonefile.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

__attribute__((constructor)) static void confine_injection(void) {
    const char *native_key = "STALLIONFS_TEST_NATIVE_EXECUTABLE";
    const char *launcher_key = "STALLIONFS_TEST_FORWARD_EXECUTABLE";
    const char *pid_key = "STALLIONFS_TEST_FORWARD_PID";
    const char *parent = getenv("STALLIONFS_TEST_CUT_PARENT");
    char parent_pid[32], pid[32], raw[PATH_MAX], path[PATH_MAX];
    snprintf(parent_pid, sizeof(parent_pid), "%ld", (long)getppid());
    snprintf(pid, sizeof(pid), "%ld", (long)getpid());
    uint32_t size = sizeof(raw);
    if (parent && !strcmp(parent, parent_pid) && !_NSGetExecutablePath(raw, &size) && realpath(raw, path)) {
        const char *native = getenv(native_key);
        const char *launcher = getenv(launcher_key);
        const char *owner = getenv(pid_key);
        if (native && !owner && !strcmp(path, native)) {
            // The installed native CLI can exec its console helper in this process.
            if ((launcher && setenv(pid_key, pid, 1)) || unsetenv(native_key)) _exit(90);
            return;
        }
        if (!native && launcher && !strcmp(path, launcher) && (!owner || !strcmp(owner, pid))) {
            // A direct Python probe starts here. A native handoff must keep the PID.
            // Consume the exception before the launcher execs the final interpreter.
            if (unsetenv(launcher_key) || unsetenv(pid_key)) _exit(90);
            return;
        }
    }
    if (unsetenv(native_key) || unsetenv(launcher_key) || unsetenv(pid_key)) _exit(90);
    extern char **environ;
    for (size_t index = 0; environ[index];) {
        const char *entry = environ[index];
        const char *equals = strchr(entry, '=');
        if (strncmp(entry, "DYLD_", 5) || !equals) { index++; continue; }
        char *name = strndup(entry, (size_t)(equals - entry));
        if (!name || unsetenv(name)) _exit(90);
        free(name);
        index = 0;
    }
}

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

static void cut_ready_publication(const char *destination) {
    const char *selected = getenv("STALLIONFS_TEST_CUT_PATH");
    // An absolute destination has the same meaning for link and linkat.
    if (selected && destination[0] == '/' && !strcmp(destination, selected))
        cut("ready-link-before");
}

static int stopped_link(const char *source, const char *destination) {
    cut_ready_publication(destination);
    return link(source, destination);
}

static int stopped_linkat(int source_parent, const char *source, int destination_parent,
                          const char *destination, int flags) {
    cut_ready_publication(destination);
    return linkat(source_parent, source, destination_parent, destination, flags);
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
INTERPOSE(stopped_link, link);
INTERPOSE(stopped_linkat, linkat);
INTERPOSE(stopped_write, write);
