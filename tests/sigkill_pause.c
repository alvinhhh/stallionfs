#define _DARWIN_C_SOURCE
#include <copyfile.h>
#include <sys/clonefile.h>
#include <errno.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static atomic_uint hits;

static void cut(const char *kind) {
    int saved = errno;
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

#define INTERPOSE(replacement, original) \
    __attribute__((used)) static struct { \
        const void *new_function; const void *old_function; \
    } binding_##original __attribute__((section("__DATA,__interpose"))) = { \
        (const void *)&replacement, (const void *)&original \
    }

INTERPOSE(stopped_copy, fcopyfile);
INTERPOSE(stopped_clone, fclonefileat);
INTERPOSE(stopped_move, renamex_np);
