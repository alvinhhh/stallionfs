#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

struct counts { uint64_t files, directories, symlinks, other, bytes, skipped; };

/* Each directory descriptor is owned by this call, including on failure. */
static int walk(int fd, dev_t device, unsigned depth, struct counts *c) {
    DIR *dir = fdopendir(fd);
    if (!dir) { int e = errno; close(fd); errno = e; return -1; }
    int failure = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { failure = errno; break; }
        const char *name = entry->d_name;
        if (name[0] == '.' && (!name[1] || (name[1] == '.' && !name[2]))) continue;
        struct stat st;
        if (fstatat(dirfd(dir), name, &st, AT_SYMLINK_NOFOLLOW)) { failure = errno; break; }
        if (S_ISREG(st.st_mode)) { c->files++; c->bytes += (uint64_t)st.st_size; }
        else if (S_ISLNK(st.st_mode)) c->symlinks++;
        else if (S_ISDIR(st.st_mode)) {
            if (st.st_dev != device) { c->skipped++; continue; }
            c->directories++;
            if (depth >= 511) { failure = EOVERFLOW; break; }
            int child = openat(dirfd(dir), name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (child < 0) { failure = errno; break; }
            if (walk(child, device, depth + 1, c)) { failure = errno; break; }
        } else c->other++;
    }
    if (closedir(dir) && !failure) failure = errno;
    if (failure) { errno = failure; return -1; }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: real_world_scan DIRECTORY\n"); return 2; }
    int fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { perror("open root"); return 1; }
    struct stat st;
    if (fstat(fd, &st)) { perror("stat root"); close(fd); return 1; }
    struct counts c = {0};
    if (walk(fd, st.st_dev, 0, &c)) { perror("scan"); return 1; }
    printf("{\"files\":%" PRIu64 ",\"directories\":%" PRIu64
           ",\"symlinks\":%" PRIu64 ",\"other\":%" PRIu64
           ",\"logical_bytes\":%" PRIu64 ",\"skipped_mounts\":%" PRIu64 "}\n",
           c.files, c.directories, c.symlinks, c.other, c.bytes, c.skipped);
    return 0;
}
