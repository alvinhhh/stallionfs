#include <mach-o/dyld.h>
#include <unistd.h>
#include <stdint.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
extern char **environ;
int main(int argc, char **argv) {
    (void)argc;
    char raw[PATH_MAX], physical[PATH_MAX], target[PATH_MAX];
    uint32_t size = sizeof(raw);
    if (_NSGetExecutablePath(raw, &size) || !realpath(raw, physical)) {
        fputs("runtime alias: executable path unavailable\n", stderr); return 126;
    }
    char *slash = strrchr(physical, '/');
    if (!slash) return 126;
    *slash = 0;
    if (snprintf(target, sizeof(target), "%s/%s", physical, TARGET) >= sizeof(target)) return 126;
    execve(target, argv, environ);
    perror("runtime alias"); return 126;
}
