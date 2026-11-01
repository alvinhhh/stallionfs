#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Remain alive to reap the command when its private group is terminated. */
static void interrupted(int number) { (void)number; }
static double seconds(struct timeval value) {
    return (double)value.tv_sec + (double)value.tv_usec / 1000000.0;
}

int main(int argc, char **argv) {
    char *end = NULL;
    if (argc < 4) return 125;
    errno = 0;
    long descriptor = strtol(argv[1], &end, 10);
    if (errno || !end || *end || descriptor < 3 || descriptor > INT_MAX ||
        argv[2][0] != '-' || argv[2][1] != '-' || argv[2][2]) return 125;
    int metrics = (int)descriptor;
    struct sigaction action = {0};
    action.sa_handler = interrupted;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 125;
    struct timespec start, finish;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 125;
    pid_t child = fork();
    if (child < 0) { perror("measurement fork"); return 125; }
    if (!child) {
        signal(SIGTERM, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        if (close(metrics)) { perror("measurement descriptor close"); _exit(126); }
        execvp(argv[3], argv + 3);
        int failure = errno;
        perror("measurement exec");
        _exit(failure == ENOENT ? 127 : 126);
    }
    int status;
    struct rusage usage;
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno != EINTR) { perror("measurement wait4"); return 125; }
    }
    if (clock_gettime(CLOCK_MONOTONIC, &finish)) return 125;
    int result = WIFEXITED(status) ? WEXITSTATUS(status) : -WTERMSIG(status);
    double wall = (double)(finish.tv_sec - start.tv_sec) +
                  (double)(finish.tv_nsec - start.tv_nsec) / 1000000000.0;
    unsigned long long rss = (unsigned long long)usage.ru_maxrss;
#ifndef __APPLE__
    rss *= 1024;
#endif
    int written = dprintf(metrics,
        "{\"returncode\":%d,\"wall_s\":%.9f,\"cpu_s\":%.9f,\"peak_rss_bytes\":%llu}\n",
        result, wall, seconds(usage.ru_utime) + seconds(usage.ru_stime), rss);
    if (close(metrics) || written < 0) return 125;
    return 0;
}
