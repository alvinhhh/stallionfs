"""Tiny fake-call tests of the C directory admission and clone gate."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HEADER = r'''
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>

#define NODE_LIMIT 5120
#define FD_LIMIT 256
struct fake_node { int parent; char name[16]; struct stat info; };
struct fake_fd { int node, alive, stream, position, closes; };
static struct fake_node nodes[NODE_LIMIT];
static struct fake_fd handles[FD_LIMIT];
static struct dirent entries[FD_LIMIT];
static struct stat base_info, parent_info;
static int node_count, next_fd, live, peak, clone_calls, leaf_opens, mount_calls;
static int failure, failure_fd, first_uncertain, acquisition_after_uncertain;
static int named_reads[NODE_LIMIT];

enum faults { HEALTHY, STALE_OPEN, OTHER_DEVICE, MOUNT_BEFORE, MOUNT_AFTER,
    READ_ERROR, FDOPEN_ERROR, CLOSE_ERROR, PRIMARY_AND_CLOSE_ERROR,
    NAME_REPLACED, SOURCE_REPLACED, PARENT_REPLACED, DESTINATION_APPEARED,
    NATIVE_ERROR, CLOSE_AFTER_ERROR, FDOPEN_AND_CLOSE_ERROR,
    STAT_ERROR, NAMED_ERROR, DUP_ERROR, OPEN_ERROR, DIRENT_STALE };

static struct stat make_info(mode_t kind, ino_t inode) {
    struct stat value = {0};
    value.st_dev = 7; value.st_ino = inode; value.st_mode = kind | 0700;
    value.st_uid = geteuid(); value.st_gid = getegid(); value.st_nlink = 1;
    return value;
}

static void reset_fake(void) {
    memset(nodes, 0, sizeof(nodes)); memset(handles, 0, sizeof(handles));
    memset(named_reads, 0, sizeof(named_reads));
    node_count = 1; next_fd = 32; live = peak = 3;
    clone_calls = leaf_opens = mount_calls = first_uncertain = acquisition_after_uncertain = 0;
    failure = HEALTHY; failure_fd = -1;
    nodes[0].parent = -1; nodes[0].info = make_info(S_IFDIR, 100);
    base_info = make_info(S_IFDIR, 80); parent_info = make_info(S_IFDIR, 81);
    for (int fd = 10; fd <= 12; fd++) handles[fd] = (struct fake_fd){.node = fd == 11 ? 0 : -1, .alive = 1};
}

static int add_node(int parent, mode_t kind) {
    assert(node_count < NODE_LIMIT);
    int node = node_count++;
    nodes[node].parent = parent;
    snprintf(nodes[node].name, sizeof(nodes[node].name), "entry-%02d", node);
    nodes[node].info = make_info(kind, 100 + node);
    return node;
}

static void allowed_tree(void) {
    int directory = add_node(0, S_IFDIR);
    int deep = add_node(directory, S_IFDIR);
    add_node(0, S_IFREG); add_node(directory, S_IFLNK); add_node(deep, S_IFREG);
}

static int owned_fd(int node) {
    if (first_uncertain) acquisition_after_uncertain++;
    assert(next_fd < FD_LIMIT);
    int fd = next_fd++;
    handles[fd] = (struct fake_fd){.node = node, .alive = 1};
    live++; if (live > peak) peak = live;
    return fd;
}

static void valid_fd(int fd) {
    assert(fd >= 0 && fd < FD_LIMIT && handles[fd].alive);
}

static struct stat fd_info(int fd) {
    valid_fd(fd);
    if (fd == 10) return base_info;
    if (fd == 12) return parent_info;
    return nodes[handles[fd].node].info;
}

static int fake_fcntl(int fd, int command, ...) {
    assert(fd == 11 && command == F_DUPFD_CLOEXEC);
    if (failure == DUP_ERROR) { errno = EMFILE; return -1; }
    return owned_fd(0);
}

static int fake_fstat(int fd, struct stat *value) {
    if (failure == STAT_ERROR && fd >= 32 && handles[fd].node == 1) { errno = EIO; return -1; }
    *value = fd_info(fd);
    if (failure == STALE_OPEN && handles[fd].node == 1 && fd >= 32) value->st_ino++;
    return 0;
}

static int child_node(int parent, const char *name) {
    for (int node = 1; node < node_count; node++)
        if (nodes[node].parent == parent && !strcmp(nodes[node].name, name)) return node;
    errno = ENOENT; return -1;
}

static int fake_fstatat(int fd, const char *name, struct stat *value, int flags) {
    valid_fd(fd); assert(flags == AT_SYMLINK_NOFOLLOW);
    if (fd == 10) {
        if (!strcmp(name, "source")) {
            *value = nodes[0].info;
            if (failure == SOURCE_REPLACED) value->st_ino++;
            return 0;
        }
        assert(!strcmp(name, "parent")); *value = parent_info;
        if (failure == PARENT_REPLACED) value->st_ino++;
        return 0;
    }
    if (fd == 12) {
        assert(!strcmp(name, "output"));
        if (failure == DESTINATION_APPEARED) { *value = make_info(S_IFREG, 999); return 0; }
        errno = ENOENT; return -1;
    }
    int node = child_node(handles[fd].node, name);
    if (node < 0) return -1;
    if (failure == NAMED_ERROR && node == 1) { errno = EACCES; return -1; }
    *value = nodes[node].info;
    named_reads[node]++;
    if (failure == NAME_REPLACED && named_reads[node] > 1) value->st_ino++;
    return 0;
}

static int fake_openat(int fd, const char *name, int flags, ...) {
    valid_fd(fd);
    assert((flags & (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)) == (O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    int node = child_node(handles[fd].node, name);
    if (node < 0) return -1;
    if (failure == OPEN_ERROR && node == 1) { errno = EMFILE; return -1; }
    if (!S_ISDIR(nodes[node].info.st_mode)) { leaf_opens++; errno = EACCES; return -1; }
    return owned_fd(node);
}

static DIR *fake_fdopendir(int fd) {
    valid_fd(fd); assert(fd >= 32 && !handles[fd].stream);
    if ((failure == FDOPEN_ERROR || failure == FDOPEN_AND_CLOSE_ERROR) && failure_fd < 0) {
        failure_fd = fd; errno = ENOMEM; return NULL;
    }
    handles[fd].stream = 1;
    return (DIR *)(uintptr_t)(fd + 1);
}

static int fake_dirfd(DIR *directory) {
    int fd = (int)(uintptr_t)directory - 1;
    valid_fd(fd); assert(handles[fd].stream); return fd;
}

static struct dirent *fake_readdir(DIR *directory) {
    int fd = fake_dirfd(directory);
    int position = handles[fd].position++;
    struct dirent *entry = &entries[fd]; memset(entry, 0, sizeof(*entry));
    if (failure == READ_ERROR) { errno = EIO; return NULL; }
    if (position < 2) {
        strcpy(entry->d_name, position ? ".." : "."); return entry;
    }
    int found = 0;
    for (int node = 1; node < node_count; node++) {
        if (nodes[node].parent != handles[fd].node) continue;
        if (found++ != position - 2) continue;
        strcpy(entry->d_name, nodes[node].name);
        entry->d_ino = nodes[node].info.st_ino;
        if (failure == DIRENT_STALE && node == 1) entry->d_ino++;
        /* Deliberately wrong for links, directories and unsupported entries. */
        entry->d_type = DT_REG;
        return entry;
    }
    errno = 0; return NULL;
}

static int consume_fd(int fd) {
    valid_fd(fd); assert(fd >= 32 && handles[fd].closes++ == 0);
    int fail = failure == CLOSE_ERROR || failure == CLOSE_AFTER_ERROR ||
        failure == PRIMARY_AND_CLOSE_ERROR || (failure == FDOPEN_AND_CLOSE_ERROR && fd == failure_fd);
    if (!fail || failure == CLOSE_AFTER_ERROR) { handles[fd].alive = 0; live--; }
    if (fail) { first_uncertain = 1; errno = EBUSY; return -1; }
    return 0;
}

static int fake_closedir(DIR *directory) { return consume_fd(fake_dirfd(directory)); }
static int fake_close(int fd) { return consume_fd(fd); }

static int fake_no_mounts(int fd) {
    assert(fd == 11); mount_calls++;
    if ((failure == MOUNT_BEFORE && mount_calls == 1) || (failure == MOUNT_AFTER && mount_calls == 2)) {
        errno = EXDEV; return -1;
    }
    return 0;
}

static int fake_fclonefileat(int source, int parent, const char *name, int flags) {
    assert(source == 11 && parent == 12 && !strcmp(name, "output"));
    assert(flags == (CLONE_NOFOLLOW | CLONE_ACL));
    clone_calls++;
    if (failure == NATIVE_ERROR) { errno = ENOSPC; return -1; }
    return 0;
}

#define fcntl fake_fcntl
#define fstat fake_fstat
#define fstatat fake_fstatat
#define openat fake_openat
#define fdopendir fake_fdopendir
#define dirfd fake_dirfd
#define readdir fake_readdir
#define closedir fake_closedir
#define close fake_close
#define no_mounts fake_no_mounts
#define fclonefileat fake_fclonefileat
'''


HARNESS = r'''
#define STALLIONFS_DIRECTORY_PREFLIGHT_TEST_HEADER HEADER_PATH
#define main unused_probe_main
#include HELPER_PATH
#undef main

static void exercise_profile(int expected, int expected_calls, int expected_close_error,
                             const struct probe_profile *profile) {
    struct stat source = nodes[0].info;
    int calls = 0, close_error = 0;
    errno = 0;
    int result = (profile ? probe_clone_profile(10, 11, 12, "source", "parent", "output",
                                               &source, &parent_info, &calls, &close_error, profile)
                          : probe_clone_admitted(10, 11, 12, "source", "parent", "output",
                                                 &source, &parent_info, &calls, &close_error));
    int error = result ? errno : 0;
    assert(error == expected && result == (expected ? -1 : 0));
    assert(calls == expected_calls && clone_calls == expected_calls);
    assert(close_error == expected_close_error && leaf_opens == 0);
    assert(peak <= 6 && !acquisition_after_uncertain);
    for (int fd = 10; fd <= 12; fd++) assert(handles[fd].alive && !handles[fd].closes);
    for (int fd = 32; fd < next_fd; fd++) {
        assert(handles[fd].closes == 1);
        if (!first_uncertain) assert(!handles[fd].alive);
    }
    if (!first_uncertain) assert(live == 3);
}

static void exercise(int expected, int calls, int close_error) {
    exercise_profile(expected, calls, close_error, NULL);
}

static void docs_tree(void) {
    int directories[100], a = add_node(0, S_IFDIR), b = add_node(0, S_IFDIR);
    for (int i = 0; i < 100; i++) directories[i] = add_node(i % 2 ? a : b, S_IFDIR);
    int metadata = add_node(0, S_IFDIR), nested = add_node(metadata, S_IFDIR);
    for (int i = 0; i < 5000; i++) nodes[add_node(directories[i % 100], S_IFREG)].info.st_size = 20000;
    int first = add_node(metadata, S_IFREG), alias = add_node(nested, S_IFREG);
    nodes[first].info.st_size = nodes[alias].info.st_size = 8388608;
    nodes[first].info.st_nlink = nodes[alias].info.st_nlink = 2;
    nodes[alias].info.st_ino = nodes[first].info.st_ino;
    assert(node_count == 5107);
}

int main(int argc, char **argv) {
    assert(argc == 2); int group = atoi(argv[1]);
    if (group == 1) {
        reset_fake(); allowed_tree(); exercise(0, 1, 0);
        reset_fake(); for (int i = 0; i < 17; i++) add_node(0, S_IFREG); exercise(0, 1, 0);
        reset_fake(); allowed_tree();
        while (node_count < 18) add_node(node_count % 2 ? 0 : 2, S_IFREG);
        exercise(0, 1, 0);
        reset_fake(); failure = NATIVE_ERROR; allowed_tree(); exercise(ENOSPC, 1, 0);
    } else if (group == 2) {
        const mode_t types[] = {S_IFIFO, S_IFSOCK, S_IFCHR, S_IFBLK};
        for (unsigned i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
            reset_fake(); int directory = add_node(0, S_IFDIR); add_node(directory, types[i]);
            exercise(ENOTSUP, 0, 0);
        }
    } else if (group == 3) {
        reset_fake(); for (int i = 0; i < 18; i++) add_node(0, S_IFREG); exercise(E2BIG, 0, 0);
        assert(named_reads[18] == 0);
        reset_fake(); int a = add_node(0, S_IFDIR), b = add_node(a, S_IFDIR); add_node(b, S_IFDIR);
        exercise(ELOOP, 0, 0);
    } else if (group == 4) {
        const int faults[] = {STALE_OPEN, DIRENT_STALE, OTHER_DEVICE, MOUNT_BEFORE, MOUNT_AFTER,
                              NAME_REPLACED, SOURCE_REPLACED, PARENT_REPLACED, DESTINATION_APPEARED};
        const int errors[] = {ESTALE, ESTALE, EXDEV, EXDEV, EXDEV, ESTALE, ESTALE, ESTALE, EEXIST};
        for (unsigned i = 0; i < sizeof(faults) / sizeof(faults[0]); i++) {
            reset_fake(); allowed_tree(); failure = faults[i];
            if (failure == OTHER_DEVICE) nodes[1].info.st_dev++;
            exercise(errors[i], 0, 0);
        }
    } else if (group == 6) {
        reset_fake(); docs_tree(); exercise_profile(0, 1, 0, &docs_profile);
        reset_fake(); docs_tree(); exercise(E2BIG, 0, 0);  /* Default is still eighteen. */
        reset_fake(); docs_tree(); nodes[node_count - 1].info.st_size++;
        exercise_profile(E2BIG, 0, 0, &docs_profile);
        reset_fake(); docs_tree(); nodes[node_count - 1].info.st_size--;
        exercise_profile(EINVAL, 0, 0, &docs_profile);
        reset_fake(); docs_tree(); nodes[node_count - 1].info.st_nlink = 3;
        exercise_profile(E2BIG, 0, 0, &docs_profile);
        reset_fake(); docs_tree(); failure = CLOSE_AFTER_ERROR;
        exercise_profile(EBUSY, 0, EBUSY, &docs_profile);
    } else {
        assert(group == 5);
        reset_fake(); failure = READ_ERROR; exercise(EIO, 0, 0);
        reset_fake(); failure = FDOPEN_ERROR; exercise(ENOMEM, 0, 0);
        reset_fake(); failure = CLOSE_ERROR; exercise(EBUSY, 0, EBUSY);
        reset_fake(); failure = CLOSE_AFTER_ERROR; exercise(EBUSY, 0, EBUSY);
        reset_fake(); allowed_tree(); failure = CLOSE_ERROR; exercise(EBUSY, 0, EBUSY);
        reset_fake(); allowed_tree(); failure = CLOSE_AFTER_ERROR; exercise(EBUSY, 0, EBUSY);
        reset_fake(); add_node(0, S_IFIFO); failure = PRIMARY_AND_CLOSE_ERROR; exercise(ENOTSUP, 0, EBUSY);
        reset_fake(); failure = FDOPEN_AND_CLOSE_ERROR; exercise(ENOMEM, 0, EBUSY);
        reset_fake(); allowed_tree(); failure = STAT_ERROR; exercise(EIO, 0, 0);
        reset_fake(); allowed_tree(); failure = NAMED_ERROR; exercise(EACCES, 0, 0);
        reset_fake(); failure = DUP_ERROR; exercise(EMFILE, 0, 0);
        reset_fake(); allowed_tree(); failure = OPEN_ERROR; exercise(EMFILE, 0, 0);
    }
    return 0;
}
'''


@unittest.skipUnless(sys.platform == 'darwin' and
                     (os.environ.get('GITHUB_ACTIONS') == 'true' or
                      os.environ.get('STALLIONFS_TEST_DIRECTORY_PREFLIGHT') == '1'),
                     'Enable the tiny fake-call C harness on Darwin')
class DirectoryTypePreflight(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='directory-type-fake-')
        cls.addClassCleanup(temporary.cleanup)
        root = Path(temporary.name)
        header = root / 'fake.h'; header.write_text(HEADER)
        helper = Path(__file__).with_name('native_directory_clone_probe.c').resolve()
        code = root / 'fake.c'
        code.write_text(HARNESS.replace('HEADER_PATH', json.dumps(str(header))).replace('HELPER_PATH', json.dumps(str(helper))))
        cls.binary = root / 'fake'
        compiled = subprocess.run(['/usr/bin/xcrun', 'clang', '-std=c11', '-O0', '-Wall', '-Wextra',
                                   '-Werror', '-pthread', str(code), '-o', str(cls.binary)],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=45)
        if compiled.returncode:
            raise AssertionError(compiled.stderr.decode(errors='replace'))

    def exercise(self, group):
        child = subprocess.run([str(self.binary), str(group)], stdin=subprocess.DEVNULL,
                               capture_output=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))
        self.assertEqual(child.stdout, b'')

    def test_regular_symlink_directory_and_exact_eighteen_entries_reach_one_clone(self):
        self.exercise(1)

    def test_fifo_socket_and_devices_are_never_opened_and_never_cloned(self):
        self.exercise(2)

    def test_entry_and_directory_depth_limits_refuse_before_clone(self):
        self.exercise(3)

    def test_stale_identity_device_mount_and_final_binding_errors_refuse_before_clone(self):
        self.exercise(4)

    def test_enumeration_and_close_faults_preserve_primary_errno_and_one_close_ownership(self):
        self.exercise(5)

    def test_explicit_fixed_docs_profile_preserves_default_limits_and_refuses_wrong_size_or_close(self):
        self.exercise(6)


if __name__ == '__main__': unittest.main()
