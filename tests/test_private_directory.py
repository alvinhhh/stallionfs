"""Private store boundaries must account for macOS ACLs as well as mode bits."""
import os
from pathlib import Path
import pwd
import subprocess
import sys
import tempfile
import unittest

from stallionfs import _scan
from stallionfs.core import Store, StallionError, private_directory, run
from stallionfs import images


@unittest.skipUnless(sys.platform == 'darwin', 'macOS ACLs required')
class PrivateDirectories(unittest.TestCase):
    def test_store_acl_validation_preserves_permissions_and_rejects_before_writing(self):
        user = pwd.getpwuid(os.getuid()).pw_name
        cases = [('read', 'group:everyone allow list,search', False, False),
                 ('mutate', 'group:everyone allow add_file,add_subdirectory,delete_child', False, False),
                 ('inherited', 'group:everyone allow list,search,add_file,add_subdirectory,delete_child,file_inherit,directory_inherit', True, False),
                 ('deny', 'group:everyone deny delete', False, True),
                 ('owner', f'user:{user} allow list,search,add_file,add_subdirectory,delete_child', False, True)]
        with tempfile.TemporaryDirectory(prefix='stallion-private-') as temporary:
            base = Path(temporary).resolve()
            for name, acl, inherited, allowed in cases:
                parent = base / name
                parent.mkdir(mode=0o700)
                try:
                    run(['/bin/chmod', '+a', acl, parent])
                    root = parent / 'store' if inherited else parent
                    if inherited:
                        root.mkdir(mode=0o700)
                    before = run(['/bin/ls', '-lde', root]).splitlines()[1:]
                    identity = root.stat()
                    self.assertEqual(identity.st_mode & 0o777, 0o700)
                    with self.subTest(case=name):
                        if allowed:
                            Store(root)
                            private_directory(root)
                            images._directory(root)
                        else:
                            with self.assertRaises(StallionError): Store(root)
                            with self.assertRaises(StallionError): private_directory(root)
                            with self.assertRaises(StallionError): images._directory(root)
                            self.assertEqual(list(root.iterdir()), [])
                        self.assertEqual(run(['/bin/ls', '-lde', root]).splitlines()[1:], before)
                        self.assertEqual((root.stat().st_ino, root.stat().st_mode), (identity.st_ino, identity.st_mode))
                finally:
                    run(['/bin/chmod', '-RN', parent])
            target = base / 'target'; target.mkdir(mode=0o700)
            alias = base / 'alias'; alias.symlink_to(target, target_is_directory=True)
            for suffix in ('', '/', '///'):
                with self.assertRaises(OSError): _scan._private_directory(str(alias) + suffix)
            _scan._private_directory(str(target) + '///')
            target.chmod(0o755)
            with self.assertRaises(OSError): _scan._private_directory(target)
            for check in (_scan._private_directory, private_directory, images._directory):
                with self.assertRaises(FileNotFoundError): check(base / 'disappeared')

    def test_native_acl_inspection_errors_and_unknown_grants_fail_closed(self):
        source = Path(__file__).resolve().parents[1] / 'stallionfs'
        with tempfile.TemporaryDirectory(prefix='stallion-acl-fault-') as temporary:
            base = Path(temporary).resolve()
            wrapper = base / 'faults.c'
            wrapper.write_text(r'''
#include "_tree.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <membership.h>
#include <stdlib.h>
#include <sys/acl.h>
#include <unistd.h>
#include <uuid/uuid.h>
static int fault;
acl_t test_acl_get_fd_np(int fd, acl_type_t type) {
    (void)fd; (void)type;
    if (fault == 1) { errno = EIO; return NULL; }
    if (fault == 2) { errno = ENOTSUP; return NULL; }
    acl_t acl = acl_init(1); assert(acl);
    acl_entry_t entry; assert(!acl_create_entry(&acl, &entry));
    assert(!acl_set_tag_type(entry, ACL_EXTENDED_ALLOW));
    uuid_t owner; assert(!mbr_uid_to_uuid(getuid(), owner));
    if (fault == 8) uuid_parse("AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE", owner);
    assert(!acl_set_qualifier(entry, owner));
    assert(!acl_set_permset_mask_np(entry, ACL_LIST_DIRECTORY));
    return acl;
}
int test_acl_get_entry(acl_t acl, int which, acl_entry_t *entry) {
    if (fault == 3) { errno = EIO; return -1; }
    return acl_get_entry(acl, which, entry);
}
int test_acl_get_tag_type(acl_entry_t entry, acl_tag_t *tag) {
    if (fault == 4) { *tag = ACL_UNDEFINED_TAG; return 0; }
    return acl_get_tag_type(entry, tag);
}
int test_acl_get_permset_mask_np(acl_entry_t entry, acl_permset_mask_t *mask) {
    if (fault == 5) { errno = EIO; return -1; }
    if (fault == 6) { *mask = (acl_permset_mask_t)1 << 63; return 0; }
    return acl_get_permset_mask_np(entry, mask);
}
void *test_acl_get_qualifier(acl_entry_t entry) {
    if (fault == 7) { errno = EIO; return NULL; }
    return acl_get_qualifier(entry);
}
int test_close(int fd) {
    int result = close(fd);
    if (!result && fault == 9) { errno = EIO; return -1; }
    return result;
}
static int descriptors(void) {
    int count = 0;
    for (int fd = 0; fd < 1024; fd++) if (fcntl(fd, F_GETFD) >= 0) count++;
    return count;
}
int main(int argc, char **argv) {
    assert(argc == 2);
    int before = descriptors();
    int expected[] = {0, EIO, ENOTSUP, EIO, EINVAL, EIO, EINVAL, EIO, EPERM, EIO};
    for (fault = 0; fault < 10; fault++) {
        errno = 0;
        assert(stallion_private_directory(argv[1]) == (fault ? -1 : 0));
        assert(errno == expected[fault]);
        assert(descriptors() == before);
    }
    return 0;
}
''')
            replacements = ['acl_get_fd_np', 'acl_get_entry', 'acl_get_tag_type',
                            'acl_get_permset_mask_np', 'acl_get_qualifier', 'close']
            common = ['cc', '-O2', '-Wall', '-Wextra', '-Werror', '-pthread', '-I', str(source)]
            subprocess.run([*common, *(f'-D{name}=test_{name}' for name in replacements),
                            '-c', str(source / '_tree.c'), '-o', str(base / 'tree.o')], check=True)
            subprocess.run([*common, str(wrapper), str(base / 'tree.o'), '-o', str(base / 'faults')], check=True)
            subprocess.run([str(base / 'faults'), str(base)], check=True, timeout=15)


if __name__ == '__main__':
    unittest.main()
