"""Ownership contracts using disposable privileged fixtures, never host accounts."""
from copy import deepcopy
import errno
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shlex
import subprocess
import sys
import sysconfig
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'Ownership integration requires macOS APFS')
class Ownership(unittest.TestCase):
    def privileged_case(self, name):
        import stallionfs
        command = [sys.executable, '-I', '-B', str(Path(__file__).resolve()), name,
                   str(Path(stallionfs.__file__).resolve().parent.parent),
                   str(os.getuid() or 65533), str(os.getgid() or 65533)]
        if os.geteuid() != 0:
            probe = subprocess.run(['/usr/bin/sudo', '-n', '/usr/bin/true'],
                                   capture_output=True, text=True, timeout=15)
            if probe.returncode:
                if os.environ.get('CI') == 'true':
                    self.fail(f'CI requires passwordless sudo for ownership fixtures: {probe.stderr}')
                self.skipTest('Ownership fixture requires root or passwordless sudo')
            command = ['/usr/bin/sudo', '-n', '--', *command]
        result = subprocess.run(command, capture_output=True, text=True, timeout=180, cwd='/')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_privileged_copy_clone_move_preserve_foreign_ownership(self):
        self.privileged_case('privileged')

    def test_unprivileged_copy_refuses_loss_clone_uses_darwin_ownership_move_preserves(self):
        self.privileged_case('unprivileged')

    def test_move_round_trip_preserves_acl_xattrs_resource_fork_and_aliases(self):
        self.privileged_case('metadata')

    def test_image_import_preserves_foreign_ownership_and_aliases(self):
        self.privileged_case('image')


def run_case(name, package, uid, gid):
    sys.path.insert(0, package)
    tests = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location('ownership_checks', tests / 'perf/native_correctness.py')
    checks = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(checks)
    case = unittest.TestCase()
    case.assertEqual(os.geteuid(), 0)
    binary = Path(sysconfig.get_path('scripts')) / 'sfs'
    case.assertTrue(binary.is_file(), f'Installed native CLI missing: {binary}')
    foreign_uid = 65534 if uid != 65534 else 65532
    foreign_gid = 65534 if gid != 65534 else 65532

    def fixture(parent, owner, group):
        source = parent / 'source'
        source.mkdir(mode=0o755)
        (source / 'directory').mkdir(mode=0o755)
        (source / 'directory/file').write_bytes(b'ownership\x00contents')
        (source / 'directory/file').chmod(0o644)
        os.link(source / 'directory/file', source / 'alias')
        (source / 'link').symlink_to('directory/file')
        for path in (source / 'directory/file', source / 'directory', source / 'link', source):
            os.lchown(path, owner, group)
        source.chmod(0o777)
        (source / 'directory').chmod(0o777)
        observed = checks.snapshot(source)
        case.assertEqual({(row['uid'], row['gid']) for row in observed['entries'].values()},
                         {(owner, group)})
        return source, observed

    def compare(before, path, move=False):
        after = checks.snapshot(path)
        report = checks.verify_move(before, after) if move else checks.compare(before, after)
        case.assertTrue(report['strict_equal'], report)
        if move:
            case.assertTrue(report['move_identity'], report)
        return after

    def operate(operation, source, destination, actor=None, strategy=None):
        credentials = {} if actor is None else dict(user=uid, group=gid, extra_groups=[])
        argv = [str(binary), '--json', operation, str(source), str(destination)]
        if strategy:
            argv += ['--strategy', strategy]
        return subprocess.run(argv, capture_output=True, text=True, timeout=30,
                              cwd='/', **credentials)

    with tempfile.TemporaryDirectory(prefix='stallionfs-ownership-') as temporary:
        base = Path(temporary).resolve()
        if name in ('privileged', 'unprivileged'):
            base.chmod(0o755)
            for owner, group in ((foreign_uid, foreign_gid), (uid, foreign_gid)):
                for operation, strategy in (('copy', 'materialized'), ('copy', 'auto'),
                                            ('clone', None), ('move', None)):
                    for shape in ('tree', 'file', 'directory', 'link', 'alias'):
                        parent = base / f'{owner}-{operation}-{strategy}-{shape}'
                        parent.mkdir(mode=0o700)
                        if name == 'unprivileged':
                            os.chown(parent, uid, gid)
                        tree, _ = fixture(parent, owner, group)
                        source = tree if shape == 'tree' else tree / {
                            'file': 'directory/file', 'directory': 'directory',
                            'link': 'link', 'alias': 'alias'}[shape]
                        before = checks.snapshot(source)
                        destination = parent / 'destination'
                        result = operate(operation, source, destination,
                                         actor=uid if name == 'unprivileged' else None,
                                         strategy=strategy)
                        context = (name, owner, operation, strategy, shape, result.stderr)
                        if name == 'unprivileged' and operation == 'copy':
                            case.assertEqual(result.returncode, 1, context)
                            error = json.loads(result.stderr)['error']
                            case.assertTrue(any(error.endswith(os.strerror(code)) for code in
                                                (errno.EPERM, errno.EACCES, errno.ENOTSUP)), context)
                            # Copy must never report success after dropping uid/gid.
                            report = checks.verify_source(before, checks.snapshot(source))
                            case.assertTrue(report['unchanged'], report)
                            if os.path.lexists(destination):
                                case.assertFalse(checks.compare(before, checks.snapshot(destination))['strict_equal'])
                            continue
                        case.assertEqual(result.returncode, 0, context)
                        expected = deepcopy(before)
                        if name == 'unprivileged' and operation == 'clone':
                            # clonefile(2): ownership is that of a newly created inode.
                            for row in expected['entries'].values():
                                row['uid'], row['gid'] = uid, gid
                        compare(expected, destination, move=operation == 'move')
                        if operation == 'move':
                            case.assertFalse(os.path.lexists(source))
                        else:
                            report = checks.verify_source(before, checks.snapshot(source))
                            case.assertTrue(report['unchanged'], report)
        elif name == 'metadata':
            source, _ = fixture(base, uid, gid)
            path = source / 'directory/file'
            for attribute, value in (('org.stallionfs.ownership', b'\x00binary\xff'),
                                     ('com.apple.ResourceFork', b'fork\x00\xff')):
                subprocess.run(['/usr/bin/xattr', '-wx', attribute, value.hex(), str(path)],
                               check=True, capture_output=True, timeout=15)
            user = pwd.getpwuid(os.getuid()).pw_name
            acl = f'user:{user} allow read,readattr,readextattr,readsecurity'
            subprocess.run(['/bin/chmod', '+a', acl, str(path)], check=True,
                           capture_output=True, timeout=15)
            before = checks.snapshot(source)
            row = before['entries']['directory/file']
            case.assertTrue(row['acl']['text_hex'])
            case.assertIn(b'com.apple.ResourceFork'.hex(), row['xattrs'])
            case.assertIn(b'org.stallionfs.ownership'.hex(), row['xattrs'])
            for destination in (base / 'moved', base / 'restored'):
                result = operate('move', source, destination)
                case.assertEqual(result.returncode, 0, result.stderr)
                compare(before, destination, move=True)
                case.assertFalse(source.exists())
                source = destination
        elif name == 'image':
            from stallionfs import _image
            host = base / 'host'
            host.mkdir(mode=0o700)
            source, _ = fixture(host, foreign_uid, foreign_gid)
            os.chown(source, 0, os.getegid())
            source.chmod(0o700)
            before = checks.snapshot(source)
            output = base / 'candidate'
            output.mkdir(mode=0o700)
            def pair(path):
                info = path.stat()
                return [info.st_dev, info.st_ino]
            attempted = []
            result = _image.create_from_tree(
                {'directory': str(source), 'root': pair(source)},
                {'directory': str(output), 'parent': pair(output), 'component': 'image.sfs',
                 'before_create': lambda: attempted.append(True)}, 1 << 26)
            case.assertTrue(result['candidate_complete'], result)
            case.assertEqual(attempted, [True])
            checker = base / 'describe-image'
            repository = tests.parent
            subprocess.run([*shlex.split(os.environ.get('CC', 'cc')), '-O0',
                            '-Wno-deprecated-declarations', '-I', str(repository / 'filesystem'),
                            str(tests / 'native_image_fixture.c'), str(repository / 'filesystem/image.c'),
                            '-o', str(checker)], check=True, capture_output=True, timeout=60)
            inodes = {}
            for relative, expected in before['entries'].items():
                result = subprocess.run([str(checker), 'describe', str(output),
                                         'repo/' + relative if relative else 'repo'],
                                        check=True, capture_output=True, text=True, timeout=15)
                observed = json.loads(result.stdout)
                case.assertEqual((observed['uid'], observed['gid']),
                                 (expected['uid'], expected['gid']), relative)
                case.assertEqual(observed['mode'] & 0o7777, expected['mode'], relative)
                if expected['kind'] == 'file':
                    case.assertEqual(observed['sha256'], expected['sha256'], relative)
                elif expected['kind'] == 'symlink':
                    case.assertEqual(observed['target'], expected['symlink_bytes'], relative)
                inodes[relative] = observed['inode']
            case.assertEqual(inodes['alias'], inodes['directory/file'])
            case.assertNotEqual(inodes['link'], inodes['directory/file'])
            report = checks.verify_source(before, checks.snapshot(source))
            case.assertTrue(report['unchanged'], report)
        else:
            raise ValueError(name)


if __name__ == '__main__':
    run_case(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
