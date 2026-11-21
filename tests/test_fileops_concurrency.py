"""Exact-path contention between independent installed CLI processes."""
import errno
import importlib.util
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import sysconfig
import tempfile
import unittest


LAUNCH = '''
import os, sys
os.write(1, b'R')
if sys.stdin.buffer.read(1) != b'G':
    raise SystemExit('Missing launch permission')
os.execv(sys.argv[1], sys.argv[1:])
'''


@unittest.skipUnless(sys.platform == 'darwin', 'Native CLI contention requires macOS APFS')
class FileOperationContention(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='stallionfs-contention-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.binary = Path(sysconfig.get_path('scripts')) / 'sfs'
        self.assertTrue(self.binary.is_file(), f'Installed native CLI missing: {self.binary}')
        spec = importlib.util.spec_from_file_location(
            'contention_checks', Path(__file__).parent / 'perf/native_correctness.py')
        self.checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checks)

    def fixture(self, parent, name):
        source = parent / name
        source.mkdir(mode=0o755)
        for index in range(128):
            (source / f'{name}-{index:03}').write_bytes(name.encode() * 1024)
        os.link(source / f'{name}-000', source / 'alias')
        (source / 'link').symlink_to(f'{name}-000')
        return source, self.checks.snapshot(source)

    def race(self, commands):
        children = []
        try:
            for command in commands:
                children.append(subprocess.Popen(
                    [sys.executable, '-I', '-B', '-c', LAUNCH, str(self.binary), '--json', *map(str, command)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
            for child in children:
                self.assertTrue(select.select([child.stdout], [], [], 15)[0], 'CLI launcher did not become ready')
                self.assertEqual(child.stdout.read(1), b'R')
            for child in children:
                child.stdin.write(b'G')
                child.stdin.flush()
            results = []
            for child in children:
                stdout, stderr = child.communicate(timeout=30)
                results.append((child.returncode, stdout, stderr))
            self.assertEqual(sorted(result[0] for result in results), [0, 1], results)
            return results
        finally:
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.communicate()

    def assert_source_unchanged(self, before, source):
        report = self.checks.verify_source(before, self.checks.snapshot(source))
        self.assertTrue(report['unchanged'], report)

    def assert_error(self, result, code):
        self.assertEqual(result[0], 1, result)
        error = json.loads(result[2])['error']
        self.assertTrue(error.endswith(os.strerror(code)), result)

    def test_copy_clone_compete_for_one_destination_without_merging(self):
        for operations in (('copy', 'copy'), ('clone', 'clone'), ('copy', 'clone')):
            with self.subTest(operations=operations):
                parent = self.base / '-'.join(operations)
                parent.mkdir(mode=0o700)
                fixtures = [self.fixture(parent, name) for name in ('first', 'second')]
                destination = parent / 'destination'
                results = self.race([(operation, source, destination)
                                     for operation, (source, _) in zip(operations, fixtures)])
                winner = next(index for index, result in enumerate(results) if result[0] == 0)
                self.assert_error(results[1 - winner], errno.EEXIST)
                report = self.checks.verify_clone(fixtures[winner][1], self.checks.snapshot(destination))
                self.assertTrue(report['strict_equal'], report)
                self.assertTrue(report['independent_clone'], report)
                self.assertIs(report['sparse_preserved'], True, report)
                for source, before in fixtures:
                    self.assert_source_unchanged(before, source)
                self.assertEqual({path.name for path in parent.iterdir()}, {'first', 'second', 'destination'})

    def test_no_clobber_moves_compete_for_same_destination_or_same_source(self):
        for shared_source in (False, True):
            with self.subTest(shared_source=shared_source):
                parent = self.base / str(shared_source)
                parent.mkdir(mode=0o700)
                first = self.fixture(parent, 'first')
                fixtures = [first, first if shared_source else self.fixture(parent, 'second')]
                destinations = [parent / 'destination', parent / ('other' if shared_source else 'destination')]
                results = self.race([('move', source, destination)
                                     for (source, _), destination in zip(fixtures, destinations)])
                winner = next(index for index, result in enumerate(results) if result[0] == 0)
                self.assert_error(results[1 - winner], errno.ENOENT if shared_source else errno.EEXIST)
                report = self.checks.verify_move(fixtures[winner][1], self.checks.snapshot(destinations[winner]))
                self.assertTrue(report['strict_equal'], report)
                self.assertTrue(report['move_identity'], report)
                self.assertFalse(fixtures[winner][0].exists())
                if shared_source:
                    self.assertFalse(destinations[1 - winner].exists())
                    expected_names = {destinations[winner].name}
                else:
                    self.assert_source_unchanged(fixtures[1 - winner][1], fixtures[1 - winner][0])
                    expected_names = {fixtures[1 - winner][0].name, 'destination'}
                self.assertEqual({path.name for path in parent.iterdir()}, expected_names)
