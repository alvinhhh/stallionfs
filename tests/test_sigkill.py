"""External process death at real syscall boundaries, not simulated cancellation."""
import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import sysconfig
import tempfile
import time
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'SIGKILL integration requires macOS APFS')
class ProcessDeath(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix='stallionfs-sigkill-hook-')
        cls.addClassCleanup(temporary.cleanup)
        cls.library = Path(temporary.name).resolve() / 'pause.dylib'
        tests = Path(__file__).resolve().parent
        subprocess.run([*shlex.split(os.environ.get('CC', 'cc')), '-std=c11', '-dynamiclib',
                        '-O2', '-Wall', '-Wextra', '-Werror', str(tests / 'sigkill_pause.c'),
                        '-o', str(cls.library)], check=True, timeout=30)
        spec = importlib.util.spec_from_file_location('sigkill_checks', tests / 'perf/native_correctness.py')
        cls.checks = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.checks)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='stallionfs-sigkill-')
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.root = self.base / 'store'
        self.binary = Path(sysconfig.get_path('scripts')) / 'sfs'
        self.assertTrue(self.binary.is_file(), f'Installed native CLI missing: {self.binary}')

    def command(self, *arguments):
        return [str(self.binary), '--root', str(self.root), '--json', *map(str, arguments)]

    def cli(self, *arguments):
        result = subprocess.run(self.command(*arguments), capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return json.loads(result.stdout)

    def fixture(self, path):
        path.mkdir(mode=0o755)
        for index in range(128):
            (path / f'leaf-{index:03}').write_bytes(bytes([index]) * 4096)
        (path / 'leaf-000').chmod(0o640)
        os.link(path / 'leaf-000', path / 'alias')
        (path / 'link').symlink_to('leaf-000')
        return self.checks.snapshot(path)

    def unchanged(self, before, path):
        report = self.checks.verify_source(before, self.checks.snapshot(path))
        self.assertTrue(report['unchanged'], report)

    def kill_stopped(self, process):
        pid, status = os.waitpid(process.pid, os.WUNTRACED)
        self.assertEqual(pid, process.pid)
        self.assertTrue(os.WIFSTOPPED(status), f'Process did not stop: wait status {status}')
        self.assertEqual(os.WSTOPSIG(status), signal.SIGSTOP)
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, -signal.SIGKILL, (stdout, stderr))

    def cut(self, kind, *arguments, count=1):
        read, write = os.pipe()
        try:
            environment = {**os.environ, 'DYLD_INSERT_LIBRARIES': str(self.library),
                           'STALLIONFS_TEST_CUT_KIND': kind, 'STALLIONFS_TEST_CUT_COUNT': str(count),
                           'STALLIONFS_TEST_CUT_FD': str(write)}
            process = subprocess.Popen(self.command(*arguments), env=environment, pass_fds=(write,),
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            os.close(write)
            write = None
            try:
                self.assertTrue(select.select([read], [], [], 15)[0], 'Installed CLI did not reach pause hook')
                self.assertEqual(os.read(read, 1), b'R', 'CLI exited without reaching pause hook')
                self.kill_stopped(process)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
        finally:
            os.close(read)
            if write is not None:
                os.close(write)

    def test_killed_copy_clone_preserve_source_and_allow_partial_destination(self):
        source = self.base / 'source'
        before = self.fixture(source)
        for operation in ('copy', 'clone'):
            for count in (1, 7):
                with self.subTest(operation=operation, completed_calls=count):
                    destination = self.base / f'{operation}-{count}'
                    self.cut(operation, operation, source, destination, count=count)
                    self.unchanged(before, source)
                    partial = self.checks.snapshot(destination)
                    self.assertLessEqual(partial['entries'].keys(), before['entries'].keys())
                    self.assertGreater(len(partial['entries']), 1)
                    source_inodes = {tuple(row['device_inode']) for row in before['entries'].values()}
                    for name, row in partial['entries'].items():
                        self.assertEqual(row['kind'], before['entries'][name]['kind'])
                        self.assertNotIn(tuple(row['device_inode']), source_inodes)

    def test_killed_move_has_exactly_one_complete_inode_tree(self):
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                source = self.base / f'source-{phase}'
                destination = self.base / f'destination-{phase}'
                before = self.fixture(source)
                self.cut(f'move-{phase}', 'move', source, destination)
                self.assertEqual([source.exists(), destination.exists()],
                                 [phase == 'before', phase == 'after'])
                survivor = source if source.exists() else destination
                report = self.checks.verify_move(before, self.checks.snapshot(survivor))
                self.assertTrue(report['strict_equal'], report)
                self.assertTrue(report['move_identity'], report)
                self.assertIs(report['sparse_preserved'], True, report)

    def repository(self):
        source = self.base / 'repository'
        source.mkdir()
        (source / 'payload').mkdir()
        (source / 'payload/file').write_text('original\n')
        for arguments in (('init', '-q'), ('add', '.'),
                          ('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                           'commit', '-qm', 'Fixture')):
            subprocess.run(['git', '-C', str(source), *arguments], check=True,
                           capture_output=True, timeout=15)
        return source

    def test_killed_preparation_is_unpublished_reported_and_not_cached(self):
        source = self.repository()
        before = self.checks.snapshot(source / 'payload')
        marker = self.base / 'started'
        setup = (f'import os, signal, time; from pathlib import Path; marker = Path({str(marker)!r}); '
                 'first = not marker.exists(); '
                 'marker.write_text(os.getcwd()) if first else None; '
                 'os.kill(os.getppid(), signal.SIGSTOP) if first else None; '
                 'time.sleep(60) if first else None')
        arguments = ('prepare', source, '--key', 'sigkill', '--', sys.executable, '-I', '-B', '-c', setup)
        process = subprocess.Popen(self.command(*arguments), start_new_session=True,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists(), 'Preparation did not reach its setup command')
            self.kill_stopped(process)
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        stage_repo = Path(marker.read_text())
        staged = self.checks.snapshot(stage_repo)
        self.assertEqual(staged['entries']['payload/file']['sha256'], before['entries']['file']['sha256'])
        self.assertEqual(stage_repo.parent.parent, self.root / 'staging')
        self.assertEqual(self.cli('list', 'seeds'), [])
        self.assertIn(stage_repo.parent.name, self.cli('doctor')['staging_entries'])
        self.unchanged(staged, stage_repo)
        self.unchanged(before, source / 'payload')
        prepared = self.cli(*arguments)
        self.assertFalse(prepared['cached'])
        seed_payload = self.checks.snapshot(self.root / 'seeds' / prepared['id'] / 'repo/payload')
        self.assertEqual(seed_payload['entries']['file']['sha256'], before['entries']['file']['sha256'])
        self.unchanged(staged, stage_repo)
        self.unchanged(before, source / 'payload')

    def test_killed_rollback_reconciles_both_sides_of_exchange_without_replay(self):
        source = self.repository()
        seed = self.cli('prepare', source, '--key', 'rollback')['id']
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                workspace = self.cli('create', seed)
                repo = Path(workspace['path'])
                saved = self.cli('snapshot', workspace['id'], '--quiescent')
                snapshot_repo = self.root / 'snapshots' / saved['id'] / 'repo'
                expected = self.checks.snapshot(snapshot_repo)
                (repo / 'payload/file').write_text('modified workspace\n')
                old = self.checks.snapshot(repo)
                self.cut(f'move-{phase}', 'rollback', workspace['id'], saved['id'], '--quiescent')
                journal = self.root / 'journals' / (workspace['id'] + '.json')
                intent = json.loads(journal.read_text())
                recovery = self.root / 'recovery' / intent['recovery'] / 'repo'
                candidate = self.checks.snapshot(recovery if phase == 'before' else repo)
                cloned = self.checks.verify_clone(expected, candidate)
                self.assertTrue(cloned['strict_equal'], cloned)
                self.assertTrue(cloned['independent_clone'], cloned)
                self.cli('mount', workspace['id'])
                self.assertFalse(journal.exists())
                record = json.loads((recovery.parent / 'meta.json').read_text())
                self.assertEqual(record['outcome'], 'not-exchanged' if phase == 'before' else 'exchanged')
                settled = []
                for path, baseline in ((repo, old if phase == 'before' else candidate),
                                       (recovery, candidate if phase == 'before' else old)):
                    observed = self.checks.snapshot(path)
                    report = self.checks.verify_move(baseline, observed)
                    self.assertTrue(report['strict_equal'], report)
                    self.assertTrue(report['move_identity'], report)
                    self.assertIs(report['sparse_preserved'], True, report)
                    settled.append((path, observed))
                self.cli('mount', workspace['id'])
                for path, baseline in settled:
                    self.unchanged(baseline, path)
                self.unchanged(expected, snapshot_repo)
                self.assertEqual(list((self.root / 'staging').iterdir()), [])
