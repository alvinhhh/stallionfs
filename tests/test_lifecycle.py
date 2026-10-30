"""Small owned-folder tests for managed recovery and cooperative retirement."""
import contextlib
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from stallionfs import core, lifecycle, _scan
from stallionfs.core import Store, StallionError, git, read_json, write_json


@unittest.skipUnless(sys.platform == 'darwin', 'requires native APFS clone and exchange')
class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self._prior_failures = len(self._outcome.result.failures) + len(self._outcome.result.errors)
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-lifecycle-test-')).resolve()
        self.store = Store(self.base / 'store')
        self.workspace = 'a' * 32
        self.path = self.store.root / 'workspaces' / self.workspace
        self.path.mkdir(mode=0o700)
        self.repo = self.path / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-b', 'main')
        (self.repo / 'file').write_text('original\n')
        (self.repo / '.gitignore').write_text('ignored\n')
        git(self.repo, 'add', '.')
        git(self.repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Fixture')
        self.meta = {'id': self.workspace, 'commit': git(self.repo, 'rev-parse', 'HEAD'), 'branch': 'main'}
        write_json(self.path / 'meta.json', self.meta)

    def tearDown(self):
        result = self._outcome.result
        if len(result.failures) + len(result.errors) > self._prior_failures:
            print(f'Lifecycle fixture retained at {self.base}', file=sys.stderr)
        else:
            core.remove_tree(self.base)

    def snapshot(self):
        return self.store.snapshot(self.workspace, quiescent=True)['id']

    def stale(self):
        self.store.enroll(self.workspace)
        state = self.store.close(self.workspace, quiescent=True)
        state['closed_at'] = time.time() - lifecycle.STALE_SECONDS - 10
        lifecycle.replace_json(self.store._state(self.workspace), state)
        self.store.cleanup_config(enabled=True)
        return state

    def test_git_state_and_metadata_are_independent(self):
        git(self.repo, 'checkout', '-b', 'edited-branch')
        (self.repo / 'file').write_text('staged\n')
        git(self.repo, 'add', 'file')
        (self.repo / 'file').write_text('unstaged\n')
        (self.repo / 'untracked').write_text('untracked\n')
        (self.repo / 'ignored').write_text('ignored\n')
        (self.repo / 'executable').write_text('script\n')
        (self.repo / 'executable').chmod(0o751)
        subprocess.run(['/usr/bin/xattr', '-w', 'com.stallionfs.test', 'metadata', self.repo / 'executable'], check=True)
        os.link(self.repo / 'untracked', self.repo / 'linked')
        before = git(self.repo, 'status', '--porcelain', '--untracked-files=all')
        snapshot = self.snapshot()
        saved = self.store.root / 'snapshots' / snapshot / 'repo'
        self.assertEqual((saved / 'untracked').stat().st_ino, (saved / 'linked').stat().st_ino)
        self.assertNotEqual((saved / 'untracked').stat().st_ino, (self.repo / 'untracked').stat().st_ino)
        (self.repo / 'file').write_text('later\n')
        (self.repo / 'ignored').unlink()
        git(self.repo, 'checkout', '-b', 'later-branch')
        result = self.store.rollback(self.workspace, snapshot, quiescent=True)
        self.assertEqual(git(self.repo, 'status', '--porcelain', '--untracked-files=all'), before)
        self.assertEqual(git(self.repo, 'branch', '--show-current'), 'edited-branch')
        self.assertEqual(git(self.repo, 'show', ':file'), 'staged')
        self.assertEqual((self.repo / 'file').read_text(), 'unstaged\n')
        self.assertEqual((self.repo / 'ignored').read_text(), 'ignored\n')
        self.assertEqual((self.repo / 'executable').stat().st_mode & 0o777, 0o751)
        self.assertEqual(subprocess.check_output(['/usr/bin/xattr', '-p', 'com.stallionfs.test', self.repo / 'executable']).strip(), b'metadata')
        previous = self.store.root / 'recovery' / result['recovery'] / 'repo'
        self.assertEqual((previous / 'file').read_text(), 'later\n')
        self.assertEqual(git(previous, 'branch', '--show-current'), 'later-branch')
        (self.repo / 'file').write_text('independent\n')
        self.assertEqual((saved / 'file').read_text(), 'unstaged\n')

    def test_requires_quiescence_and_exclusive_lease(self):
        with self.assertRaisesRegex(StallionError, 'quiescent'):
            self.store.snapshot(self.workspace)
        with self.assertRaisesRegex(StallionError, 'quiescent'):
            self.store.close(self.workspace)
        with self.store._lease(self.workspace):
            with self.assertRaisesRegex(StallionError, 'managed use'):
                self.snapshot()
        self.assertEqual(self.store.snapshots(self.workspace), [])

    def test_exchange_then_interrupt_reconciles_actual_old_workspace(self):
        snapshot = self.snapshot()
        (self.repo / 'file').write_text('current\n')
        old_identity = lifecycle.identity(self.repo)
        native_move = _scan.move
        def interrupted(*args, **kwargs):
            native_move(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(_scan, 'move', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.store.rollback(self.workspace, snapshot, quiescent=True)
        slots = list((self.store.root / 'recovery').iterdir())
        self.assertEqual(len(slots), 1)
        self.assertEqual(lifecycle.identity(slots[0] / 'repo'), old_identity)
        self.assertEqual((slots[0] / 'repo/file').read_text(), 'current\n')
        self.assertEqual((self.repo / 'file').read_text(), 'original\n')
        self.assertEqual(read_json(slots[0] / 'meta.json')['outcome'], 'exchanged')
        self.assertEqual(list((self.store.root / 'journals').iterdir()), [])

    def test_intent_publication_interrupt_does_not_exchange(self):
        snapshot = self.snapshot()
        (self.repo / 'file').write_text('current\n')
        writer = core.write_json
        def interrupted(path, record):
            writer(path, record)
            if path.parent.name == 'journals':
                raise KeyboardInterrupt()
        with patch.object(core, 'write_json', side_effect=interrupted), patch.object(_scan, 'move') as exchange:
            with self.assertRaises(KeyboardInterrupt):
                self.store.rollback(self.workspace, snapshot, quiescent=True)
        exchange.assert_not_called()
        self.assertEqual((self.repo / 'file').read_text(), 'current\n')
        slot = next((self.store.root / 'recovery').iterdir())
        self.assertEqual(read_json(slot / 'meta.json')['outcome'], 'not-exchanged')

    def test_failed_finalization_is_reconciled_before_next_mutation(self):
        snapshot = self.snapshot()
        (self.repo / 'file').write_text('current\n')
        replace = lifecycle.replace_json
        def fail(path, record):
            if path.name == 'meta.json' and path.parent.parent.name == 'recovery':
                raise OSError(errno.ENOSPC, 'full')
            return replace(path, record)
        with patch.object(lifecycle, 'replace_json', side_effect=fail):
            with self.assertRaises(OSError):
                self.store.rollback(self.workspace, snapshot, quiescent=True)
        self.assertEqual(len(list((self.store.root / 'journals').iterdir())), 1)
        self.store.enroll(self.workspace)
        self.assertEqual(list((self.store.root / 'journals').iterdir()), [])
        self.assertEqual((self.repo / 'file').read_text(), 'original\n')
        slot = next((self.store.root / 'recovery').iterdir())
        self.assertEqual((slot / 'repo/file').read_text(), 'current\n')

    def test_missing_or_changed_identity_blocks_reconciliation(self):
        snapshot = self.snapshot()
        replace = lifecycle.replace_json
        def fail(path, record):
            if path.name == 'meta.json' and path.parent.parent.name == 'recovery':
                raise OSError('metadata failure')
            return replace(path, record)
        with patch.object(lifecycle, 'replace_json', side_effect=fail):
            with self.assertRaises(OSError):
                self.store.rollback(self.workspace, snapshot, quiescent=True)
        self.repo.rename(self.path / 'retained-repo')
        self.repo.mkdir()
        with self.assertRaisesRegex(StallionError, 'Uncertain rollback'):
            self.store.enroll(self.workspace)
        self.assertTrue((self.path / 'retained-repo/file').exists())
        self.assertTrue(list((self.store.root / 'journals').iterdir()))

    def test_clone_and_exchange_failures_preserve_both_sources(self):
        snapshot = self.snapshot()
        (self.repo / 'file').write_text('current\n')
        for operation in ('clone', 'exchange'):
            with self.subTest(operation=operation):
                target, attribute = (core, 'clone_tree') if operation == 'clone' else (_scan, 'move')
                with patch.object(target, attribute, side_effect=OSError(errno.ENOSPC, 'full')):
                    with self.assertRaises(OSError):
                        self.store.rollback(self.workspace, snapshot, quiescent=True)
                self.assertEqual((self.repo / 'file').read_text(), 'current\n')
                saved = self.store.root / 'snapshots' / snapshot / 'repo/file'
                self.assertEqual(saved.read_text(), 'original\n')
                # Incomplete recovery is explicit retained data, never an automatic retry target.
                for slot in list((self.store.root / 'recovery').iterdir()):
                    self.store.purge('recovery', slot.name, yes=True)

    def test_cleanup_is_opt_in_and_protected_from_gc(self):
        self.assertFalse(self.store.cleanup(apply=True)['enabled'])
        self.stale()
        self.assertEqual(self.store.cleanup()['would_retire'], [self.workspace])
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [self.workspace])
        trash = self.store.root / 'trash' / self.workspace
        self.assertTrue((trash / 'repo/file').exists())
        self.assertEqual(self.store.gc(older_than=0, yes=True), [])
        self.assertTrue(trash.exists())
        self.store.move(self.workspace, restore=True)
        self.assertEqual(read_json(self.store._state(self.workspace))['status'], 'open')
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])

    def test_cleanup_skips_open_unknown_clock_corrupt_identity_and_mounts(self):
        state = self.stale()
        cases = ({'status': 'open'}, {'status': 'unknown'}, {'generation': 'old'}, {'enrolled': False},
                 {'closed_at': time.time() + 86400}, {'closed_at': float('nan')},
                 {'closed_at': float('inf')}, {'object': [0, 0]}, {'payload': [0, 0]})
        for changes in cases:
            with self.subTest(changes=changes):
                self.store._state(self.workspace).write_text(json.dumps({'format': 1, **state, **changes}))
                self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        self.store._state(self.workspace).write_text('{broken')
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        lifecycle.replace_json(self.store._state(self.workspace), state)
        with patch.object(_scan, 'mounts', return_value=[{'path': str(self.repo / 'nested')} ]):
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        with self.store._lease(self.workspace):
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        self.store._state(self.workspace).unlink()
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        self.assertTrue(self.repo.exists())

    def test_retirement_rename_interrupt_already_has_protection(self):
        self.stale()
        native_move = _scan.move
        def interrupted(*args, **kwargs):
            native_move(*args, **kwargs)
            raise KeyboardInterrupt()
        with patch.object(_scan, 'move', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                self.store.cleanup(apply=True)
        self.assertEqual(self.store.gc(older_than=0, yes=True), [])
        self.assertTrue((self.store.root / 'trash' / self.workspace / 'repo/file').exists())

    def test_failed_retirement_rename_preserves_current_and_protection(self):
        self.stale()
        with patch.object(_scan, 'move', side_effect=OSError('rename failed')):
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        self.assertTrue(self.repo.exists())
        self.assertTrue((self.store.root / 'protected' / f'{self.workspace}.json').exists())
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        self.store.enroll(self.workspace)
        self.assertFalse((self.store.root / 'protected' / f'{self.workspace}.json').exists())
        self.assertTrue(self.repo.exists())

    def test_command_completion_or_released_lease_never_closes(self):
        self.stale()
        result = self.store.run(self.workspace, [sys.executable, '-c', 'raise SystemExit(7)'])
        self.assertEqual(result['returncode'], 7)
        self.assertEqual(read_json(self.store._state(self.workspace))['status'], 'open')
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        with self.store._lease(self.workspace):
            pass
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])

    def test_retention_limit_stops_without_eviction(self):
        snapshot = self.snapshot()
        with patch.object(lifecycle, 'RETENTION_COUNT', 1):
            with self.assertRaisesRegex(StallionError, 'retention limit'):
                self.snapshot()
        self.assertEqual(self.store.snapshots(self.workspace)[0]['id'], snapshot)
        self.assertTrue(self.repo.exists())

    def test_image_capture_uses_detach_flush_clone_and_preserves_remount_failure(self):
        from stallionfs import images
        import shutil
        image = self.path / 'workspace.sparseimage'
        image.write_bytes(b'original image')
        image.chmod(0o600)
        (self.path / 'volume').mkdir(mode=0o700)
        lifecycle.replace_json(self.path / 'meta.json', {**self.meta, 'backend': 'image'})
        attached = {'mountpoint': str(self.path / 'volume'), 'device': '/dev/disk999'}
        calls = []
        def clone(source, target):
            calls.append('clone')
            shutil.copy2(source, target)
        with patch.object(images, 'mounted', return_value=attached), \
             patch.object(images, 'detach', side_effect=lambda *args: calls.append('detach')), \
             patch.object(images, 'flush', side_effect=lambda *args: calls.append('flush')), \
             patch.object(images, 'clone', side_effect=clone), \
             patch.object(self.store, '_mount'), patch.object(self.store, '_standalone_git'):
            snapshot = self.store.snapshot(self.workspace)['id']
            self.assertEqual(calls, ['detach', 'flush', 'clone'])
            image.write_bytes(b'current image')
            with patch.object(self.store, '_mount', side_effect=OSError('remount failed')):
                with self.assertRaisesRegex(OSError, 'remount failed'):
                    self.store.rollback(self.workspace, snapshot)
        self.assertEqual(image.read_bytes(), b'original image')
        slot = next((self.store.root / 'recovery').iterdir())
        self.assertEqual((slot / 'workspace.sparseimage').read_bytes(), b'current image')
        self.assertEqual((self.store.root / 'snapshots' / snapshot / 'workspace.sparseimage').read_bytes(), b'original image')

    def test_image_unknown_busy_and_flush_failure_never_close_or_clone(self):
        from stallionfs import images
        image = self.path / 'workspace.sparseimage'
        image.write_bytes(b'keep image')
        image.chmod(0o600)
        (self.path / 'volume').mkdir(mode=0o700)
        lifecycle.replace_json(self.path / 'meta.json', {**self.meta, 'backend': 'image'})
        for failure in ('mounted', 'detach', 'flush'):
            with self.subTest(failure=failure), \
                 patch.object(images, 'mounted', return_value=None), \
                 patch.object(images, 'detach'), patch.object(images, 'flush'), \
                 patch.object(images, 'clone') as clone, \
                 patch.object(images, failure, side_effect=StallionError('unavailable')), \
                 patch.object(self.store, '_mount', return_value={'path': str(self.repo)}), \
                 patch.object(self.store, '_standalone_git'):
                with self.assertRaises(StallionError):
                    self.store.close(self.workspace, quiescent=True)
                self.assertEqual(read_json(self.store._state(self.workspace))['status'], 'open')
                with self.assertRaises(StallionError):
                    self.store.snapshot(self.workspace)
                clone.assert_not_called()
                self.assertEqual(image.read_bytes(), b'keep image')

    def test_closed_image_flush_rejects_attachment_or_changed_identity(self):
        from stallionfs import images
        image = self.base / 'closed.sparseimage'
        image.write_bytes(b'keep image')
        image.chmod(0o600)
        with patch.object(images, 'mounted', return_value={'device': '/dev/disk999'}), \
             patch.object(images.fcntl, 'fcntl') as flush:
            with self.assertRaises(StallionError):
                images.flush(image)
            flush.assert_not_called()
        def changed(*args):
            image.rename(self.base / 'retained.sparseimage')
            image.write_bytes(b'replacement')
        with patch.object(images, 'mounted', return_value=None), \
             patch.object(images.fcntl, 'fcntl', side_effect=changed):
            with self.assertRaisesRegex(StallionError, 'changed while flushing'):
                images.flush(image)
        self.assertEqual((self.base / 'retained.sparseimage').read_bytes(), b'keep image')

    def test_external_git_storage_and_config_references_are_rejected(self):
        gitdir = self.repo / '.git'
        cases = ('alternates', 'include', 'commondir', 'worktrees')
        for case in cases:
            with self.subTest(case=case):
                if case == 'include':
                    git(self.repo, 'config', '--local', 'include.path', str(self.base / 'external-config'))
                else:
                    target = gitdir / {'alternates': 'objects/info/alternates', 'commondir': 'commondir', 'worktrees': 'worktrees'}[case]
                    target.write_text(str(self.base / 'external'))
                with self.assertRaisesRegex(StallionError, 'standalone Git|external worktree'):
                    self.snapshot()
                if case == 'include':
                    git(self.repo, 'config', '--local', '--unset', 'include.path')
                else:
                    target.unlink()
        gitdir.rename(self.base / 'external-git')
        gitdir.write_text(f'gitdir: {self.base / "external-git"}\n')
        with self.assertRaisesRegex(StallionError, 'standalone Git'):
            self.snapshot()
        self.assertTrue((self.base / 'external-git' / 'HEAD').exists())
        self.assertEqual(self.store.snapshots(self.workspace), [])

    def test_git_validation_rejects_unreadable_subtrees(self):
        def unreadable(*args, **kwargs):
            kwargs['onerror'](PermissionError('unreadable Git metadata'))
            return iter(())
        with patch.object(core.os, 'walk', side_effect=unreadable):
            with self.assertRaisesRegex(PermissionError, 'unreadable Git metadata'):
                self.store._standalone_git(self.repo)
        self.assertTrue((self.repo / '.git/HEAD').exists())
        self.assertEqual(self.store.snapshots(self.workspace), [])

    def test_abandoned_process_lease_does_not_imply_closed(self):
        self.stale()
        script = """import os, sys
from stallionfs.core import Store
store = Store(sys.argv[1])
with store._lease(sys.argv[2]):
    path, meta = store.object('workspaces', sys.argv[2])
    store._open(sys.argv[2], path, meta)
    os._exit(17)
"""
        child = subprocess.run([sys.executable, '-c', script, str(self.store.root), self.workspace])
        self.assertEqual(child.returncode, 17)
        with self.store._lease(self.workspace):
            pass
        self.assertEqual(read_json(self.store._state(self.workspace))['status'], 'open')
        self.assertEqual(self.store.cleanup(apply=True)['retired'], [])

    def test_large_sparse_payload_has_no_logical_size_quota(self):
        large = self.repo / 'large'
        with large.open('wb') as stream:
            stream.truncate(80 * 1024 ** 3)
        snapshot = self.snapshot()
        with large.open('r+b') as stream:
            stream.write(b'changed')
        self.store.rollback(self.workspace, snapshot, quiescent=True)
        self.assertEqual(large.stat().st_size, 80 * 1024 ** 3)
        with large.open('rb') as stream:
            self.assertEqual(stream.read(7), b'\0' * 7)

    def test_uncertain_protection_survives_gc_and_restore(self):
        self.store.move(self.workspace)
        protection = self.store.root / 'protected' / f'{self.workspace}.json'
        protection.write_text('{incomplete')
        self.assertEqual(self.store.gc(older_than=0, yes=True), [])
        self.store.move(self.workspace, restore=True)
        self.assertEqual(protection.read_text(), '{incomplete')
        self.assertEqual(read_json(self.store._state(self.workspace))['status'], 'open')
        self.assertTrue((self.repo / 'file').exists())

    def test_purge_honors_use_lease_and_unknown_rollback_journal(self):
        self.store.move(self.workspace)
        with self.store._lease(self.workspace):
            with self.assertRaisesRegex(StallionError, 'managed use'):
                self.store.purge('trash', self.workspace, yes=True)
        journal = self.store.root / 'journals' / ('b' * 32 + '.json')
        journal.write_text('{incomplete')
        with self.assertRaisesRegex(StallionError, 'pending rollback'):
            self.store.purge('trash', self.workspace, yes=True)
        self.assertTrue((self.store.root / 'trash' / self.workspace / 'repo/file').exists())

    def test_interrupted_purge_keeps_partial_deletion_out_of_snapshots(self):
        first, second = self.snapshot(), self.snapshot()
        def interrupted(path, **kwargs):
            (path / 'meta.json').unlink()
            raise KeyboardInterrupt()
        with patch.object(core, 'remove_tree', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt) as raised:
                self.store.purge('snapshots', first, yes=True)
        self.assertEqual([item['id'] for item in self.store.snapshots(self.workspace)], [second])
        stage = next((self.store.root / 'staging').iterdir())
        self.assertEqual((stage / 'expired/repo/file').read_text(), 'original\n')
        self.assertTrue(any(str(stage) in note for note in raised.exception.__notes__))

    def test_interrupted_protected_purge_does_not_orphan_protection(self):
        self.stale()
        self.store.cleanup(apply=True)
        protection = self.store.root / 'protected' / f'{self.workspace}.json'
        self.assertTrue(protection.exists())
        with patch.object(core, 'remove_tree', side_effect=KeyboardInterrupt()):
            with self.assertRaises(KeyboardInterrupt):
                self.store.purge('trash', self.workspace, yes=True)
        self.assertFalse(protection.exists())
        self.assertFalse((self.store.root / 'trash' / self.workspace).exists())
        stage = next((self.store.root / 'staging').iterdir())
        self.assertEqual((stage / 'expired/repo/file').read_text(), 'original\n')

    def test_cli_snapshot_run_and_cleanup_controls(self):
        from contextlib import redirect_stdout
        from io import StringIO
        from stallionfs.__main__ import main
        subprocess.run([sys.executable, '-c', 'import stallionfs.lifecycle; from stallionfs.core import Store'], check=True)
        def command(*args):
            output = StringIO()
            with redirect_stdout(output):
                status = main(['--root', str(self.store.root), '--json', *args])
            return status, json.loads(output.getvalue())
        status, snapshot = command('snapshot', self.workspace, '--quiescent')
        self.assertEqual(status, 0)
        self.assertEqual(command('snapshots', self.workspace)[1][0]['id'], snapshot['id'])
        status, result = command('run', self.workspace, '--', sys.executable, '-c', 'raise SystemExit(9)')
        self.assertEqual(status, 9)
        self.assertEqual(result['returncode'], 9)
        self.assertFalse(command('cleanup')[1]['enabled'])
        self.assertTrue(command('cleanup', '--enable')[1]['enabled'])
        self.assertEqual(command('cleanup', '--apply')[1]['retired'], [])
        self.assertFalse(command('cleanup', '--disable')[1]['enabled'])

    def test_snapshot_metadata_failure_retains_unpublished_clone(self):
        original = core.write_json
        def fail(path, record):
            if path.name == 'meta.json' and path.parent.parent.name == 'staging':
                raise OSError(errno.ENOSPC, 'snapshot metadata failed')
            return original(path, record)
        with patch.object(core, 'write_json', side_effect=fail):
            with self.assertRaises(OSError):
                self.snapshot()
        self.assertEqual(self.store.snapshots(self.workspace), [])
        stage = next((self.store.root / 'staging').iterdir())
        self.assertEqual((stage / 'repo/file').read_text(), 'original\n')
        self.assertEqual((self.repo / 'file').read_text(), 'original\n')

    def test_maintenance_skips_held_store_lock(self):
        self.stale()
        with core.lock(self.store.root / '.lock'):
            self.assertIsNone(self.store.opportunistic_cleanup())
        self.assertTrue(self.repo.exists())

    def arm_session(self):
        self.store.enroll(self.workspace)
        self.store.cleanup_config(enabled=True)
        state = read_json(self.store._state(self.workspace))
        state['auto_retire'] = {'generation': state['generation']}
        lifecycle.replace_json(self.store._state(self.workspace), state)
        return state

    def wait_for(self, predicate, description):
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail(f'Timed out waiting for owned fixture: {description}')

    def lease_is_free(self):
        try:
            with self.store._lease(self.workspace):
                return True
        except StallionError:
            return False

    def writer_script(self):
        script = self.base / 'owned-writer.py'
        script.write_text("""import os, pathlib, sys, time
ready, release, done, output = map(pathlib.Path, sys.argv[1:])
fd = int(os.environ['STALLIONFS_LEASE_FD'])
os.fstat(fd)
ready.write_text(str(os.getpid()))
deadline = time.monotonic() + 15
while not release.exists() and time.monotonic() < deadline:
    time.sleep(0.01)
output.write_text('writer finished')
os.close(fd)
done.write_text('done')
""")
        return script

    def test_auto_retire_normal_and_nonzero_exit_observe_exact_session(self):
        self.store.enroll(self.workspace)
        self.store.cleanup_config(enabled=True)
        generations = []
        for status in (0, 9):
            command = [sys.executable, '-c',
                       "import os; os.fstat(int(os.environ['STALLIONFS_LEASE_FD'])); "
                       f"assert len(os.environ['STALLIONFS_LEASE_GENERATION']) == 32; raise SystemExit({status})"]
            result = self.store.run(self.workspace, command, auto_retire=True)
            self.assertEqual(result['returncode'], status)
            state = read_json(self.store._state(self.workspace))
            self.assertEqual(state['status'], 'open')
            self.assertEqual(state['auto_retire']['generation'], state['generation'])
            self.assertTrue(lifecycle.finite_time(state['auto_retire']['idle_since']))
            generations.append(state['generation'])
        self.assertNotEqual(*generations)

    def test_auto_retire_parent_close_does_not_unlock_inherited_child(self):
        self.store.enroll(self.workspace)
        self.store.cleanup_config(enabled=True)
        ready, release, done = (self.base / name for name in ('ready', 'release', 'done'))
        writer = self.writer_script()
        launcher = self.base / 'owned-launcher.py'
        launcher.write_text("""import os, pathlib, subprocess, sys, time
fd = int(os.environ['STALLIONFS_LEASE_FD'])
subprocess.Popen([sys.executable, *sys.argv[1:]], pass_fds=(fd,))
deadline = time.monotonic() + 8
while not pathlib.Path(sys.argv[2]).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
raise SystemExit(3)
""")
        try:
            result = self.store.run(self.workspace, [sys.executable, str(launcher), str(writer), str(ready),
                                    str(release), str(done), str(self.repo / 'child-write')], auto_retire=True)
            self.assertEqual(result['returncode'], 3)
            self.assertTrue(ready.exists())
            self.assertFalse(self.lease_is_free())
            self.assertNotIn('idle_since', read_json(self.store._state(self.workspace))['auto_retire'])
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            release.touch()
            self.wait_for(done.exists, 'child completion')
            self.wait_for(self.lease_is_free, 'inherited lease release')
            before = time.time()
            self.store.cleanup(apply=True)
            state = read_json(self.store._state(self.workspace))
            self.assertGreaterEqual(state['auto_retire']['idle_since'], before)
            self.assertEqual((self.repo / 'child-write').read_text(), 'writer finished')
        finally:
            release.touch()
            self.wait_for(self.lease_is_free, 'owned child shutdown')

    def test_killed_wrapper_and_exited_child_leave_grandchild_lease_held(self):
        self.store.enroll(self.workspace)
        self.store.cleanup_config(enabled=True)
        ready, release, done, child_release, child_done = (
            self.base / name for name in ('grand-ready', 'grand-release', 'grand-done', 'child-release', 'child-done'))
        writer = self.writer_script()
        agent = self.base / 'owned-agent.py'
        agent.write_text("""import os, pathlib, subprocess, sys, time
fd = int(os.environ['STALLIONFS_LEASE_FD'])
subprocess.Popen([sys.executable, *sys.argv[1:6]], pass_fds=(fd,))
deadline = time.monotonic() + 15
while not pathlib.Path(sys.argv[6]).exists() and time.monotonic() < deadline:
    time.sleep(0.01)
os.close(fd)
pathlib.Path(sys.argv[7]).write_text('child finished')
""")
        wrapper_code = "from stallionfs.core import Store; import sys; Store(sys.argv[1]).run(sys.argv[2], sys.argv[3:], auto_retire=True)"
        wrapper = subprocess.Popen([sys.executable, '-c', wrapper_code, str(self.store.root), self.workspace,
                                    sys.executable, str(agent), str(writer), str(ready), str(release), str(done),
                                    str(self.repo / 'grandchild-write'), str(child_release), str(child_done)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            self.wait_for(ready.exists, 'FD-retaining grandchild')
            wrapper.kill()
            self.assertEqual(wrapper.wait(timeout=5), -9)
            child_release.touch()
            self.wait_for(child_done.exists, 'intermediate child exit')
            self.assertFalse(self.lease_is_free())
            original = self.store._state(self.workspace).read_bytes()
            self.assertEqual(self.store.cleanup()['would_retire'], [])
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
            self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
            release.touch()
            self.wait_for(done.exists, 'grandchild completion')
            self.wait_for(self.lease_is_free, 'last inherited descriptor close')
            self.store.cleanup()
            self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
            before = time.time()
            self.store.cleanup(apply=True)
            state = read_json(self.store._state(self.workspace))
            self.assertGreaterEqual(state['auto_retire']['idle_since'], before)
            state['auto_retire']['idle_since'] -= lifecycle.STALE_SECONDS + 1
            lifecycle.replace_json(self.store._state(self.workspace), state)
            self.assertEqual(self.store.cleanup()['would_retire'], [self.workspace])
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [self.workspace])
            trash = self.store.root / 'trash' / self.workspace
            self.assertEqual(self.store.gc(older_than=0, yes=True), [])
            self.assertTrue((trash / 'repo/grandchild-write').exists())
            self.store.move(self.workspace, restore=True)
            restored = read_json(self.store._state(self.workspace))
            self.assertNotEqual(restored['generation'], state['generation'])
            self.assertNotIn('auto_retire', restored)
            self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
        finally:
            child_release.touch()
            release.touch()
            if wrapper.poll() is None:
                wrapper.terminate()
                wrapper.wait(timeout=5)
            self.wait_for(self.lease_is_free, 'owned grandchild shutdown')
            wrapper.stderr.close()

    def test_auto_retire_generation_race_and_ordinary_reopen(self):
        old = self.arm_session()
        new = self.arm_session()
        original = self.store._state(self.workspace).read_bytes()
        self.store._observe_idle(self.workspace, old['generation'])
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
        self.store._observe_idle(self.workspace, new['generation'])
        state = read_json(self.store._state(self.workspace))
        since = state['auto_retire']['idle_since']
        self.store.cleanup(apply=True)
        self.assertEqual(read_json(self.store._state(self.workspace))['auto_retire']['idle_since'], since)
        self.store.mount(self.workspace)
        self.assertNotIn('auto_retire', read_json(self.store._state(self.workspace)))
        self.store._observe_idle(self.workspace, new['generation'])
        self.assertNotIn('auto_retire', read_json(self.store._state(self.workspace)))

    def test_auto_retire_preview_and_pending_journal_never_write(self):
        state = self.arm_session()
        original = self.store._state(self.workspace).read_bytes()
        policy = (self.store.root / 'cleanup.json').read_bytes()
        self.store.cleanup()
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
        self.assertEqual((self.store.root / 'cleanup.json').read_bytes(), policy)
        journal = self.store.root / 'journals' / f'{self.workspace}.json'
        journal.write_text('{unresolved')
        with patch.object(self.store, '_reconcile', side_effect=AssertionError('cleanup must not reconcile')):
            for apply in (False, True):
                self.assertEqual(len(self.store.cleanup(apply=apply)['skipped']), 1)
            self.store._observe_idle(self.workspace, state['generation'])
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
        self.assertEqual(journal.read_text(), '{unresolved')
        self.assertEqual((self.store.root / 'cleanup.json').read_bytes(), policy)

    def test_auto_retire_malformed_disabled_future_and_changed_states_stay_ineligible(self):
        state = self.arm_session()
        changes = [
            {'auto_retire': None}, {'auto_retire': True}, {'auto_retire': {'generation': 'b' * 32}},
            {'auto_retire': {'generation': state['generation'], 'idle_since': None}},
            {'auto_retire': {'generation': state['generation'], 'idle_since': float('nan')}},
            {'auto_retire': {'generation': state['generation'], 'idle_since': 10 ** 400}},
            {'auto_retire': {'generation': state['generation'], 'idle_since': time.time() + 100}},
            {'generation': 12345678901234567890123456789012}, {'enrolled': False},
            {'object': [0, 0]}, {'payload': [0, 0]}, {'status': 'unknown'}]
        for change in changes:
            with self.subTest(change=change):
                self.store._state(self.workspace).write_text(json.dumps({**state, **change}))
                original = self.store._state(self.workspace).read_bytes()
                self.assertEqual(self.store.cleanup(apply=True)['retired'], [])
                self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
        lifecycle.replace_json(self.store._state(self.workspace), state)
        self.store.cleanup_config(enabled=False)
        self.store._observe_idle(self.workspace, state['generation'])
        self.assertNotIn('idle_since', read_json(self.store._state(self.workspace))['auto_retire'])
        self.assertFalse(self.store.cleanup(apply=True)['enabled'])

    def test_auto_retire_rejects_policy_enrollment_and_images_before_launch(self):
        state = self.arm_session()
        original = self.store._state(self.workspace).read_bytes()
        self.store.cleanup_config(enabled=False)
        with patch.object(lifecycle.subprocess, 'run') as launch, patch.object(self.store, '_mount') as mount:
            with self.assertRaisesRegex(StallionError, 'Enable cleanup'):
                self.store.run(self.workspace, ['unused'], auto_retire=True)
            lifecycle.replace_json(self.store.root / 'cleanup.json', {'enabled': True, 'cursor': 123})
            with self.assertRaisesRegex(StallionError, 'Invalid cleanup'):
                self.store.run(self.workspace, ['unused'], auto_retire=True)
            lifecycle.replace_json(self.store.root / 'cleanup.json', {'enabled': True})
            lifecycle.replace_json(self.store._state(self.workspace), {**state, 'enrolled': False})
            with self.assertRaisesRegex(StallionError, 'enrollment'):
                self.store.run(self.workspace, ['unused'], auto_retire=True)
            lifecycle.replace_json(self.store._state(self.workspace), state)
            image = self.path / 'workspace.sparseimage'
            image.write_bytes(b'owned fixture only')
            image.chmod(0o600)
            (self.path / 'volume').mkdir(mode=0o700)
            lifecycle.replace_json(self.path / 'meta.json', {**self.meta, 'backend': 'image'})
            with self.assertRaisesRegex(StallionError, 'folder workspaces only'):
                self.store.run(self.workspace, ['unused'], auto_retire=True)
            launch.assert_not_called()
            mount.assert_not_called()
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)

    def test_cleanup_cursor_visits_later_ids_despite_busy_and_ineligible_entries(self):
        self.store.cleanup_config(enabled=True)
        ids = [f'{number:032x}' for number in range(1, 12)]
        for value in ids:
            path = self.store.root / 'workspaces' / value
            path.mkdir(mode=0o700)
            (path / 'repo').mkdir()
            meta = {**self.meta, 'id': value}
            write_json(path / 'meta.json', meta)
            self.store._open(value, path, meta, enrolled=True)
        target = ids[-1]
        state = read_json(self.store._state(target))
        state.update(status='closed', closed_at=time.time() - lifecycle.STALE_SECONDS - 1)
        lifecycle.replace_json(self.store._state(target), state)
        cursor_before = self.store.cleanup_config().get('cursor')
        self.assertEqual(self.store.cleanup()['would_retire'], [target])
        self.assertEqual(self.store.cleanup_config().get('cursor'), cursor_before)
        with contextlib.ExitStack() as leases:
            for value in ids[:9]:
                leases.enter_context(self.store._lease(value))
            first = self.store.opportunistic_cleanup()
            self.assertEqual(first['retired'], [])
            self.assertEqual(len(first['skipped']), 8)
            self.assertEqual(self.store.cleanup_config()['cursor'], ids[7])
            self.assertEqual(self.store.opportunistic_cleanup()['retired'], [target])
        self.assertFalse((self.store.root / 'workspaces' / target).exists())
        lifecycle.replace_json(self.store.root / 'cleanup.json', {'enabled': True, 'cursor': target})
        self.store.opportunistic_cleanup()
        self.assertEqual(self.store.cleanup_config()['cursor'], ids[6])
        self.assertNotIn('cursor', first)

    def test_cleanup_cursor_compare_preserves_concurrent_policy_and_settings(self):
        first, second = '1' * 32, '2' * 32
        lifecycle.replace_json(self.store.root / 'cleanup.json', {'enabled': True, 'custom': 'keep'})
        self.store._advance_cursor(None, first)
        self.store._advance_cursor(None, second)
        self.assertEqual(self.store.cleanup_config()['cursor'], first)
        self.store.cleanup_config(enabled=False)
        self.store._advance_cursor(first, second)
        policy = self.store.cleanup_config()
        self.assertFalse(policy['enabled'])
        self.assertEqual(policy['cursor'], first)
        self.assertEqual(policy['custom'], 'keep')

    def test_cleanup_disable_between_items_stops_observation_and_retirement(self):
        self.arm_session()
        later = ['b' * 32, 'c' * 32]
        originals = {}
        for value in later:
            path = self.store.root / 'workspaces' / value
            path.mkdir(mode=0o700)
            (path / 'repo').mkdir()
            meta = {**self.meta, 'id': value}
            write_json(path / 'meta.json', meta)
            state = self.store._open(value, path, meta, enrolled=True)
            state['auto_retire'] = {'generation': state['generation']}
            if value == later[-1]:
                state['auto_retire']['idle_since'] = time.time() - lifecycle.STALE_SECONDS - 1
            lifecycle.replace_json(self.store._state(value), state)
            originals[value] = self.store._state(value).read_bytes()
        lock = core.lock
        disabled = False

        @contextlib.contextmanager
        def disable_after_item(path, **kwargs):
            nonlocal disabled
            with lock(path, **kwargs):
                yield
            if path == self.store.root / '.lock' and kwargs.get('shared') and not disabled:
                disabled = True
                self.assertTrue(self.lease_is_free())
                self.store.cleanup_config(enabled=False)

        with patch.object(core, 'lock', disable_after_item):
            result = self.store.cleanup(apply=True, limit=8)
        self.assertTrue(disabled)
        self.assertFalse(result['enabled'])
        self.assertEqual(result['retired'], [])
        self.assertIn('idle_since', read_json(self.store._state(self.workspace))['auto_retire'])
        for value in later:
            self.assertEqual(self.store._state(value).read_bytes(), originals[value])
            self.assertTrue((self.store.root / 'workspaces' / value).exists())
            self.assertFalse((self.store.root / 'protected' / f'{value}.json').exists())
        self.assertNotIn('cursor', self.store.cleanup_config())

    def test_cleanup_policy_lock_covers_item_and_disabled_observer_skips_use_lease(self):
        state = self.arm_session()
        eligible = self.store._eligible
        checked = []

        def protected_item(*args, **kwargs):
            with self.assertRaises(BlockingIOError):
                with core.lock(self.store.root / '.lock', blocking=False):
                    self.fail('Policy change must wait for the active item')
            checked.append(args[0])
            return eligible(*args, **kwargs)

        with patch.object(self.store, '_eligible', side_effect=protected_item):
            self.store._observe_idle(self.workspace, state['generation'])
            self.store.cleanup(apply=True)
        self.assertEqual(checked, [self.workspace, self.workspace])
        self.assertTrue(self.lease_is_free())
        self.store.cleanup_config(enabled=False)
        original = self.store._state(self.workspace).read_bytes()
        with patch.object(self.store, '_workspace_lock', side_effect=AssertionError('Disabled observer must stop before the use lease')):
            self.store._observe_idle(self.workspace, state['generation'])
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)
        self.store.cleanup_config(enabled=True)
        with core.lock(self.store.root / '.lock'):
            self.store._observe_idle(self.workspace, state['generation'])
        self.assertEqual(self.store._state(self.workspace).read_bytes(), original)

    def test_create_only_json_remains_create_only(self):
        path = self.base / 'marker.json'
        write_json(path, {'value': 'original'})
        with self.assertRaises(FileExistsError):
            write_json(path, {'value': 'replacement'})
        self.assertEqual(read_json(path)['value'], 'original')


if __name__ == '__main__':
    unittest.main()
