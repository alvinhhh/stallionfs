"""Small owned-folder tests for managed recovery and cooperative retirement."""
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

    def test_create_only_json_remains_create_only(self):
        path = self.base / 'marker.json'
        write_json(path, {'value': 'original'})
        with self.assertRaises(FileExistsError):
            write_json(path, {'value': 'replacement'})
        self.assertEqual(read_json(path)['value'], 'original')


if __name__ == '__main__':
    unittest.main()
