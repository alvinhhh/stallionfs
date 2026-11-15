"""Real locked disposal controls on tiny owned trees; no image or Git actor."""
import contextlib
import errno
import io
import json
import multiprocessing
import os
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch
import uuid

from stallionfs import core, _native_create_request as request, _native_create_recovery as recovery
from stallionfs import _native_creation_purge as purge, _native_create_authority as authority, _bundle
from stallionfs._bundle import GIT_CONTRACT, PUBLISHER_TEAM
from stallionfs.__main__ import main


class CreationDisposal(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='sfs-disposal-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "selected store's path"
        self.store = core.Store(self.root)
        self.seed = 'b' * 64
        self.seed_path = self.root / 'seeds' / self.seed
        self.seed_path.mkdir(mode=0o700)
        from native_writer_fixture import INPUT, qualify
        qualify(self)
        self.contract = {**GIT_CONTRACT, 'input_inventory_sha256': INPUT, 'payload_entries': 239, 'payload_sha256': '1' * 64,
            'descriptor_sha256': '2' * 64, 'executable_sha256': '3' * 64,
            'source_build_id': '4' * 64, 'publisher': PUBLISHER_TEAM}

    def attempt(self):
        workspace, transaction = uuid.uuid4().hex, uuid.uuid4().hex
        with core.lock(self.root / '.lock') as store, core.lock(self.root / 'locks' / ('seed-' + self.seed)) as seed:
            with request.prepare_controller(self.root, (store, seed), self.seed_path,
                    {'id': self.seed, 'commit': '5' * 40}, workspace=workspace, transaction=transaction,
                    name='', jobs=1, capacity=1, budget=None, install_profile=None, host=None,
                    runtime=self.contract) as (a, spec, record):
                record['replacement'] = {'workspace': uuid.uuid4().hex, 'transaction': uuid.uuid4().hex,
                                         'parent_spec_digest': request.digest(spec)}
                request.phase(a, self.root / 'journals' / (workspace + '.json'), record, 'clone')
        stage = Path(record['stage'])
        repo = stage / 'input/repo'; repo.mkdir(); (repo / 'data').write_bytes(b'owned disposable input')
        image = stage / 'owned/image.sfs'; image.write_bytes(b'opaque partial image'); image.chmod(0o600)
        return record

    def paths(self, record):
        return self.root / 'journals' / (record['workspace'] + '.json'), self.root / 'lifecycle' / (record['workspace'] + '.json')

    def call(self, record, confirm=True):
        return purge.purge_creation(self.root, record['workspace'], record['transaction'], confirm=confirm)

    def snapshot(self):
        return {str(path.relative_to(self.root)): (path.lstat().st_ino, path.lstat().st_mode,
                os.readlink(path) if path.is_symlink() else path.read_bytes() if path.is_file() else None)
                for path in self.root.rglob('*')}

    def cli(self, *args):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, {'STALLIONFS_HOME': str(self.base / 'conflicting root')}), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = main(['--root', str(self.root), *args])
        return status, stdout.getvalue(), stderr.getvalue()

    def inspect_interrupted(self, record):
        before = self.snapshot()
        for target in (record['workspace'], None):
            observed = recovery.inventory(self.root, target)
            self.assertTrue(observed['inventory_complete'], observed)
            row, = [row for row in observed['entries'] if row.get('workspace') == record['workspace']
                    and row.get('authoritative')]
            self.assertEqual(row['status'], 'purge-interrupted', observed)
            self.assertEqual(row['transaction'], record['transaction'])
            self.assertEqual(row['replacement'], record['replacement'])
            self.assertEqual(row['stage'], record['stage'])
            self.assertTrue(row['disposal']['completion_pending'])
        status, out, err = self.cli('creations', record['workspace'])
        self.assertEqual(status, 1); self.assertFalse(out)
        self.assertIn('Creation purge interrupted. Some files may have been removed.', err)
        self.assertNotIn('Files preserved', err)
        import shlex
        self.assertIn(shlex.join(['sfs', '--root', str(self.root), 'creations', record['workspace']]), err)
        status, out, err = self.cli('--json', 'creations', record['workspace'])
        self.assertEqual(status, 1); self.assertFalse(out)
        self.assertEqual(json.loads(err)['entries'][-1]['status'], 'purge-interrupted')
        status, out, err = self.cli('creations')
        self.assertEqual(status, 0); self.assertFalse(err); self.assertNotIn('Files preserved', out)
        status, out, err = self.cli('creations', record['workspace'], '--purge', record['transaction'])
        self.assertEqual(status, 1); self.assertFalse(out); self.assertIn('Creation purge interrupted.', err)
        status, out, err = self.cli('creations', record['workspace'], '--continue', record['transaction'])
        self.assertEqual(status, 1); self.assertFalse(out); self.assertIn('Creation purge interrupted.', err)
        self.assertEqual(self.snapshot(), before)

    def assert_fenced_retry(self, record):
        journal, completion = self.paths(record)
        events = []
        real_fsync, real_unlink = os.fsync, os.unlink
        def fsync(fd):
            info = os.fstat(fd)
            for label, path in (('completion', completion), ('lifecycle', completion.parent), ('journals', journal.parent)):
                if path.exists() and recovery.pair(info) == recovery.pair(path.lstat()): events.append(label)
            return real_fsync(fd)
        def unlink(path, **kwargs):
            if str(path) == journal.name: events.append('unlink-journal')
            return real_unlink(path, **kwargs)
        with patch.object(os, 'fsync', fsync), patch.object(os, 'unlink', unlink):
            result = self.call(record)
        self.assertEqual(result['status'], 'purged', result)
        self.assertEqual(result['replacement'], record['replacement'])
        cut = events.index('unlink-journal')
        self.assertIn('completion', events[:cut]); self.assertIn('lifecycle', events[:cut])
        self.assertIn('journals', events[cut + 1:])
        self.assertFalse(journal.exists())
        self.assertEqual(core.read_json(completion)['replacement'], record['replacement'])

    def test_inspection_after_each_removal_keeps_truthful_progress(self):
        for boundary in ('input/repo', 'owned/image.sfs', 'native-create', 'create-spec.json', '.'):
            with self.subTest(boundary=boundary):
                record = self.attempt(); original = request.publish
                def publish(a, path, value):
                    result = original(a, path, value)
                    if any(item['path'] == boundary and item.get('absent') for item in value.get('disposal', {}).get('entries', [])):
                        raise OSError('controlled interruption after removal')
                    return result
                with patch.object(request, 'publish', publish): result = self.call(record)
                self.assertEqual(result['status'], 'interrupted', result)
                self.inspect_interrupted(record)
                self.assert_fenced_retry(record)

    def legacy_attempt(self):
        record = self.attempt(); stage = Path(record['stage'])
        spec = recovery.semantic(core.read_json(stage / 'create-spec.json'))
        spec.update(protocol=2, method=request.LEGACY_METHOD, runtime={**_bundle.LEGACY_GIT_CONTRACT,
            **{key: spec['runtime'][key] for key in ('payload_entries', 'payload_sha256', 'descriptor_sha256',
                'executable_sha256', 'source_build_id', 'publisher')}})
        record.update(protocol=2, spec_digest=request.digest(spec))
        record['replacement']['parent_spec_digest'] = request.digest(spec)
        for path, value in ((stage / 'create-spec.json', spec), (stage / 'native-create', request.marker(record)),
                            (self.paths(record)[0], record)):
            path.write_text(json.dumps({'format': 1, **value}))
        return record

    def legacy_partial(self):
        record = self.legacy_attempt(); original = request.publish
        def stop(a, path, value):
            result = original(a, path, value)
            if any(item['path'] == 'input/repo' and item.get('absent')
                   for item in value.get('disposal', {}).get('entries', [])):
                raise OSError('historical fixture interruption after removal')
            return result
        # Only fixture construction models the formerly permitted v2 disposal.
        with patch.object(authority, 'current', return_value=None), patch.object(request, 'publish', stop):
            self.assertEqual(self.call(record)['status'], 'interrupted')
        self.assertFalse((Path(record['stage']) / 'input/repo').exists())
        return record

    def test_retired_partial_disposal_reports_history_without_fresh_authority(self):
        record = self.legacy_partial(); before = self.snapshot()
        self.inspect_interrupted(record)
        with patch.object(purge, 'execute', side_effect=AssertionError('retired deletion')) as execute, \
                patch.object(request, 'publish', side_effect=AssertionError('retired publication')):
            for confirm in (False, True):
                with self.subTest(confirm=confirm):
                    result = self.call(record, confirm)
                    self.assertEqual(result['status'], 'interrupted', result)
                    self.assertEqual(result['code'], 'unverified-writer', result)
                    self.assertIsNone(result['files_removed'])
                    self.assertFalse(result.get('eligible', False))
                    self.assertEqual(result['stage'], record['stage'])
                    self.assertEqual(result['input'], str(Path(record['stage']) / 'input/repo'))
                    self.assertEqual(result['backing'], str(Path(record['stage']) / 'owned/image.sfs'))
                    self.assertEqual(result['replacement'], record['replacement'])
                    self.assertTrue(result['disposal']['completion_pending'])
                    args = ['creations', record['workspace'], '--purge', record['transaction']]
                    if confirm: args.append('--confirm')
                    status, out, err = self.cli(*args)
                    self.assertEqual((status, out), (1, ''))
                    self.assertIn('Creation purge interrupted. Some files may have been removed.', err)
                    self.assertNotIn('Files preserved', err)
                    self.assertNotIn('A process may still be writing.', err)
                    self.assertEqual(self.snapshot(), before)
            execute.assert_not_called()

    def test_retired_pristine_attempt_keeps_writer_refusal(self):
        record = self.legacy_attempt(); before = self.snapshot()
        for confirm in (False, True):
            result = self.call(record, confirm)
            self.assertEqual(result['status'], 'writer-unverified', result)
            self.assertEqual(result['code'], 'unverified-writer', result)
            self.assertFalse(result['files_removed']); self.assertFalse(result.get('eligible', False))
            self.assertNotIn('disposal', result)
        status, out, err = self.cli('creations', record['workspace'], '--purge', record['transaction'])
        self.assertEqual((status, out), (1, ''))
        self.assertIn('Creation retained. A process may still be writing.', err)
        self.assertNotIn('Creation purge interrupted.', err)
        self.assertEqual(self.snapshot(), before)

    def test_retired_completion_reports_history_and_refuses_reused_stage(self):
        record = self.legacy_attempt()
        with patch.object(authority, 'current', return_value=None):
            self.assertEqual(self.call(record)['status'], 'purged')
        before = self.snapshot()
        with patch.object(purge, 'execute', side_effect=AssertionError('completed deletion')) as execute:
            for confirm in (False, True):
                result = self.call(record, confirm)
                self.assertEqual(result['status'], 'purged', result)
                self.assertTrue(result['already_complete']); self.assertFalse(result['files_removed'])
                self.assertEqual(result['replacement'], record['replacement'])
            execute.assert_not_called()
        self.assertEqual(self.snapshot(), before)
        stage = Path(record['stage']); stage.mkdir(mode=0o700)
        (stage / 'unrelated').write_bytes(b'reused namespace')
        before = self.snapshot()
        for confirm in (False, True):
            result = self.call(record, confirm)
            self.assertEqual(result['status'], 'blocked', result)
            self.assertEqual(result['code'], 'namespace-reused', result)
            self.assertFalse(result['files_removed'])
        self.assertEqual(self.snapshot(), before)

    def test_invalid_retired_disposal_cannot_supply_interrupted_observation(self):
        record = self.legacy_partial(); journal, _ = self.paths(record)
        value = core.read_json(journal)
        value['disposal']['entries'][0]['authorized'] = False
        journal.write_text(json.dumps(value))
        before = self.snapshot()
        for confirm in (False, True):
            result = self.call(record, confirm)
            self.assertEqual(result['status'], 'blocked', result)
            self.assertEqual(result['code'], 'invalid-disposal-entry', result)
            self.assertFalse(result['files_removed']); self.assertFalse(result.get('eligible', False))
        self.assertEqual(self.snapshot(), before)

    def partial_completion(self, record, fault):
        _, completion = self.paths(record)
        original_write, original_close, original_fsync = os.write, os.close, os.fsync
        injected = []
        def selected(fd):
            return completion.exists() and recovery.pair(os.fstat(fd)) == recovery.pair(completion.lstat())
        def write(fd, data):
            if selected(fd):
                if fault == 'short-enospc':
                    if not injected:
                        injected.append(True); return original_write(fd, data[:len(data) // 2])
                    raise OSError(errno.ENOSPC, 'completion full')
                if fault == 'zero': injected.append(True); return 0
                if fault == 'enospc': injected.append(True); raise OSError(errno.ENOSPC, 'completion full')
            return original_write(fd, data)
        def close(fd):
            fail = fault == 'close' and selected(fd) and not injected
            result = original_close(fd)
            if fail: injected.append(True); raise OSError(errno.EIO, 'completion close response')
            return result
        def fsync(fd):
            fail = fault == 'file-fsync' and selected(fd) and os.fstat(fd).st_size > 0
            fail |= fault == 'directory-fsync' and completion.exists() and completion.stat().st_size > 0 \
                and recovery.pair(os.fstat(fd)) == recovery.pair(completion.parent.stat())
            if fail: injected.append(True); raise OSError(errno.EIO, 'completion fence')
            return original_fsync(fd)
        with patch.object(os, 'write', write), patch.object(os, 'close', close), patch.object(os, 'fsync', fsync):
            result = self.call(record)
        self.assertTrue(injected)
        self.assertEqual(result['status'], 'interrupted', result)

    def test_completion_write_close_and_fence_failures_resume_exactly(self):
        for fault in ('short-enospc', 'zero', 'enospc', 'close', 'file-fsync', 'directory-fsync'):
            with self.subTest(fault=fault):
                record = self.attempt(); self.partial_completion(record, fault)
                self.assertFalse(Path(record['stage']).exists())
                self.inspect_interrupted(record)
                self.assert_fenced_retry(record)

    def test_completion_substitution_and_conflicts_are_preserved(self):
        for change in ('inode', 'symlink', 'hardlink', 'prefix', 'oversized', 'missing'):
            with self.subTest(change=change):
                record = self.attempt(); self.partial_completion(record, 'short-enospc')
                _, path = self.paths(record)
                if change in ('inode', 'symlink', 'missing'):
                    saved = self.base / ('saved-' + change); path.rename(saved)
                    if change == 'inode': path.write_bytes(saved.read_bytes()); path.chmod(0o600)
                    elif change == 'symlink': path.symlink_to(saved)
                elif change == 'hardlink': os.link(path, self.base / 'completion-alias')
                elif change == 'prefix': path.write_bytes(b'wrong' + path.read_bytes())
                else: path.write_bytes(path.read_bytes() + b'X' * 65536)
                before = self.snapshot()
                result = self.call(record)
                self.assertEqual(result['status'], 'blocked', result)
                self.assertEqual(self.snapshot(), before)

    def test_authorization_retry_fences_before_deletion(self):
        record = self.attempt(); journal, _ = self.paths(record)
        real_fsync, real_remove = os.fsync, core.remove_tree
        def fail_authority(fd):
            if recovery.pair(os.fstat(fd)) == recovery.pair(journal.parent.stat()):
                value = core.read_json(journal)
                if any(item['authorized'] for item in value.get('disposal', {}).get('entries', [])):
                    raise OSError(errno.EIO, 'authorization directory fence')
            return real_fsync(fd)
        with patch.object(os, 'fsync', fail_authority), patch.object(core, 'remove_tree', side_effect=AssertionError('early removal')):
            first = self.call(record)
        self.assertEqual(first['status'], 'interrupted', first)
        self.assertTrue((Path(record['stage']) / 'input/repo/data').exists())
        before = self.snapshot()
        with patch.object(os, 'fsync', side_effect=OSError(errno.EIO, 'retry fence failed')), \
                patch.object(core, 'remove_tree', side_effect=AssertionError('removal before retry fence')):
            second = self.call(record)
        self.assertEqual(second['status'], 'interrupted', second)
        self.assertEqual(self.snapshot(), before)
        events = []
        def fsync(fd):
            for label, path in (('journal', journal), ('directory', journal.parent)):
                if path.exists() and recovery.pair(os.fstat(fd)) == recovery.pair(path.stat()): events.append(label)
            return real_fsync(fd)
        def remove(path, **kwargs):
            self.assertIn('journal', events)
            self.assertIn('directory', events)
            return real_remove(path, **kwargs)
        with patch.object(os, 'fsync', fsync), patch.object(core, 'remove_tree', remove): result = self.call(record)
        self.assertEqual(result['status'], 'purged', result)

    def test_controller_death_across_completion_publication(self):
        context = multiprocessing.get_context('fork')
        for boundary in ('created', 'bound', 'partial', 'full-write', 'file-fsync', 'before-directory-fsync',
                         'after-directory-fsync', 'before-journal-unlink', 'after-journal-unlink'):
            with self.subTest(boundary=boundary):
                record = self.attempt(); journal, completion = self.paths(record)
                reader, writer = context.Pipe(duplex=False)
                def child():
                    original_open, original_write, original_fsync, original_unlink = os.open, os.write, os.fsync, os.unlink
                    original_publish = request.publish
                    def stop(): writer.send(boundary); signal.pause()
                    def selected(fd):
                        return completion.exists() and recovery.pair(os.fstat(fd)) == recovery.pair(completion.stat())
                    def opened(path, flags, *args, **kwargs):
                        fd = original_open(path, flags, *args, **kwargs)
                        if boundary == 'created' and flags & os.O_EXCL and selected(fd): stop()
                        return fd
                    def publish(a, path, value):
                        result = original_publish(a, path, value)
                        if boundary == 'bound' and 'completion_file' in value: stop()
                        return result
                    def write(fd, data):
                        if boundary == 'partial' and selected(fd):
                            original_write(fd, data[:len(data) // 2]); stop()
                        result = original_write(fd, data)
                        if boundary == 'full-write' and selected(fd): stop()
                        return result
                    def fsync(fd):
                        complete = completion.exists() and completion.stat().st_size > 0
                        directory = recovery.pair(os.fstat(fd)) == recovery.pair(completion.parent.stat())
                        if boundary == 'before-directory-fsync' and complete and directory: stop()
                        result = original_fsync(fd)
                        if boundary == 'file-fsync' and complete and selected(fd): stop()
                        if boundary == 'after-directory-fsync' and complete and directory: stop()
                        return result
                    def unlink(path, **kwargs):
                        if boundary == 'before-journal-unlink' and str(path) == journal.name: stop()
                        result = original_unlink(path, **kwargs)
                        if boundary == 'after-journal-unlink' and str(path) == journal.name: stop()
                        return result
                    with patch.object(os, 'open', opened), patch.object(os, 'write', write), patch.object(os, 'fsync', fsync), \
                            patch.object(os, 'unlink', unlink), patch.object(request, 'publish', publish):
                        writer.send(self.call(record))
                process = context.Process(target=child); process.start(); writer.close()
                try:
                    self.assertTrue(reader.poll(15), boundary); self.assertEqual(reader.recv(), boundary)
                finally:
                    if process.is_alive(): process.kill()
                    process.join(10); process.close(); reader.close()
                if journal.exists():
                    self.inspect_interrupted(record); self.assert_fenced_retry(record)
                else:
                    result = self.call(record)
                    self.assertEqual(result['status'], 'purged', result)
                    self.assertEqual(result['replacement'], record['replacement'])


if __name__ == '__main__':
    unittest.main()
