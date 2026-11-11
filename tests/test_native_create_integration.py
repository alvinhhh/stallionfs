"""Closed-image creation/replacement tests with controlled package-verifier seams.

These do not qualify a signed or installed companion, activation, or mounting.
"""
import copy
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from stallionfs import core, _native, _native_create_git as git
from stallionfs import _native_create_recovery as recovery
from stallionfs import _native_create_request as request
from stallionfs._native_creation_purge import purge_creation
from test_native_create_git import CreationGit


@unittest.skipUnless(os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT'), 'requires explicitly qualified private Git fixture')
class CreationIntegration(CreationGit):
    # Reuse only fixture methods, not the independent boundary tests.
    test_actual_prepared_seed_and_tracking_config = None
    test_actual_prepared_reftable = None
    test_actual_prepared_sha256_and_detached_source = None
    test_generic_prepare_and_create_preserve_defaults_without_hooks_or_trace = None
    test_log_identity_and_contained_head_symlink = None
    test_configured_descendant_hook_cannot_run_on_success = None
    test_transient_and_path_escape_before_actor = None

    def setUp(self):
        super().setUp()
        from stallionfs._bundle import GIT_CONTRACT, PUBLISHER_TEAM
        self.runtime['contract'] = {**GIT_CONTRACT, 'payload_entries': 239, 'payload_sha256': '1' * 64,
            'descriptor_sha256': '2' * 64, 'executable_sha256': self.runtime['contract']['executable_sha256'],
            'source_build_id': '3' * 64, 'publisher': PUBLISHER_TEAM}
        self.runtime['check'] = lambda: None
        self.addCleanup(patch.stopall)
        patch.object(git, 'qualified_runtime', return_value=self.runtime).start()
        # Intentionally controlled verifier seam. No codesign/Host invocation.
        patch.object(_native, 'preflight_create', return_value=None).start()
        seed, self.commit = self.prepare()
        self.seed = seed.parent.name

    def create(self, **kwargs):
        return self.store._build_owned_native_candidate(self.seed, native_capacity_gib=1, jobs=1, **kwargs)

    def retained(self):
        before = set((self.store.root / 'journals').glob('*.json'))
        with patch.object(core, 'clone_tree', side_effect=OSError('controlled clone interruption')):
            with self.assertRaises(OSError):
                self.create(name='retained')
        journals = list(set((self.store.root / 'journals').glob('*.json')) - before)
        self.assertEqual(len(journals), 1)
        record = core.read_json(journals[0]); record.pop('format')
        return journals[0], record

    def test_complete_request_and_native_receipt(self):
        result = self.create(name='a.b')
        self.assertTrue(result['candidate_created'])
        stage = Path(result['retained_stage'])
        record = core.read_json(Path(result['journal'])); record.pop('format')
        spec = core.read_json(stage / 'create-spec.json'); spec.pop('format')
        self.assertEqual(record['phase'], 'complete')
        self.assertEqual(record['spec_digest'], request.digest(spec))
        self.assertEqual(core.read_json(stage / 'native-create'), {'format': 1, **request.marker(record)})
        self.assertEqual(spec['budget'], request.DEFAULT_BUDGET)
        self.assertFalse(result['native_image_result']['budget_explicit'])
        self.assertEqual(len(result['native_image_result']['resources']['budget']), 6)
        self.assertFalse((stage / 'input').exists())
        observed = recovery.inventory(self.store.root, record['workspace'])
        self.assertEqual(observed['entries'][-1]['status'], 'candidate', observed)

    def test_replacement_preserves_old_stage_and_returns_same_child(self):
        journal, old = self.retained()
        stage = Path(old['stage'])
        before = {str(path.relative_to(stage)): (path.stat().st_ino, path.read_bytes())
                  for path in stage.iterdir() if path.is_file()}
        response = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(response['status'], 'replacement-created', response)
        self.assertNotEqual(response['workspace'], old['workspace'])
        self.assertEqual(before, {str(path.relative_to(stage)): (path.stat().st_ino, path.read_bytes())
                                 for path in stage.iterdir() if path.is_file()})
        reserved = core.read_json(journal)['replacement']
        child_journal = self.store.root / 'journals' / (reserved['workspace'] + '.json')
        child = core.read_json(child_journal)
        child_spec = core.read_json(Path(child['stage']) / 'create-spec.json')
        self.assertEqual(child_spec['parent']['spec_digest'], reserved['parent_spec_digest'])
        # Complete candidates follow phase-one continuation; don't invoke native install in this fixture.
        with patch('stallionfs._native_create_retry.finalize', return_value={'status': 'installed-unmounted',
                  'workspace': reserved['workspace'], 'transaction': reserved['transaction']}):
            again = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(again['workspace'], response['workspace'], again)
        self.assertEqual(core.read_json(journal)['replacement'], reserved)

    def test_candidate_requires_verifier_before_clone(self):
        with patch.object(_native, 'preflight_create', side_effect=core.StallionError('verifier refused')):
            with patch.object(core, 'clone_tree', side_effect=AssertionError('clone before verifier')):
                with self.assertRaises(core.StallionError):
                    self.create()
        record = core.read_json(next((self.store.root / 'journals').glob('*.json')))
        self.assertEqual(record['phase'], 'preflight')
        self.assertFalse((Path(record['stage']) / 'input/repo').exists())

    def test_preview_and_exact_disposal_preserve_seed_and_locks(self):
        journal, old = self.retained()
        before = journal.read_bytes()
        preview = purge_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(preview['status'], 'preview', preview)
        self.assertEqual(journal.read_bytes(), before)
        result = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
        self.assertEqual(result['status'], 'purged', result)
        self.assertFalse(Path(old['stage']).exists())
        self.assertFalse(journal.exists())
        self.assertTrue((self.store.root / 'seeds' / self.seed).exists())
        self.assertTrue((self.store.root / 'locks' / ('use-' + old['workspace'])).exists())
        again = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
        self.assertEqual(again['status'], 'purged', again)

    def test_pending_actor_is_never_disposal_authority(self):
        journal, old = self.retained()
        old['actors'] = [{'role': '00-config', 'environment': git.POLICY, 'child_pending': True, 'outcome': 'running'}]
        from stallionfs.lifecycle import replace_json
        replace_json(journal, old)
        before = journal.read_bytes()
        result = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
        self.assertEqual(result['status'], 'writer-unverified', result)
        self.assertEqual(journal.read_bytes(), before)
        self.assertTrue(Path(old['stage']).exists())

    def test_purged_parent_preserves_one_attempted_child_and_lock_binding(self):
        journal, old = self.retained()
        with patch.object(core, 'clone_tree', side_effect=OSError('child interrupted')):
            failed = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(failed['status'], 'blocked', failed)
        reserved = core.read_json(journal)['replacement']
        child_path = self.store.root / 'journals' / (reserved['workspace'] + '.json')
        child = child_path.read_bytes()
        purged = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
        self.assertEqual(purged['status'], 'purged', purged)
        for target in (old['workspace'], None):
            observed = recovery.inventory(self.store.root, target)
            self.assertTrue(observed['inventory_complete'], observed)
            self.assertTrue(any(row.get('workspace') == old['workspace'] and row.get('status') == 'purged'
                                and row.get('replacement') == reserved for row in observed['entries']), observed)
        with patch.object(core, 'clone_tree', side_effect=AssertionError('recursive retry')):
            followed = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(followed['status'], 'retained-child', followed)
        self.assertEqual(followed['workspace'], reserved['workspace'])
        self.assertEqual(child_path.read_bytes(), child)
        lease = self.store.root / 'locks' / ('use-' + reserved['workspace'])
        data = lease.read_bytes(); lease.rename(lease.with_name(lease.name + '-retained'))
        lease.write_bytes(data); lease.chmod(0o600)
        refused = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(refused.get('code'), 'lock-substitution', refused)
        self.assertEqual(child_path.read_bytes(), child)

    def test_disposal_refuses_hardlinked_backing_and_unknown_stage_bytes(self):
        for kind in ('hardlink', 'unknown'):
            with self.subTest(kind=kind):
                journal, old = self.retained(); stage = Path(old['stage'])
                outside = self.base / ('retained-' + kind); outside.write_bytes(b'preserved')
                if kind == 'hardlink':
                    outside.chmod(0o600); os.link(outside, stage / 'owned/image.sfs')
                else:
                    (stage / 'unrecognized').write_bytes(b'unknown')
                before = journal.read_bytes()
                result = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
                self.assertEqual(result['status'], 'blocked', result)
                self.assertEqual(journal.read_bytes(), before)
                self.assertEqual(outside.read_bytes(), b'preserved')
                self.assertTrue(stage.exists())

    def test_replacement_refusals_preserve_control_bytes_and_names(self):
        from stallionfs.lifecycle import replace_json
        cases = ('store-lock', 'lease-missing', 'lease-inode', 'lease-generation', 'lease-hardlink',
                 'lease-symlink', 'digest', 'install-phase', 'pending-helper', 'legacy')
        for case in cases:
            with self.subTest(case=case):
                journal, old = self.retained(); stage = Path(old['stage'])
                lease = self.store.root / 'locks' / ('use-' + old['workspace'])
                restored = None
                if case in ('store-lock', 'lease-missing', 'lease-inode', 'lease-symlink'):
                    target = self.store.root / '.lock' if case == 'store-lock' else lease
                    saved = target.with_name(target.name + '-saved'); target.rename(saved)
                    restored = (target, saved)
                    if case in ('store-lock', 'lease-inode'):
                        target.write_bytes(saved.read_bytes()); target.chmod(0o600)
                    elif case == 'lease-symlink':
                        target.symlink_to(saved)
                elif case == 'lease-generation':
                    lease.write_text('0' * 64 + '\n')
                elif case == 'lease-hardlink':
                    os.link(lease, lease.with_name(lease.name + '-alias'))
                else:
                    if case == 'digest': old['spec_digest'] = '0' * 64
                    elif case == 'install-phase': old['phase'] = 'install'
                    elif case == 'pending-helper': old.update(child_pending=True, helpers=[])
                    elif case == 'legacy':
                        for field in ('protocol', 'phase', 'spec_digest', 'actors'): old.pop(field, None)
                    replace_json(journal, old)
                def snapshot():
                    paths = [journal, *stage.rglob('*'), *self.store.root.joinpath('locks').iterdir()]
                    return {str(p): (p.lstat().st_ino, p.lstat().st_mode,
                            os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None) for p in paths}
                before = snapshot()
                try:
                    with patch.object(core, 'clone_tree', side_effect=AssertionError('effect after refusal')):
                        result = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
                    self.assertIn(result['status'], ('blocked', 'busy'), result)
                    self.assertEqual(snapshot(), before)
                    self.assertNotIn('replacement', core.read_json(journal))
                finally:
                    if restored:
                        target, saved = restored
                        if os.path.lexists(target): target.unlink()
                        saved.rename(target)

    def test_lost_git_terminal_receipt_replaces_without_opening_old_input(self):
        import multiprocessing
        import signal
        context = multiprocessing.get_context('fork')
        reader, writer = context.Pipe(duplex=False)
        before = set((self.store.root / 'journals').glob('*.json'))
        def child():
            real_publish = request.publish
            def publish(a, path, value):
                actors = value.get('actors', [])
                if actors and actors[-1]['role'] == '04-checkout' and actors[-1].get('reaped') is True:
                    writer.send('terminal-not-published'); signal.pause()
                return real_publish(a, path, value)
            with patch.object(request, 'publish', publish): self.create(name='lost-receipt')
        process = context.Process(target=child); process.start(); writer.close()
        try:
            self.assertTrue(reader.poll(15)); self.assertEqual(reader.recv(), 'terminal-not-published')
        finally:
            if process.is_alive(): process.kill()
            process.join(10); process.close(); reader.close()
        journal, = set((self.store.root / 'journals').glob('*.json')) - before
        old = core.read_json(journal)
        self.assertTrue(old['actors'][-1]['child_pending'])
        stage = Path(old['stage']); old_input = stage / 'input'
        def snapshot():
            return {str(p.relative_to(stage)): (p.lstat().st_ino, p.lstat().st_mode,
                    os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
                    for p in stage.rglob('*')}
        retained = snapshot(); real_open = os.open
        def opened(path, *args, **kwargs):
            if isinstance(path, (str, bytes, os.PathLike)):
                candidate = Path(os.fsdecode(path))
                if not candidate.is_absolute() and kwargs.get('dir_fd') is not None:
                    import fcntl
                    candidate = Path(fcntl.fcntl(kwargs['dir_fd'], 50, bytes(1024)).split(b'\0', 1)[0].decode()) / candidate
                self.assertFalse(candidate == old_input or candidate.is_relative_to(old_input), 'old input opened')
            return real_open(path, *args, **kwargs)
        with patch.object(os, 'open', opened):
            result = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
        self.assertEqual(result['status'], 'replacement-created', result)
        self.assertEqual(snapshot(), retained)
        self.assertTrue(core.read_json(journal)['actors'][-1]['child_pending'])
        refused = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
        self.assertEqual(refused['status'], 'writer-unverified', refused)

    def test_real_controller_death_bootstrap_resumes_same_reservation(self):
        import multiprocessing
        context = multiprocessing.get_context('fork')
        checkpoints = ('stage', 'input', 'owned', 'lease-open', 'lease-prefix', 'lease-full', 'work-lock',
                       'spec-prefix', 'spec-full', 'marker-prefix', 'marker-full', 'journal-prefix', 'journal-full', 'bootstrap-final')
        for checkpoint in checkpoints:
            with self.subTest(checkpoint=checkpoint):
                journal, old = self.retained()
                original_stage = Path(old['stage'])
                original = {p.name: p.read_bytes() for p in original_stage.iterdir() if p.is_file()}
                reader, writer = context.Pipe(duplex=False)
                def child():
                    import signal
                    opened = {}
                    real_open, real_write, real_mkdir = os.open, os.write, os.mkdir
                    real_control, real_validate = request._control, request.validate
                    def stop():
                        writer.send(checkpoint)
                        signal.pause()
                    def role(path):
                        name = Path(path).name
                        if name.startswith('use-'): return 'lease'
                        if name.startswith('workspace-'): return 'work'
                        if name == 'create-spec.json': return 'spec'
                        if name == 'native-create': return 'marker'
                        if len(name) == 37 and name.endswith('.json') and name != journal.name: return 'journal'
                    def opened_file(path, flags, *args, **kwargs):
                        fd = real_open(path, flags, *args, **kwargs)
                        opened[fd] = role(path)
                        if flags & os.O_CREAT:
                            if opened[fd] == 'lease' and checkpoint == 'lease-open': stop()
                            if opened[fd] == 'work' and checkpoint == 'work-lock': stop()
                        return fd
                    def write(fd, data):
                        if opened.get(fd) and checkpoint == opened[fd] + '-prefix' and len(data) > 1:
                            real_write(fd, data[:len(data) // 2]); stop()
                        return real_write(fd, data)
                    def mkdir(path, *args, **kwargs):
                        result = real_mkdir(path, *args, **kwargs)
                        name = Path(path).name
                        if checkpoint == name or checkpoint == 'stage' and name.startswith('native-create-'): stop()
                        return result
                    def control(a, path, expected, **kwargs):
                        result = real_control(a, path, expected, **kwargs)
                        if kwargs.get('finish') and checkpoint == str(role(path)) + '-full': stop()
                        return result
                    def validate(a, record, **kwargs):
                        result = real_validate(a, record, **kwargs)
                        if checkpoint == 'bootstrap-final' and record['workspace'] != old['workspace'] and record['phase'] == 'specified': stop()
                        return result
                    with patch.object(os, 'open', opened_file), patch.object(os, 'write', write), patch.object(os, 'mkdir', mkdir), \
                         patch.object(request, '_control', control), patch.object(request, 'validate', validate):
                        writer.send(recovery.continue_creation(self.store.root, old['workspace'], old['transaction']))
                process = context.Process(target=child)
                process.start(); writer.close()
                try:
                    self.assertTrue(reader.poll(15), checkpoint)
                    observed = reader.recv()
                    self.assertEqual(observed, checkpoint)
                finally:
                    if process.is_alive(): process.kill()
                    process.join(10); reader.close()
                    self.assertFalse(process.is_alive())
                    process.close()
                reserved = core.read_json(journal)['replacement']
                result = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
                self.assertEqual(result['status'], 'replacement-created', result)
                self.assertEqual(result['workspace'], reserved['workspace'])
                self.assertEqual(core.read_json(journal)['replacement'], reserved)
                self.assertEqual(original, {p.name: p.read_bytes() for p in original_stage.iterdir() if p.is_file()})

    def test_two_controllers_reserve_once(self):
        import multiprocessing
        context = multiprocessing.get_context('fork')
        journal, old = self.retained()
        readers, processes = [], []
        for _ in range(2):
            reader, writer = context.Pipe(duplex=False)
            def child(connection):
                connection.send(recovery.continue_creation(self.store.root, old['workspace'], old['transaction']))
            process = context.Process(target=child, args=(writer,)); process.start(); writer.close()
            readers.append(reader); processes.append(process)
        results = []
        try:
            for reader in readers:
                self.assertTrue(reader.poll(20))
                results.append(reader.recv())
        finally:
            for process in processes:
                process.join(10)
                if process.is_alive(): process.kill(); process.join(5)
                process.close()
            for reader in readers: reader.close()
        self.assertEqual(sum(row['status'] == 'replacement-created' for row in results), 1, results)
        self.assertEqual(sum(row['status'] == 'busy' for row in results), 1, results)
        reservation = core.read_json(journal)['replacement']
        self.assertEqual(len(list((self.store.root / 'staging').glob('native-create-' + reservation['transaction']))), 1)

    def test_reservation_crash_barriers_precede_child_effects(self):
        import multiprocessing
        context = multiprocessing.get_context('fork')
        for checkpoint in ('reservation-write', 'reservation-fsync', 'reservation-rename', 'reservation-dirsync'):
            with self.subTest(checkpoint=checkpoint):
                journal, old = self.retained()
                reader, writer = context.Pipe(duplex=False)
                def child():
                    import signal
                    opened, renamed = {}, [False]
                    real_open, real_write, real_fsync, real_replace = os.open, os.write, os.fsync, os.replace
                    def stop(): writer.send(checkpoint); signal.pause()
                    def opened_file(path, flags, *args, **kwargs):
                        fd = real_open(path, flags, *args, **kwargs)
                        opened[fd] = str(path)
                        return fd
                    def write(fd, data):
                        result = real_write(fd, data)
                        if Path(opened.get(fd, '')).name.startswith('.' + journal.name + '.') and checkpoint == 'reservation-write': stop()
                        return result
                    def fsync(fd):
                        result = real_fsync(fd)
                        if Path(opened.get(fd, '')).name.startswith('.' + journal.name + '.') and checkpoint == 'reservation-fsync': stop()
                        if renamed[0] and checkpoint == 'reservation-dirsync' and os.fstat(fd).st_ino == journal.parent.stat().st_ino: stop()
                        return result
                    def replace(source, destination, *args, **kwargs):
                        result = real_replace(source, destination, *args, **kwargs)
                        if str(destination) == journal.name:
                            renamed[0] = True
                            if checkpoint == 'reservation-rename': stop()
                        return result
                    with patch.object(os, 'open', opened_file), patch.object(os, 'write', write), \
                         patch.object(os, 'fsync', fsync), patch.object(os, 'replace', replace):
                        writer.send(recovery.continue_creation(self.store.root, old['workspace'], old['transaction']))
                before = set((self.store.root / 'staging').iterdir())
                process = context.Process(target=child); process.start(); writer.close()
                try:
                    self.assertTrue(reader.poll(15)); self.assertEqual(reader.recv(), checkpoint)
                finally:
                    if process.is_alive(): process.kill()
                    process.join(10); process.close(); reader.close()
                self.assertEqual(set((self.store.root / 'staging').iterdir()), before)
                reserved = core.read_json(journal).get('replacement')
                result = recovery.continue_creation(self.store.root, old['workspace'], old['transaction'])
                self.assertEqual(result['status'], 'replacement-created', result)
                if reserved:
                    self.assertEqual(core.read_json(journal)['replacement'], reserved)

    def test_public_cli_eligible_preview_confirm_and_repeated_completion(self):
        import contextlib
        import io
        from stallionfs.__main__ import main
        journal, old = self.retained()
        prefix = ['--root', str(self.store.root), 'creations', old['workspace'], '--purge', old['transaction']]
        for suffix, expected in (([], 'No files removed. Add --confirm'), (['--confirm'], 'Creation purge complete.'),
                                 (['--confirm'], 'Creation purge complete.')):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = main(prefix + suffix)
            self.assertEqual(result, 0, output.getvalue())
            self.assertIn(expected, output.getvalue())
        self.assertFalse(journal.exists())
        for tail in ([], ['--continue', old['transaction']]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                result = main(['--root', str(self.store.root), 'creations', old['workspace'], *tail])
            self.assertEqual(result, 0, output.getvalue())
            self.assertIn('purged', output.getvalue())

    def test_disposal_kills_resume_and_preserve_external_link_targets(self):
        import multiprocessing
        context = multiprocessing.get_context('fork')
        for checkpoint in ('authority', 'input', 'backing', 'marker', 'stage', 'completion'):
            with self.subTest(checkpoint=checkpoint):
                journal, old = self.retained()
                stage = Path(old['stage'])
                repo = stage / 'input/repo'; repo.mkdir()
                outside = self.base / ('outside-' + checkpoint); outside.write_bytes(b'outside retained')
                (repo / 'escape').symlink_to(outside)
                os.link(outside, repo / 'linked')
                image = stage / 'owned/image.sfs'; image.write_bytes(b'opaque failed candidate'); image.chmod(0o600)
                reader, writer = context.Pipe(duplex=False)
                def child():
                    import signal
                    from stallionfs import _native_creation_purge as disposal
                    real_publish, real_completion = request.publish, disposal.publish_completion
                    real_remove, real_unlink, real_rmdir = core.remove_tree, os.unlink, os.rmdir
                    def stop(): writer.send(checkpoint); signal.pause()
                    def publish(a, path, value):
                        result = real_publish(a, path, value)
                        if checkpoint == 'authority' and 'disposal' in value and not any(x['authorized'] for x in value['disposal']['entries']): stop()
                        return result
                    def remove(path, **kwargs):
                        result = real_remove(path, **kwargs)
                        if checkpoint == 'input' and Path(path) == repo: stop()
                        return result
                    def unlink(path, **kwargs):
                        result = real_unlink(path, **kwargs)
                        if checkpoint == 'backing' and str(path) == 'image.sfs' or checkpoint == 'marker' and str(path) == 'native-create': stop()
                        return result
                    def rmdir(path, **kwargs):
                        result = real_rmdir(path, **kwargs)
                        if checkpoint == 'stage' and str(path) == stage.name: stop()
                        return result
                    def completion(a, record):
                        result = real_completion(a, record)
                        if checkpoint == 'completion': stop()
                        return result
                    with patch.object(request, 'publish', publish), patch.object(disposal, 'publish_completion', completion), \
                         patch.object(core, 'remove_tree', remove), patch.object(os, 'unlink', unlink), patch.object(os, 'rmdir', rmdir):
                        writer.send(purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True))
                process = context.Process(target=child); process.start(); writer.close()
                try:
                    self.assertTrue(reader.poll(15)); self.assertEqual(reader.recv(), checkpoint)
                finally:
                    if process.is_alive(): process.kill()
                    process.join(10); process.close(); reader.close()
                result = purge_creation(self.store.root, old['workspace'], old['transaction'], confirm=True)
                self.assertEqual(result['status'], 'purged', result)
                self.assertEqual(outside.read_bytes(), b'outside retained')
                self.assertFalse(stage.exists()); self.assertFalse(journal.exists())
                self.assertTrue((self.store.root / 'locks' / ('use-' + old['workspace'])).exists())
