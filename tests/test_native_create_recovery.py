"""Synthetic protocol tests using owned temporary trees and a fake backing guard.

These exercise durable controller state, not the native filesystem or OS helpers.
"""
import contextlib
import copy
import errno
import fcntl
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import core, _native, _native_create_recovery as recovery


class CreateRecovery(unittest.TestCase):
    workspace = '1' * 32
    transaction = '2' * 32
    seed = '3' * 64

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-create-recovery-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.root = self.base / 'store'
        self.root.mkdir(mode=0o700)
        for name in recovery.PARENTS + ('seeds', 'trash', 'snapshots', 'protected'):
            (self.root / name).mkdir(mode=0o700)
        self.save(self.root / 'store.json', {'application': 'stallionfs'})
        for path in (self.root / '.lock', self.root / 'locks' / ('use-' + self.workspace),
                     self.root / 'locks' / ('workspace-' + self.workspace)):
            path.touch(mode=0o600)
        self.stage = self.root / 'staging' / 'build-fixture'
        self.stage.mkdir(mode=0o700)
        self.owned = self.stage / 'owned'; self.owned.mkdir(mode=0o700)
        self.final = self.root / 'workspaces' / self.workspace
        self.journal = self.root / 'journals' / (self.workspace + '.json')
        self.image = self.owned / 'image.sfs'
        self.image.write_bytes(b'opaque synthetic image; never interpreted by native code')
        self.image.chmod(0o600)
        self.anchor = {'generation': 2, 'root_digest': '4' * 64, 'committed_end': 16384}
        self.target = {'component': 'image.sfs', 'parent': self.ident(self.stage), 'object': self.ident(self.owned),
                       'file': self.ident(self.image), 'uuid': '5' * 32, 'anchor': self.anchor}
        receipt = dict(status=0, uuid=self.target['uuid'], device=self.target['file'][0], inode=self.target['file'][1],
                       poisoned=False, transaction_active=False, phase=0, system_errno=0, coverage=0,
                       incomplete_reason=0, limit_reason=0, fence_attempted=0, fence_succeeded=0,
                       physical_end=self.anchor['committed_end'], **self.anchor)
        result = {'identity': {'file': self.target['file'], 'uuid': self.target['uuid']}, 'anchor': self.anchor,
                  'candidate_complete': True, 'import_committed': True, 'verified': True,
                  'creation_disposition': 'known_created', 'outcome': 'candidate-created',
                  'ok': True, 'creation_attempted': True, 'reason': 'none', 'error_code': 0, 'local_error': 0,
                  'descriptor_close_error': 0, 'failed_record': (1 << 64) - 1, 'observed_file': self.target['file'],
                  'resources': {'entries': 1, 'scratch_bytes': 4096, 'xattr_memory_high_water': 0,
                      'policy': 'finite-traversal-v2', 'budget': {key: 4096 for key in recovery.BUDGET_KEYS}},
                  'budget_explicit': False, 'budget_saturated': False, 'parent_steps': 0, 'abort': None,
                  'failure_path_error': 0, 'xattr_names_scratch_high_water': 0, 'failure_path': None}
        for key in ('creation', 'original', 'commit', 'verify', 'close', 'reopen', 'reopen_close'):
            result[key] = dict(receipt)
        result['creation']['generation'] = 1
        result['commit'].update(fence_attempted=3, fence_succeeded=3)
        result['verify']['coverage'] = 1
        self.meta = {'id': self.workspace, 'seed': self.seed, 'transaction': self.transaction, 'name': 'fixture',
                     'branch': 'stallionfs/fixture-' + self.workspace, 'commit': '6' * 40, 'created': 123.5,
                     'backend': 'native-image', 'ownership': 'store-created', 'state': 'candidate',
                     'capacity_gib': 1, 'native_image': self.target, 'creation_proof': 'native-create.json'}
        self.proof = {'operation': 'native-create', 'id': self.workspace, 'transaction': self.transaction,
                      'seed': self.seed, 'native_image': self.target, 'import_contract': 'prepared-tree-v1', 'result': result}
        self.record = {'operation': 'native-create', 'workspace': self.workspace, 'transaction': self.transaction,
                       'seed': self.seed, 'stage': str(self.stage), 'stage_identity': self.ident(self.stage),
                       'candidate': str(self.owned), 'object': self.ident(self.owned), 'final': str(self.final),
                       'creation_attempted': True, 'outcome': 'candidate-created', 'result': result,
                       'native_image': {k: self.target[k] for k in ('component', 'file', 'uuid', 'anchor')}}
        self.save(self.owned / 'native-create.json', self.proof)
        self.save(self.owned / 'meta.json', self.meta)
        self.save(self.journal, self.record)
        self.save(self.stage / 'native-create', self.record)
        self.guard_calls = []; self.guard_active = False; self.guard_anchor = self.anchor
        self.stack = contextlib.ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(_native._image, 'with_backing_guard', side_effect=self.guard))
        self.stack.enter_context(patch.object(_native._scan, 'move', side_effect=self.exclusive_move))
        for module, names in ((core, ('git', 'run', 'clone_tree', 'remove_tree')),
                              (_native, ('execute_owned', 'qualify', 'mount', 'unmount'))):
            for name in names:
                if hasattr(module, name):
                    self.stack.enter_context(patch.object(module, name, side_effect=AssertionError('forbidden: ' + name)))
        self.stack.enter_context(patch.object(core.Store, 'object', side_effect=AssertionError('seed read')))
        self.stack.enter_context(patch.object(_native._image, 'create_from_tree', side_effect=AssertionError('import'), create=True))

    @staticmethod
    def ident(path):
        info = path.lstat(); return [info.st_dev, info.st_ino]

    @staticmethod
    def save(path, value):
        path.write_text(json.dumps({'format': 1, **value})); path.chmod(0o600)

    @staticmethod
    def read(path):
        return recovery.semantic(json.loads(path.read_text()))

    def snapshot(self):
        return {str(p.relative_to(self.base)): (p.lstat().st_mode, p.lstat().st_ino,
                   os.readlink(p) if p.is_symlink() else p.read_bytes() if p.is_file() else None)
                for p in [self.base, *self.base.rglob('*')]}

    def guard(self, target, callback, expected=None):
        self.guard_calls.append((copy.deepcopy(target), copy.deepcopy(expected)))
        if expected is not None and expected != self.guard_anchor:
            raise core.StallionError('synthetic original-anchor mismatch')
        owner = self
        class Token:
            close_result = None
            def verify(self, current):
                owner.assertTrue(owner.guard_active)
                owner.assertEqual(owner.ident(Path(current['directory'])), current['parent'])
                owner.assertEqual(owner.ident(Path(current['directory']) / 'image.sfs'), current['file'])
        token = Token(); self.guard_active = True
        try:
            callback(token)
        finally:
            token.close_result = dict(self.guard_anchor, status=0, core_consumed=True, parent_close_errno=0,
                poisoned=False, transaction_active=False, device=target['file'][0], inode=target['file'][1], uuid=target['uuid'])
            self.guard_active = False

    @staticmethod
    def exclusive_move(source, destination):
        if os.path.lexists(destination):
            raise FileExistsError(errno.EEXIST, 'synthetic exclusive destination')
        os.rename(source, destination)

    def continuation(self, **kwargs):
        return recovery.continue_creation(self.root, self.workspace, self.transaction, **kwargs)

    def assert_installed(self, result):
        self.assertEqual(result['status'], 'installed-unmounted', result)
        self.assertEqual(self.ident(self.final / 'image.sfs'), self.target['file'])
        self.assertEqual((self.final / 'image.sfs').read_bytes(), b'opaque synthetic image; never interpreted by native code')
        self.assertFalse(self.journal.exists())
        self.assertEqual(self.read(self.final / 'meta.json')['state'], 'installed')

    def test_inventory_existing_absent_and_markerless_is_read_only(self):
        orphan = self.root / 'staging' / 'orphan'; orphan.mkdir(mode=0o700)
        (orphan / 'input').mkdir(mode=0o700)
        (orphan / 'input' / 'must-not-read').write_text('private input')
        before = self.snapshot()
        result = recovery.inventory(self.root)
        self.assertTrue(result['inventory_complete'], result)
        self.assertIn('candidate', [r['status'] for r in result['entries']])
        self.assertTrue(any(r.get('path') == str(orphan) and r['status'] == 'unclassified' for r in result['entries']))
        self.assertEqual(before, self.snapshot())
        self.assertEqual(recovery.inventory(self.base / 'missing')['status'], 'unavailable')
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.guard_calls, [])

    def test_missing_locks_or_containers_never_repaired(self):
        for path in (self.root / '.lock', self.root / 'locks' / ('use-' + self.workspace)):
            contents = path.read_bytes(); path.unlink(); before = self.snapshot()
            self.assertEqual(self.continuation()['status'], 'blocked')
            self.assertEqual(before, self.snapshot()); path.write_bytes(contents); path.chmod(0o600)
        (self.root / 'lifecycle').rmdir(); before = self.snapshot()
        self.assertFalse(recovery.inventory(self.root)['inventory_complete'])
        self.assertEqual(before, self.snapshot())

    def test_success_repeated_calls_and_guarded_rename_syncs(self):
        events = []
        rename, fsync = os.rename, os.fsync
        def moved(*args, **kwargs):
            self.assertTrue(self.guard_active); events.append('rename'); return rename(*args, **kwargs)
        def synced(fd):
            identity = recovery.pair(os.fstat(fd))
            if events and identity in (self.ident(self.stage), self.ident(self.final.parent)):
                self.assertTrue(self.guard_active); events.append(tuple(identity))
            return fsync(fd)
        with patch.object(recovery.os, 'rename', side_effect=moved), patch.object(recovery.os, 'fsync', side_effect=synced):
            self.assert_installed(self.continuation())
        self.assertEqual(events[0], 'rename')
        self.assertIn(tuple(self.ident(self.stage)), events)
        self.assertIn(tuple(self.ident(self.final.parent)), events)
        state = (self.root / 'lifecycle' / (self.workspace + '.json')).read_bytes()
        proof = (self.final / 'native-install.json').read_bytes()
        with patch.object(recovery.os, 'rename', side_effect=AssertionError('rename replay')):
            self.assert_installed(self.continuation())
        self.assertEqual(state, (self.root / 'lifecycle' / (self.workspace + '.json')).read_bytes())
        self.assertEqual(proof, (self.final / 'native-install.json').read_bytes())
        self.assertTrue(all(expected == self.anchor for _, expected in self.guard_calls))

    def test_anchor_mismatch_before_any_write(self):
        self.guard_anchor = dict(self.anchor, generation=3)
        before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked')
        self.assertEqual(before, self.snapshot())

    def test_stale_transaction_and_unknown_schema_unchanged(self):
        before = self.snapshot()
        self.assertEqual(recovery.continue_creation(self.root, self.workspace, 'a' * 32)['status'], 'blocked')
        self.assertEqual(before, self.snapshot())
        for value in ({**self.record, 'recovery_version': 2}, {**self.record, 'helpers': []},
                      {**self.record, 'child_pending': False}, {**self.record, 'result': {}},
                      {**self.record, 'candidate': str(self.base / 'foreign')}):
            self.save(self.journal, value); before = self.snapshot()
            self.assertEqual(self.continuation()['status'], 'blocked')
            self.assertEqual(before, self.snapshot())
        self.assertEqual(self.guard_calls, [])

    def test_marker_before_journal_and_orphan_proof_are_visible_only(self):
        self.journal.unlink(); before = self.snapshot()
        observed = recovery.inventory(self.root)
        self.assertTrue(any(r.get('workspace') == self.workspace for r in observed['entries']))
        self.assertEqual(self.continuation()['status'], 'blocked')
        self.assertEqual(before, self.snapshot())

    def test_preflight_archive_must_agree_without_promoting_journal(self):
        archive = self.stage / 'discovery'; archive.mkdir(mode=0o700)
        self.record.update(helpers=[], child_pending=False, discovery={'ok': True, 'protocol': 1, 'modules': []})
        initial = {k: self.record[k] for k in recovery.KEYS | {'helpers', 'child_pending'}}
        initial['discovery'] = self.record['discovery']
        initial.update(creation_attempted=False, outcome='preparing',
                       native_image={'component': 'image.sfs', 'file': None, 'uuid': None, 'anchor': None})
        self.save(archive / 'record.json', initial)
        self.save(self.journal, self.record); self.save(self.stage / 'native-create', self.record)
        wrong = {**initial, 'transaction': 'f' * 32}
        self.save(archive / 'record.json', wrong); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        self.save(archive / 'record.json', initial)
        self.assert_installed(self.continuation())

    def test_empty_volume_reused_and_occupied_alias_refused(self):
        volume = self.owned / 'volume'; volume.mkdir(mode=0o700)
        saved = self.ident(volume)
        (volume / 'occupied').write_bytes(b'x'); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        (volume / 'occupied').unlink(); volume.rmdir(); volume.symlink_to(self.base, target_is_directory=True)
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        volume.unlink(); volume.mkdir(mode=0o700); saved = self.ident(volume)
        self.assert_installed(self.continuation()); self.assertEqual(saved, self.ident(self.final / 'volume'))

    def test_aggregate_budgets_and_targeted_inventory(self):
        with patch.object(recovery, 'MAX_ENTRIES', 1):
            result = recovery.inventory(self.root)
        self.assertFalse(result['inventory_complete']); self.assertTrue(result['incomplete_paths'])
        with patch.object(recovery, 'MAX_TOTAL_BYTES', 80):
            result = recovery.inventory(self.root)
        self.assertFalse(result['inventory_complete'])
        with patch.object(recovery, 'MAX_DOCUMENT_BYTES', 100):
            result = recovery.inventory(self.root)
        self.assertFalse(result['inventory_complete'])
        result = recovery.inventory(self.root, self.workspace)
        self.assertTrue(result['inventory_complete']); self.assertEqual(result['scope'], self.workspace)

    def test_substitution_and_duplicate_ownership_refuse(self):
        alias = self.root / 'journals' / ('a' * 32 + '.json')
        self.save(alias, self.record); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot()); alias.unlink()
        old = self.image.read_bytes(); self.image.unlink(); self.image.write_bytes(old); self.image.chmod(0o600)
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_both_locations_and_neither_location_refuse(self):
        self.final.mkdir(mode=0o700); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        self.final.rmdir(); moved = self.stage / 'retained'; self.owned.rename(moved); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_failure_after_rename_does_not_repeat_rename(self):
        rename = os.rename
        def changed(*args, **kwargs):
            rename(*args, **kwargs); raise OSError(errno.EIO, 'after rename')
        with patch.object(recovery.os, 'rename', side_effect=changed):
            self.assertEqual(self.continuation()['status'], 'blocked')
        with patch.object(recovery.os, 'rename', side_effect=AssertionError('repeat rename')):
            self.assert_installed(self.continuation())

    def test_failed_old_guard_receipt_preserved(self):
        installed = recovery.installed_metadata(self.meta, self.ident(self.final.parent), 'production', None)
        failed = {'status': 5, 'core_consumed': False}
        self.record['installation'] = {'metadata': installed, 'first_mount_attempted': False,
            'rename_attempted': False, 'outcome': 'prepared', 'guard': failed}
        self.save(self.journal, self.record)
        self.assert_installed(self.continuation())
        proof = self.read(self.final / 'native-install.json')
        self.assertEqual(proof['previous_installation']['guard'], failed)
        self.assertEqual(proof['previous_installation']['continuation_receipts'][-1]['outcome'], 'consumed')

    def test_lifecycle_collision_and_changed_generation_refuse(self):
        path = self.root / 'lifecycle' / (self.workspace + '.json')
        self.save(path, {'id': self.workspace, 'generation': '7' * 32, 'status': 'open', 'enrolled': False,
                         'object': self.target['object'], 'payload': self.target['file']})
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        path.unlink(); self.assert_installed(self.continuation())
        state = self.read(path); state['generation'] = '9' * 32; self.save(path, state)
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_after_first_mount_handoff_does_not_guard_or_rewind(self):
        self.assert_installed(self.continuation())
        proof = self.read(self.final / 'native-install.json'); proof['first_mount_attempted'] = True
        proof['first_use'] = {'accepted': True, 'operation': '8' * 32}
        self.save(self.final / 'native-install.json', proof)
        self.guard_calls.clear(); before = self.snapshot()
        result = self.continuation()
        self.assertEqual(result['status'], 'already-installed', result)
        self.assertEqual(result['handoff'], 'mount-state'); self.assertEqual(self.guard_calls, [])
        self.assertEqual(before, self.snapshot())

    def test_settings_frozen_and_no_seed_reads(self):
        host = '/tmp/Fixture.app/Contents/MacOS/StallionFS'
        self.assert_installed(self.continuation(host=host))
        before = self.snapshot(); self.assertEqual(self.continuation(host='/tmp/Other.app/Contents/MacOS/StallionFS')['status'], 'blocked')
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.read(self.final / 'meta.json')['native_host'], host)

    def test_malformed_metadata_hardlink_and_duplicate_json_keys(self):
        path = self.owned / 'meta.json'
        original = path.read_bytes(); outside = self.base / 'other'; outside.write_bytes(original); outside.chmod(0o600)
        path.unlink(); os.link(outside, path); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        path.unlink(); path.write_bytes(b'{"format":1,"format":1}'); path.chmod(0o600)
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_substitution_after_admission_is_refused(self):
        original = recovery.Admission.lock
        changed = []
        def lock(a, path, shared=False):
            result = original(a, path, shared)
            if path.name.startswith('workspace-'):
                path.unlink(); path.touch(mode=0o600); changed.append(path)
            return result
        with patch.object(recovery.Admission, 'lock', lock):
            result = self.continuation()
        self.assertTrue(changed); self.assertEqual(result['status'], 'blocked')
        self.assertTrue(self.owned.exists()); self.assertFalse(self.final.exists())


    def test_destination_appearing_at_exclusive_move_is_retained(self):
        def conflict(source, destination):
            Path(destination).mkdir(mode=0o700)
            return self.exclusive_move(source, destination)
        with patch.object(_native._scan, 'move', side_effect=conflict):
            result = self.continuation()
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(self.owned.exists()); self.assertTrue(self.final.exists())
        self.assertEqual(self.ident(self.image), self.target['file'])
        before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked')
        self.assertEqual(before, self.snapshot())

    def test_guard_close_failure_is_not_completed_and_is_preserved(self):
        original = self.guard
        def bad_close(target, callback, expected=None):
            tokens = []
            def held(token):
                tokens.append(token); return callback(token)
            original(target, held, expected)
            tokens[0].close_result['core_consumed'] = False
        with patch.object(_native._image, 'with_backing_guard', side_effect=bad_close):
            result = self.continuation()
        self.assertEqual(result['status'], 'blocked')
        self.assertTrue(self.journal.exists()); self.assertFalse((self.final / 'native-install.json').exists())
        failed = self.read(self.journal)['installation']['continuation_receipts'][0]
        self.assertEqual(failed['outcome'], 'failed'); self.assertFalse(failed['guard']['core_consumed'])
        self.assert_installed(self.continuation())
        proof = self.read(self.final / 'native-install.json')
        self.assertEqual(proof['previous_installation']['continuation_receipts'][0], failed)
        self.assertEqual(proof['previous_installation']['continuation_receipts'][1]['outcome'], 'consumed')

    def test_invalid_lifecycle_intent_refused_before_mutation(self):
        installed = recovery.installed_metadata(self.meta, self.ident(self.final.parent), 'production', None)
        self.record['installation'] = {'metadata': installed, 'first_mount_attempted': False,
            'rename_attempted': False, 'outcome': 'prepared', 'guard': None, 'lifecycle': {'arbitrary': 'state'}}
        self.save(self.journal, self.record); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        self.assertEqual(self.guard_calls, [])

    def test_unknown_proof_and_origin_versions_refused(self):
        for record in (dict(self.proof, recovery_version=2), dict(self.proof, format=2)):
            self.save(self.owned / 'native-create.json', record); before = self.snapshot()
            self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        self.save(self.owned / 'native-create.json', self.proof)
        metadata = copy.deepcopy(self.meta); metadata['native_image']['format'] = 1
        self.save(self.owned / 'meta.json', metadata); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_pending_helper_archive_never_promotes_journal(self):
        archive = self.stage / 'discovery'; archive.mkdir(mode=0o700)
        pending = {**self.record, 'helpers': [], 'child_pending': True}
        self.save(self.journal, pending); self.save(self.stage / 'native-create', pending)
        terminal = {**pending, 'child_pending': False}
        self.save(archive / 'record.json', terminal); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())
        self.assertEqual(self.guard_calls, [])

    def test_complete_producer_result_rejects_unknown_and_failed_authority(self):
        mutations = [
            ((), 'recovery_version', 2), (('close',), 'recovery_version', 2),
            ((), 'ok', False), ((), 'descriptor_close_error', 5), ((), 'creation_attempted', False),
            ((), 'error_code', 5), ((), 'local_error', 5), ((), 'failure_path_error', 5),
            ((), 'failed_record', 0), ((), 'failure_path', 'repo/file'), ((), 'reason', 'core'),
            ((), 'abort', {}), ((), 'budget_explicit', 1), ((), 'observed_file', [True, 2]),
            (('identity',), 'recovery_version', 2), (('anchor',), 'recovery_version', 2),
            (('resources',), 'recovery_version', 2), (('resources', 'budget'), 'recovery_version', 2),
            (('resources', 'budget'), 'checks', False), (('resources',), 'entries', -1),
        ]
        for operation in ('creation', 'original', 'commit', 'verify', 'close', 'reopen', 'reopen_close'):
            mutations.extend([((operation,), 'format', 1), ((operation,), 'status', False),
                              ((operation,), 'system_errno', 5), ((operation,), 'phase', 17),
                              ((operation,), 'transaction_active', True), ((operation,), 'physical_end', 0)])
        original = copy.deepcopy(self.proof['result'])
        for path, field, value in mutations:
            with self.subTest(path=path, field=field):
                changed = copy.deepcopy(original); current = changed
                for component in path: current = current[component]
                current[field] = value
                record = dict(self.record, result=changed); proof = dict(self.proof, result=changed)
                self.save(self.journal, record); self.save(self.stage / 'native-create', record)
                self.save(self.owned / 'native-create.json', proof)
                before = self.snapshot()
                self.assertEqual(self.continuation()['status'], 'blocked')
                self.assertEqual(before, self.snapshot()); self.assertEqual(self.guard_calls, [])
        # All producer fields are mandatory, even if the smaller historical validator never read them.
        for field in original:
            with self.subTest(missing=field):
                changed = copy.deepcopy(original); del changed[field]
                record = dict(self.record, result=changed)
                self.save(self.journal, record); self.save(self.stage / 'native-create', record)
                self.save(self.owned / 'native-create.json', dict(self.proof, result=changed))
                before = self.snapshot()
                self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def legacy_installed_proof(self):
        installed = recovery.installed_metadata(self.meta, self.ident(self.final.parent), 'production', None)
        installation = {'metadata': installed, 'first_mount_attempted': False, 'rename_attempted': True,
                        'outcome': 'rename-attempted', 'guard': {'status': 5, 'core_consumed': False}}
        self.save(self.journal, dict(self.record, installation=installation))
        self.owned.rename(self.final); (self.final / 'volume').mkdir(mode=0o700)
        self.save(self.final / 'meta.json', installed)
        guard = dict(self.anchor, status=0, core_consumed=True, parent_close_errno=0, poisoned=False,
                     transaction_active=False, device=self.target['file'][0], inode=self.target['file'][1], uuid=self.target['uuid'])
        proof = {'operation': 'native-install', 'id': self.workspace, 'transaction': self.transaction,
                 'target': installed['native_image'], 'complete': True, 'guard': guard,
                 'previous_installation': installation, 'first_mount_attempted': False, 'first_use': {'accepted': False}}
        self.save(self.final / 'native-install.json', proof)
        return proof

    def test_legacy_install_proof_binds_generation_without_rewriting_history(self):
        historical = self.legacy_installed_proof()
        self.assert_installed(self.continuation())
        proof = self.read(self.final / 'native-install.json')
        for key, value in historical.items(): self.assertEqual(proof[key], value)
        state_path = self.root / 'lifecycle' / (self.workspace + '.json')
        state = self.read(state_path); self.assertEqual(proof['lifecycle'], state)
        self.assert_installed(self.continuation()); self.assertEqual(state, self.read(state_path))
        self.save(state_path, dict(state, generation='e' * 32)); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_legacy_lifecycle_binding_and_state_interruptions_retry_exact_generation(self):
        for filename in ('native-install.json', self.workspace + '.json'):
            for after in (False, True):
                with self.subTest(filename=filename, after=after):
                    fixture = CreateRecovery(); fixture.setUp(); historical = fixture.legacy_installed_proof()
                    publish = recovery.Admission.publish; hit = False
                    def fail(a, path, value):
                        nonlocal hit
                        selected = path.name == filename and (filename == 'native-install.json' or path.parent.name == 'lifecycle')
                        if selected and not hit:
                            hit = True
                            if after: publish(a, path, value)
                            raise OSError(errno.EIO, 'lifecycle binding boundary')
                        return publish(a, path, value)
                    try:
                        with patch.object(recovery.Admission, 'publish', fail):
                            self.assertEqual(fixture.continuation()['status'], 'blocked')
                        self.assertTrue(hit)
                        intended = fixture.read(fixture.journal)['installation']['lifecycle']
                        fixture.assert_installed(fixture.continuation())
                        proof = fixture.read(fixture.final / 'native-install.json')
                        self.assertEqual(proof['lifecycle'], intended)
                        self.assertEqual(proof['previous_installation'], historical['previous_installation'])
                        self.assertEqual(fixture.read(fixture.root / 'lifecycle' / (fixture.workspace + '.json')), intended)
                    finally: fixture.doCleanups()

    def test_publisher_remnants_never_supply_authority_or_block_other_candidates(self):
        # Contents can be empty, truncated, or complete stale records; only the canonical journal is authority.
        remnants = []
        for owner, contents in ((self.workspace, b''), (self.workspace, b'{"format":'),
                                ('b' * 32, json.dumps({'format': 1, **self.record}).encode())):
            path = self.root / 'journals' / ('.' + owner + '.json.' + str(len(remnants)) * 32)
            path.write_bytes(contents); path.chmod(0o600); remnants.append((path, contents, self.ident(path)))
        before = self.snapshot(); observed = recovery.inventory(self.root)
        self.assertTrue(observed['inventory_complete'], observed); self.assertEqual(before, self.snapshot())
        self.assertEqual(sum(r.get('kind') == 'publication-remnant' for r in observed['entries']), 3)
        self.assert_installed(self.continuation())
        for path, contents, identity in remnants:
            self.assertEqual(path.read_bytes(), contents); self.assertEqual(self.ident(path), identity)
        # A complete temporary journal does not replace a missing canonical journal or independent install proof.
        (self.final / 'native-install.json').unlink(); before = self.snapshot()
        self.assertEqual(self.continuation()['status'], 'blocked'); self.assertEqual(before, self.snapshot())

    def test_failed_journal_publication_allows_unrelated_candidate_to_finish(self):
        write = os.write; failed = False
        def interrupted(fd, data):
            nonlocal failed
            if not failed:
                failed = True; raise OSError(errno.EIO, 'journal write failed before effect')
            return write(fd, data)
        with patch.object(recovery.os, 'write', side_effect=interrupted):
            self.assertEqual(self.continuation()['status'], 'blocked')
        remnants = {p: (self.ident(p), p.read_bytes()) for p in self.journal.parent.iterdir() if p.name.startswith('.')}
        self.assertTrue(remnants)
        stage = self.root / 'staging' / 'build-other'; stage.mkdir(mode=0o700)
        owned = stage / 'owned'; owned.mkdir(mode=0o700)
        image = owned / 'image.sfs'; image.write_bytes(b'other candidate'); image.chmod(0o600)
        workspace, transaction = 'b' * 32, 'c' * 32
        target = dict(self.target, parent=self.ident(stage), object=self.ident(owned), file=self.ident(image), uuid='d' * 32)
        result = copy.deepcopy(self.proof['result'])
        result['identity'] = {'file': target['file'], 'uuid': target['uuid']}; result['observed_file'] = target['file']
        for key in ('creation', 'original', 'commit', 'verify', 'close', 'reopen', 'reopen_close'):
            result[key].update(device=target['file'][0], inode=target['file'][1], uuid=target['uuid'])
        meta = dict(self.meta, id=workspace, transaction=transaction, branch='stallionfs/fixture-' + workspace, native_image=target)
        proof = dict(self.proof, id=workspace, transaction=transaction, native_image=target, result=result)
        record = dict(self.record, workspace=workspace, transaction=transaction, stage=str(stage), stage_identity=self.ident(stage),
                      candidate=str(owned), object=self.ident(owned), final=str(self.final.parent / workspace), result=result,
                      native_image={key: target[key] for key in ('component', 'file', 'uuid', 'anchor')})
        for path, value in ((owned / 'meta.json', meta), (owned / 'native-create.json', proof),
                            (stage / 'native-create', record), (self.journal.parent / (workspace + '.json'), record)):
            self.save(path, value)
        for prefix in ('use-', 'workspace-'):
            (self.root / 'locks' / (prefix + workspace)).touch(mode=0o600)
        retained_journal = self.journal.read_bytes()
        completed = recovery.continue_creation(self.root, workspace, transaction)
        self.assertEqual(completed['status'], 'installed-unmounted', completed)
        self.assertEqual(self.journal.read_bytes(), retained_journal)
        self.assertEqual((self.final.parent / workspace / 'image.sfs').read_bytes(), b'other candidate')
        for path, (identity, contents) in remnants.items():
            self.assertEqual(self.ident(path), identity); self.assertEqual(path.read_bytes(), contents)
        self.assert_installed(self.continuation())
        for path, (identity, contents) in remnants.items():
            self.assertEqual(self.ident(path), identity); self.assertEqual(path.read_bytes(), contents)

    def test_unknown_or_unsafe_publisher_remnants_remain_conservative(self):
        for name, alias in (('.' + self.workspace + '.json.not-a-publisher-id', False),
                            ('.' + self.workspace + '.json.' + 'd' * 32, True)):
            path = self.root / 'journals' / name
            if alias: path.symlink_to(self.journal)
            else: path.write_bytes(b''); path.chmod(0o600)
            before = self.snapshot(); self.assertEqual(self.continuation()['status'], 'blocked')
            self.assertEqual(before, self.snapshot()); path.unlink()

    def test_every_publication_syscall_boundary_retains_or_recovers(self):
        operations = ('write', 'fsync', 'replace', 'rename', 'unlink', 'close', 'mkdir')
        originals = {name: getattr(os, name) for name in (*operations, 'open')}
        counts = {name: 0 for name in operations}
        with contextlib.ExitStack() as stack:
            for name in operations:
                def counted(*args, _name=name, **kwargs):
                    counts[_name] += 1
                    return originals[_name](*args, **kwargs)
                stack.enter_context(patch.object(recovery.os, name, side_effect=counted))
            self.assert_installed(self.continuation())
        exercised = 0
        for name in operations:
            self.assertGreater(counts[name], 0, name)
            for ordinal in range(1, counts[name] + 1):
                for after in (False, True):
                    with self.subTest(operation=name, ordinal=ordinal, after=after):
                        fixture = CreateRecovery(); fixture.setUp()
                        remaining = ordinal; triggered = False; opened = set()
                        def tracked_open(*args, **kwargs):
                            descriptor = originals['open'](*args, **kwargs)
                            opened.add(descriptor); return descriptor
                        def tracked_close(descriptor):
                            result = originals['close'](descriptor); opened.discard(descriptor); return result
                        def failing(*args, **kwargs):
                            nonlocal remaining, triggered
                            remaining -= 1
                            hit = remaining == 0
                            if hit:
                                triggered = True
                                if not after:
                                    raise OSError(errno.EIO, 'synthetic before ' + name)
                            result = (tracked_close if name == 'close' else originals[name])(*args, **kwargs)
                            if hit:
                                raise OSError(errno.EIO, 'synthetic after ' + name)
                            return result
                        try:
                            with contextlib.ExitStack() as stack:
                                stack.enter_context(patch.object(recovery.os, 'open', side_effect=tracked_open))
                                if name != 'close':
                                    stack.enter_context(patch.object(recovery.os, 'close', side_effect=tracked_close))
                                stack.enter_context(patch.object(recovery.os, name, side_effect=failing))
                                result = fixture.continuation()
                            self.assertTrue(triggered)
                            self.assertEqual(result['status'], 'blocked', result)
                            original_location = fixture.final if fixture.final.exists() else fixture.owned
                            self.assertEqual(fixture.ident(original_location / 'image.sfs'), fixture.target['file'])
                            self.assertEqual((original_location / 'image.sfs').read_bytes(),
                                             b'opaque synthetic image; never interpreted by native code')
                            before_retry = fixture.snapshot()
                            with patch.object(recovery.os, 'rename', wraps=originals['rename']) as moved:
                                retried = fixture.continuation()
                            if retried['status'] == 'busy':
                                self.assertEqual(name, 'close')
                                self.assertFalse(after)
                                self.assertEqual(before_retry, fixture.snapshot(), retried)
                                # Model process exit for a close that was injected before its effect.
                                for descriptor in list(opened):
                                    originals['close'](descriptor); opened.remove(descriptor)
                                retried = fixture.continuation()
                            fixture.assert_installed(retried)
                            for relative, (_, inode, content) in before_retry.items():
                                if re.fullmatch(r'store/journals/\.[0-9a-f]{32}\.json\.[0-9a-f]{32}', relative):
                                    remnant = fixture.base / relative
                                    self.assertEqual((remnant.stat().st_ino, remnant.read_bytes()), (inode, content))
                            if original_location == fixture.final:
                                self.assertEqual(moved.call_count, 0)
                            exercised += 1
                        finally:
                            # Only descriptors created by this fixture are reclaimed after injected pre-close failures.
                            for descriptor in opened:
                                try: originals['close'](descriptor)
                                except OSError: pass
                            fixture.doCleanups()
        self.assertGreater(exercised, 100)
        print('Synthetic syscall boundaries:', exercised, counts)

    def test_busy_and_lock_order_with_owned_process(self):
        code = """import fcntl, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
sys.stdout.write('held\\n'); sys.stdout.flush()
sys.stdin.read(1)
os.close(fd)
"""
        for name in ('.lock', 'locks/use-' + self.workspace, 'locks/workspace-' + self.workspace):
            with self.subTest(lock=name):
                with subprocess.Popen([sys.executable, '-I', '-B', '-c', code, str(self.root / name)],
                                      stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as child:
                    try:
                        import selectors
                        with selectors.DefaultSelector() as selector:
                            selector.register(child.stdout, selectors.EVENT_READ)
                            self.assertTrue(selector.select(timeout=5), 'owned lock child did not start')
                        self.assertEqual(child.stdout.readline().strip(), 'held')
                        before = self.snapshot(); order = []
                        original = recovery.Admission.lock
                        def ordered(a, path, shared=False):
                            order.append(path.name); return original(a, path, shared)
                        with patch.object(recovery.Admission, 'lock', ordered):
                            result = self.continuation()
                        self.assertEqual(result['status'], 'busy', result)
                        expected = ['.lock', 'use-' + self.workspace, 'workspace-' + self.workspace]
                        self.assertEqual(order, expected[:len(order)])
                        self.assertEqual(before, self.snapshot())
                        if name == '.lock':
                            inspected = recovery.inventory(self.root)
                            self.assertEqual(inspected['status'], 'busy'); self.assertFalse(inspected['inventory_complete'])
                        child.stdin.write('x'); child.stdin.flush(); child.wait(timeout=5)
                        self.assertEqual(child.returncode, 0, child.stderr.read())
                    finally:
                        if child.poll() is None:
                            child.kill(); child.wait(timeout=5)

    def test_continuation_holds_compatible_create_purge_forget_order(self):
        # Harmless substitutes acquire exactly the existing operations' lock order; no data operation runs.
        code = """import fcntl, os, sys
fds = []
try:
    for name in sys.argv[1:]:
        fd = os.open(name, os.O_RDONLY); fds.append(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
except BlockingIOError:
    print('busy')
else:
    print('admitted')
finally:
    for fd in reversed(fds): os.close(fd)
"""
        seed_lock = self.root / 'locks' / ('seed-' + self.seed); seed_lock.touch(mode=0o600)
        unrelated = self.root / 'locks' / ('workspace-' + 'b' * 32); unrelated.touch(mode=0o600)
        routes = ((self.root / '.lock', seed_lock), (self.root / '.lock', unrelated),
                  (self.root / '.lock', self.root / 'locks' / ('use-' + self.workspace),
                   self.root / 'locks' / ('workspace-' + self.workspace)))
        original = self.guard
        def guard(target, callback, expected=None):
            for route in routes:
                result = subprocess.run([sys.executable, '-I', '-B', '-c', code, *map(str, route)],
                    capture_output=True, text=True, timeout=5, check=True)
                self.assertEqual(result.stdout.strip(), 'busy')
            return original(target, callback, expected)
        with patch.object(_native._image, 'with_backing_guard', side_effect=guard):
            self.assert_installed(self.continuation())
        for route in routes:
            result = subprocess.run([sys.executable, '-I', '-B', '-c', code, *map(str, route)],
                capture_output=True, text=True, timeout=5, check=True)
            self.assertEqual(result.stdout.strip(), 'admitted')


if __name__ == '__main__':
    unittest.main()
