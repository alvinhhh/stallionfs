"""Writer admission on inert owned controller fixtures; no Git or image execution."""
import copy
import hashlib
import json
from pathlib import Path
import shutil
import unittest
from unittest.mock import patch

from stallionfs import core, _native, _bundle, _native_create_authority as authority
from stallionfs import _native_create_recovery as recovery, _native_create_request as request
from stallionfs import _native_creation_purge as disposal, _native_purge as purge
from test_native_create_recovery import CreateRecovery
from test_native_creation_purge import CreationDisposal


class WriterAuthority(unittest.TestCase):
    def setUp(self):
        self.fixture = CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        self.fixture.setUp(); self.addCleanup(self.fixture.doCleanups)

    def test_complete_packet_survives_retired_stage_without_opening_logs(self):
        f = self.fixture
        authority.proof(f.meta, f.proof)
        f.assert_installed(f.continuation())
        shutil.rmtree(f.stage)
        f.guard_calls.clear()
        result = f.continuation()
        self.assertEqual(result['status'], 'installed-unmounted', result)
        self.assertEqual(len(f.guard_calls), 1)

    def test_missing_legacy_and_partial_packets_refuse_before_guard_or_rename(self):
        f = self.fixture
        original = copy.deepcopy(f.proof)
        for change in ('missing', 'legacy', 'partial', 'copied-spec', 'argv', 'pid', 'helper', 'streams', 'build'):
            value = copy.deepcopy(original)
            if change == 'missing': value.pop('writer')
            elif change == 'legacy': value['writer']['spec']['protocol'] = 2
            elif change == 'partial': value['writer']['actors'].pop()
            elif change == 'copied-spec': value['writer']['spec']['object'] = [1, 999]
            elif change == 'argv': value['writer']['actors'][4]['argv'].append('--unsafe')
            elif change == 'pid': value['writer']['actors'][0]['pid'] = True
            elif change == 'helper': value['writer']['preflight']['helpers'][0]['argv'] = ['/bin/true']
            elif change == 'streams': value['writer']['actors'][0]['streams_durable'] = False
            else: value['writer']['spec']['runtime']['input_inventory_sha256'] = '0' * 64
            if 'writer' in value: value['writer']['spec_digest'] = request.digest(value['writer']['spec'])
            f.save(f.owned / 'native-create.json', value)
            before = f.snapshot(); f.guard_calls.clear()
            with self.subTest(change=change):
                observed = recovery.inventory(f.root, f.workspace)
                self.assertEqual(observed['entries'][-1]['status'], 'candidate', observed)
                result = f.continuation()
                self.assertEqual(result['status'], 'blocked', result)
                self.assertFalse(f.guard_calls)
                self.assertEqual(f.snapshot(), before)
                self.assertFalse(f.final.exists())

    def test_old_installed_proof_without_journal_remains_inspectable(self):
        f = self.fixture
        f.assert_installed(f.continuation())
        value = f.read(f.final / 'native-create.json'); value.pop('writer')
        f.save(f.final / 'native-create.json', value)
        before = f.snapshot(); f.guard_calls.clear()
        observed = recovery.inventory(f.root, f.workspace)
        self.assertEqual(observed['entries'][-1]['status'], 'already-installed', observed)
        result = f.continuation()
        self.assertEqual(result['status'], 'blocked', result)
        self.assertFalse(f.guard_calls)
        with self.assertRaises(core.StallionError):
            _native.recover_install(core.Store.__new__(core.Store), f.final, f.read(f.final / 'meta.json'))
        self.assertEqual(f.snapshot(), before)

    def test_v2_completed_journal_retains_inspection_without_install_authority(self):
        f = self.fixture
        spec = copy.deepcopy(f.proof['writer']['spec'])
        spec.update(protocol=2, method=request.LEGACY_METHOD, runtime={**_bundle.LEGACY_GIT_CONTRACT,
            **{key: spec['runtime'][key] for key in ('payload_entries', 'payload_sha256', 'descriptor_sha256',
                'executable_sha256', 'source_build_id', 'publisher')}})
        spec['store_lock'] = f.ident(f.root / '.lock')
        spec['workspace_lock'] = f.ident(f.root / 'locks' / ('workspace-' + f.workspace))
        spec['lease']['file'] = f.ident(f.root / 'locks' / ('use-' + f.workspace))
        (f.root / 'locks' / ('use-' + f.workspace)).write_text(spec['lease']['generation'] + '\n')
        actors = copy.deepcopy(f.proof['writer']['actors'])
        for actor in actors:
            actor.update(runtime=spec['runtime'], environment='native-git-empty-environment-v2')
        f.record.update(protocol=2, spec_digest=request.digest(spec), phase='complete', actors=actors)
        f.save(f.stage / 'create-spec.json', spec)
        f.save(f.stage / 'native-create', request.marker(f.record))
        f.save(f.journal, f.record)
        value = copy.deepcopy(f.proof); value.pop('writer'); f.save(f.owned / 'native-create.json', value)
        before = f.snapshot()
        observed = recovery.inventory(f.root, f.workspace)
        self.assertEqual(observed['entries'][-1]['status'], 'candidate', observed)
        self.assertEqual(f.continuation()['status'], 'blocked')
        self.assertFalse(f.guard_calls); self.assertEqual(f.snapshot(), before)

    def test_v2_partial_reservation_is_readable_but_cannot_replace_or_purge(self):
        fixture = CreationDisposal('test_authorization_retry_fences_before_deletion')
        fixture.setUp(); self.addCleanup(fixture.doCleanups)
        record = fixture.attempt(); stage = Path(record['stage'])
        spec = recovery.semantic(core.read_json(stage / 'create-spec.json'))
        spec.update(protocol=2, method=request.LEGACY_METHOD, runtime={**_bundle.LEGACY_GIT_CONTRACT,
            **{key: spec['runtime'][key] for key in ('payload_entries', 'payload_sha256', 'descriptor_sha256',
                'executable_sha256', 'source_build_id', 'publisher')}})
        record.update(protocol=2, spec_digest=request.digest(spec))
        from native_writer_fixture import writer
        origin = dict(self.fixture.meta, id=spec['workspace'], transaction=spec['transaction'], seed=spec['seed'],
            commit=spec['commit'], name=spec['name'], branch=spec['branch'], capacity_gib=spec['capacity_gib'],
            native_image=dict(self.fixture.target, parent=spec['stage_identity'], object=spec['object']))
        record['actors'] = writer(origin, stage)['actors']
        for actor in record['actors']:
            actor.update(runtime=spec['runtime'], environment='native-git-empty-environment-v2')
        record['phase'] = 'branch'
        record['replacement']['parent_spec_digest'] = request.digest(spec)
        fixture.save = self.fixture.save
        fixture.save(stage / 'create-spec.json', spec); fixture.save(stage / 'native-create', request.marker(record))
        fixture.save(fixture.root / 'journals' / (record['workspace'] + '.json'), record)
        before = fixture.snapshot()
        observed = recovery.inventory(fixture.root, record['workspace'])
        self.assertEqual(observed['entries'][-1]['replacement'], record['replacement'])
        for confirm in (False, True):
            result = disposal.purge_creation(fixture.root, record['workspace'], record['transaction'], confirm=confirm)
            self.assertEqual(result['status'], 'writer-unverified', result)
            self.assertFalse(result['files_removed'])
        with patch('stallionfs._native_create_git.qualified_runtime', side_effect=AssertionError('runtime effect')):
            self.assertEqual(recovery.continue_creation(fixture.root, record['workspace'], record['transaction'])['status'], 'blocked')
        self.assertEqual(fixture.snapshot(), before)

    def test_retained_purge_packet_validates_after_creation_proof_removal(self):
        f = self.fixture
        data = (json.dumps({'format': 1, **f.proof}, sort_keys=True, indent=2) + '\n').encode()
        binding = {'path': 'native-create.json', 'kind': 'file', 'identity': purge.identity((f.owned / 'native-create.json').stat()),
                   'sha256': hashlib.sha256(data).hexdigest()}
        target = {'directory': str(f.owned), 'component': 'image.sfs', 'parent': f.target['object'],
                  'file': f.target['file'], 'uuid': f.target['uuid']}
        record = {'workspace': f.workspace, 'target': target, 'creation': {'origin': f.meta, 'proof': f.proof},
                  'creation_binding': binding, 'manifest': [binding]}
        (f.owned / 'native-create.json').unlink()
        purge.writer_authority(record)
        for field in ('creation', 'creation_binding'):
            changed = copy.deepcopy(record); changed.pop(field)
            with self.subTest(field=field), self.assertRaises(core.StallionError): purge.writer_authority(changed)
        changed = copy.deepcopy(record); changed['creation']['proof']['writer']['actors'].pop()
        with self.assertRaises(core.StallionError): purge.writer_authority(changed)

    def test_direct_guard_keeps_its_independent_authority(self):
        f = self.fixture
        target = {'directory': str(f.owned), 'component': 'image.sfs', 'parent': f.target['object'],
                  'file': f.target['file'], 'uuid': f.target['uuid']}
        receipt = _native.guarded(target, anchor=f.anchor, expected_anchor=f.anchor)
        self.assertTrue(receipt['core_consumed'])

    def test_metadata_cleanup_restarts_after_creation_proof_unlink(self):
        f = self.fixture
        store = core.Store.__new__(core.Store); store.root = f.root
        operation = '9' * 32
        container = 'native-purge-' + f.workspace + '-' + operation
        tombstone_path = f.root / 'staging' / container; tombstone_path.mkdir(mode=0o700)
        resource_path = tombstone_path / 'owned'
        f.owned.rename(resource_path)
        created = resource_path / 'native-create.json'
        created.write_text(json.dumps({'format': 1, **f.proof}, sort_keys=True, indent=2) + '\n')
        for name in ('native-install.json', 'native-location.json'):
            f.save(resource_path / name, {'inert': True})
        for name in ('volume', 'native-operations'):
            (resource_path / name).mkdir(mode=0o700)
        protection = f.root / 'protected' / (f.workspace + '.json'); f.save(protection, {'inert': True})
        marker = tombstone_path / 'native-purge.json'; f.save(marker, {'inert': True})
        record = {}
        with purge.descriptors(record) as opening:
            fds = purge.parents(store, opening)
            tombstone = opening(fds['staging'], container)
            resource = opening(tombstone, 'owned')
            manifest = purge.scan(opening, resource, f.workspace)
            target = {'directory': str(f.root / 'trash' / f.workspace), 'component': 'image.sfs',
                'parent': f.target['object'], 'file': f.target['file'], 'uuid': f.target['uuid']}
            origin_target = dict(target, parent=f.ident(f.root / 'workspaces'), object=f.target['object'])
            origin_target.pop('directory')
            record.update(schema=1, operation='native-purge', id=operation, workspace=f.workspace,
                authorized=True, stage='metadata-removal-authorized', target=target,
                object=purge.identity(resource_path.stat()),
                parents={name: purge.identity(__import__('os').fstat(fd)) for name, fd in fds.items()},
                container=container, container_identity=purge.identity(tombstone_path.stat()),
                marker={'identity': purge.identity(marker.stat()), 'sha256': hashlib.sha256(marker.read_bytes()).hexdigest()},
                protection={'identity': purge.identity(protection.stat()), 'sha256': hashlib.sha256(protection.read_bytes()).hexdigest()},
                manifest=manifest, manifest_digest=purge.digest(manifest), data_absent=True, cleanup_complete=False,
                unlink_outcome='returned', guard_outcome='consumed',
                ownership={'transaction': f.transaction, 'origin_target': origin_target}, previous_unresolved=None,
                creation={'origin': f.meta, 'proof': f.proof},
                creation_binding=next(row for row in manifest if row['path'] == 'native-create.json'))
            (resource_path / 'image.sfs').unlink()
            purge.writer_authority(record); purge.save(store, record)
            original_unlink = purge.os.unlink
            def crash(name, **kwargs):
                original_unlink(name, **kwargs)
                if name == 'native-create.json': raise OSError('controlled death after proof unlink')
            with patch.object(purge.os, 'unlink', side_effect=crash), self.assertRaisesRegex(OSError, 'after proof unlink'):
                purge.metadata_phase(store, record, opening, fds, tombstone, resource)
        self.assertFalse(created.exists())
        # A fresh controller admits the fenced packet without reopening that proof.
        record = core.read_json(f.root / 'journals' / (f.workspace + '.json'))
        purge.writer_authority(record)
        with purge.descriptors(record) as opening:
            fds = purge.parents(store, opening, record)
            tombstone = opening(fds['staging'], container, record['container_identity'])
            resource = opening(tombstone, 'owned', record['object'])
            purge.metadata_phase(store, record, opening, fds, tombstone, resource)
        self.assertFalse(resource_path.exists())
        self.assertEqual(record['stage'], 'resource-removal-authorized')
