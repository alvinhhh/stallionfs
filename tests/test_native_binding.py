"""Owned fixture protocol tests. Device changes are simulated, never rebooted."""
import contextlib
import copy
import errno
import fcntl
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import core, _native, _native_binding as binding, _native_create_recovery as recovery
import test_native_create_recovery as fixtures


class Renumbered:
    def __init__(self, original, device):
        self.original, self.st_dev = original, device
        self.st_ino = original.st_ino
    def __getattr__(self, name):
        return getattr(self.original, name)
    def __eq__(self, other):
        return isinstance(other, Renumbered) and self.st_dev == other.st_dev and self.st_ino == other.st_ino and self.original == other.original


class HostingBinding(unittest.TestCase):
    def setUp(self):
        self.f = fixtures.CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
        self.f.setUp(); self.addCleanup(self.f.doCleanups)
        self.f.assert_installed(self.f.continuation())
        self.store = core.Store.__new__(core.Store); self.store.root = self.f.root
        self.path = self.f.final
        self.meta = self.f.read(self.path / 'meta.json')
        self.sidecar = self.path / binding.NAME

    @contextlib.contextmanager
    def renumber(self):
        real_stat, real_fstat = os.stat, os.fstat
        device = real_stat(self.path).st_dev + 17
        def stat(*args, **kwargs): return Renumbered(real_stat(*args, **kwargs), device)
        def fstat(*args, **kwargs): return Renumbered(real_fstat(*args, **kwargs), device)
        with patch.object(os, 'stat', side_effect=stat), patch.object(os, 'fstat', side_effect=fstat):
            yield

    def historical_bytes(self):
        return {name: (self.path / name).read_bytes() for name in
                ('meta.json', 'native-create.json', 'native-install.json')}

    def adopt(self): return binding.adopt_current(self.f.root, self.f.workspace, self.f.transaction)

    def test_device_renumber_resolves_mount_and_creation_without_rewriting_history(self):
        before = self.historical_bytes(); sidecar = self.sidecar.read_bytes()
        with self.renumber():
            target = _native.recover_install(self.store, self.path, self.meta)
            self.assertEqual(target['file'], self.f.ident(self.path / 'image.sfs'))
            self.assertEqual(self.f.continuation()['status'], 'installed-unmounted')
            self.assertEqual(self.f.guard_calls[-1][0], target)
            self.assertEqual(before, self.historical_bytes())
            self.assertEqual(sidecar, self.sidecar.read_bytes())
            state = core.read_json(self.store._state(self.f.workspace))
            self.assertFalse(self.store._valid_state(self.f.workspace, self.path, self.meta, state, 1e10))

    def test_legacy_changed_device_refuses_then_adopts_current_image(self):
        self.sidecar.unlink(); before = self.historical_bytes()
        with self.renumber():
            with self.assertRaisesRegex(core.StallionError, 'adopt-current'):
                _native.recover_install(self.store, self.path, self.meta)
            result = self.adopt()
            self.assertEqual(result['status'], 'current-image-adopted', result)
            record = self.f.read(self.sidecar)
            self.assertEqual(record['authority'], 'current-image-adoption')
            self.assertNotEqual(record['admitted_target']['file'][0], record['origin_target']['file'][0])
            self.assertEqual(_native.recover_install(self.store, self.path, self.meta), record['admitted_target'])
            self.assertEqual(self.f.continuation()['status'], 'installed-unmounted')
            receipt = self.sidecar.read_bytes()
            self.assertTrue(self.adopt()['already_adopted'])
            self.assertEqual(receipt, self.sidecar.read_bytes())
        self.assertEqual(before, self.historical_bytes())

    def test_file_ids_above_32_bits_survive_enrollment_and_resolution(self):
        real_stat, real_fstat = os.stat, os.fstat
        real_identity = binding._scan.hosting_identity
        def wide(info):
            row = Renumbered(info, info.st_dev); row.st_ino += 1 << 40
            return row
        def identity(fd):
            row = real_identity(fd); row['file_id'] += 1 << 40
            return row
        with patch.object(os, 'stat', side_effect=lambda *a, **kw: wide(real_stat(*a, **kw))), \
             patch.object(os, 'fstat', side_effect=lambda *a, **kw: wide(real_fstat(*a, **kw))), \
             patch.object(binding._scan, 'hosting_identity', side_effect=identity):
            f = fixtures.CreateRecovery('test_success_repeated_calls_and_guarded_rename_syncs')
            try:
                f.setUp(); f.assert_installed(f.continuation())
                record = f.read(f.final / binding.NAME)
                self.assertTrue(all(record['stable'][key] > 1 << 32 for key in ('collection', 'object', 'file')))
                store = core.Store.__new__(core.Store); store.root = f.root
                target = _native.recover_install(store, f.final, f.read(f.final / 'meta.json'))
                self.assertEqual(target['file'], f.ident(f.final / 'image.sfs'))
            finally: f.doCleanups()

    def test_wrong_volume_malformed_missing_and_wide_file_ids(self):
        real = binding._scan.hosting_identity
        for change in ('wrong', 'missing', 'null', 'malformed', 'wide', 'boolean'):
            def altered(fd):
                row = real(fd)
                if change == 'wrong': row['volume_uuid'] = '12345678-1234-1234-1234-123456789abc'
                elif change == 'missing': row.pop('volume_uuid')
                elif change == 'null': row['volume_uuid'] = '00000000-0000-0000-0000-000000000000'
                elif change == 'malformed': row['volume_uuid'] = 'volume'
                elif change == 'wide': row['file_id'] += 1 << 32
                else: row['file_id'] = True
                return row
            with self.subTest(change=change), patch.object(binding._scan, 'hosting_identity', side_effect=altered):
                with self.assertRaises((core.StallionError, KeyError)):
                    binding.resolve(self.store, self.path, self.meta)

    def test_replaced_inode_symlink_hardlink_mode_owner_and_acl(self):
        image = self.path / 'image.sfs'; saved = self.path / 'saved'
        image.rename(saved)
        try:
            for kind in ('replacement', 'symlink', 'hardlink'):
                if kind == 'replacement': image.write_bytes(saved.read_bytes()); image.chmod(0o600)
                elif kind == 'symlink': image.symlink_to(saved)
                else: os.link(saved, image)
                with self.subTest(kind=kind), self.assertRaises((OSError, core.StallionError)):
                    binding.resolve(self.store, self.path, self.meta)
                image.unlink()
        finally: saved.rename(image)
        image.chmod(0o644)
        with self.assertRaises((OSError, core.StallionError)):
            binding.resolve(self.store, self.path, self.meta)
        image.chmod(0o600)
        actual_fstat = os.fstat
        inode = image.stat().st_ino
        def foreign_owner(fd):
            row = actual_fstat(fd)
            if row.st_ino == inode:
                changed = Renumbered(row, row.st_dev); changed.st_uid = row.st_uid + 1
                return changed
            return row
        with patch.object(os, 'fstat', side_effect=foreign_owner), self.assertRaises(core.StallionError):
            binding.resolve(self.store, self.path, self.meta)
        subprocess.run(['/bin/chmod', '+a', 'everyone allow read', str(image)], check=True)
        try:
            with self.assertRaises((OSError, core.StallionError)):
                binding.resolve(self.store, self.path, self.meta)
        finally: subprocess.run(['/bin/chmod', '-N', str(image)], check=True)

    def test_pending_mounted_uncertain_move_and_purge_refuse_adoption(self):
        self.sidecar.unlink()
        for operation in ('native-mount', 'native-unmount', 'native-retire', 'native-return', 'native-purge', 'native-create-purge'):
            self.f.save(self.f.journal, {'operation': operation})
            before = self.historical_bytes()
            with self.subTest(operation=operation):
                self.assertEqual(self.adopt()['status'], 'blocked')
                self.assertFalse(self.sidecar.exists())
                self.assertEqual(before, self.historical_bytes())
            self.f.journal.unlink()
        for state in ('mounted', 'uncertain'):
            self.f.save(self.path / 'native-mount.json', {'state': state})
            self.assertEqual(self.adopt()['status'], 'blocked')
            (self.path / 'native-mount.json').unlink()
        self.f.save(self.path / 'native-location.json', {})
        self.assertEqual(self.adopt()['status'], 'blocked')

    def test_actual_mounted_namespace_and_unresolved_owned_actor_refuse(self):
        self.sidecar.unlink()
        with patch.object(core.Store, '_no_mounts', side_effect=core.StallionError('mounted')):
            self.assertEqual(self.adopt()['status'], 'blocked')
        parent = self.path / 'native-operations'; parent.mkdir(mode=0o700)
        owner = parent / ('7' * 32); owner.mkdir(mode=0o700)
        self.f.save(owner / 'record.json', {'workspace': self.f.workspace, 'id': owner.name,
                                          'operation': 'native-unmount', 'outcome': 'incomplete', 'child_pending': True})
        self.assertEqual(self.adopt()['status'], 'blocked')
        self.assertFalse(self.sidecar.exists())

    def test_stale_pending_operation_blocks_stable_translation(self):
        before = self.sidecar.read_bytes()
        self.f.save(self.f.journal, {'operation': 'native-unmount', 'target': binding.historical_target(self.path, self.meta)})
        with self.renumber(), self.assertRaises(core.StallionError):
            _native.recover_install(self.store, self.path, self.meta)
        self.assertEqual(self.sidecar.read_bytes(), before)

    def test_conflicting_creation_owner_refuses_current_adoption(self):
        self.sidecar.unlink()
        other = copy.deepcopy(self.f.record); other['transaction'] = '9' * 32
        self.f.save(self.f.stage / 'native-create', other)
        self.assertEqual(self.adopt()['status'], 'blocked')
        self.assertFalse(self.sidecar.exists())

    def test_transaction_changed_creation_proof_and_changed_anchor_refuse(self):
        result = binding.adopt_current(self.f.root, self.f.workspace, '8' * 32)
        self.assertEqual(result['status'], 'blocked')
        before = self.f.read(self.path / 'native-create.json')
        value = copy.deepcopy(before); value.pop('writer')
        self.f.save(self.path / 'native-create.json', value)
        with self.assertRaises(core.StallionError): binding.resolve(self.store, self.path, self.meta)
        self.f.save(self.path / 'native-create.json', before)
        self.sidecar.unlink()
        self.f.guard_anchor = dict(self.f.anchor, generation=3)
        self.assertEqual(self.adopt()['status'], 'blocked')
        self.assertFalse(self.sidecar.exists())

    def test_consumed_close_failure_and_interruption_leave_no_binding(self):
        self.sidecar.unlink()
        with patch.object(_native, 'guarded', side_effect=core.StallionError('consumed close failed')):
            self.assertEqual(self.adopt()['status'], 'blocked')
        self.assertFalse(self.sidecar.exists())
        with patch.object(binding, 'publish', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt): self.adopt()
        self.assertFalse(self.sidecar.exists())
        self.assertEqual(self.adopt()['status'], 'current-image-adopted')

    def test_interruption_after_publication_is_idempotent(self):
        self.sidecar.unlink(); real = binding.publish
        def published(*args): real(*args); raise KeyboardInterrupt
        with patch.object(binding, 'publish', side_effect=published):
            with self.assertRaises(KeyboardInterrupt): self.adopt()
        before = self.sidecar.read_bytes()
        self.assertTrue(self.adopt()['already_adopted'])
        self.assertEqual(before, self.sidecar.read_bytes())

    def test_competing_adopter_serializes_and_publication_is_not_replaced(self):
        self.sidecar.unlink()
        fd = os.open(self.f.root / '.lock', os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.adopt()['status'], 'busy')
            self.assertFalse(self.sidecar.exists())
        finally: os.close(fd)
        self.assertEqual(self.adopt()['status'], 'current-image-adopted')
        before = self.sidecar.read_bytes()
        self.assertTrue(self.adopt()['already_adopted'])
        self.assertEqual(before, self.sidecar.read_bytes())

    def test_publication_inode_substitution_refuses_even_equal_bytes(self):
        self.sidecar.unlink(); real = binding._scan._publish_no_replace
        def substitute(parent, source, destination):
            real(parent, source, destination)
            target = self.sidecar
            value = target.read_bytes(); target.unlink(); target.write_bytes(value); target.chmod(0o600)
        with patch.object(binding._scan, '_publish_no_replace', side_effect=substitute):
            self.assertEqual(self.adopt()['status'], 'blocked')
        with self.assertRaises(core.StallionError): binding.resolve(self.store, self.path, self.meta)

    def test_backing_and_evidence_mutation_during_guard_refuse_publication(self):
        self.sidecar.unlink(); real = _native.guarded
        for name in ('image.sfs', 'native-install.json'):
            path = self.path / name
            original = path.read_bytes()
            def mutate(target, callback, **kwargs):
                def changed(token):
                    path.write_bytes(original + b' ')
                    return callback(token)
                return real(target, changed, **kwargs)
            with self.subTest(name=name), patch.object(_native, 'guarded', side_effect=mutate):
                self.assertEqual(self.adopt()['status'], 'blocked')
                self.assertFalse(self.sidecar.exists())
            path.write_bytes(original)

    def test_retained_lifecycle_authority_refuses_translated_target(self):
        from stallionfs import _native_create_authority as authority
        self.sidecar.unlink()
        with self.renumber():
            self.assertEqual(self.adopt()['status'], 'current-image-adopted')
            target = _native.recover_install(self.store, self.path, self.meta)
            packet = authority.installed(self.path, self.meta)
            with self.assertRaises(core.StallionError):
                authority.retained(packet, target, self.f.workspace)
            with self.assertRaises(core.StallionError):
                authority.retained({k: packet[k] for k in ('origin', 'proof')}, target, self.f.workspace)
            altered = copy.deepcopy(packet); altered['hosting']['binding']['stable']['file'] += 1
            with self.assertRaises(core.StallionError): authority.retained(altered, target, self.f.workspace)
            with self.assertRaises(core.StallionError):
                authority.retained(packet, dict(target, uuid='0' * 32), self.f.workspace)

    def test_cli_adopts_exact_selected_transaction_and_rejects_bad_options(self):
        from stallionfs.__main__ import main
        import io
        self.sidecar.unlink()
        with contextlib.redirect_stdout(io.StringIO()) as out:
            code = main(['--json', '--root', str(self.f.root), 'creations', self.f.workspace,
                         '--adopt-current', self.f.transaction])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())['authority'], 'current-image-adoption')
        for arguments in (['creations', '--adopt-current', self.f.transaction],
                          ['creations', self.f.workspace, '--adopt-current', 'bad'],
                          ['creations', self.f.workspace, '--adopt-current', self.f.transaction,
                           '--continue', self.f.transaction]):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                main(arguments)


class DescriptorAccessor(unittest.TestCase):
    def test_owned_descriptor_directory_and_file_share_persistent_volume(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name); image = path / 'owned'; image.touch(mode=0o600)
            fds = [os.open(p, os.O_RDONLY) for p in (path, image)]
            try:
                rows = [binding._scan.hosting_identity(fd) for fd in fds]
                self.assertEqual(rows[0]['volume_uuid'], rows[1]['volume_uuid'])
                self.assertEqual([r['file_id'] for r in rows], [os.fstat(fd).st_ino for fd in fds])
            finally:
                for fd in fds: os.close(fd)

    def test_real_closed_guard_uuid_anchor_and_exclusive_descriptor_admission(self):
        from stallionfs import _image
        with tempfile.TemporaryDirectory(prefix='sfs-closed-binding-') as name:
            root = Path(name).resolve(); image_dir = root / 'image'; image_dir.mkdir(mode=0o700)
            fixture = root / 'fixture'
            subprocess.run(['xcrun', 'clang', '-O1', '-Ifilesystem', 'tests/native_image_fixture.c',
                            'filesystem/image.c', '-o', str(fixture)], check=True, capture_output=True)
            subprocess.run([str(fixture), 'seed', str(image_dir)], check=True, capture_output=True)
            target = {'directory': str(image_dir), 'component': 'image.sfs',
                      'parent': recovery.pair(image_dir.stat()), 'file': None}
            observed = _image.inspect(target)
            self.assertTrue(observed['ok'], observed)
            target.update(observed['identity'])
            first = _native.guarded(target)
            anchor = {k: first[k] for k in ('generation', 'committed_end', 'root_digest')}
            self.assertEqual(first['physical_end'], anchor['committed_end'])
            closed = _native.guarded(target, expected_anchor=anchor, anchor=anchor)
            self.assertTrue(_native._consumed(closed, target, anchor))
            with self.assertRaises(OSError):
                _native.guarded(dict(target, uuid='0' * 32))
            with self.assertRaises(OSError):
                _native.guarded(target, expected_anchor=dict(anchor, generation=anchor['generation'] + 1))
            def competing(token):
                with self.assertRaises(OSError) as caught: _native.guarded(target)
                self.assertEqual(caught.exception.errno, errno.EBUSY)
            _native.guarded(target, competing)
