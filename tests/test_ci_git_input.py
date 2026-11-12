"""Admission boundaries before controlled real-Git fixture execution."""
import importlib.util
import io
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile


def admission_module():
    path = Path(__file__).resolve().parents[1] / 'tools/ci_git_input.py'
    spec = importlib.util.spec_from_file_location('uninitialized_ci_git_input', path)
    admission = importlib.util.module_from_spec(spec); spec.loader.exec_module(admission)
    return admission


class UninitializedInput(unittest.TestCase):
    def test_runtime_refuses_without_pre_discovery_admission(self):
        admission = admission_module()
        with self.assertRaisesRegex(RuntimeError, 'before test discovery'):
            admission.runtime()

    def test_binding_refuses_a_change_after_the_validated_read(self):
        from stallionfs import _bundle
        admission = admission_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'input'; path.write_bytes(b'input')
            retained = admission._Bindings(_bundle)
            def reader(path, expected=None):
                data = path.read_bytes(); path.write_bytes(data + b' ')
                return data
            retained.reader = reader
            with self.assertRaisesRegex(ValueError, 'changed during validation'):
                retained.read(path)

    def test_binding_does_not_replace_its_first_validated_identity(self):
        from stallionfs import _bundle
        admission = admission_module()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary).resolve() / 'input'; path.write_bytes(b'input')
            retained = admission._Bindings(_bundle)
            calls = []
            def reader(path, expected=None):
                calls.append(path); return path.read_bytes()
            retained.reader = reader
            retained.read(path)
            path.rename(path.with_name('retained')); path.write_bytes(b'input')
            with self.assertRaisesRegex(ValueError, 'validation identity changed'):
                retained.read(path)
            self.assertEqual(len(calls), 1)

    def test_declared_wheel_budget_refuses_before_any_member_body_read(self):
        admission = admission_module()
        members = []
        for index, size in enumerate((64 * 1024 ** 2, 64 * 1024 ** 2, 1)):
            info = zipfile.ZipInfo(str(index)); info.file_size = size
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            members.append(info)
        class Archive:
            opened = 0
            def infolist(self): return members
            def open(self, member):
                self.opened += 1; raise AssertionError('Member body must not be opened')
        archive = Archive()
        with self.assertRaisesRegex(ValueError, 'Wheel byte limit'):
            admission._wheel_files(archive)
        self.assertEqual(archive.opened, 0)

    def test_wheel_stream_reads_are_bounded_and_match_declared_sizes(self):
        admission = admission_module()
        for size, body, accepted in ((1, b'ab', False), (2, b'a', False), (3, b'abc', True)):
            with self.subTest(size=size, body=body):
                info = zipfile.ZipInfo('member'); info.file_size = size
                info.external_attr = (stat.S_IFREG | 0o644) << 16
                requests = []
                class Stream(io.BytesIO):
                    def read(self, count=-1):
                        requests.append(count); return super().read(count)
                class Archive:
                    def infolist(self): return [info]
                    def open(self, member): return Stream(body)
                if accepted:
                    files, _ = admission._wheel_files(Archive())
                    self.assertEqual(files, {'member': body})
                else:
                    with self.assertRaises(ValueError): admission._wheel_files(Archive())
                self.assertTrue(requests)
                self.assertTrue(all(0 < count <= 65536 for count in requests))


@unittest.skipUnless(os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT'), 'requires explicitly qualified private Git fixture')
class AdmittedInput(unittest.TestCase):
    def test_installed_package_removal_and_mode_changes_refuse(self):
        import stallionfs
        from stallionfs import _scan, _image
        from qualified_git_fixture import runtime
        targets = [Path(_scan.__file__).resolve(), Path(_image.__file__).resolve(),
                   Path(stallionfs.__file__).resolve().with_name('core.py')]
        original = Path.lstat
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        for target in targets:
            for change in ('missing', 'mode'):
                with self.subTest(target=target.name, change=change):
                    value = runtime(); reads = []
                    def changed(path, *args, **kwargs):
                        if path == target:
                            reads.append(path)
                            if change == 'missing': raise FileNotFoundError('Simulated installed member removal')
                            info = original(path, *args, **kwargs)
                            data = {field: getattr(info, field) for field in fields}; data['st_mode'] ^= 0o100
                            return SimpleNamespace(**data)
                        return original(path, *args, **kwargs)
                    with patch.object(Path, 'lstat', changed):
                        with self.assertRaises((ValueError, OSError)): value['check']()
                    self.assertTrue(reads)

    def test_contract_uses_the_registered_native_payload(self):
        from qualified_git_fixture import runtime
        from stallionfs import _bundle
        value = runtime()
        contract = value['contract']
        required = {'input_inventory_sha256', 'payload_entries', 'payload_sha256',
                    'descriptor_sha256', 'executable_sha256', 'source_build_id', 'publisher'}
        self.assertEqual(set(contract), set(_bundle.GIT_CONTRACT) | required)
        _bundle.git_contract({key: contract[key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}})
        payload = _bundle.git_payload(Path(value['executable']).parent.parent)
        self.assertEqual(contract['payload_entries'], payload['entries'])
        self.assertEqual(contract['payload_sha256'], payload['sha256'])
        self.assertEqual(contract['executable_sha256'], payload['executable_sha256'])
        value['check']()

    def test_external_fixture_path_is_refused(self):
        from qualified_git_fixture import runtime
        with patch.dict(os.environ, STALLIONFS_TEST_QUALIFIED_GIT='/usr/bin/git'):
            with self.assertRaisesRegex(ValueError, 'External fixture executable'):
                runtime()

    def test_runtime_substitution_refuses_before_actor(self):
        from qualified_git_fixture import runtime
        value = runtime()
        value['executable'] = '/usr/bin/git'
        with self.assertRaisesRegex(ValueError, 'Fixture runtime changed'):
            value['check']()
        value = runtime()
        value['contract']['input_inventory_sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Fixture runtime changed'):
            value['check']()
