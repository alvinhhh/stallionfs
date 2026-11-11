"""Synthetic companion metadata admission; no app or signature execution."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import _bundle, _native_create_git as git, _native


class NativeRuntime(unittest.TestCase):
    def setUp(self):
        from native_writer_fixture import INPUT, qualify
        qualify(self)
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-runtime-admission-')
        self.addCleanup(self.temp.cleanup)
        self.app = Path(self.temp.name).resolve() / 'Fixture.app'
        self.host = self.app / 'Contents/MacOS/StallionFS'
        def file(path, data=b'inert', mode=0o755):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data); path.chmod(mode)
        file(self.host)
        for key in ('python', 'helper', 'git'):
            file(self.app / _bundle.RELATIVE_PATHS[key])
        for key in ('site_packages', 'git_exec_path', 'git_template_dir'):
            (self.app / _bundle.RELATIVE_PATHS[key]).mkdir(parents=True, exist_ok=True)
        for name in ('sfs', 'stallionfs'):
            file((self.app / _bundle.RELATIVE_PATHS['helper']).with_name(name))
        for name in ('__init__.py', '__main__.py', '_bundle.py', '_scan.cpython-313-darwin.so', '_image.cpython-313-darwin.so'):
            file(self.app / _bundle.RELATIVE_PATHS['site_packages'] / 'stallionfs' / name, mode=0o644)
        self.gitroot = (self.app / _bundle.RELATIVE_PATHS['git']).parent.parent
        self.payload = _bundle.git_payload(self.gitroot)
        self.metadata = {'schema': 2, 'python_version': '3.13.18', 'soabi': 'cpython-313-darwin', 'package_version': '0.6.3',
            'source_build_id': '1' * 64, 'bundle_version': '1', 'paths': _bundle.RELATIVE_PATHS,
            'git': {**_bundle.GIT_CONTRACT, 'input_inventory_sha256': INPUT,
                    'payload_entries': self.payload['entries'], 'payload_sha256': self.payload['sha256']}}
        self.descriptor = self.app / _bundle.DESCRIPTOR
        self.save()

    def save(self):
        self.descriptor.write_text(json.dumps(self.metadata))
        self.descriptor.chmod(0o644)

    def test_source_module_uses_exact_explicit_companion(self):
        self.assertIsNone(_bundle.paths())
        context = git.qualified_runtime(self.host)
        self.assertEqual(context['executable'], str(self.gitroot / 'bin/git'))
        self.assertEqual(context['contract']['descriptor_sha256'], hashlib.sha256(self.descriptor.read_bytes()).hexdigest())
        self.assertEqual(context['contract']['executable_sha256'], hashlib.sha256(b'inert').hexdigest())
        context['check']()
        (self.gitroot / 'bin/git').write_bytes(b'changed')
        with self.assertRaises(Exception): context['check']()
        with self.assertRaises(Exception): git.qualified_runtime(self.host)

    def test_legacy_descriptor_is_generic_only(self):
        self.metadata['schema'] = 1; self.metadata.pop('git'); self.save()
        self.assertEqual(_bundle.from_host(self.host)['metadata']['schema'], 1)
        with self.assertRaises(Exception): git.qualified_runtime(self.host)

    def test_no_real_v3_build_is_implicitly_qualified(self):
        with patch.object(_bundle, 'QUALIFIED_GIT_INPUTS', frozenset()):
            with self.assertRaises(Exception): git.qualified_runtime(self.host)
        self.metadata['git'] = dict(_bundle.LEGACY_GIT_CONTRACT,
            payload_entries=self.payload['entries'], payload_sha256=self.payload['sha256'])
        self.save()
        with self.assertRaises(Exception): git.qualified_runtime(self.host)

    def test_wrong_contract_and_payload_refuse(self):
        for key in ('source_sha256', 'build_config_sha256', 'input_inventory_sha256', 'payload_sha256'):
            with self.subTest(key=key):
                original = self.metadata['git'][key]
                self.metadata['git'][key] = '0' * 64; self.save()
                with self.assertRaises(Exception): git.qualified_runtime(self.host)
                self.metadata['git'][key] = original; self.save()

    def test_link_hardlink_and_alias_runtime_refuse(self):
        executable = self.gitroot / 'bin/git'
        alias = self.app.parent / 'external'; os.link(executable, alias)
        with self.assertRaises(Exception): git.qualified_runtime(self.host)
        alias.unlink()
        executable.unlink(); executable.symlink_to('/bin/sh')
        with self.assertRaises(Exception): git.qualified_runtime(self.host)
        outside = self.app.parent / 'Alias.app'; outside.symlink_to(self.app)
        with self.assertRaises(Exception): _bundle.from_host(outside / 'Contents/MacOS/StallionFS')

    def test_package_verifier_binds_publisher_and_selected_app(self):
        class Operation:
            record = {}
            def command(self, label, argv):
                self.label, self.argv = label, argv
                return {'returncode': 0}
        operation = Operation()
        _native.verify_package(operation, self.host)
        self.assertEqual(operation.label, 'verify-package')
        self.assertEqual(operation.argv[-1], str(self.app))
        self.assertIn(_bundle.PUBLISHER_TEAM, operation.argv[-2])
        self.assertIn('-R', operation.argv)
