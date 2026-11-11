"""Synthetic packaging/signing-boundary fixtures; no runtime or signer executes."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('package_git_fixture', SOURCE / 'tools/package_fskit.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class GitPayloadFinalization(unittest.TestCase):
    def setUp(self):
        old = os.umask(0o077)
        self.addCleanup(os.umask, old)
        self.temporary = tempfile.TemporaryDirectory(prefix='package-git-fixture-', dir=SOURCE.parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.bundle = package._runtime_bundle()
        self.bundle.QUALIFIED_GIT_INPUTS = frozenset({'6' * 64})
        selected = patch.object(package, '_runtime_bundle', return_value=self.bundle)
        selected.start(); self.addCleanup(selected.stop)

    def fixture(self, name='Candidate'):
        self.app = self.root / (name + '.app')
        self.git = self.app / 'Contents/Resources/Runtime/Git'
        for relative, data, mode in (('bin/git', b'inert unsigned executable', 0o755),
                                     ('share/git-core/templates/template', b'inert template', 0o644)):
            target = self.git / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(mode)
        (self.git / 'libexec/git-core').mkdir(parents=True)
        (self.git / 'libexec/git-core/git').symlink_to('../../bin/git')
        for directory in [self.app, *self.app.rglob('*')]:
            if directory.is_dir() and not directory.is_symlink(): directory.chmod(0o755)
        payload = self.bundle.git_payload(self.git)
        self.value = {'schema': 2, 'python_version': '3.13.18', 'soabi': 'cpython-313-darwin',
            'package_version': '0.6.3', 'source_build_id': 'a' * 64, 'bundle_version': '9',
            'paths': dict(self.bundle.RELATIVE_PATHS), 'git': dict(self.bundle.GIT_CONTRACT, input_inventory_sha256='6' * 64,
                payload_entries=payload['entries'], payload_sha256=payload['sha256'])}
        self.descriptor = self.app / self.bundle.DESCRIPTOR
        self.write_descriptor(self.value)
        self.original = self.descriptor.read_bytes()
        self.proof = {'expected_descriptor_sha256': digest(self.original),
            'before_rows': package._runtime_inventory(self.git), 'signed_leaf_sha256': {}}

    def write_descriptor(self, value):
        self.descriptor.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')
        self.descriptor.chmod(0o644)

    def sign_fixture(self):
        target = self.git / 'bin/git'
        target.write_bytes(target.read_bytes() + b'\nsynthetic signature transform')
        self.proof['signed_leaf_sha256'] = {'bin/git': digest(target.read_bytes())}

    def finalize(self):
        return package.finalize_git_payload(self.app, **self.proof)

    def assert_no_temporary(self):
        self.assertEqual(list(self.descriptor.parent.glob('.runtime.json.*')), [])

    def test_explicit_signed_leaf_bytes_finalize_only_generated_fields(self):
        self.fixture()
        self.sign_fixture()
        result = self.finalize()
        value = json.loads(self.descriptor.read_bytes())
        payload = self.bundle.git_payload(self.git)
        self.assertEqual(result, dict(self.bundle.GIT_CONTRACT, input_inventory_sha256='6' * 64,
            payload_entries=payload['entries'], payload_sha256=payload['sha256']))
        self.assertNotEqual(result['payload_sha256'], self.value['git']['payload_sha256'])
        expected = dict(self.value, git=result)
        self.assertEqual(value, expected)
        self.assertEqual(self.descriptor.stat().st_mode & 0o777, 0o644)
        self.assert_no_temporary()

    def test_app_only_or_unapproved_changes_cannot_be_promoted(self):
        self.fixture()
        self.sign_fixture()
        with self.assertRaises(TypeError): package.finalize_git_payload(self.app)
        for approved in ({}, {'bin/git': '0' * 64}, {'missing': '1' * 64}, {'../outside': '1' * 64}):
            self.proof['signed_leaf_sha256'] = approved
            with self.subTest(approved=approved), self.assertRaises(ValueError): self.finalize()
            self.assertEqual(self.descriptor.read_bytes(), self.original)
            self.assert_no_temporary()

    def test_descriptor_provenance_and_original_payload_remain_bound(self):
        for change in ('descriptor-pin', 'contract', 'source', 'build', 'input', 'extra',
                       'boolean-contract-schema', 'legacy-schema', 'boolean-schema', 'rows', 'row-order', 'count'):
            self.fixture(change)
            if change == 'descriptor-pin': self.proof['expected_descriptor_sha256'] = '0' * 64
            elif change == 'rows': self.proof['before_rows'][0]['mode'] = '0o700'
            elif change == 'row-order': self.proof['before_rows'].reverse()
            else:
                value = json.loads(self.original)
                if change == 'contract': value['git']['contract'] = 'unknown'
                elif change in ('source', 'build', 'input'):
                    key = {'source': 'source_sha256', 'build': 'build_config_sha256', 'input': 'input_inventory_sha256'}[change]
                    value['git'][key] = '0' * 64
                elif change == 'extra': value['git']['trusted'] = True
                elif change == 'boolean-contract-schema': value['git']['schema'] = True
                elif change == 'legacy-schema':
                    value['schema'] = 1
                    value.pop('git')
                elif change == 'boolean-schema': value['schema'] = True
                else: value['git']['payload_entries'] = True
                self.write_descriptor(value)
                self.original = self.descriptor.read_bytes()
                self.proof['expected_descriptor_sha256'] = digest(self.original)
            with self.subTest(change=change), self.assertRaises(ValueError): self.finalize()
            self.assertEqual(self.descriptor.read_bytes(), self.original)
            self.assert_no_temporary()

    def test_payload_namespace_modes_links_and_ordinary_files_are_fixed(self):
        for change in ('extra', 'missing', 'mode', 'hardlink', 'symlink', 'escape', 'cycle', 'git-alias', 'descriptor-link'):
            self.fixture(change)
            target = self.git / 'bin/git'
            if change == 'extra': (self.git / 'unlisted').write_bytes(b'unlisted')
            elif change == 'missing': (self.git / 'share/git-core/templates/template').unlink()
            elif change == 'mode': target.chmod(0o700)
            elif change == 'hardlink':
                os.link(target, self.root / 'outside-hardlink')
            elif change in ('symlink', 'escape', 'cycle'):
                link = self.git / 'libexec/git-core/git'
                link.unlink()
                link.symlink_to('../../share/git-core/templates/template' if change == 'symlink'
                    else '../../../../../outside' if change == 'escape' else 'git')
            elif change == 'git-alias':
                relocated = self.root / 'relocated-git'
                self.git.rename(relocated)
                self.git.symlink_to(relocated, target_is_directory=True)
            else:
                replacement = self.root / 'descriptor-copy'
                self.descriptor.rename(replacement)
                self.descriptor.symlink_to(replacement)
            with self.subTest(change=change), self.assertRaises((ValueError, OSError)): self.finalize()
            self.assertEqual(self.descriptor.read_bytes(), self.original)
            self.assert_no_temporary()

    def test_outer_seal_and_app_alias_refuse_without_writing(self):
        for change in ('directory', 'dangling-symlink', 'app-alias'):
            self.fixture(change)
            if change == 'app-alias':
                alias = self.root / 'Alias.app'
                alias.symlink_to(self.app, target_is_directory=True)
                self.app = alias
            else:
                seal = self.app / 'Contents/_CodeSignature'
                if change == 'directory': seal.mkdir()
                else: seal.symlink_to(self.root / 'missing-seal')
            with self.subTest(change=change), self.assertRaises((ValueError, OSError)): self.finalize()
            self.assertEqual(self.descriptor.read_bytes(), self.original)
            self.assert_no_temporary()

    def test_write_replace_and_readback_faults_do_not_report_success(self):
        for fault in ('short-write', 'replace', 'readback'):
            self.fixture(fault)
            self.sign_fixture()
            original_read = package._runtime_read_at
            reads = 0
            def read(root, name):
                nonlocal reads
                result = original_read(root, name)
                if name == 'runtime.json':
                    reads += 1
                    if reads == 2: return b'wrong readback'
                return result
            context = patch.object(package.os, 'write', return_value=1) if fault == 'short-write' else (
                patch.object(package.os, 'replace', side_effect=OSError('replace failed')) if fault == 'replace'
                else patch.object(package, '_runtime_read_at', side_effect=read))
            with self.subTest(fault=fault), context, self.assertRaises((ValueError, OSError)): self.finalize()
            if fault != 'readback': self.assertEqual(self.descriptor.read_bytes(), self.original)
            else: self.assertNotEqual(self.descriptor.read_bytes(), self.original)
            self.assert_no_temporary()

    def test_mid_write_descriptor_payload_and_seal_changes_refuse(self):
        for change in ('descriptor', 'payload', 'seal'):
            self.fixture(change)
            self.sign_fixture()
            original_write = package.os.write
            def write(fd, data):
                result = original_write(fd, data)
                if change == 'descriptor': self.descriptor.write_bytes(b'preserve replacement')
                elif change == 'payload': (self.git / 'bin/git').write_bytes(b'unapproved later bytes')
                else: (self.app / 'Contents/_CodeSignature').mkdir()
                return result
            with self.subTest(change=change), patch.object(package.os, 'write', side_effect=write), \
                    self.assertRaises(ValueError): self.finalize()
            self.assertEqual(self.descriptor.read_bytes(), b'preserve replacement' if change == 'descriptor' else self.original)
            self.assert_no_temporary()


if __name__ == '__main__':
    unittest.main()
