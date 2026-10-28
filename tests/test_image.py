"""Owned, offline APFS image qualification; no mount or hardware power-cut claim."""
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest


@unittest.skipUnless(sys.platform == 'darwin', 'Offline image core requires macOS APFS')
class ImageCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='stallionfs-image-tests-')).resolve()
        cls.failed = False
        cls.executables = {}
        cls.source = Path(__file__).resolve().parents[1]
        cls.common = [*shlex.split(os.environ.get('CC', 'cc')), '-std=c11', '-O2', '-g',
                      '-Wall', '-Wextra', '-Werror', '-Wno-deprecated-declarations',
                      '-I', str(cls.source / 'filesystem'), *shlex.split(os.environ.get('CFLAGS', ''))]
        try:
            cls.compile('normal')
        except BaseException:
            print(f'Image compilation evidence retained: {cls.base}', file=sys.stderr)
            raise

    @classmethod
    def compile(cls, name, *defines):
        if name in cls.executables:
            return cls.executables[name]
        obj, exe = cls.base / f'{name}.o', cls.base / name
        replacements = ('pread', 'pwrite', 'fcntl', 'fsync', 'flock', 'close',
                        'openat', 'fstat', 'fstatat', 'fstatfs')
        commands = [
            [*cls.common, *defines, *(f'-D{n}=sfs_test_{n}' for n in replacements),
             '-c', str(cls.source / 'filesystem/image.c'), '-o', str(obj)],
            [*cls.common, *defines, str(cls.source / 'tests/image_driver.c'), str(obj), '-o', str(exe)],
        ]
        for index, command in enumerate(commands):
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (cls.base / f'{name}-compile-{index}.txt').write_text(result.stdout + result.stderr)
            if result.returncode:
                raise AssertionError(f'Image compilation failed; retained {cls.base}\n{result.stderr}')
        cls.executables[name] = exe
        return exe

    @classmethod
    def tearDownClass(cls):
        if cls.failed:
            print(f'Failed image fixtures and receipts retained: {cls.base}', file=sys.stderr)
        else:
            shutil.rmtree(cls.base)

    def scenario(self, name, executable='normal'):
        try:
            result = subprocess.run([str(self.executables[executable]), name], cwd=self.base,
                                    capture_output=True, text=True, timeout=90)
            receipt = self.base / f'{executable}-{name}.json'
            receipt.write_text(json.dumps({'scenario': name, 'returncode': result.returncode,
                                          'stdout': result.stdout, 'stderr': result.stderr}, indent=2))
            self.assertEqual(result.returncode, 0, f'{name}: {result.stderr}\n{result.stdout}\nRetained: {self.base}')
            self.assertIn(f'PASS {name}', result.stdout)
            print(result.stdout, end='', flush=True)
        except BaseException:
            type(self).failed = True
            raise

    def test_create_reopen_atomic_snapshot_ranges_and_iteration(self):
        self.scenario('basic')

    def test_creation_locks_fences_identity_and_retained_failures(self):
        self.scenario('creation')

    def test_exact_io_errors_poisoning_and_no_implicit_recovery(self):
        self.scenario('io')

    def test_process_cuts_and_separate_discard_unflushed_write_model(self):
        self.scenario('cuts')

    def test_review_newer_anchor_slot_errno_and_io_poisoning(self):
        self.scenario('review')

    def test_security_inode_counter_floors_and_per_pass_payload_verification(self):
        self.scenario('security')

    def test_parser_checksums_slot_pairs_and_read_only_recovery(self):
        self.scenario('parser')

    def test_admission_file_entry_snapshot_name_and_generation_limits(self):
        self.scenario('limits')

    def test_independent_metadata_and_physical_tail_capacity(self):
        try:
            self.compile('metadata', '-DSFS_METADATA_MAX=512')
            self.compile('capacity', '-DSFS_IMAGE_MAX=UINT64_C(131072)')
            self.scenario('metadata', 'metadata')
            self.scenario('capacity', 'capacity')
        except BaseException:
            type(self).failed = True
            raise
