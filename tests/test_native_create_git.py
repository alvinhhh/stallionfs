"""Qualified Git boundary regressions; opt-in executable must be independently pinned."""
import copy
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from stallionfs import core
from stallionfs import _native_create_git as git


@unittest.skipUnless(os.environ.get('STALLIONFS_TEST_QUALIFIED_GIT'), 'requires explicitly qualified private Git fixture')
class CreationGit(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-native-git-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.executable = str(Path(os.environ['STALLIONFS_TEST_QUALIFIED_GIT']).resolve())
        self.runtime = {'executable': self.executable, 'exec_path': str(Path(self.executable).parent.parent / 'libexec/git-core'),
                        'contract': {'executable_sha256': hashlib.sha256(Path(self.executable).read_bytes()).hexdigest()}}
        home = self.base / 'home'; home.mkdir(mode=0o700)
        (home / '.gitconfig').write_text('[user]\n name = Fixture\n email = fixture@example.invalid\n')
        self.environment = {'HOME': str(home), 'PATH': str(Path(self.executable).parent) + ':/usr/bin:/bin',
                            'LANG': 'C', 'LC_ALL': 'C'}
        self.envpatch = patch.dict(os.environ, self.environment, clear=True)
        self.envpatch.start(); self.addCleanup(self.envpatch.stop)
        self.source = self.base / 'source'; self.source.mkdir()
        self.command(self.source, 'init', '-b', 'main')
        (self.source / 'file').write_text('prepared bytes\n')
        self.command(self.source, 'add', 'file')
        self.command(self.source, 'commit', '-m', 'Fixture')
        self.store = core.Store(self.base / 'store')

    def command(self, path, *args):
        result = subprocess.run([self.executable, '-C', str(path), *args], env=self.environment,
                                capture_output=True, timeout=10)
        if result.returncode:
            self.fail(result.stderr.decode())
        return result.stdout.decode().strip()

    def prepare(self, *, ref_format='files', key=''):
        if ref_format == 'reftable':
            with (Path(self.environment['HOME']) / '.gitconfig').open('a') as stream:
                stream.write('[init]\n defaultRefFormat = reftable\n')
        seed = self.store.prepare(self.source, key='fixture-' + ref_format + key)
        return self.store.root / 'seeds' / seed['id'] / 'repo', seed['commit']

    def checkout(self, seed, commit, suffix='a'):
        stage = self.base / ('stage-' + suffix); stage.mkdir(mode=0o700)
        repo = stage / 'repo'; shutil.copytree(seed, repo)
        before = (repo / '.git/config').read_bytes(), (repo / '.git/index').read_bytes(), (repo / 'file').read_bytes()
        record, saved = {}, []
        git.checkout(repo, commit, 'stallionfs/test-' + suffix * 32, stage, record,
                     lambda: saved.append(copy.deepcopy(record)), self.runtime)
        self.assertEqual(before, ((repo / '.git/config').read_bytes(), (repo / '.git/index').read_bytes(), (repo / 'file').read_bytes()))
        self.assertEqual(self.command(repo, 'rev-parse', 'HEAD'), commit)
        self.assertEqual(len(record['actors']), 5)
        self.assertTrue(all(actor['streams_durable'] and actor['reaped'] for actor in record['actors']))
        return repo, record

    def test_actual_prepared_seed_and_tracking_config(self):
        seed, commit = self.prepare()
        self.assertIn('branch.main.remote', self.command(seed, 'config', '--local', '--name-only', '--list'))
        self.checkout(seed, commit)

    def test_actual_prepared_reftable(self):
        seed, commit = self.prepare(ref_format='reftable')
        self.assertTrue((seed / '.git/reftable/tables.list').exists())
        self.checkout(seed, commit)

    def test_actual_prepared_sha256_and_detached_source(self):
        for number, ref_format in enumerate(('files', 'reftable')):
            with self.subTest(ref_format=ref_format):
                self.source = self.base / ('sha256-' + ref_format); self.source.mkdir()
                self.command(self.source, 'init', '-b', 'main', '--object-format=sha256')
                (self.source / 'file').write_text('SHA256 prepared bytes\n')
                self.command(self.source, 'add', 'file'); self.command(self.source, 'commit', '-m', 'SHA256')
                for detached in (False, True):
                    if detached: self.command(self.source, 'checkout', '--detach')
                    seed, commit = self.prepare(ref_format=ref_format, key='-detached' if detached else '-branch')
                    self.assertEqual(len(commit), 64)
                    self.checkout(seed, commit, chr(101 + number * 2 + detached))

    def test_generic_prepare_and_create_preserve_defaults_without_hooks_or_trace(self):
        sentinel, trace = self.base / 'outside-hook', self.base / 'outside-trace'
        config = Path(self.environment['HOME']) / '.gitconfig'
        with config.open('a') as stream:
            stream.write('[init]\n defaultRefFormat = reftable\n[credential]\n helper = fixture-auth\n'
                         '[trace2]\n eventTarget = ' + str(trace) + '\n')
            for event in ('post-checkout', 'reference-transaction'):
                stream.write('[hook "fixture-' + event + '"]\n event = ' + event + '\n command = echo BAD >> ' + str(sentinel) + '\n')
        seed, commit = self.prepare(ref_format='reftable')
        created = self.store.create(seed.parent.name)
        self.assertTrue((Path(created['path']) / '.git/reftable/tables.list').exists())
        self.assertEqual(core.git(seed, 'config', '--global', '--get', 'credential.helper'), 'fixture-auth')
        self.assertEqual(core.git(seed, 'config', '--global', '--get', 'user.name'), 'Fixture')
        self.assertFalse(sentinel.exists()); self.assertFalse(trace.exists())

    def test_log_identity_and_contained_head_symlink(self):
        seed, commit = self.prepare()
        for number, setting in enumerate(('false', 'always', 'true')):
            self.command(seed, 'config', 'core.logAllRefUpdates', setting)
            self.command(seed, 'config', 'committer.name', 'Local Committer')
            self.command(seed, 'config', 'committer.email', 'local@example.invalid')
            self.command(seed, 'config', 'core.hooksPath', '.hooks')
            self.command(seed, 'config', 'core.preferSymlinkRefs', 'true')
            repo, _ = self.checkout(seed, commit, chr(98 + number))
            self.assertTrue((repo / '.git/HEAD').is_symlink())
            self.assertIn('Local Committer', (repo / '.git/logs/HEAD').read_text())

    def test_configured_descendant_hook_cannot_run_on_success(self):
        seed, commit = self.prepare()
        sentinel = self.base / 'outside-writer'
        for event in ('post-checkout', 'reference-transaction'):
            self.command(seed, 'config', '--add', 'hook.fixture-' + event + '.event', event)
            self.command(seed, 'config', 'hook.fixture-' + event + '.command',
                         '(for x in 1 2 3; do echo BAD >> ' + str(sentinel) + '; sleep .02; done) &')
        self.checkout(seed, commit)
        self.assertFalse(sentinel.exists())

    def test_transient_and_path_escape_before_actor(self):
        seed, commit = self.prepare()
        for number, name in enumerate(sorted(git.TRANSIENT)):
            with self.subTest(name=name):
                stage = self.base / ('refusal-' + str(number)); stage.mkdir(mode=0o700)
                repo = stage / 'repo'; shutil.copytree(seed, repo)
                (repo / '.git' / name).write_text(commit)
                with patch.object(git._native, 'execute_owned', side_effect=AssertionError('actor before refusal')):
                    with self.assertRaises(core.StallionError):
                        git.checkout(repo, commit, 'stallionfs/' + 'f' * 32, stage, {}, lambda: None, self.runtime)
                self.assertFalse((stage / 'actors').exists())
        for kind in ('symlink', 'hardlink', 'fifo'):
            with self.subTest(kind=kind):
                stage = self.base / ('refusal-' + kind); stage.mkdir(mode=0o700)
                repo = stage / 'repo'; shutil.copytree(seed, repo)
                config = repo / '.git/config'; original = config.read_bytes(); config.unlink()
                outside = self.base / ('outside-' + kind); outside.write_bytes(original)
                if kind == 'symlink': config.symlink_to(outside)
                elif kind == 'hardlink': os.link(outside, config)
                else: os.mkfifo(config)
                with patch.object(git._native, 'execute_owned', side_effect=AssertionError('actor before refusal')):
                    with self.assertRaises(core.StallionError):
                        git.checkout(repo, commit, 'stallionfs/' + 'f' * 32, stage, {}, lambda: None, self.runtime)
                self.assertEqual(outside.read_bytes(), original)
