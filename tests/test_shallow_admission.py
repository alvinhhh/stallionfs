"""Shallow-file admission identity without the macOS native runtime."""
import importlib
import os
from pathlib import Path
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


class ShallowAdmission(unittest.TestCase):
    def setUp(self):
        self.package = '_shallow_admission_' + str(id(self))
        package = ModuleType(self.package)
        package.__path__ = [str(Path(__file__).resolve().parents[1] / 'stallionfs')]
        scan = ModuleType(self.package + '._scan')
        scan._private_directory = lambda path: None
        image = ModuleType(self.package + '._image')
        isolated = patch.dict(sys.modules, {
            self.package: package, scan.__name__: scan, image.__name__: image})
        isolated.start()
        self.addCleanup(isolated.stop)
        global core, git
        core = importlib.import_module(self.package + '.core')
        git = importlib.import_module(self.package + '._native_create_git')
        self.temp = tempfile.TemporaryDirectory(prefix='sfs-shallow-admission-')
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve() / 'repo'
        gitdir = self.repo / '.git'
        gitdir.mkdir(parents=True)
        (gitdir / 'config').write_text('[core]\n\trepositoryformatversion = 0\n')
        (gitdir / 'HEAD').write_text('ref: refs/heads/main\n')
        self.shallow = gitdir / 'shallow'
        self.shallow.write_text('a' * 40 + '\n')

    def test_shallow_requires_allowance(self):
        with self.assertRaises(core.StallionError):
            git.structure(self.repo)

    def test_rewritten_shallow_changes_admission(self):
        admitted = git.structure(self.repo, allow_shallow=True)
        self.assertEqual(git.structure(self.repo, allow_shallow=True), admitted)
        with self.shallow.open('r+') as stream:
            stream.write('b' * 40 + '\n')
        self.assertNotEqual(git.structure(self.repo, allow_shallow=True), admitted)

    def test_replaced_or_removed_shallow_changes_admission(self):
        admitted = git.structure(self.repo, allow_shallow=True)
        replacement = self.shallow.with_name('shallow.new')
        replacement.write_text('a' * 40 + '\n')
        os.replace(replacement, self.shallow)
        self.assertNotEqual(git.structure(self.repo, allow_shallow=True), admitted)
        self.shallow.unlink()
        self.assertNotEqual(git.structure(self.repo, allow_shallow=True), admitted)

    def test_shallow_added_after_admission_changes_admission(self):
        self.shallow.unlink()
        admitted = git.structure(self.repo, allow_shallow=True)
        self.shallow.write_text('a' * 40 + '\n')
        self.assertNotEqual(git.structure(self.repo, allow_shallow=True), admitted)
