"""Run on APFS: python3 -m unittest discover -s tests -v."""

from concurrent.futures import ThreadPoolExecutor
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from stallionfs.core import Store, StallionError, clone_tree, git, run


@unittest.skipUnless(sys.platform == "darwin", "APFS integration tests require macOS")
class Workspaces(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="stallionfs-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source with spaces"
        self.source.mkdir()
        git(self.source, "init", "-b", "main")
        git(self.source, "config", "user.email", "test@example.invalid")
        git(self.source, "config", "user.name", "Test")
        (self.source / "file").write_text("original\n")
        (self.source / ".gitignore").write_text("dependencies/\n.env\n")
        (self.source / "executable").write_text("#!/bin/sh\nexit 0\n")
        (self.source / "executable").chmod(0o755)
        (self.source / "link").symlink_to("file")
        git(self.source, "add", ".")
        git(self.source, "commit", "-m", "Fixture")
        self.store = Store(self.base / "storage")

    def prepare(self, **kwargs):
        return self.store.prepare(self.source, key="test-v1", **kwargs)

    def test_lifecycle_and_git_isolation(self):
        (self.source / ".env").write_text("secret never copied")
        seed = self.prepare(command=[sys.executable, "-c", "from pathlib import Path; p=Path('dependencies'); p.mkdir(); (p/'module').write_text('module')"])
        workspace = self.store.create(seed["id"], name="feature")
        repo = Path(workspace["path"])
        seed_repo = self.store.root / "seeds" / seed["id"] / "repo"
        self.assertFalse((repo / ".env").exists())
        self.assertEqual((repo / "dependencies/module").read_text(), "module")
        self.assertEqual(os.readlink(repo / "link"), "file")
        self.assertTrue(os.access(repo / "executable", os.X_OK))
        self.assertNotEqual((repo / "file").stat().st_ino, (seed_repo / "file").stat().st_ino)
        (repo / "file").write_text("changed\n")
        (repo / "dependencies/module").write_text("changed module")
        self.assertEqual((seed_repo / "file").read_text(), "original\n")
        self.assertEqual((seed_repo / "dependencies/module").read_text(), "module")
        self.assertEqual((self.source / "file").read_text(), "original\n")
        git(repo, "add", "file")
        git(repo, "-c", "user.email=test@example.invalid", "-c", "user.name=Test", "commit", "-m", "Independent change")
        self.assertNotEqual(git(repo, "rev-parse", "HEAD"), seed["commit"])
        self.assertEqual(git(seed_repo, "rev-parse", "HEAD"), seed["commit"])
        self.assertEqual(git(self.source, "status", "--porcelain"), "")
        moved = self.store.move(workspace["id"])
        self.assertFalse(repo.exists())
        self.assertEqual(self.store.gc(older_than=0), [workspace["id"]])
        self.assertTrue(Path(moved["path"]).exists())
        restored = self.store.move(workspace["id"], restore=True)
        self.assertEqual(git(restored["path"], "log", "-1", "--format=%s"), "Independent change")
        self.store.move(workspace["id"])
        self.assertEqual(self.store.gc(older_than=0, yes=True), [workspace["id"]])
        self.assertEqual(self.store.list("trash"), [])

    def test_cache_identity_and_concurrent_prepare(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            seeds = list(pool.map(lambda _: self.prepare(), range(4)))
        self.assertEqual(len({s["id"] for s in seeds}), 1)
        self.assertEqual(sum(not s["cached"] for s in seeds), 1)
        self.assertNotEqual(seeds[0]["id"], self.store.prepare(self.source, key="test-v2")["id"])
        (self.source / "file").write_text("next commit\n")
        git(self.source, "commit", "-am", "Change")
        self.assertNotEqual(self.prepare()["id"], seeds[0]["id"])

    def test_parallel_create_and_process_cli(self):
        seed = self.prepare()["id"]
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json", "create", seed]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: json.loads(run(command)), range(4)))
        self.assertEqual(len({r["id"] for r in results}), 4)
        for result in results:
            self.assertEqual(git(result["path"], "branch", "--show-current"), result["branch"])
        self.assertEqual(len(self.store.list()), 4)
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_failure_does_not_publish_partial_seed_or_workspace(self):
        with self.assertRaises(StallionError):
            self.prepare(command=[sys.executable, "-c", "raise SystemExit(17)"])
        self.assertEqual(self.store.list("seeds"), [])
        seed = self.prepare()["id"]
        def partial(source, destination):
            destination.mkdir()
            (destination / "partial").write_text("partial")
            raise OSError(28, "disk full")
        with patch("stallionfs.core.clone_tree", partial), self.assertRaises(OSError):
            self.store.create(seed)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_source_and_command_validation(self):
        (self.source / "file").write_text("uncommitted")
        with self.assertRaisesRegex(StallionError, "Commit or stash"):
            self.prepare()
        git(self.source, "checkout", "--", "file")
        with self.assertRaisesRegex(StallionError, "tracked files"):
            self.prepare(command=[sys.executable, "-c", "from pathlib import Path; Path('file').write_text('change')"])
        with self.assertRaisesRegex(StallionError, "overlap"):
            Store(self.source / "storage").prepare(self.source, key="test")

    def test_escaping_symlinks_and_special_files_rejected(self):
        for statement in ("Path('escape').symlink_to('../outside')", "Path('escape').symlink_to('/tmp')", "__import__('os').mkfifo('pipe')"):
            with self.subTest(statement=statement), self.assertRaises(StallionError):
                self.prepare(command=[sys.executable, "-c", f"from pathlib import Path; {statement}"])

    def test_id_paths_storage_permissions_and_corruption(self):
        for value in ("../source", "/", "", "A" * 32):
            with self.assertRaises(StallionError):
                self.store.move(value)
        with self.assertRaises(StallionError):
            self.store.gc(older_than=float("nan"), yes=True)
        insecure = self.base / "insecure"
        insecure.mkdir(mode=0o755)
        with self.assertRaisesRegex(StallionError, "0700"):
            Store(insecure)
        alias = self.base / "alias"
        alias.symlink_to(self.store.root)
        with self.assertRaisesRegex(StallionError, "symlink"):
            Store(alias)
        seed = self.prepare()["id"]
        meta = self.store.root / "seeds" / seed / "meta.json"
        meta.write_text('{"format": 1, "id": "wrong"}')
        with self.assertRaisesRegex(StallionError, "mismatch"):
            self.store.create(seed)

    def test_trash_symlink_never_deletes_target(self):
        victim = self.base / "victim"
        victim.mkdir()
        (victim / "precious").write_text("keep")
        (self.store.root / "trash" / ("a" * 32)).symlink_to(victim)
        with self.assertRaises(StallionError):
            self.store.gc(older_than=0, yes=True)
        self.assertEqual((victim / "precious").read_text(), "keep")

    def test_linked_worktree_source_and_environment_isolation(self):
        linked = self.base / "linked"
        git(self.source, "worktree", "add", "--detach", str(linked), "HEAD")
        seed = self.store.prepare(linked, key="linked")["id"]
        with patch.dict(os.environ, {"GIT_DIR": str(self.source / ".git"), "GIT_WORK_TREE": str(self.source)}):
            result = self.store.create(seed)
        self.assertTrue((Path(result["path"]) / ".git").is_dir())
        self.assertEqual(git(self.source, "branch", "--show-current"), "main")

    def test_doctor_and_cli_errors(self):
        self.assertEqual(self.store.doctor()["isolation"], "passed")
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json", "remove", "../oops"]
        result = subprocess.run(command, capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("error", json.loads(result.stderr))

    def test_deleting_seed_preserves_workspaces(self):
        seed = self.prepare()["id"]
        workspace = self.store.create(seed)
        self.assertEqual(self.store.forget(seed), {"would_delete": seed})
        self.store.forget(seed, yes=True)
        self.assertEqual(self.store.list("seeds"), [])
        self.assertEqual(git(workspace["path"], "show", "HEAD:file"), "original")
        self.assertEqual((Path(workspace["path"]) / "file").read_text(), "original\n")

    def test_native_copy_fallback_is_rejected(self):
        seed = self.prepare()["id"]
        lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
        def report_fallback(state, option, result):
            result._obj.value = False
            return 0
        lib.copyfile_state_get = report_fallback
        with patch("stallionfs.core.ctypes.CDLL", return_value=lib), self.assertRaises(OSError):
            self.store.create(seed)
        self.assertEqual(self.store.list(), [])
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_interrupted_preparation_is_not_cached(self):
        marker = self.base / "started"
        setup = f"from pathlib import Path; import time; Path({str(marker)!r}).touch(); time.sleep(20)"
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root),
                   "prepare", str(self.source), "--key", "interrupt", "--", sys.executable, "-c", setup]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130)
            self.assertEqual(self.store.list("seeds"), [])
            self.assertEqual(list((self.store.root / "staging").iterdir()), [])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_relocatable_git_and_trash_age(self):
        with self.assertRaisesRegex(StallionError, "core.worktree"):
            self.prepare(command=["git", "config", "core.worktree", str(self.source)])
        seed = self.prepare()["id"]
        workspace = self.store.create(seed)
        moved = self.store.move(workspace["id"])
        self.assertEqual(self.store.gc(), [])
        path = Path(moved["path"]).parent
        old = time.time() - 2 * 86400
        os.utime(path, (old, old))
        self.assertEqual(self.store.gc(), [workspace["id"]])


if __name__ == "__main__":
    unittest.main()
