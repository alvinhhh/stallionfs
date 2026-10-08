"""Run on APFS: python3 -m unittest discover -s tests -v."""

from concurrent.futures import ThreadPoolExecutor
import errno
from io import StringIO
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import ANY, patch

from stallionfs.core import Store, StallionError, clone_tree, git, remove_tree, run


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

    def test_worker_limit_is_forwarded_and_invalid_limits_leave_storage_unchanged(self):
        seed = self.prepare()["id"]
        with patch("stallionfs.core.clone_tree", wraps=clone_tree) as copying:
            workspace = self.store.create(seed, jobs=1)
            copying.assert_called_once_with(self.store.root / "seeds" / seed / "repo", ANY, jobs=1)
        self.assertEqual(git(workspace["path"], "branch", "--show-current"), workspace["branch"])
        self.store.move(workspace["id"])
        before = sorted(str(path.relative_to(self.store.root)) for path in self.store.root.rglob("*"))
        for jobs in (0, 5, True, 1.5, "1"):
            with self.subTest(jobs=jobs):
                with self.assertRaises(StallionError): self.store.create(seed, jobs=jobs)
                with self.assertRaises(StallionError): self.store.gc(older_than=0, yes=True, jobs=jobs)
                self.assertEqual(sorted(str(path.relative_to(self.store.root)) for path in self.store.root.rglob("*")), before)
        with patch("stallionfs.core.remove_tree", wraps=remove_tree) as reclaiming:
            self.assertEqual(self.store.gc(older_than=0, yes=True, jobs=1), [workspace["id"]])
            reclaiming.assert_called_once_with(ANY, jobs=1)
            retired = reclaiming.call_args.args[0]
            self.assertEqual(retired.name, "expired")
            self.assertEqual(retired.parent.parent, self.store.root / "staging")
        self.assertEqual(list((self.store.root / "staging").iterdir()), [])

    def test_failure_does_not_publish_partial_seed_or_workspace(self):
        with self.assertRaises(StallionError) as failed:
            self.prepare(command=[sys.executable, "-c", "raise SystemExit(17)"])
        self.assertEqual(self.store.list("seeds"), [])
        retained = set((self.store.root / "staging").iterdir())
        self.assertEqual(len(retained), 1)
        first = next(iter(retained))
        self.assertEqual(failed.exception.__notes__, [f"Unfinished files retained at {first}"])
        self.assertEqual((first / "repo/file").read_text(), "original\n")
        seed = self.prepare()["id"]
        error = OSError(28, "disk full")
        def partial(source, destination, *, jobs=4):
            destination.mkdir()
            (destination / "partial").write_text("partial")
            raise error
        with patch("stallionfs.core.clone_tree", partial), self.assertRaises(OSError) as failed:
            self.store.create(seed)
        self.assertIs(failed.exception, error)
        self.assertEqual(self.store.list(), [])
        added = set((self.store.root / "staging").iterdir()) - retained
        self.assertEqual(len(added), 1)
        second = next(iter(added))
        self.assertEqual((second / "repo/partial").read_text(), "partial")
        self.assertEqual(error.__notes__, [f"Unfinished files retained at {second}"])

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

    def test_parallel_gc_preserves_symlink_targets_and_reports_errors(self):
        seed = self.prepare()["id"]
        victim = self.base / "keep"
        victim.mkdir()
        (victim / "precious").write_text("keep")
        identifiers = []
        for _ in range(4):
            workspace = self.store.create(seed)
            (Path(workspace["path"]) / "external").symlink_to(victim)
            self.store.move(workspace["id"])
            identifiers.append(workspace["id"])
        original = remove_tree
        barrier = threading.Barrier(4, timeout=5)

        def reclaim(path, *, jobs=4):
            self.assertEqual(jobs, 1)  # Four roots share the four-worker budget.
            barrier.wait()  # Fails if reclamation regresses to serial traversal.
            original(path, jobs=jobs)

        with patch("stallionfs.core.remove_tree", reclaim):
            self.assertCountEqual(self.store.gc(older_than=0, yes=True), identifiers)
        self.assertEqual((victim / "precious").read_text(), "keep")
        self.assertEqual(self.store.list("trash"), [])
        workspace = self.store.create(seed)
        (Path(workspace["path"]) / "external").symlink_to(victim)
        self.store.move(workspace["id"])
        expired = self.store.root / "trash" / workspace["id"]
        os.utime(expired, (time.time() - 120,) * 2)
        recent = self.store.create(seed)
        self.store.move(recent["id"])
        failure = PermissionError("denied after partial deletion")

        def partial(path, *, jobs=4):
            self.assertEqual(json.loads((path / "meta.json").read_text())["id"], workspace["id"])
            (path / "meta.json").unlink()
            raise failure

        with patch("stallionfs.core.remove_tree", partial), self.assertRaises(PermissionError) as caught:
            self.store.gc(older_than=60, yes=True)
        self.assertIs(caught.exception, failure)
        retained = list((self.store.root / "staging").iterdir())
        self.assertEqual(len(retained), 1)
        stage = retained[0]
        self.assertFalse(stage.is_symlink())
        self.assertEqual((stage.stat().st_uid, stage.stat().st_mode & 0o777), (os.getuid(), 0o700))
        self.assertEqual(failure.__notes__, [f"Unfinished files retained at {stage}"])
        self.assertFalse(expired.exists())
        self.assertFalse((stage / "expired/meta.json").exists())
        self.assertEqual((stage / "expired/repo/file").read_text(), "original\n")
        self.assertTrue((stage / "expired/repo/external").is_symlink())
        self.assertEqual((victim / "precious").read_text(), "keep")
        self.assertEqual([row["id"] for row in self.store.list("trash")], [recent["id"]])
        self.assertEqual(self.store.gc(older_than=60), [])
        self.assertEqual(self.store.gc(older_than=60, yes=True), [])
        self.assertEqual(list((self.store.root / "staging").iterdir()), retained)
        restored = self.store.move(recent["id"], restore=True)
        self.assertEqual((Path(restored["path"]) / "file").read_text(), "original\n")
        self.assertEqual(self.store.list("trash"), [])

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

    def test_native_clone_rejects_fallback_and_handles_interruption(self):
        seed = self.prepare()["id"]
        shim = self.base / "unsupported.c"
        shim.write_text('''#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/clonefile.h>
static int unsupported(int a, int b, const char *c, unsigned f) {
    (void)a; (void)b; (void)c; (void)f;
    if (getenv("STALLIONFS_TEST_INTERRUPT")) { raise(SIGINT); errno = EINTR; return -1; }
    errno = ENOTSUP; return -1;
}
__attribute__((used, section("__DATA,__interpose")))
static struct { const void *replacement; const void *original; } interpose = {
    (const void *)unsupported, (const void *)fclonefileat
};
''')
        library = self.base / "unsupported.dylib"
        run(["cc", "-dynamiclib", str(shim), "-o", str(library)])
        program = f'''import errno, os
from pathlib import Path
from stallionfs.core import Store
store = Store({str(self.store.root)!r})
before = set((store.root / "staging").iterdir())
try:
    store.create({seed!r})
except (OSError, KeyboardInterrupt) as exc:
    if os.environ.get("STALLIONFS_TEST_INTERRUPT"):
        assert isinstance(exc, KeyboardInterrupt), exc
    else:
        assert isinstance(exc, OSError) and exc.errno == errno.ENOTSUP, exc
    assert any("Unfinished files retained at" in note for note in exc.__notes__)
else:
    raise AssertionError("unsupported clone silently fell back to copying")
assert store.list() == []
assert len(set((store.root / "staging").iterdir()) - before) == 1
'''
        for fault in ({}, {"STALLIONFS_TEST_INTERRUPT": "1"}):
            result = subprocess.run([sys.executable, "-c", program], capture_output=True, text=True,
                                    env={**os.environ, "DYLD_INSERT_LIBRARIES": str(library), **fault})
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_clone_preserves_metadata_and_never_follows_links(self):
        source = self.base / "clone-source"
        source.mkdir()
        directory = source / "nested"
        directory.mkdir()
        target = directory / "file"
        target.write_bytes(b"original")
        target.chmod(0o754)
        directory.chmod(0o750)
        principal = pwd.getpwuid(os.getuid()).pw_name
        for path in (source, directory, target):
            run(["xattr", "-w", "com.stallionfs.test", "metadata", path])
            run(["chmod", "+a", f"user:{principal} allow read,write", path])
        (source / "external").symlink_to(self.source, target_is_directory=True)
        (source / "dangling").symlink_to("absent")
        os.utime(target, ns=(1_700_000_000_123456789,) * 2)
        os.utime(directory, ns=(1_700_000_000_987654321,) * 2)
        destination = self.base / "clone-destination"
        clone_tree(source, destination)
        for path in (source, directory, target):
            copied = destination / path.relative_to(source)
            self.assertEqual(copied.stat().st_mode, path.stat().st_mode)
            self.assertEqual(copied.stat().st_mtime_ns, path.stat().st_mtime_ns)
            self.assertEqual(run(["xattr", "-p", "com.stallionfs.test", copied]), "metadata")
            self.assertEqual(run(["ls", "-lde", copied]).splitlines()[1:], run(["ls", "-lde", path]).splitlines()[1:])
        self.assertEqual(os.readlink(destination / "external"), str(self.source))
        self.assertEqual(os.readlink(destination / "dangling"), "absent")
        (destination / "nested/file").write_bytes(b"changed")
        self.assertEqual(target.read_bytes(), b"original")
        with self.assertRaises(FileExistsError):
            clone_tree(source, destination)
        with self.assertRaises(OSError):
            clone_tree(source / "external", self.base / "must-not-exist")
        self.assertFalse((self.base / "must-not-exist").exists())
        os.mkfifo(source / "fifo")
        with self.assertRaises(OSError) as error:
            clone_tree(source, self.base / "unsupported")
        self.assertEqual(error.exception.errno, errno.ENOTSUP)

    def test_interrupted_preparation_is_not_cached(self):
        marker = self.base / "started"
        setup = f"from pathlib import Path; import time; Path({str(marker)!r}).touch(); time.sleep(20)"
        command = [sys.executable, "-m", "stallionfs", "--root", str(self.store.root), "--json",
                   "prepare", str(self.source), "--key", "interrupt", "--", sys.executable, "-c", setup]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(marker.exists())
            process.send_signal(signal.SIGINT)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 130)
            self.assertEqual(stdout, "")
            self.assertEqual(self.store.list("seeds"), [])
            retained = list((self.store.root / "staging").iterdir())
            self.assertEqual(len(retained), 1)
            self.assertEqual(json.loads(stderr), {"error": "interrupted", "notes": [f"Unfinished files retained at {retained[0]}"]})
            self.assertEqual((retained[0] / "repo/file").read_text(), "original\n")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_cli_plain_interrupt_preserves_notes(self):
        from stallionfs.__main__ import main

        interrupted = KeyboardInterrupt()
        note = f"Unfinished files retained at {self.store.root / 'staging/build-test'}"
        interrupted.add_note(note)
        with patch.object(Store, "prepare", side_effect=interrupted), \
                patch("sys.stdout", new_callable=StringIO) as stdout, \
                patch("sys.stderr", new_callable=StringIO) as stderr:
            status = main(["--root", str(self.store.root), "prepare", str(self.source), "--key", "interrupt"])
        self.assertEqual(status, 130)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), f"stallionfs: interrupted\n{note}\n")

    def test_failed_setup_retains_files_used_by_descendant(self):
        owned = Path(tempfile.mkdtemp(prefix="stallionfs-descendant-")).resolve()
        observer = '''from pathlib import Path
import sys, time
root = Path(sys.argv[1])
deadline = time.monotonic() + 4
(root / 'ready').touch()
while not (root / 'stop').exists() and time.monotonic() < deadline:
    if not Path('file').is_file(): (root / 'missing').touch()
    time.sleep(0.01)
(root / 'finished').touch()
'''
        setup = f'''from pathlib import Path
import subprocess, sys, time
root = Path({str(owned)!r})
subprocess.Popen([sys.executable, '-I', '-B', '-c', {observer!r}, str(root)],
                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
deadline = time.monotonic() + 2
while not (root / 'ready').exists():
    if time.monotonic() >= deadline: raise RuntimeError('Observer startup timeout')
    time.sleep(0.01)
raise SystemExit(17)
'''
        try:
            command = [sys.executable, '-I', '-B', '-m', 'stallionfs', '--json', '--root', str(owned / 'store'),
                       'prepare', str(self.source), '--key', 'descendant', '--', sys.executable, '-I', '-B', '-c', setup]
            failed = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(failed.returncode, 1, failed.stderr)
            self.assertEqual(failed.stdout, '')
            error = json.loads(failed.stderr)
            retained = list((owned / 'store/staging').iterdir())
            self.assertEqual(len(retained), 1)
            self.assertEqual(error['notes'], [f'Unfinished files retained at {retained[0]}'])
            self.assertEqual((retained[0] / 'repo/file').read_text(), 'original\n')
            self.assertFalse((owned / 'finished').exists(), 'Observer exited before failure was checked')
            time.sleep(0.05)
            self.assertFalse((owned / 'missing').exists(), 'Setup failure deleted files used by its descendant')
        finally:
            (owned / 'stop').touch()
            deadline = time.monotonic() + 5
            while not (owned / 'finished').exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if (owned / 'finished').exists():
                # The marker is the observer's final filesystem operation.
                remove_tree(owned)
            else:
                raise RuntimeError(f'Observer completion unknown; retained fixture at {owned}')

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
