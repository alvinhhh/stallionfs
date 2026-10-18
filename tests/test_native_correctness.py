"""Metadata and content oracles for disposable native-operation fixtures."""
import ctypes
from copy import deepcopy
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("native_correctness", Path(__file__).parent / "perf/native_correctness.py")
checks = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checks)


class NativeCorrectness(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="native-correctness-")
        self.base = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_content_metadata_symlink_bytes_and_access_time_exclusion(self):
        root = self.base / "source"
        root.mkdir()
        path = root / "file"
        path.write_bytes(b"content\0bytes")
        path.chmod(0o640)
        os.utime(path, ns=(1_600_000_000_000_000_000, 1_700_000_000_123_456_789))
        os.symlink(b"missing\n", os.fsencode(root / "link"))
        observed = checks.snapshot(root)
        row = observed["entries"]["file"]
        self.assertEqual(row["sha256"], hashlib.sha256(b"content\0bytes").hexdigest())
        self.assertEqual((row["mode"], row["uid"], row["gid"]), (0o640, os.getuid(), path.stat().st_gid))
        self.assertEqual(row["mtime_ns"], path.stat().st_mtime_ns)
        self.assertEqual(observed["entries"]["link"]["symlink_bytes"], b"missing\n".hex())
        after = checks.snapshot(root)
        after["entries"]["file"]["atime_ns"] += 1
        self.assertTrue(checks.compare(observed, after)["strict_equal"])
        self.assertTrue(checks.verify_source(observed, after)["unchanged"])
        after["entries"]["file"]["device_inode"][1] += 1
        self.assertFalse(checks.verify_source(observed, after)["unchanged"])
        path.write_bytes(b"wrong contents")
        losses = checks.compare(observed, checks.snapshot(root))["candidate_losses"]
        self.assertIn("sha256", {loss["field"] for loss in losses})

    def test_move_rejects_replaced_child_with_unchanged_root_and_content(self):
        root = self.base / "tree"
        root.mkdir()
        (root / "child").write_bytes(b"same content")
        before = checks.snapshot(root)
        after = deepcopy(before)
        self.assertTrue(checks.verify_move(before, after)["move_identity"])
        after["entries"]["child"]["device_inode"][1] += 1
        self.assertTrue(checks.compare(before, after)["strict_equal"])
        result = checks.verify_move(before, after)
        self.assertFalse(result["move_identity"])
        self.assertEqual([x["path"] for x in result["move_identity_changes"]], ["child"])
        self.assertEqual(before["entries"][""]["device_inode"], after["entries"][""]["device_inode"])

    def test_sharing_observation_reuses_existing_regular_file_descriptor(self):
        path = self.base / "source"
        path.write_bytes(b"observed data")
        observed_fd = []
        def observe(fd):
            observed_fd.append(fd)
            self.assertEqual(os.fstat(fd).st_ino, path.stat().st_ino)
            return {"available": False, "unavailable": "mock unsupported"}
        with mock.patch.object(checks, "_clone_attributes", side_effect=observe), \
             mock.patch.object(checks.os, "open", wraps=os.open) as opened:
            before = checks.snapshot(path)
            after = checks.snapshot(path, observe_sharing=True)
        self.assertEqual(len(observed_fd), 1)
        self.assertEqual(opened.call_count, 2)  # One ordinary content descriptor per snapshot.
        self.assertNotIn("clone_attributes", before["entries"][""])
        self.assertFalse(after["entries"][""]["clone_attributes"]["available"])
        self.assertTrue(checks.verify_source(before, after)["unchanged"])
        changed = deepcopy(after)
        changed["entries"][""]["clone_attributes"] = {"available": True, "clone_id": 99,
                                                       "extended_flags": 65, "clone_refcount": 7}
        self.assertTrue(checks.verify_source(after, changed)["unchanged"])

    def test_hardlink_topology_baseline_loss_and_clone_independence(self):
        source = self.base / "source"
        source.mkdir()
        (source / "a").write_bytes(b"linked")
        os.link(source / "a", source / "b")
        original = checks.snapshot(source)
        self.assertEqual(original["hardlink_groups"], [["a", "b"]])
        destination = self.base / "destination"
        shutil.copytree(source, destination)
        copied = checks.snapshot(destination)
        report = checks.verify_clone(original, copied, baseline=copied)
        self.assertFalse(report["strict_equal"])
        self.assertTrue(report["independent_clone"])
        self.assertTrue(report["baseline_equivalent"])
        self.assertEqual(report["adjudication"], "matches_baseline_with_losses")
        self.assertIn("hardlink_groups", {row["field"] for row in report["baseline_losses"]})
        self.assertEqual(checks.verify_clone(original, original)["shared_source_inodes"], ["", "a", "b"])
        unrelated = self.base / "unrelated"
        os.link(source / "a", unrelated)
        self.assertEqual(checks.verify_clone(original, checks.snapshot(unrelated))["shared_source_inodes"], [""])

    def test_clone_rejects_hardlinked_symlink(self):
        source = self.base / "source-link"
        destination = self.base / "destination-link"
        source.symlink_to("absent-target")
        os.link(source, destination, follow_symlinks=False)
        original, copied = checks.snapshot(source), checks.snapshot(destination)
        self.assertEqual(original["entries"][""]["kind"], "symlink")
        self.assertEqual(original["entries"][""]["device_inode"], copied["entries"][""]["device_inode"])
        self.assertTrue(checks.compare(original, copied)["strict_equal"])
        result = checks.verify_clone(original, copied)
        self.assertFalse(result["independent_clone"])
        self.assertEqual(result["shared_source_inodes"], [""])

    def test_symlink_hardlink_topology_preserved_and_split(self):
        root = self.base / "links"
        root.mkdir()
        first, alias = root / "first", root / "alias"
        first.symlink_to("absent-target")
        os.link(first, alias, follow_symlinks=False)
        before = checks.snapshot(root)
        self.assertEqual(before["hardlink_groups"], [["alias", "first"]])
        preserved = checks.snapshot(root)
        self.assertTrue(checks.compare(before, preserved)["strict_equal"])
        alias.unlink()
        alias.symlink_to("absent-target")
        for name, path in (("alias", alias), ("", root)):
            row = before["entries"][name]
            os.utime(path, ns=(row["atime_ns"], row["mtime_ns"]), follow_symlinks=False)
        split = checks.snapshot(root)
        self.assertNotEqual(split["entries"]["alias"]["device_inode"],
                            split["entries"]["first"]["device_inode"])
        result = checks.compare(before, split)
        self.assertFalse(result["strict_equal"])
        self.assertEqual({loss["field"] for loss in result["candidate_losses"]}, {"hardlink_groups"})

    def test_xattr_loss_is_reported_including_resource_fork_on_macos(self):
        path = self.base / "file"
        path.write_bytes(b"data fork")
        name = b"com.apple.ResourceFork" if sys.platform == "darwin" else b"user.stallionfs-test"
        value = b"resource\0fork\xff"
        if hasattr(os, "setxattr"):
            try:
                os.setxattr(path, name, value)
            except OSError as exc:
                if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                    self.skipTest("Fixture filesystem does not support xattrs")
                raise
        elif sys.platform == "darwin":
            libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
            libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p,
                                     ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
            libc.setxattr.restype = ctypes.c_int
            if libc.setxattr(os.fsencode(path), name, value, len(value), 0, 0):
                error = ctypes.get_errno()
                if error in {errno.ENOTSUP, errno.EOPNOTSUPP}:
                    self.skipTest("Fixture filesystem does not support xattrs")
                raise OSError(error, os.strerror(error))
        else:
            self.skipTest("No xattr setter on this platform")
        original = checks.snapshot(path)
        self.assertEqual(original["entries"][""]["xattrs"][name.hex()], value.hex())
        copied = self.base / "copy"
        shutil.copyfile(path, copied)
        result = checks.compare(original, checks.snapshot(copied))
        self.assertIn("xattrs", {row["field"] for row in result["candidate_losses"]})

    def test_sparse_observations_do_not_claim_physical_sharing(self):
        sparse, dense = self.base / "sparse", self.base / "dense"
        with sparse.open("wb") as stream:
            stream.write(b"x")
            stream.seek(8 * 1024 * 1024 - 1)
            stream.write(b"y")
        with sparse.open("rb") as source, dense.open("wb") as destination:
            shutil.copyfileobj(source, destination, 1024 * 1024)
        original, copied = checks.snapshot(sparse), checks.snapshot(dense)
        self.assertEqual(original["entries"][""]["sha256"], copied["entries"][""]["sha256"])
        report = checks.compare(original, copied)
        if original["entries"][""]["allocated_bytes"] == copied["entries"][""]["allocated_bytes"] and original["entries"][""]["holes"] == copied["entries"][""]["holes"]:
            self.assertEqual(report["sparse_observation_differences"], [])
        else:
            self.assertTrue(report["sparse_observation_differences"])
        left, right = original["entries"][""]["holes"]["ranges"], copied["entries"][""]["holes"]["ranges"]
        self.assertIs(report["sparse_preserved"], None if left is None or right is None else left == right)
        self.assertIn("Not measured", original["physical_sharing"])

    def test_equal_allocation_observations_do_not_establish_sharing(self):
        source, destination = self.base / "source", self.base / "destination"
        source.write_bytes(b"data")
        destination.write_bytes(b"data")
        for ranges in ([], [[1, 3]], None):
            with self.subTest(ranges=ranges):
                holes = {"ranges": ranges, "unavailable": "unsupported" if ranges is None else None}
                with mock.patch.object(checks, "_holes", return_value=holes):
                    original, copied = checks.snapshot(source), checks.snapshot(destination)
                copied["entries"][""]["allocated_bytes"] = original["entries"][""]["allocated_bytes"]
                report = checks.compare(original, copied)
                self.assertEqual(report["sparse_observation_differences"], [])
                self.assertIs(report["sparse_preserved"], None if ranges is None else True)
                sharing = checks.clone_sharing(original, copied)
                self.assertIsNone(sharing["full_data_stream_sharing"])
                self.assertEqual(sharing["counts"]["unknown"], 1)
                for observed in (original, copied):
                    self.assertIn("Not measured", observed["physical_sharing"])

    def test_sparse_gate_unknown_and_loss_remain_separate_from_allocation(self):
        path = self.base / "file"
        path.write_bytes(b"data")
        original = checks.snapshot(path)
        original["entries"][""]["holes"] = {"ranges": [[1, 3]], "unavailable": None}
        changed = deepcopy(original)
        changed["entries"][""]["allocated_bytes"] += 4096
        self.assertTrue(checks.compare(original, changed)["sparse_preserved"])
        changed["entries"][""]["holes"]["ranges"] = []
        report = checks.compare(original, changed, baseline=changed)
        self.assertFalse(report["sparse_preserved"])
        self.assertTrue(report["baseline_equivalent"])
        self.assertFalse(report["baseline_sparse_preserved"])
        self.assertTrue(report["candidate_vs_baseline_sparse_preserved"])
        changed["entries"][""]["holes"] = {"ranges": None, "unavailable": "unsupported"}
        self.assertIsNone(checks.compare(original, changed)["sparse_preserved"])
        self.assertFalse(checks.verify_source(original, changed)["unchanged"])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL fixture")
    def test_acl_loss_is_reported_independently_of_xattrs(self):
        path, copied = self.base / "acl-file", self.base / "copy"
        path.write_bytes(b"data")
        subprocess.run(["/bin/chmod", "+a", "everyone allow read", str(path)], check=True, capture_output=True)
        original = checks.snapshot(path)
        self.assertIsNone(original["entries"][""]["acl"]["unavailable"])
        self.assertIsNotNone(original["entries"][""]["acl"]["text_hex"])
        shutil.copyfile(path, copied)
        report = checks.compare(original, checks.snapshot(copied))
        self.assertIn("acl", {row["field"] for row in report["candidate_losses"]})

    def test_acl_null_errors_and_allocations_fail_closed(self):
        api = mock.Mock()
        api.acl_free.return_value = 0
        with mock.patch.object(checks.sys, "platform", "darwin"), mock.patch.object(checks, "_darwin_metadata_api", return_value=api):
            def absent(_path, _kind):
                ctypes.set_errno(errno.ENOENT)
                return None
            api.acl_get_link_np.side_effect = absent
            self.assertEqual(checks._acl(b"fixture"), {"text_hex": None, "unavailable": None})
            api.acl_get_link_np.side_effect = None
            api.acl_get_link_np.return_value = None
            with self.assertRaises(OSError) as raised:
                checks._acl(b"fixture")
            self.assertEqual(raised.exception.errno, errno.EIO)
            api.acl_get_link_np.return_value = 123
            api.acl_to_text.return_value = None
            with self.assertRaises(OSError):
                checks._acl(b"fixture")
            api.acl_free.assert_called_once_with(123)
            api.acl_free.reset_mock()
            text = ctypes.create_string_buffer(b"acl text")
            def serialize(_acl, length):
                ctypes.cast(length, ctypes.POINTER(ctypes.c_ssize_t))[0] = 8
                return ctypes.addressof(text)
            api.acl_to_text.side_effect = serialize
            self.assertEqual(checks._acl(b"fixture")["text_hex"], b"acl text".hex())
            self.assertEqual(api.acl_free.call_args_list, [mock.call(ctypes.addressof(text)), mock.call(123)])

    def test_unavailable_acl_cannot_pass_and_metadata_loss_is_explicit(self):
        path = self.base / "file"
        path.write_bytes(b"data")
        original = checks.snapshot(path)
        for field in ("mode", "uid", "gid", "mtime_ns", "flags"):
            changed = deepcopy(original)
            changed["entries"][""][field] = 999
            report = checks.compare(original, changed)
            self.assertFalse(report["strict_equal"])
            self.assertIn(field, {row["field"] for row in report["candidate_losses"]})
        unavailable = {"text_hex": None, "unavailable": "unsupported"}
        with mock.patch.object(checks, "_acl", return_value=unavailable):
            unverified = checks.snapshot(path)
        report = checks.compare(unverified, unverified, baseline=unverified)
        self.assertFalse(report["strict_equal"])
        self.assertFalse(report["baseline_equivalent"])
        self.assertEqual(report["adjudication"], "unverifiable_metadata")
        self.assertIn("acl", report["unavailable_fields"]["actual"])

    def test_unsupported_type_and_metadata_permission_fail_closed(self):
        path = self.base / "file"
        path.write_bytes(b"data")
        with mock.patch.object(checks, "_xattrs", side_effect=PermissionError(errno.EACCES, "denied")):
            with self.assertRaises(PermissionError):
                checks.snapshot(path)
        if hasattr(os, "mkfifo"):
            fifo = self.base / "pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "Unsupported"):
                checks.snapshot(fifo)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO fixture")
    def test_special_metadata_requires_opt_in_and_never_opens_the_entry(self):
        fifo = self.base / "pipe\nname"
        os.mkfifo(fifo, 0o640)
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            checks.snapshot(fifo)
        with mock.patch.object(checks.os, "open", side_effect=AssertionError("Special entry opened")):
            original = checks.snapshot(fifo, allow_special=True)
            after = checks.snapshot(fifo, allow_special=True)
        row = original["entries"][""]
        self.assertEqual((row["kind"], row["special_type"], row["rdev"]), ("special", stat.S_IFIFO, fifo.lstat().st_rdev))
        self.assertNotIn("sha256", row)
        self.assertTrue(checks.verify_source(original, after)["unchanged"])
        for field, value in (("special_type", stat.S_IFSOCK), ("rdev", row["rdev"] + 1)):
            changed = deepcopy(original)
            changed["entries"][""][field] = value
            self.assertFalse(checks.verify_source(original, changed)["unchanged"])
        fifo.chmod(0o600)
        self.assertFalse(checks.verify_source(original, checks.snapshot(fifo, allow_special=True))["unchanged"])


if __name__ == "__main__":
    unittest.main()
