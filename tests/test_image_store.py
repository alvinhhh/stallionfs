"""Real disk-image lifecycle checks; enable with STALLIONFS_TEST_IMAGES=1."""
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

from stallionfs.core import StallionError, Store, git, read_json, remove_tree, write_json


class ImageRecoveryTests(unittest.TestCase):
    def test_staging_retains_attached_or_uninspectable_image(self):
        from stallionfs import images
        for state in ({"device": "/dev/disk999", "mountpoint": None}, OSError("inspection failed")):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as temporary:
                store = Store(Path(temporary) / "store")
                options = {"side_effect": state} if isinstance(state, OSError) else {"return_value": state}
                with patch.object(images, "mounted", **options):
                    with self.assertRaises((StallionError, OSError)):
                        with store.staging() as stage:
                            image = stage / "workspace.sparseimage"
                            image.write_bytes(b"keep image")
                self.assertEqual(image.read_bytes(), b"keep image")

    def test_interrupted_marker_write_is_retryable_and_never_replaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "ready.json"
            def interrupted(value, stream, **options):
                stream.write('{"format":')
                raise OSError("out of space while writing marker")
            with patch("stallionfs.core.json.dump", side_effect=interrupted):
                with self.assertRaises(OSError):
                    write_json(marker, {"id": "original"})
            self.assertFalse(marker.exists())
            write_json(marker, {"id": "original"})
            with self.assertRaises(FileExistsError):
                write_json(marker, {"id": "replacement"})
            self.assertEqual(read_json(marker)["id"], "original")
            self.assertEqual(list(marker.parent.iterdir()), [marker])


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("STALLIONFS_TEST_IMAGES") == "1",
                     "requires macOS disk-image access and explicit test selection")
class ImageStoreTests(unittest.TestCase):
    def test_lifecycle_and_interrupted_mount(self):
        from stallionfs import images
        # Resolve /var and /tmp aliases before comparing native mount paths.
        base = Path(tempfile.mkdtemp(prefix="stallionfs-image-test-")).resolve()
        store = Store(base / "store")
        try:
            source = base / "source"
            source.mkdir()
            git(source, "init", "-b", "main")
            (source / "file").write_bytes(b"original\n")
            git(source, "add", ".")
            git(source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-m", "fixture")
            seed = store.prepare(source, key="image-test", image_size=1)
            self.assertTrue(store.prepare(source, key="image-test", image_size=1)["cached"])
            with ThreadPoolExecutor(max_workers=2) as pool:
                workspaces = list(pool.map(lambda _: store.create(seed["id"]), range(2)))
            first, second = workspaces
            first_repo, second_repo = Path(first["path"]), Path(second["path"])
            (first_repo / "file").write_bytes(b"edited\n")
            self.assertEqual((second_repo / "file").read_bytes(), b"original\n")
            self.assertEqual((source / "file").read_bytes(), b"original\n")
            with (first_repo / "file").open("rb"):
                with self.assertRaises((StallionError, OSError)):
                    store.move(first["id"])
                self.assertTrue(first_repo.is_dir())
            store.unmount(first["id"])
            self.assertFalse(first_repo.exists())
            self.assertEqual(Path(store.mount(first["id"])["path"]), first_repo)
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            store.move(first["id"])
            self.assertEqual(Path(store.move(first["id"], restore=True)["path"]), first_repo)
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")

            attach = images.attach
            def interrupted(image, point):
                attach(image, point)
                raise OSError("interrupted after successful attachment")
            with patch.object(images, "attach", side_effect=interrupted):
                with self.assertRaisesRegex(StallionError, "retained"):
                    store.create(seed["id"])
            retained = next(x for x in store.list() if x["id"] not in {first["id"], second["id"]})
            recovered = store.mount(retained["id"])
            self.assertEqual((Path(recovered["path"]) / "file").read_bytes(), b"original\n")
            with self.assertRaisesRegex(StallionError, "mounted"):
                remove_tree(store.root / "workspaces" / first["id"])
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            store.forget(seed["id"], yes=True)
            store.unmount(first["id"])
            store.mount(first["id"])
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            for item in store.list():
                store.move(item["id"])
            self.assertEqual(len(store.gc(older_than=0)), 3)
            self.assertEqual(len(store.gc(older_than=0, yes=True)), 3)
            self.assertEqual(store.list("trash"), [])
        finally:
            # Preserve backing files if a test ever fails to detach a volume.
            for item in store.list():
                if item.get("backend") == "image":
                    store.unmount(item["id"])
            remove_tree(base)


if __name__ == "__main__":
    unittest.main()
