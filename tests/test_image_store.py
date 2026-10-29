"""Real disk-image lifecycle checks; enable with STALLIONFS_TEST_IMAGES=1."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
import errno
import os
from pathlib import Path
import re
import sys
import subprocess
import tempfile
import traceback
import unittest
from unittest.mock import patch

from stallionfs.core import StallionError, Store, git, read_json, remove_tree, write_json
if __package__:
    from .image_failure_diagnostics import failure_scope
else:
    from image_failure_diagnostics import failure_scope


class ImageFixture:
    """Explicit operation ownership; a failed detach is never retried by cleanup."""
    def __init__(self, store, base):
        self.store, self.base = store, base
        self.failed = set()
        self.unknown = False

    def call(self, method, *args, workspace=None, expected=False, stage='body', **kwargs):
        kind = 'trash' if kwargs.get('restore') else 'workspaces'
        image = self.store.root / kind / workspace / 'workspace.sparseimage' if workspace else None
        point = image.parent / 'volume' if image else None
        with failure_scope(self.base, image, workspace=workspace, mountpoint=point, stage=stage, expected=expected == 'busy'):
            try:
                return method(*args, **kwargs)
            except Exception as error:
                if not (expected and isinstance(error, (StallionError, OSError))):
                    if workspace:
                        self.failed.add(workspace)
                    else:
                        self.unknown = True
                raise

    def cleanup(self):
        errors = []
        if self.unknown:
            return errors  # No identity for the failed operation: retain without guessing.
        try:
            if self.store.root != self.base / 'store':
                raise StallionError('Uncertain fixture ownership')
            items = self.store.list()
            seen = set()
            for item in items:
                identifier = item.get('id')
                if (not isinstance(identifier, str) or not re.fullmatch('[0-9a-f]{32}', identifier) or
                        identifier in seen or item.get('backend') != 'image' or
                        item.get('path') != str(self.store.root / 'workspaces' / identifier / 'volume/repo')):
                    raise StallionError('Uncertain cleanup ownership; fixture retained')
                seen.add(identifier)
        except Exception as error:
            return [(error, error.__traceback__)]
        for item in items:
            if item['id'] in self.failed:
                continue
            try:
                self.call(self.store.unmount, item['id'], workspace=item['id'], stage='cleanup')
            except Exception as error:
                errors.append((error, error.__traceback__))
        return errors


def _cleanup_notes(primary, errors, base):
    try:
        primary.add_note(f'Image fixture failure at {base}; no further cleanup will run')
        for error, trace in errors:
            primary.add_note('Separate cleanup failure:\n' + ''.join(traceback.format_exception(type(error), error, trace)))
    except Exception:
        pass  # Reporting cannot replace the body or cleanup exception.


@contextmanager
def image_fixture(store, base):
    fixture = ImageFixture(store, base)
    try:
        yield fixture
    except BaseException as primary:
        # Interrupts propagate without starting further destructive cleanup.
        errors = fixture.cleanup() if isinstance(primary, Exception) else []
        _cleanup_notes(primary, errors, base)
        raise
    else:
        errors = fixture.cleanup()
        if errors:
            primary, trace = errors[0]
            _cleanup_notes(primary, errors[1:], base)
            raise primary.with_traceback(trace)
        if fixture.failed or fixture.unknown:
            raise StallionError(f'Unresolved image operation; entire fixture retained at {base}')
        # Only successful body AND successful owned cleanup can authorize removal.
        try:
            remove_tree(base)
        except BaseException as error:
            _cleanup_notes(error, [], base)
            raise


class ImageRecoveryTests(unittest.TestCase):
    def test_image_command_preserves_machine_status(self):
        from stallionfs import images
        result = subprocess.CompletedProcess(['owned-command'], errno.EBUSY, b'', b'localized busy message')
        with patch.object(images.subprocess, 'run', return_value=result):
            with self.assertRaises(StallionError) as raised:
                images._command('owned-command')
        self.assertEqual(raised.exception.returncode, errno.EBUSY)
        self.assertIn('localized busy message', str(raised.exception))

    def test_detach_completes_only_verified_unmounted_busy_attachment_once(self):
        from stallionfs import images, _scan
        cases = ('success', 'still-mounted', 'changed-device', 'changed-image', 'inspection-error',
                 'mount-inventory-error', 'unrelated-mountpoint', 'volume-still-mounted',
                 'unrelated-volume', 'already-detached', 'second-busy', 'still-attached',
                 'nonbusy', 'unstructured-error', 'interrupt', 'first-success')
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                image, point = base / 'workspace.sparseimage', base / 'volume'
                image.write_bytes(b'owned image')
                image.chmod(0o600)
                point.mkdir(mode=0o700)
                initial = dict(image=str(image), device='/dev/disk999', mountpoint=str(point),
                               volume_device='/dev/disk1000s1')
                remaining = {**initial, 'mountpoint': None, 'volume_device': None}
                first = StallionError('first detach failed')
                first.returncode = errno.EPERM if case == 'nonbusy' else errno.EBUSY
                if case == 'unstructured-error':
                    first = StallionError('no machine status')
                if case == 'interrupt':
                    first = KeyboardInterrupt()
                second = StallionError('second detach failed')
                second.returncode = errno.EBUSY
                inspection = OSError('inspection failed')
                if case == 'still-mounted':
                    remaining = initial
                elif case == 'changed-device':
                    remaining = {**remaining, 'device': '/dev/disk998'}
                elif case == 'inspection-error':
                    remaining = inspection
                elif case == 'already-detached':
                    remaining = None
                states = [initial, remaining, remaining if case == 'still-attached' else None]
                if case == 'first-success':
                    states = [initial, None]
                commands = []
                def command(*args):
                    commands.append(args)
                    if len(commands) == 1:
                        if case == 'changed-image':
                            image.rename(base / 'original.sparseimage')
                            image.write_bytes(b'replacement image')
                            image.chmod(0o600)
                        if case != 'first-success':
                            raise first
                    elif case == 'second-busy':
                        raise second
                    return b''
                native = []
                if case == 'volume-still-mounted':
                    native = [dict(device=initial['volume_device'], path=str(base / 'elsewhere'))]
                elif case == 'unrelated-volume':
                    native = [dict(device='/dev/disk998s1', path=str(point))]
                options = {'side_effect': inspection} if case == 'mount-inventory-error' else {'return_value': native}
                with patch.object(images, 'mounted', side_effect=states), \
                     patch.object(images, '_command', side_effect=command), \
                     patch.object(images.os.path, 'ismount', return_value=case == 'unrelated-mountpoint'), \
                     patch.object(_scan, 'mounts', **options):
                    if case in ('success', 'first-success'):
                        images.detach(image, point)
                    else:
                        with self.assertRaises(KeyboardInterrupt if case == 'interrupt' else StallionError) as raised:
                            images.detach(image, point)
                        if case == 'still-attached':
                            self.assertIn('remains attached', str(raised.exception))
                        else:
                            self.assertIs(raised.exception, second if case == 'second-busy' else first)
                        if case in ('inspection-error', 'mount-inventory-error'):
                            self.assertIs(raised.exception.__cause__, inspection)
                        if case == 'second-busy':
                            self.assertIs(raised.exception.__context__, first)
                attempts = 2 if case in ('success', 'second-busy', 'still-attached') else 1
                self.assertEqual(commands, [('/usr/bin/hdiutil', 'detach', initial['device'])] * attempts)
                self.assertTrue(image.exists())

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
    def test_snapshot_rollback_and_protected_retirement(self):
        from stallionfs import lifecycle
        base = Path(tempfile.mkdtemp(prefix="stallionfs-image-lifecycle-test-")).resolve()
        store = Store(base / "store")
        with image_fixture(store, base) as fixture:
            source = base / "source"
            source.mkdir()
            git(source, "init", "-b", "main")
            (source / "file").write_text("original\n")
            git(source, "add", ".")
            git(source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-m", "Fixture")
            seed = fixture.call(store.prepare, source, key="image-lifecycle", image_size=1)
            workspace = fixture.call(store.create, seed["id"])
            value, repo = workspace["id"], Path(workspace["path"])
            (repo / "file").write_text("snapshot state\n")
            (repo / "untracked").write_text("preserved\n")
            git(repo, "config", "--local", "include.path", str(base / "external-config"))
            with self.assertRaisesRegex(StallionError, "external worktree"):
                fixture.call(store.snapshot, value, workspace=value, expected=True)
            git(repo, "config", "--local", "--unset", "include.path")
            fixture.call(store.unmount, value, workspace=value)
            closed_snapshot = fixture.call(store.snapshot, value, workspace=value)
            self.assertFalse(repo.exists())
            fixture.call(store.mount, value, workspace=value)
            snapshot = fixture.call(store.snapshot, value, workspace=value)
            self.assertEqual((repo / "file").read_text(), "snapshot state\n")
            (repo / "file").write_text("later state\n")
            result = fixture.call(store.rollback, value, snapshot["id"], workspace=value)
            self.assertEqual((repo / "file").read_text(), "snapshot state\n")
            self.assertEqual((repo / "untracked").read_text(), "preserved\n")
            self.assertTrue((store.root / "recovery" / result["recovery"] / "workspace.sparseimage").exists())
            fixture.call(store.enroll, value, workspace=value)
            closed = fixture.call(store.close, value, quiescent=True, workspace=value)
            closed["closed_at"] -= lifecycle.STALE_SECONDS + 10
            lifecycle.replace_json(store._state(value), closed)
            fixture.call(store.cleanup_config, enabled=True)
            retired = fixture.call(store.cleanup, apply=True)
            self.assertEqual(retired["retired"], [value])
            self.assertEqual(fixture.call(store.gc, older_than=0, yes=True), [])
            restored = fixture.call(store.move, value, restore=True, workspace=value)
            self.assertEqual((Path(restored["path"]) / "file").read_text(), "snapshot state\n")
            self.assertEqual(read_json(store._state(value))["status"], "open")

    def test_lifecycle_and_interrupted_mount(self):
        from stallionfs import images
        # Resolve /var and /tmp aliases before comparing native mount paths.
        base = Path(tempfile.mkdtemp(prefix="stallionfs-image-test-")).resolve()
        store = Store(base / "store")
        with image_fixture(store, base) as fixture:
            source = base / "source"
            source.mkdir()
            git(source, "init", "-b", "main")
            (source / "file").write_bytes(b"original\n")
            git(source, "add", ".")
            git(source, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                "commit", "-m", "fixture")
            seed = fixture.call(store.prepare, source, key="image-test", image_size=1)
            self.assertTrue(fixture.call(store.prepare, source, key="image-test", image_size=1)["cached"])
            with ThreadPoolExecutor(max_workers=2) as pool:
                workspaces = list(pool.map(lambda _: fixture.call(store.create, seed["id"]), range(2)))
            first, second = workspaces
            first_repo, second_repo = Path(first["path"]), Path(second["path"])
            (first_repo / "file").write_bytes(b"edited\n")
            self.assertEqual((second_repo / "file").read_bytes(), b"original\n")
            self.assertEqual((source / "file").read_bytes(), b"original\n")
            with (first_repo / "file").open("rb"):
                with self.assertRaises((StallionError, OSError)):
                    fixture.call(store.move, first["id"], workspace=first["id"], expected='busy')
                self.assertTrue(first_repo.is_dir())
            fixture.call(store.unmount, first["id"], workspace=first["id"])
            self.assertFalse(first_repo.exists())
            self.assertEqual(Path(fixture.call(store.mount, first["id"], workspace=first["id"])["path"]), first_repo)
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            fixture.call(store.move, first["id"], workspace=first["id"])
            self.assertEqual(Path(fixture.call(store.move, first["id"], restore=True, workspace=first["id"])["path"]), first_repo)
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")

            attach = images.attach
            def interrupted(image, point):
                attach(image, point)
                raise OSError("interrupted after successful attachment")
            with patch.object(images, "attach", side_effect=interrupted):
                with self.assertRaisesRegex(StallionError, "retained"):
                    fixture.call(store.create, seed["id"], expected=True)
            retained = next(x for x in fixture.call(store.list) if x["id"] not in {first["id"], second["id"]})
            recovered = fixture.call(store.mount, retained["id"], workspace=retained["id"])
            self.assertEqual((Path(recovered["path"]) / "file").read_bytes(), b"original\n")
            with self.assertRaisesRegex(StallionError, "mounted"):
                remove_tree(store.root / "workspaces" / first["id"])
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            fixture.call(store.forget, seed["id"], yes=True)
            fixture.call(store.unmount, first["id"], workspace=first["id"])
            fixture.call(store.mount, first["id"], workspace=first["id"])
            self.assertEqual((first_repo / "file").read_bytes(), b"edited\n")
            for item in fixture.call(store.list):
                fixture.call(store.move, item["id"], workspace=item["id"])
            self.assertEqual(len(fixture.call(store.gc, older_than=0)), 3)
            self.assertEqual(len(fixture.call(store.gc, older_than=0, yes=True)), 3)
            self.assertEqual(fixture.call(store.list, "trash"), [])


if __name__ == "__main__":
    unittest.main()
