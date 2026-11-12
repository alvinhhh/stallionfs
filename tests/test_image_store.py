"""Real disk-image lifecycle checks; enable with STALLIONFS_TEST_IMAGES=1."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, nullcontext
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
    from .image_failure_diagnostics import failure_scope, observe_detach, detach_observation_selection, observe_seed_create
else:
    from image_failure_diagnostics import failure_scope, observe_detach, detach_observation_selection, observe_seed_create


class ImageFixture:
    """Explicit operation ownership; a failed detach is never retried by cleanup."""
    def __init__(self, store, base):
        self.store, self.base = store, base
        self.failed = set()
        self.unknown = False
        self.cleanup_observation = None

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

    def cleanup(self, *, observe=False):
        selected, self.cleanup_observation = (self.cleanup_observation if observe else None), None
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
                with observe_detach() if item['id'] == selected else nullcontext():
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
        errors = fixture.cleanup(observe=True)
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

    def test_detach_uses_one_unchanged_target_and_preserves_every_command_error(self):
        from stallionfs import images
        for status in (1, 5, 16, 64, None, 'interrupt'):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                image, point = base / 'workspace.sparseimage', base / 'volume'
                image.write_bytes(b'owned image'); image.chmod(0o600)
                current = dict(image=str(image), device='/dev/disk999', mountpoint=str(point),
                               volume_device='/dev/disk1000s1')
                primary = KeyboardInterrupt() if status == 'interrupt' else StallionError('eject failed')
                if isinstance(status, int):
                    primary.returncode = status
                with patch.object(images, 'mounted', return_value=current) as inspect, \
                        patch.object(images, '_command', side_effect=primary) as command:
                    with self.assertRaises(type(primary)) as raised:
                        images.detach(image, point)
                self.assertIs(raised.exception, primary)
                self.assertEqual(inspect.call_count, 2)
                command.assert_called_once_with('/usr/sbin/diskutil', 'eject', '/dev/disk999')
                self.assertEqual(image.read_bytes(), b'owned image')

    def test_detach_refuses_changed_mapping_or_backing_before_command(self):
        from stallionfs import images
        for change in ('device', 'volume_device', 'mountpoint', 'image', 'missing', 'backing', 'owner'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                image, point = base / 'workspace.sparseimage', base / 'volume'
                image.write_bytes(b'owned image'); image.chmod(0o600)
                current = dict(image=str(image), device='/dev/disk999', mountpoint=str(point),
                               volume_device='/dev/disk1000s1')
                calls = []
                def mounted(_image):
                    calls.append(_image)
                    if len(calls) == 1:
                        return current
                    if change == 'backing':
                        image.rename(base / 'original.sparseimage')
                        image.write_bytes(b'replaced'); image.chmod(0o600)
                        return current
                    if change == 'owner':
                        raise StallionError('attachment belongs to another user')
                    return None if change == 'missing' else dict(current, **{change: 'changed'})
                with patch.object(images, 'mounted', side_effect=mounted), \
                        patch.object(images, '_command') as command:
                    with self.assertRaises(StallionError):
                        images.detach(image, point)
                command.assert_not_called()
                self.assertTrue(image.exists())

    def test_attachment_inventory_requires_explicit_classifiable_records(self):
        from stallionfs import images
        invalid = ({}, {'images': None}, {'images': {}}, {'images': 'bad'},
                   {'images': [None]}, {'images': [{}]}, {'images': [{'image-path': ''}]},
                   {'images': [{'image-path': 'relative.sparseimage'}]},
                   {'images': [{'image-path': '/bad\0path'}]})
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image, point = base / 'workspace.sparseimage', base / 'volume'
            image.write_bytes(b'owned image'); image.chmod(0o600)
            valid = {'images': [dict({'image-path': str(image), 'owner-uid': os.getuid(),
                                     'system-entities': [{'dev-entry': '/dev/disk999'}]})]}
            for inventory in invalid:
                for phase in ('before', 'after'):
                    with self.subTest(inventory=inventory, phase=phase), \
                            patch.object(images, '_plist', side_effect=[inventory] if phase == 'before'
                                         else [valid, valid, inventory]), \
                            patch.object(images, '_command') as command, \
                            patch.object(images.os.path, 'ismount', return_value=False):
                        with self.assertRaises(StallionError):
                            images.detach(image, point)
                        self.assertEqual(command.call_count, int(phase == 'after'))
                        self.assertEqual(image.read_bytes(), b'owned image')
            unrelated = base / 'unrelated.sparseimage'
            unrelated.write_bytes(b'unrelated image'); unrelated.chmod(0o600)
            for inventory in ({'images': []}, {'images': [{'image-path': str(unrelated)}]}):
                with self.subTest(inventory=inventory), patch.object(images, '_plist', return_value=inventory), \
                        patch.object(images, '_command') as command, \
                        patch.object(images.os.path, 'ismount', return_value=False):
                    self.assertIsNone(images.mounted(image))
                    images.detach(image, point)
                    command.assert_not_called()
            for entries in (None, {}, [None], [{}], [{'dev-entry': '/dev/disk999s1'}]):
                bad = {'images': [dict(valid['images'][0], **{'system-entities': entries})]}
                with self.subTest(entries=entries), patch.object(images, '_plist', return_value=bad):
                    with self.assertRaises(StallionError):
                        images.mounted(image)

    def test_inventory_resolves_owned_alias_and_refuses_unclassifiable_paths(self):
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image, point = base / 'workspace.sparseimage', base / 'volume'
            image.write_bytes(b'owned image'); image.chmod(0o600)
            alias = base / 'alias.sparseimage'; alias.symlink_to(image)
            entry = {'image-path': str(alias), 'owner-uid': os.getuid(),
                     'system-entities': [{'dev-entry': '/dev/disk999'}]}
            valid = {'images': [entry]}
            with patch.object(images, '_plist', return_value=valid):
                self.assertEqual(images.mounted(image), dict(image=str(image), device='/dev/disk999',
                                                            mountpoint=None, volume_device=None))
            missing, loop, denied = base / 'missing.sparseimage', base / 'loop.sparseimage', base / 'denied.sparseimage'
            loop.symlink_to(loop)
            denied.symlink_to(image)
            original_lstat = os.lstat
            for recorded in (missing, loop, denied):
                for phase in ('before', 'after'):
                    primary = PermissionError('inventory path is unreadable')
                    def lstat(path, *args, **kwargs):
                        if Path(path) == denied:
                            raise primary
                        return original_lstat(path, *args, **kwargs)
                    unknown = {'images': [dict(entry, **{'image-path': str(recorded)})]}
                    with self.subTest(recorded=recorded.name, phase=phase), \
                            patch.object(images.os, 'lstat', side_effect=lstat), \
                            patch.object(images, '_plist', side_effect=[unknown] if phase == 'before'
                                         else [valid, valid, unknown]), \
                            patch.object(images, '_command') as command, \
                            patch.object(images.os.path, 'ismount', return_value=False):
                        with self.assertRaisesRegex(StallionError, 'Cannot classify') as caught:
                            images.detach(image, point)
                    self.assertEqual(command.call_count, int(phase == 'after'))
                    self.assertIsInstance(caught.exception.__cause__, (OSError, RuntimeError))
                    if recorded == denied:
                        self.assertIs(caught.exception.__cause__, primary)
                    self.assertEqual(image.read_bytes(), b'owned image')

    def test_real_inventory_rejects_owner_change_reordered_target_and_disappearance(self):
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image, point = base / 'workspace.sparseimage', base / 'volume'
            image.write_bytes(b'owned image'); image.chmod(0o600)
            entry = {'image-path': str(image), 'owner-uid': os.getuid(),
                     'system-entities': [{'dev-entry': '/dev/disk999'}, {'dev-entry': '/dev/disk1000'}]}
            initial = {'images': [entry]}
            changes = ({'images': []}, {'images': [entry, entry]},
                       {'images': [dict(entry, **{'owner-uid': os.getuid() + 1})]},
                       {'images': [dict(entry, **{'system-entities': list(reversed(entry['system-entities']))})]})
            for changed in changes:
                with self.subTest(changed=changed), patch.object(images, '_plist', side_effect=[initial, changed]), \
                        patch.object(images, '_command') as command:
                    with self.assertRaises(StallionError):
                        images.detach(image, point)
                command.assert_not_called()
                self.assertEqual(image.read_bytes(), b'owned image')

    def test_eject_success_requires_absence_and_unchanged_backing(self):
        from stallionfs import images
        for case in ('success', 'attached', 'mounted', 'replaced', 'private', 'wrong-point', 'absent-mounted'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                image, point = base / 'workspace.sparseimage', base / 'volume'
                image.write_bytes(b'owned image'); image.chmod(0o600)
                current = dict(image=str(image), device='/dev/disk999', mountpoint=None, volume_device=None)
                if case == 'wrong-point':
                    current['mountpoint'] = str(base / 'other')
                inventory = {'images': [{'image-path': str(image), 'owner-uid': os.getuid(),
                                        'system-entities': [{'dev-entry': '/dev/disk999'}]}]}
                def command(*args):
                    if case == 'replaced':
                        image.rename(base / 'original.sparseimage')
                        image.write_bytes(b'replaced'); image.chmod(0o600)
                    elif case == 'private':
                        image.chmod(0o644)
                    return b''
                if case in ('wrong-point', 'absent-mounted'):
                    context = patch.object(images, 'mounted', return_value=current if case == 'wrong-point' else None)
                else:
                    context = patch.object(images, '_plist', side_effect=[inventory, inventory,
                        inventory if case == 'attached' else {'images': []}])
                with context, patch.object(images, '_command', side_effect=command) as native, \
                        patch.object(images.os.path, 'ismount', return_value=case in ('mounted', 'absent-mounted')):
                    if case == 'success':
                        images.detach(image, point)
                    else:
                        with self.assertRaises(StallionError):
                            images.detach(image, point)
                self.assertEqual(native.call_count, 0 if case in ('wrong-point', 'absent-mounted') else 1)
                self.assertTrue(image.exists())

    def test_build_never_retries_detach_or_loses_primary_recovery_error(self):
        from stallionfs import images
        for failure in ('detach', 'interrupt', 'populate', 'cleanup', 'flush'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as temporary:
                base = Path(temporary).resolve()
                source, image = base / 'source', base / 'workspace.sparseimage'
                source.mkdir(mode=0o700)
                primary = KeyboardInterrupt('eject interrupted') if failure == 'interrupt' else OSError(failure)
                primary.returncode = 64
                recovery = StallionError('cleanup failed')
                def command(*args):
                    if args[1] == 'create':
                        image.write_bytes(b'preserved image'); image.chmod(0o600)
                    elif failure in ('populate', 'cleanup'):
                        raise primary
                    return b''
                detach_error = primary if failure in ('detach', 'interrupt') else recovery if failure == 'cleanup' else None
                with patch.object(images, '_require_supported'), patch('stallionfs.core.validate_tree'), \
                        patch.object(images, '_command', side_effect=command), \
                        patch.object(images, 'attach', side_effect=lambda _image, point: point / 'repo'), \
                        patch.object(images.os, 'chown'), \
                        patch.object(images, 'mounted', return_value={'device': '/dev/disk999'}) as inspect, \
                        patch.object(images, 'detach', side_effect=detach_error) as detach, \
                        patch.object(images, 'flush', side_effect=primary if failure == 'flush' else None) as flush:
                    with self.assertRaises(BaseException) as caught:
                        images.build(source, image, 1)
                detach.assert_called_once()
                self.assertEqual(inspect.call_count, int(failure in ('populate', 'cleanup')))
                self.assertEqual(flush.call_count, int(failure == 'flush'))
                if failure == 'cleanup':
                    self.assertIs(caught.exception.__cause__, primary)
                    self.assertIn('cleanup failed', str(caught.exception))
                    self.assertIn('keep image', str(caught.exception))
                else:
                    self.assertIs(caught.exception, primary)
                self.assertEqual(image.read_bytes(), b'preserved image')

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
        observation = detach_observation_selection()
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
            with observe_seed_create(base):
                seed = fixture.call(store.prepare, source, key="image-lifecycle", image_size=1)
            workspace = fixture.call(store.create, seed["id"])
            value, repo = workspace["id"], Path(workspace["path"])
            (repo / "file").write_text("snapshot state\n")
            (repo / "untracked").write_text("preserved\n")
            git(repo, "config", "--local", "include.path", str(base / "external-config"))
            with self.assertRaisesRegex(StallionError, "external worktree"):
                fixture.call(store.snapshot, value, workspace=value, expected=True)
            git(repo, "config", "--local", "--unset", "include.path")
            with observe_detach() if observation == 'initial-unmount' else nullcontext():
                fixture.call(store.unmount, value, workspace=value)
            with observe_detach() if observation == 'closed-snapshot' else nullcontext():
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
            if observation == 'restored-cleanup':
                fixture.cleanup_observation = value

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
