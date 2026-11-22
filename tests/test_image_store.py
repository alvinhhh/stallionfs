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
import time
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
    def setUp(self):
        from stallionfs import images
        # Synthetic device names; real node admission is covered in test_image_detach.
        self.enterContext(patch.object(images, '_device_identity', return_value=(2, 100, 20, 0o60600)))

    def test_image_command_preserves_machine_status(self):
        from stallionfs import images
        result = subprocess.CompletedProcess(['owned-command'], errno.EBUSY, b'', b'localized busy message')
        with patch.object(images.subprocess, 'run', return_value=result):
            with self.assertRaises(StallionError) as raised:
                images._command('owned-command')
        self.assertEqual(raised.exception.returncode, errno.EBUSY)
        self.assertIn('localized busy message', str(raised.exception))

    def test_image_commands_are_bounded_except_tree_copy(self):
        from stallionfs import images
        result = subprocess.CompletedProcess([], 0, b'', b'')
        with patch.object(images.subprocess, 'run', return_value=result) as run:
            images._command('/usr/bin/hdiutil', 'create', 'x')
            images._command('/usr/sbin/diskutil', 'eject', '/dev/disk9')
            images._command(Path('/usr/bin/ditto'), 'source', 'destination')
        self.assertEqual([call.kwargs['timeout'] for call in run.call_args_list],
                         [images._COMMAND_SECONDS, images._COMMAND_SECONDS, None])

    def test_stuck_image_command_times_out_and_is_reaped(self):
        from stallionfs import images
        started = time.monotonic()
        with patch.object(images, '_COMMAND_SECONDS', 0.2), \
                self.assertRaises(subprocess.TimeoutExpired) as raised:
            images._command('/bin/sleep', '30')
        self.assertLess(time.monotonic() - started, 10)
        self.assertEqual(raised.exception.cmd, ['/bin/sleep', '30'])

    def test_detach_preserves_ineligible_errors_regardless_of_synthetic_returncode(self):
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

    def test_ram_disk_records_are_skipped_but_still_checked_for_ambiguity(self):
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            image = base / 'workspace.sparseimage'
            image.write_bytes(b'owned image'); image.chmod(0o600)
            owned = {'image-path': str(image), 'owner-uid': os.getuid(),
                     'system-entities': [{'dev-entry': '/dev/disk999'}]}
            ram = {'image-path': 'ram://16384', 'owner-uid': 0,
                   'system-entities': [{'dev-entry': '/dev/disk998'}]}
            with patch.object(images, '_plist', return_value={'images': [ram, owned]}):
                self.assertEqual(images._attachments(image), [owned])
            with patch.object(images, '_plist', return_value={'images': [ram]}):
                self.assertEqual(images._attachments(image), [])
            clash = dict(ram, **{'system-entities': [{'dev-entry': '/dev/disk999'}]})
            for record in (clash, dict(ram, **{'image-path': 'ram://'}), dict(ram, **{'image-path': 'ram://1/x'})):
                with self.subTest(record=record), \
                        patch.object(images, '_plist', return_value={'images': [record, owned]}), \
                        self.assertRaises(StallionError):
                    images._attachments(image)

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
                state = images.mounted(image)
                self.assertEqual({key: state[key] for key in ('image', 'device', 'mountpoint', 'volume_device')},
                                 dict(image=str(image), device='/dev/disk999', mountpoint=None, volume_device=None))
                self.assertIsInstance(state['attachment'], bytes)
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
                    return b''
                detach_error = primary if failure in ('detach', 'interrupt') else recovery if failure == 'cleanup' else None
                with patch.object(images, '_require_supported'), patch('stallionfs.core.validate_tree'), \
                        patch('stallionfs.copy', side_effect=primary if failure in ('populate', 'cleanup') else None) as populate, \
                        patch.object(images, '_command', side_effect=command), \
                        patch.object(images, 'attach', side_effect=lambda _image, point: point / 'repo'), \
                        patch.object(images.os, 'chown'), \
                        patch.object(images, 'mounted', return_value={'device': '/dev/disk999'}) as inspect, \
                        patch.object(images, 'detach', side_effect=detach_error) as detach, \
                        patch.object(images, 'flush', side_effect=primary if failure == 'flush' else None) as flush:
                    with self.assertRaises(BaseException) as caught:
                        images.build(source, image, 1)
                populate.assert_called_once()
                self.assertEqual(populate.call_args.kwargs, {'strategy': 'materialized'})
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

    def test_build_preserves_mountpoint_when_recovery_inspection_fails(self):
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            source, image = base / 'source', base / 'seed.sparseimage'
            source.mkdir(mode=0o700)
            primary = OSError('attach failed')

            def create(*args):
                image.write_bytes(b'preserved image')
                image.chmod(0o600)

            with patch.object(images, '_require_supported'), patch('stallionfs.core.validate_tree'), \
                    patch.object(images, '_command', side_effect=create), \
                    patch.object(images, 'attach', side_effect=primary) as attach, \
                    patch.object(images, 'mounted', side_effect=OSError('inventory unavailable')) as inspect, \
                    patch.object(images, 'detach') as detach, patch('stallionfs.copy') as populate:
                with self.assertRaises(StallionError) as caught:
                    images.build(source, image, 1)
            point = attach.call_args.args[1]
            self.assertIs(caught.exception.__cause__, primary)
            self.assertIn(f'keep image {image} and mount {point}', str(caught.exception))
            self.assertIn('inventory unavailable', str(caught.exception))
            self.assertTrue(point.is_dir())
            self.assertEqual(image.read_bytes(), b'preserved image')
            inspect.assert_called_once_with(image)
            detach.assert_not_called()
            populate.assert_not_called()

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

    def image_initialization_fixture(self):
        from stallionfs import images
        path = Path(self.enterContext(tempfile.TemporaryDirectory()))
        repo = path / 'volume' / 'repo'
        repo.mkdir(parents=True)
        git(repo, 'init', '--template=', '-b', 'main')
        (repo / 'file').write_text('seed\n')
        git(repo, 'add', '.')
        git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Seed')
        commit = git(repo, 'rev-parse', 'HEAD')
        git(repo, 'checkout', '--detach', commit)
        workspace = 'a' * 32
        metadata = dict(id=workspace, backend='image', branch=f'stallionfs/test-{workspace}', commit=commit)
        attach = self.enterContext(patch.object(images, 'attach', return_value=repo))
        return Store.__new__(Store), path, repo, metadata, attach

    def test_mount_resumes_branch_created_before_head_lock_failure(self):
        store, path, repo, metadata, _ = self.image_initialization_fixture()
        lock = repo / '.git' / 'HEAD.lock'
        lock.write_bytes(b'test-owned lock')
        ref = f"refs/heads/{metadata['branch']}"
        with self.assertRaisesRegex(StallionError, 'retained; retry with mount'):
            store._mount(path, metadata)
        self.assertEqual(lock.read_bytes(), b'test-owned lock')
        self.assertEqual(git(repo, 'branch', '--show-current'), '')
        self.assertEqual(git(repo, 'rev-parse', '--verify', ref), metadata['commit'])
        self.assertFalse((path / 'ready.json').exists())

        lock.unlink()
        (repo / 'file').write_text('local edit\n')
        self.assertEqual(store._mount(path, metadata)['path'], str(repo))
        self.assertEqual(git(repo, 'symbolic-ref', 'HEAD'), ref)
        self.assertEqual((repo / 'file').read_text(), 'local edit\n')
        self.assertEqual(read_json(path / 'ready.json'), {'format': 1, 'id': metadata['id']})

    def test_mount_retries_ready_marker_fsync_enospc_without_resetting_branch(self):
        store, path, repo, metadata, _ = self.image_initialization_fixture()
        marker = path / 'ready.json'
        fault = OSError(errno.ENOSPC, 'marker full')

        def write_ready(target, value):
            self.assertEqual(target, marker)
            with patch('stallionfs.core.os.fsync', side_effect=fault):
                write_json(target, value)

        with patch('stallionfs.core.write_json', side_effect=write_ready):
            with self.assertRaisesRegex(StallionError, 'retained; retry with mount') as raised:
                store._mount(path, metadata)
        self.assertIs(raised.exception.__cause__, fault)
        self.assertFalse(marker.exists())
        self.assertEqual(list(path.glob('.ready.json.*')), [])
        self.assertEqual(git(repo, 'branch', '--show-current'), metadata['branch'])

        (repo / 'file').write_text('workspace edit\n')
        git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-am', 'Workspace')
        advanced = git(repo, 'rev-parse', 'HEAD')
        store._mount(path, metadata)
        self.assertNotEqual(advanced, metadata['commit'])
        self.assertEqual(git(repo, 'rev-parse', 'HEAD'), advanced)
        self.assertEqual((repo / 'file').read_text(), 'workspace edit\n')
        self.assertEqual(read_json(marker), {'format': 1, 'id': metadata['id']})

    def test_mount_refuses_conflicting_branch_without_rewriting_it(self):
        store, path, repo, metadata, _ = self.image_initialization_fixture()
        branch = metadata['branch']
        git(repo, 'checkout', '-b', branch)
        git(repo, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit',
            '--allow-empty', '-m', 'Different branch tip')
        unexpected = git(repo, 'rev-parse', 'HEAD')
        git(repo, 'checkout', '--detach', metadata['commit'])
        with self.assertRaisesRegex(StallionError, 'unexpected workspace branch'):
            store._mount(path, metadata)
        self.assertEqual(git(repo, 'branch', '--show-current'), '')
        self.assertEqual(git(repo, 'rev-parse', f'refs/heads/{branch}'), unexpected)
        self.assertFalse((path / 'ready.json').exists())

    def test_mount_refuses_dangling_workspace_ref_before_checkout(self):
        store, path, repo, metadata, _ = self.image_initialization_fixture()
        ref = f"refs/heads/{metadata['branch']}"
        target = 'refs/heads/missing'
        git(repo, 'symbolic-ref', ref, target)
        with self.assertRaisesRegex(StallionError, 'unexpected workspace branch'):
            store._mount(path, metadata)
        self.assertEqual(git(repo, 'symbolic-ref', '--no-recurse', ref), target)
        self.assertEqual(git(repo, 'for-each-ref', '--format=%(refname)', '--', target), '')
        self.assertEqual(git(repo, 'branch', '--show-current'), '')
        self.assertEqual(git(repo, 'rev-parse', 'HEAD'), metadata['commit'])
        self.assertFalse((path / 'ready.json').exists())

    def test_mount_refuses_indirect_head_to_workspace_branch(self):
        store, path, repo, metadata, _ = self.image_initialization_fixture()
        ref = f"refs/heads/{metadata['branch']}"
        alias = 'refs/heads/alias'
        git(repo, 'branch', metadata['branch'], metadata['commit'])
        git(repo, 'symbolic-ref', alias, ref)
        git(repo, 'symbolic-ref', 'HEAD', alias)
        with self.assertRaisesRegex(StallionError, 'unexpected workspace branch'):
            store._mount(path, metadata)
        self.assertEqual(git(repo, 'symbolic-ref', '--no-recurse', 'HEAD'), alias)
        self.assertEqual(git(repo, 'symbolic-ref', '--no-recurse', alias), ref)
        self.assertEqual(git(repo, 'rev-parse', ref), metadata['commit'])
        self.assertFalse((path / 'ready.json').exists())

    def test_mount_refuses_ambiguous_ready_marker_before_attaching(self):
        from stallionfs import images
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            marker = path / 'ready.json'
            workspace = 'a' * 32
            metadata = dict(id=workspace, backend='image')
            store = Store.__new__(Store)
            raw = f'{{"format": 1, "id": "wrong", "id": "{workspace}"}}'.encode()
            marker.write_bytes(raw)
            with patch.object(images, 'attach') as attach:
                with self.assertRaisesRegex(StallionError, 'duplicate key'):
                    store._mount(path, metadata)
                self.assertEqual(marker.read_bytes(), raw)
                marker.unlink()
                marker.symlink_to('missing')
                with self.assertRaisesRegex(StallionError, 'unsafe metadata'):
                    store._mount(path, metadata)
                self.assertEqual(os.readlink(marker), 'missing')
                attach.assert_not_called()


@unittest.skipUnless(sys.platform == "darwin" and os.environ.get("STALLIONFS_TEST_IMAGES") == "1",
                     "requires macOS disk-image access and explicit test selection")
class ImageStoreTests(unittest.TestCase):
    def test_prepared_metadata_survives_build_create_snapshot_and_rollback(self):
        from stallionfs import images
        perf = str(Path(__file__).parent / 'perf')
        sys.path.insert(0, perf)
        self.addCleanup(sys.path.remove, perf)
        import native_correctness as checks

        preparation = r"""import ctypes, fcntl, os, struct, subprocess
from pathlib import Path
root = Path('metadata'); root.mkdir(mode=0o750)
(root / 'directory').mkdir(); (root / 'empty').mkdir()
(root / 'file').write_bytes(b'original\x00data')
os.link(root / 'file', root / 'alias')
for name, target in (('relative', 'file'), ('dangling', 'missing'), ('directory-link', 'directory')):
    (root / name).symlink_to(target)
with (root / 'sparse').open('wb') as stream:
    stream.write(b'HEAD'); stream.seek(8 * 1024 * 1024 - 1); stream.write(b'T')
    stream.flush()
    fcntl.fcntl(stream.fileno(), 99, struct.pack('=IIqq', 0, 0, 1024 * 1024, 6 * 1024 * 1024))
    os.fsync(stream.fileno()); fcntl.fcntl(stream.fileno(), 51)
libc = ctypes.CDLL(None, use_errno=True)
libc.setxattr.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_int]
for path in (root, root / 'directory', root / 'file', root / 'sparse', root / 'relative'):
    subprocess.run(['/bin/chmod', '-h', '+a', 'everyone allow read,readattr,readextattr,readsecurity', str(path)], check=True)
    attributes = {'user.small': b'value\x00\xff', 'user.large': bytes(range(256)) * 32,
                  'com.apple.metadata:stallionfs-test': b'apple\x00value'}
    if path.is_file() and not path.is_symlink():
        attributes['com.apple.ResourceFork'] = b'fork\x00' + bytes(range(256)) * 32
    for name, value in attributes.items():
        if libc.setxattr(os.fsencode(path), name.encode(), value, len(value), 0, 1):
            raise OSError(ctypes.get_errno(), 'setxattr', str(path))
"""
        base = Path(tempfile.mkdtemp(prefix='stallionfs-image-metadata-')).resolve()
        store = Store(base / 'store')
        with image_fixture(store, base) as fixture:
            source = base / 'source'
            source.mkdir()
            git(source, 'init', '-b', 'main')
            (source / 'tracked').write_text('tracked\n')
            git(source, 'add', '.')
            git(source, '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Fixture')
            expected = []
            original_build = images.build

            def observe_build(repo, image, capacity):
                before = checks.snapshot(Path(repo) / 'metadata')
                sparse = before['entries']['sparse']
                self.assertLess(sparse['allocated_bytes'], sparse['size'])
                self.assertIsNone(sparse['holes']['unavailable'])
                self.assertTrue(any(start <= 1024 * 1024 and end >= 7 * 1024 * 1024
                                    for start, end in sparse['holes']['ranges']))
                self.assertEqual(before['hardlink_groups'], [['alias', 'file']])
                self.assertTrue(before['entries']['relative']['acl']['text_hex'])
                self.assertTrue(before['entries']['relative']['xattrs'])
                expected.append(before)
                return original_build(repo, image, capacity)

            def assert_metadata(repo):
                observed = checks.snapshot(Path(repo) / 'metadata')
                report = checks.compare(expected[0], observed)
                self.assertTrue(report['strict_equal'], report)
                self.assertIs(report['sparse_preserved'], True, report)
                self.assertLess(observed['entries']['sparse']['allocated_bytes'],
                                observed['entries']['sparse']['size'])

            with patch.object(images, 'build', side_effect=observe_build):
                seed = fixture.call(store.prepare, source, key='metadata', image_size=1,
                                    command=[sys.executable, '-c', preparation])
            seed_image = store.root / 'seeds' / seed['id'] / 'workspace.sparseimage'
            point = base / 'inspect-seed'
            with failure_scope(base, seed_image, mountpoint=point, stage='verify-build'):
                repo = images.attach(seed_image, point)
                assert_metadata(repo)
                images.detach(seed_image, point)
            workspace = fixture.call(store.create, seed['id'])
            value, repo = workspace['id'], Path(workspace['path'])
            assert_metadata(repo)
            snapshot = fixture.call(store.snapshot, value, quiescent=True, workspace=value)
            saved = store.root / 'snapshots' / snapshot['id'] / 'workspace.sparseimage'
            with failure_scope(base, saved, mountpoint=point, stage='verify-snapshot'):
                saved_repo = images.attach(saved, point)
                assert_metadata(saved_repo)
                images.detach(saved, point)
            (repo / 'metadata/file').write_bytes(b'changed')
            subprocess.run(['/usr/bin/xattr', '-d', 'user.large', str(repo / 'metadata/file')], check=True)
            (repo / 'metadata/alias').unlink()
            (repo / 'metadata/relative').unlink()
            (repo / 'metadata/relative').symlink_to('directory')
            with (repo / 'metadata/sparse').open('r+b') as stream:
                stream.seek(2 * 1024 * 1024)
                stream.write(b'changed hole')
            fixture.call(store.rollback, value, snapshot['id'], quiescent=True, workspace=value)
            assert_metadata(repo)
            with failure_scope(base, saved, mountpoint=point, stage='verify-independent-snapshot'):
                saved_repo = images.attach(saved, point)
                assert_metadata(saved_repo)
                images.detach(saved, point)

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
