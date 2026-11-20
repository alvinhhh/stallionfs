"""Process cuts at folder publication and owned APFS image boundaries."""
import copy
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import sysconfig
import tempfile
import unittest
from unittest.mock import patch

if __package__:
    from .test_sigkill import ProcessDeathFixture, pause_at_hook
else:
    from test_sigkill import ProcessDeathFixture, pause_at_hook


def probe_workspace_hooks(library, binary, *, image_hooks=False):
    stage = 'workspace rename'
    try:
        base = library.parent / 'workspace-probe'
        base.mkdir(mode=0o700)
        source = base / 'source'
        destination = base / 'destination'
        for phase in ('before', 'after'):
            source.write_text('probe')
            pause_at_hook([sys.executable, '-I', '-B', '-c',
                           'import os, sys; os.' + ('rename' if phase == 'before' else 'replace')
                           + '(sys.argv[1], sys.argv[2])', str(source), str(destination)],
                          library, f'rename-{phase}')
        stage = 'native unlink'
        source.write_text('probe')
        pause_at_hook([str(binary), '--json', 'delete', str(source)], library, 'unlink-after')
        if image_hooks:
            source.write_text('probe')
            environment = {'STALLIONFS_TEST_CUT_PATH': str(source)}
            for kind, code in (('image-ready', 'open(sys.argv[1]).close()'),
                               ('unmount-result', 'print(\'{"unmounted": "probe"}\')')):
                stage = kind
                pause_at_hook([sys.executable, '-I', '-B', '-c', 'import os, sys; ' + code, str(source)],
                              library, kind, extra_env=environment)
    except (OSError, subprocess.SubprocessError, RuntimeError) as error:
        return f'{stage}: {error}'
    return None


def surviving_projection(before, after):
    expected = copy.deepcopy(before)
    expected['entries'] = {name: row for name, row in expected['entries'].items() if name in after['entries']}
    for name, row in expected['entries'].items():
        if row['kind'] == 'directory':
            row['mtime_ns'] = after['entries'][name]['mtime_ns']
    groups = [sorted(set(group) & after['entries'].keys()) for group in expected['hardlink_groups']]
    expected['hardlink_groups'] = sorted(group for group in groups if len(group) > 1)
    return expected


class WorkspaceFixture(ProcessDeathFixture):
    image_hooks = False

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        if cls.hook_unavailable is None:
            cls.hook_unavailable = probe_workspace_hooks(
                cls.library, Path(sysconfig.get_path('scripts')) / 'sfs', image_hooks=cls.image_hooks)

    def cut_path(self, kind, path, *arguments):
        environment = {'STALLIONFS_TEST_CUT_PATH': str(path)}
        pause_at_hook(self.command(*arguments), self.library, kind, extra_env=environment)

    def clone_equal(self, before, path):
        report = self.checks.verify_clone(before, self.checks.snapshot(path))
        self.assertTrue(report['strict_equal'], report)
        self.assertTrue(report['independent_clone'], report)
        self.assertIs(report['sparse_preserved'], True, report)

    def move_equal(self, before, path):
        report = self.checks.verify_move(before, self.checks.snapshot(path))
        self.assertTrue(report['strict_equal'], report)
        self.assertTrue(report['move_identity'], report)
        self.assertIs(report['sparse_preserved'], True, report)

    def survivors_equal(self, before, path):
        after = self.checks.snapshot(path)
        self.assertLessEqual(after['entries'].keys(), before['entries'].keys())
        report = self.checks.verify_move(surviving_projection(before, after), after)
        self.assertTrue(report['strict_equal'], report)
        self.assertTrue(report['move_identity'], report)
        self.assertIs(report['sparse_preserved'], True, report)
        return after

    def stages(self):
        return set((self.root / 'staging').iterdir())

    def reported_stage(self, previous):
        added = self.stages() - previous
        self.assertEqual(len(added), 1, added)
        stage = added.pop()
        before = self.checks.snapshot(stage)
        self.assertIn(stage.name, self.cli('doctor')['staging_entries'])
        self.unchanged(before, stage)
        return stage


@unittest.skipUnless(sys.platform == 'darwin', 'SIGKILL integration requires macOS APFS')
class WorkspaceDeath(WorkspaceFixture, unittest.TestCase):
    def test_killed_create_publishes_only_complete_workspace(self):
        source = self.repository()
        seed = self.cli('prepare', source, '--key', 'create')['id']
        seed_repo = self.root / 'seeds' / seed / 'repo'
        before = self.checks.snapshot(seed_repo)
        payload = self.checks.snapshot(seed_repo / 'payload')
        for phase in ('clone', 'before', 'after'):
            with self.subTest(phase=phase):
                previous = {row['id'] for row in self.cli('list')}
                stages = self.stages()
                if phase == 'clone':
                    self.cut('clone', 'create', seed)
                else:
                    self.cut_path(f'rename-{phase}', str(self.root / 'workspaces') + '/', 'create', seed)
                published = {row['id'] for row in self.cli('list')} - previous
                self.assertEqual(len(published), int(phase == 'after'))
                if phase == 'after':
                    workspace = self.cli('mount', published.pop())
                else:
                    stage = self.reported_stage(stages)
                    partial = self.checks.snapshot(stage / 'repo')
                    self.assertLessEqual(partial['entries'].keys(), before['entries'].keys())
                    workspace = self.cli('create', seed)
                self.clone_equal(payload, Path(workspace['path']) / 'payload')
                self.unchanged(before, seed_repo)

    def test_killed_snapshot_publishes_only_complete_capture(self):
        source = self.repository()
        seed = self.cli('prepare', source, '--key', 'snapshot')['id']
        workspace = self.cli('create', seed)
        repo = Path(workspace['path'])
        before = self.checks.snapshot(repo)
        for phase in ('clone', 'before', 'after'):
            with self.subTest(phase=phase):
                previous = {row['id'] for row in self.cli('snapshots', workspace['id'])}
                stages = self.stages()
                arguments = ('snapshot', workspace['id'], '--quiescent')
                if phase == 'clone':
                    self.cut('clone', *arguments)
                else:
                    self.cut_path(f'rename-{phase}', str(self.root / 'snapshots') + '/', *arguments)
                published = {row['id'] for row in self.cli('snapshots', workspace['id'])} - previous
                self.assertEqual(len(published), int(phase == 'after'))
                if phase == 'after':
                    saved = published.pop()
                else:
                    self.reported_stage(stages)
                    saved = self.cli(*arguments)['id']
                self.clone_equal(before, self.root / 'snapshots' / saved / 'repo')
                self.unchanged(before, repo)

    def test_killed_remove_preserves_payload_in_workspaces_or_trash(self):
        source = self.repository()
        seed = self.cli('prepare', source, '--key', 'remove')['id']
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                workspace = self.cli('create', seed)
                repo = Path(workspace['path'])
                before = self.checks.snapshot(repo)
                self.cut_path(f'rename-{phase}', str(self.root / 'trash') + '/', 'remove', workspace['id'])
                trashed = self.root / 'trash' / workspace['id'] / 'repo'
                self.assertEqual([repo.exists(), trashed.exists()], [phase == 'before', phase == 'after'])
                self.move_equal(before, repo if repo.exists() else trashed)
                recovered = self.cli('mount' if phase == 'before' else 'restore', workspace['id'])
                self.move_equal(before, Path(recovered['path']))

    def test_killed_purge_and_gc_retain_reported_remainder(self):
        source = self.repository()
        self.fixture(source / 'payload/many')
        subprocess.run(['git', '-C', str(source), 'add', '.'], check=True, capture_output=True, timeout=15)
        subprocess.run(['git', '-C', str(source), '-c', 'user.name=Fixture', '-c',
                        'user.email=fixture@example.invalid', 'commit', '-qm', 'Many files'],
                       check=True, capture_output=True, timeout=15)
        outside = self.checks.snapshot(source / 'payload')
        seed = self.cli('prepare', source, '--key', 'purge')['id']
        for operation in ('purge', 'gc'):
            with self.subTest(operation=operation):
                workspace = self.cli('create', seed)
                self.cli('remove', workspace['id'])
                trash = self.root / 'trash' / workspace['id']
                before = self.checks.snapshot(trash)
                stages = self.stages()
                arguments = ('purge', 'trash', workspace['id'], '--yes') if operation == 'purge' else (
                    'gc', '--yes', '--older-than', '0')
                self.cut('unlink-after', *arguments)
                self.assertFalse(trash.exists())
                stage = self.reported_stage(stages)
                remainder = self.survivors_equal(before, stage / 'expired')
                self.assertEqual(self.cli('gc', '--yes', '--older-than', '0'), [])
                self.unchanged(remainder, stage / 'expired')
                self.unchanged(outside, source / 'payload')

    def test_killed_native_delete_is_confined_and_survivors_intact(self):
        outside = self.base / 'outside'
        outside.mkdir()
        (outside / 'file').write_text('must survive\n')
        protected = self.checks.snapshot(outside)
        target = self.base / 'target'
        self.fixture(target)
        (target / 'outside-directory').symlink_to(outside, target_is_directory=True)
        (target / 'outside-file').symlink_to(outside / 'file')
        before = self.checks.snapshot(target)
        self.cut('unlink-after', 'delete', target, '--recursive')
        self.survivors_equal(before, target)
        self.unchanged(protected, outside)
        self.cli('delete', target, '--recursive')
        self.assertFalse(target.exists())
        self.unchanged(protected, outside)


IMAGE_GATE = (sys.platform == 'darwin' and os.environ.get('STALLIONFS_TEST_IMAGES') == '1'
              and int(platform.mac_ver()[0].split('.')[0] or 0) >= 26)


@unittest.skipUnless(IMAGE_GATE, 'Set STALLIONFS_TEST_IMAGES=1 on macOS 26 or newer to run real mount checks')
class MountedImageDeath(WorkspaceFixture, unittest.TestCase):
    image_hooks = True

    def _callTestMethod(self, method):
        try:
            super()._callTestMethod(method)
        except BaseException:
            self.retain = True
            raise
        finally:
            if self._outcome is not None and not self._outcome.success:
                self.retain = True

    def setUp(self):
        if self.hook_unavailable is not None:
            self.skipTest('SIGKILL pause hook unavailable: ' + self.hook_unavailable)
        self.base = Path(tempfile.mkdtemp(prefix='stallionfs-sigkill-images-')).resolve()
        self.root = self.base / 'store'
        self.binary = Path(sysconfig.get_path('scripts')) / 'sfs'
        self.retain = True
        self.addCleanup(self.cleanup_images)
        for binary in ('/usr/bin/hdiutil', '/usr/sbin/diskutil'):
            if not os.access(binary, os.X_OK):
                self.retain = False
                self.skipTest('SIGKILL image fixtures unavailable: missing ' + binary)
        if shutil.disk_usage(self.base).free < 3 * 1024**3:
            self.retain = False
            self.skipTest('SIGKILL image fixtures unavailable: require 3 GiB free')

    def cleanup_images(self):
        if self.retain:
            print(f'SIGKILL image fixture retained at {self.base}', file=sys.stderr)
            return
        from stallionfs import images
        try:
            for collection in ('seeds', 'workspaces', 'staging', 'snapshots', 'recovery', 'trash'):
                parent = self.root / collection
                for entry in parent.iterdir() if parent.exists() else ():
                    image = entry / 'workspace.sparseimage'
                    if not image.is_file():
                        continue
                    state = images.mounted(image)
                    if state:
                        point = Path(state['mountpoint']) if state['mountpoint'] else entry / 'volume'
                        if not point.is_relative_to(self.base):
                            raise RuntimeError('Unexpected attachment; fixture retained: ' + str(image))
                        images.detach(image, point)
                    if images.mounted(image) is not None:
                        raise RuntimeError('Image still attached; fixture retained: ' + str(image))
            from stallionfs._scan import mounts
            if any(Path(row['path']).is_relative_to(self.base) for row in mounts()):
                raise RuntimeError('Mount remains below fixture; retain ' + str(self.base))
            shutil.rmtree(self.base)
        except BaseException:
            print(f'SIGKILL image fixture retained at {self.base}', file=sys.stderr)
            raise

    def image_seed(self):
        source = self.repository()
        before = self.checks.snapshot(source / 'payload')
        seed = self.cli('prepare', source, '--key', 'image', '--image-size', '1')['id']
        self.unchanged(before, source / 'payload')
        return source, before, seed

    def content_equal(self, before, path):
        after = self.checks.snapshot(path)
        report = self.checks.compare(before, after)
        self.assertTrue(report['strict_equal'], report)
        self.assertIs(report['sparse_preserved'], True, report)

    def test_killed_image_create_keeps_closed_complete_candidate(self):
        source, payload, seed = self.image_seed()
        source_image = self.root / 'seeds' / seed / 'workspace.sparseimage'
        initialized_payload = None
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                before = self.checks.snapshot(source_image)
                previous = {row['id'] for row in self.cli('list')}
                stages = self.stages()
                self.cut_path(f'rename-{phase}', str(self.root / 'workspaces') + '/', 'create', seed)
                published = {row['id'] for row in self.cli('list')} - previous
                self.assertEqual(len(published), int(phase == 'after'))
                if phase == 'before':
                    stage = self.reported_stage(stages)
                    self.clone_equal(before, stage / 'workspace.sparseimage')
                    self.unchanged(before, source_image)
                    retry = self.cli('create', seed)
                    initialized_payload = self.checks.snapshot(Path(retry['path']) / 'payload')
                    self.assertEqual(initialized_payload['entries']['file']['sha256'],
                                     payload['entries']['file']['sha256'])
                    self.cli('unmount', retry['id'])
                else:
                    workspace_id = published.pop()
                    candidate = self.root / 'workspaces' / workspace_id / 'workspace.sparseimage'
                    self.clone_equal(before, candidate)
                    workspace = self.cli('mount', workspace_id)
                    self.content_equal(initialized_payload, Path(workspace['path']) / 'payload')
                    self.cli('unmount', workspace_id)
                self.unchanged(payload, source / 'payload')
        self.retain = False

    def test_killed_image_snapshot_keeps_closed_complete_candidate(self):
        source, payload, seed = self.image_seed()
        workspace = self.cli('create', seed)
        repo = Path(workspace['path'])
        expected = self.checks.snapshot(repo)
        for phase in ('before', 'after'):
            with self.subTest(phase=phase):
                previous = {row['id'] for row in self.cli('snapshots', workspace['id'])}
                stages = self.stages()
                self.cut_path(f'rename-{phase}', str(self.root / 'snapshots') + '/',
                              'snapshot', workspace['id'], '--quiescent')
                backing = self.root / 'workspaces' / workspace['id'] / 'workspace.sparseimage'
                before = self.checks.snapshot(backing)
                published = {row['id'] for row in self.cli('snapshots', workspace['id'])} - previous
                self.assertEqual(len(published), int(phase == 'after'))
                if phase == 'before':
                    stage = self.reported_stage(stages)
                    self.clone_equal(before, stage / 'workspace.sparseimage')
                else:
                    self.clone_equal(before, self.root / 'snapshots' / published.pop() / 'workspace.sparseimage')
                self.cli('mount', workspace['id'])
                self.content_equal(expected, repo)
                self.unchanged(payload, source / 'payload')
        self.cli('unmount', workspace['id'])
        self.retain = False

    def test_killed_mount_and_detach_reconcile_existing_attachment(self):
        from stallionfs import images
        source, payload, seed = self.image_seed()
        workspace = self.cli('create', seed)
        repo = Path(workspace['path'])
        before = self.checks.snapshot(repo)
        self.cli('unmount', workspace['id'])
        path = self.root / 'workspaces' / workspace['id']
        self.cut_path('image-ready', path / 'ready.json', 'mount', workspace['id'])
        self.assertIsNotNone(images.mounted(path / 'workspace.sparseimage'))
        self.cli('mount', workspace['id'])
        self.content_equal(before, repo)
        self.cut_path('rename-after', self.root / 'lifecycle' / (workspace['id'] + '.json'),
                      'unmount', workspace['id'])
        self.assertIsNotNone(images.mounted(path / 'workspace.sparseimage'))
        self.cli('mount', workspace['id'])
        self.content_equal(before, repo)
        self.cut('unmount-result', 'unmount', workspace['id'])
        self.assertIsNone(images.mounted(path / 'workspace.sparseimage'))
        self.cli('unmount', workspace['id'])
        self.cli('mount', workspace['id'])
        self.content_equal(before, repo)
        self.unchanged(payload, source / 'payload')
        self.cli('unmount', workspace['id'])
        self.retain = False


class WorkspaceHookCapabilities(unittest.TestCase):
    def test_probe_requires_rename_unlink_and_image_hooks(self):
        with tempfile.TemporaryDirectory() as temporary, patch(__name__ + '.pause_at_hook') as pause:
            self.assertIsNone(probe_workspace_hooks(Path(temporary) / 'pause.dylib', Path('/unused/sfs'), image_hooks=True))
        self.assertEqual([call.args[2] for call in pause.call_args_list],
                         ['rename-before', 'rename-after', 'unlink-after', 'image-ready', 'unmount-result'])

    def test_probe_failure_names_boundary(self):
        for index, stage in enumerate(('workspace rename', 'workspace rename', 'native unlink',
                                       'image-ready', 'unmount-result')):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary, \
                 patch(__name__ + '.pause_at_hook', side_effect=[None] * index + [RuntimeError('DYLD stripped')]):
                self.assertEqual(probe_workspace_hooks(Path(temporary) / 'pause.dylib', Path('/unused/sfs'),
                                                      image_hooks=True), stage + ': DYLD stripped')

    def test_unavailable_probe_skips_each_exact_integration_test(self):
        count = 0
        for case_type in (WorkspaceDeath, MountedImageDeath):
            for name in unittest.defaultTestLoader.getTestCaseNames(case_type):
                case = case_type(name)
                case.hook_unavailable = 'synthetic missing hook'
                with self.assertRaisesRegex(unittest.SkipTest, '^SIGKILL pause hook unavailable: synthetic missing hook$'):
                    case.setUp()
                count += 1
        self.assertEqual(count, 8)

    def test_survivor_projection_accepts_empty_remainder(self):
        before = {'entries': {'file': {'kind': 'file'}}, 'hardlink_groups': []}
        self.assertEqual(surviving_projection(before, {'entries': {}}), {'entries': {}, 'hardlink_groups': []})

    def test_runtime_hook_miss_is_not_converted_to_skip(self):
        case = WorkspaceDeath('test_killed_create_publishes_only_complete_workspace')
        case.binary, case.root, case.library = Path('/unused/sfs'), Path('/unused/store'), Path('/unused/pause.dylib')
        with patch(__name__ + '.pause_at_hook', side_effect=RuntimeError('hook stopped pausing')):
            with self.assertRaisesRegex(RuntimeError, 'hook stopped pausing'):
                case.cut_path('rename-before', '/unused/store/workspaces/', 'create', 'seed')

    def test_survivor_projection_keeps_file_metadata_and_filters_aliases(self):
        before = {'entries': {'.': {'kind': 'directory', 'mtime_ns': 1},
                              'file': {'kind': 'file', 'sha256': 'digest'},
                              'alias': {'kind': 'file', 'sha256': 'digest'}},
                  'hardlink_groups': [['alias', 'file']]}
        after = {'entries': {'.': {'kind': 'directory', 'mtime_ns': 2},
                             'file': {'kind': 'file', 'sha256': 'digest'}}}
        projected = surviving_projection(before, after)
        self.assertEqual(projected['entries'], after['entries'])
        self.assertEqual(projected['hardlink_groups'], [])
        self.assertEqual(before['entries']['.']['mtime_ns'], 1)
