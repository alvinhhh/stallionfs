"""Descriptor admission and bounded reads for package Git files."""
from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from stallionfs import _bundle, _git_runtime as runtime


FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink',
          'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_flags')


def changed(info, **updates):
    values = {name: getattr(info, name, 0) for name in FIELDS}
    values.update(updates)
    return SimpleNamespace(**values)


class GitPayloadReader(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='git-payload-reader-')
        self.addCleanup(temporary.cleanup)
        self.temporary = Path(temporary.name).resolve()
        self.sequence = 0

    def tree(self, name='input.bin', data=b'abcdefgh'):
        self.sequence += 1
        root = self.temporary / str(self.sequence)
        parent = root / 'sources' / 'nested'
        parent.mkdir(parents=True, mode=0o700)
        root.chmod(0o700)
        (root / 'sources').chmod(0o700)
        path = parent / name
        path.write_bytes(data)
        path.chmod(0o600)
        identities = {item: runtime._identity(item.lstat())
                      for item in (root, root / 'sources', parent, path)}
        return SimpleNamespace(root=root, path=path, identities=identities,
                               admitted=set(), data=data, info=path.lstat())

    def read(self, fixture, cap=None):
        return runtime._read_file(fixture.root, fixture.path,
                                  len(fixture.data) if cap is None else cap,
                                  fixture.identities, fixture.admitted)

    @contextmanager
    def descriptors(self, before_open=None):
        real_open, real_close = os.open, os.close
        live = set()
        events = {'opened': [], 'closed': []}

        def opened(path, flags, *args, **kwargs):
            if before_open is not None:
                before_open(path, flags, kwargs)
            descriptor = real_open(path, flags, *args, **kwargs)
            self.assertNotIn(descriptor, live)
            live.add(descriptor)
            events['opened'].append((descriptor, path, flags, kwargs.get('dir_fd')))
            return descriptor

        def closed(descriptor):
            self.assertIn(descriptor, live)
            real_close(descriptor)
            live.remove(descriptor)
            events['closed'].append(descriptor)

        try:
            with patch.object(runtime.os, 'open', opened), patch.object(runtime.os, 'close', closed):
                yield events
        finally:
            leaked = list(live)
            for descriptor in leaked:
                real_close(descriptor)
            self.assertEqual(leaked, [], 'Every reader descriptor must close')
            self.assertEqual(len(events['opened']), len(events['closed']))

    @contextmanager
    def leaf_stats(self, fixture, first=None, final=None, pathname=None):
        real_fstat, real_stat = os.fstat, os.stat
        first = {} if first is None else first
        final = first if final is None else final
        pathname = first if pathname is None else pathname
        count = 0

        def fstat(descriptor):
            nonlocal count
            info = real_fstat(descriptor)
            if stat.S_ISREG(info.st_mode):
                count += 1
                return changed(info, **(first if count == 1 else final))
            return info

        def path_stat(path, *args, **kwargs):
            info = real_stat(path, *args, **kwargs)
            if path == fixture.path.name and kwargs.get('dir_fd') is not None:
                return changed(info, **pathname)
            return info

        with patch.object(runtime.os, 'fstat', side_effect=fstat), \
                patch.object(runtime.os, 'stat', side_effect=path_stat):
            yield

    def test_local_identity_binds_flags_without_changing_bundle_identity(self):
        fixture = self.tree()
        info = changed(fixture.info, st_flags=47)
        self.assertEqual(runtime._identity(info), (*_bundle._identity(info), 47))
        self.assertEqual(len(_bundle._identity(info)), 9)

    def test_first_open_establishes_ctime_and_flags_once_with_clean_repeated_reads(self):
        for name in ('header-manifest.json', 'build-scripts.tar.xz'):
            with self.subTest(name=name):
                fixture = self.tree(name)
                original = fixture.identities[fixture.path]
                delta = {'st_ctime_ns': fixture.info.st_ctime_ns + 1,
                         'st_flags': getattr(fixture.info, 'st_flags', 0) ^ 1}
                with self.descriptors(), self.leaf_stats(fixture, first=delta):
                    self.assertEqual(self.read(fixture), fixture.data)
                    baseline = fixture.identities[fixture.path]
                    self.assertEqual(baseline[:8], original[:8])
                    self.assertEqual(baseline[8], delta['st_ctime_ns'])
                    self.assertEqual(baseline[9], delta['st_flags'])
                    self.assertEqual(self.read(fixture), fixture.data)
                    self.assertEqual(fixture.identities[fixture.path], baseline)
                self.assertEqual(fixture.admitted, {fixture.path})

    def test_first_open_object_security_mtime_and_cap_fail_before_read(self):
        fixture = self.tree()
        info = fixture.info
        cases = {'device': {'st_dev': info.st_dev + 1}, 'inode': {'st_ino': info.st_ino + 1},
            'symlink': {'st_mode': stat.S_IFLNK | 0o600},
            'directory': {'st_mode': stat.S_IFDIR | 0o700},
            'permissions': {'st_mode': info.st_mode | 0o020},
            'owner': {'st_uid': os.getuid() + 100000}, 'group': {'st_gid': info.st_gid + 1},
            'hardlink': {'st_nlink': 2}, 'negative-size': {'st_size': -1},
            'oversize': {'st_size': len(fixture.data) + 1},
            'mtime': {'st_mtime_ns': info.st_mtime_ns + 1}}
        original = fixture.identities.copy()
        for name, updates in cases.items():
            with self.subTest(change=name), self.descriptors(), self.leaf_stats(fixture, first=updates), \
                    patch.object(runtime.os, 'read') as read:
                with self.assertRaises(_bundle.BundleError):
                    self.read(fixture)
                read.assert_not_called()
                self.assertEqual(fixture.admitted, set())
                self.assertEqual(fixture.identities, original)
        with self.descriptors(), patch.object(runtime.os, 'read') as read:
            with self.assertRaises(_bundle.BundleError):
                self.read(fixture, cap=len(fixture.data) - 1)
            read.assert_not_called()

    def test_every_metadata_field_is_strict_after_first_admission(self):
        fixture = self.tree()
        with self.descriptors():
            self.assertEqual(self.read(fixture), fixture.data)
        baseline = fixture.identities.copy()
        for field in FIELDS:
            value = getattr(fixture.info, field, 0)
            replacement = value ^ 0o100 if field == 'st_mode' else value + 1
            with self.subTest(field=field), self.descriptors(), \
                    self.leaf_stats(fixture, first={field: replacement}), \
                    patch.object(runtime.os, 'read') as read:
                with self.assertRaises(_bundle.BundleError):
                    self.read(fixture, cap=len(fixture.data) + 1)
                read.assert_not_called()
                self.assertEqual(fixture.identities, baseline)

    def test_descriptor_only_change_cannot_hide_behind_restored_path_metadata(self):
        for field in ('st_ctime_ns', 'st_mtime_ns', 'st_flags', 'st_ino'):
            with self.subTest(field=field):
                fixture = self.tree()
                update = {field: getattr(fixture.info, field, 0) + 1}
                with self.descriptors(), self.leaf_stats(fixture, final=update, pathname={}), \
                        patch.object(runtime.os, 'read', side_effect=[b'X' * len(fixture.data), b'']) as read:
                    with self.assertRaises(_bundle.BundleError):
                        self.read(fixture)
                    self.assertEqual(read.call_count, 2)
                self.assertEqual(fixture.identities[fixture.path], runtime._identity(fixture.info))

    def test_replaced_symlink_hardlinked_and_nonregular_leaves_refuse(self):
        for kind in ('replacement', 'symlink', 'hardlink', 'directory'):
            with self.subTest(kind=kind):
                fixture = self.tree()
                old = fixture.path.with_name('old-input')
                fixture.path.rename(old)
                if kind == 'replacement':
                    fixture.path.write_bytes(fixture.data)
                    fixture.path.chmod(0o600)
                elif kind == 'symlink':
                    fixture.path.symlink_to(old.name)
                elif kind == 'hardlink':
                    os.link(old, fixture.path)
                else:
                    fixture.path.mkdir(mode=0o700)
                for parent in (fixture.root, fixture.root / 'sources', fixture.path.parent):
                    fixture.identities[parent] = runtime._identity(parent.lstat())
                with self.descriptors(), patch.object(runtime.os, 'read') as read:
                    with self.assertRaises((_bundle.BundleError, OSError)):
                        self.read(fixture)
                    read.assert_not_called()
                self.assertNotIn(fixture.path, fixture.admitted)

    def test_root_and_ancestor_replacements_or_symlinks_fail_at_directory_open(self):
        for kind in ('root-replacement', 'ancestor-replacement', 'ancestor-symlink'):
            with self.subTest(kind=kind):
                fixture = self.tree()
                if kind == 'root-replacement':
                    fixture.root.rename(fixture.root.with_name(fixture.root.name + '-old'))
                    fixture.root.mkdir(mode=0o700)

                def before_open(path, flags, options):
                    if kind != 'root-replacement' and path == 'sources':
                        current = fixture.root / 'sources'
                        current.rename(fixture.root / 'old-sources')
                        if kind == 'ancestor-symlink':
                            current.symlink_to('old-sources', target_is_directory=True)
                        else:
                            current.mkdir(mode=0o700)

                with self.descriptors(before_open), patch.object(runtime.os, 'read') as read:
                    with self.assertRaises((_bundle.BundleError, OSError)):
                        self.read(fixture)
                    read.assert_not_called()
                self.assertNotIn(fixture.path, fixture.admitted)

    def test_second_header_or_script_read_never_rebaselines_a_change(self):
        for name in ('header-manifest.json', 'build-scripts.tar.xz'):
            with self.subTest(name=name):
                fixture = self.tree(name)
                with self.descriptors():
                    self.assertEqual(self.read(fixture), fixture.data)
                baseline = fixture.identities.copy()
                with self.descriptors(), self.leaf_stats(fixture, first={
                        'st_ctime_ns': fixture.info.st_ctime_ns + 1}), \
                        patch.object(runtime.os, 'read') as read:
                    with self.assertRaises(_bundle.BundleError):
                        self.read(fixture)
                    read.assert_not_called()
                self.assertEqual(fixture.identities, baseline)

    def test_exact_large_reads_and_short_oversize_or_exceptional_reads_close_all_fds(self):
        fixture = self.tree(data=b'x' * 130123)
        actual_read = os.read
        with self.descriptors() as events, patch.object(runtime.os, 'read', wraps=actual_read) as read:
            self.assertEqual(self.read(fixture), fixture.data)
            self.assertTrue(all(0 < item.args[1] <= 65536 for item in read.call_args_list))
        self.assertEqual(len(events['opened']), 4)
        self.assertTrue(events['opened'][0][2] & os.O_DIRECTORY)
        self.assertTrue(all(item[2] & os.O_NOFOLLOW for item in events['opened']))
        self.assertTrue(all(item[3] is not None for item in events['opened'][1:]))
        self.assertTrue(events['opened'][-1][2] & os.O_NONBLOCK)
        for kind in ('short', 'oversize', 'exception'):
            with self.subTest(kind=kind):
                fixture = self.tree()
                blocks = {'short': [fixture.data[:-1], b''], 'oversize': [fixture.data + b'x'],
                          'exception': [fixture.data[:2], OSError('read fixture failure')]}[kind]
                with self.descriptors(), patch.object(runtime.os, 'read', side_effect=blocks):
                    with self.assertRaises((_bundle.BundleError, OSError)):
                        self.read(fixture)

    def test_ancestor_stat_errors_close_both_parent_and_new_child(self):
        for kind in ('fstat', 'path-stat'):
            with self.subTest(kind=kind):
                fixture = self.tree()
                actual_fstat, actual_stat = os.fstat, os.stat

                def fstat(descriptor):
                    info = actual_fstat(descriptor)
                    if kind == 'fstat' and info.st_ino == fixture.identities[fixture.root / 'sources'][1]:
                        raise OSError('ancestor descriptor fixture failure')
                    return info

                def path_stat(path, *args, **kwargs):
                    if kind == 'path-stat' and path == 'sources' and kwargs.get('dir_fd') is not None:
                        raise OSError('ancestor pathname fixture failure')
                    return actual_stat(path, *args, **kwargs)

                with self.descriptors() as events, patch.object(runtime.os, 'fstat', side_effect=fstat), \
                        patch.object(runtime.os, 'stat', side_effect=path_stat):
                    with self.assertRaises(OSError):
                        self.read(fixture)
                self.assertEqual(len(events['opened']), 2)

    def test_parent_identity_remains_strict_after_the_read(self):
        fixture = self.tree()
        actual_fstat = os.fstat
        parent = fixture.path.parent.lstat()
        observations = 0

        def fstat(descriptor):
            nonlocal observations
            info = actual_fstat(descriptor)
            if info.st_ino == parent.st_ino and stat.S_ISDIR(info.st_mode):
                observations += 1
                if observations > 1:
                    return changed(info, st_ctime_ns=info.st_ctime_ns + 1)
            return info

        with self.descriptors(), patch.object(runtime.os, 'fstat', side_effect=fstat):
            with self.assertRaises(_bundle.BundleError):
                self.read(fixture)
        self.assertEqual(observations, 2)


if __name__ == '__main__':
    unittest.main()
