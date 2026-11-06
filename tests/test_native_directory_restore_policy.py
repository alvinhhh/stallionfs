"""Pure mode-policy tests; never call native setters or a clone helper."""
from copy import deepcopy
import errno
import os
import stat
import unittest
from unittest import mock

import test_native_directory_restore as model

restore = model.restore


class Policy(unittest.TestCase):
    def setUp(self):
        self.symlink_flag = mock.patch.object(os, 'O_SYMLINK', 0x200000, create=True)
        self.symlink_flag.start(); self.addCleanup(self.symlink_flag.stop)

    @staticmethod
    def modes_fixture():
        source = model.snapshot({'': model.row('directory', 1, mode=0o700),
                                 'owned': model.row('file', 2, mode=0o6750, flags=66)})
        destination = deepcopy(source)
        for index, value in enumerate(destination['entries'].values(), 101):
            value['device_inode'] = [7, index]
            value['flags'] &= ~64
            if value['kind'] == 'directory': value['mtime_ns'] += 1
        destination['entries']['owned']['mode'] = 0o750
        return source, model.snapshot(destination['entries'])

    def test_mode_selector_admits_only_missing_setid_on_owned_effective_group_singleton(self):
        for expected in (0o6750, 0o4750, 0o2750):
            for actual, selected in ((0o750, ['owned']), (expected, [])):
                with self.subTest(expected=expected, actual=actual):
                    source, destination = self.modes_fixture()
                    source['entries']['owned']['mode'] = expected
                    destination['entries']['owned']['mode'] = actual
                    self.assertEqual(restore.plan(source, destination, os.geteuid())['modes'], selected)
        for change in ('permissions', 'partial_suid', 'partial_sgid', 'added_setid', 'source_uid', 'destination_uid',
                       'source_gid', 'destination_gid', 'source_alias', 'destination_alias', 'symlink'):
            with self.subTest(change=change):
                source, destination = self.modes_fixture()
                a, b = source['entries']['owned'], destination['entries']['owned']
                if change == 'permissions': b['mode'] ^= 0o010
                elif change == 'partial_suid': b['mode'] = 0o4750
                elif change == 'partial_sgid': b['mode'] = 0o2750
                elif change == 'added_setid': a['mode'], b['mode'] = 0o2750, 0o6750
                elif change == 'source_uid': a['uid'] += 1
                elif change == 'destination_uid': b['uid'] += 1
                elif change == 'source_gid': a['gid'] = b['gid'] = os.getegid() + 1
                elif change == 'destination_gid': b['gid'] += 1
                elif change == 'source_alias': a['link_count'] = 2
                elif change == 'destination_alias': b['link_count'] = 2
                else:
                    a['kind'] = b['kind'] = 'symlink'
                    a['symlink_bytes'] = b['symlink_bytes'] = b'outside'.hex()
                with self.assertRaises(restore.RestoreError):
                    restore.plan(source, destination, os.geteuid())

    def test_exact_mode_is_restored_after_acl_and_tracking_before_blockers_without_source_writes(self):
        source, destination = self.modes_fixture()
        source['entries']['owned']['acl']['text_hex'] = 'allow-read'
        destination['entries']['owned']['acl']['text_hex'] = None
        ops = model.FakeOps(source, destination)
        original = deepcopy({key: node for key, node in ops.nodes.items() if key[1] < 100})
        events = []
        for name in ('flags', 'mode', 'copy_acl', 'times'):
            method = getattr(ops, name)
            def observing(*args, name=name, method=method):
                target = args[1] if name == 'copy_acl' else args[0]
                inode = ops.descriptors[target]['info'].st_ino
                events.append((name, inode, args[-1])); return method(*args)
            setattr(ops, name, observing)
        with mock.patch.object(os, 'fchown', side_effect=AssertionError('ownership writes forbidden')):
            session = restore.Session('private', 'source', 'parent', source, ops=ops)
            try:
                result = session.restore(destination)
                self.assertEqual(result['status'], 'restored_pending_final_verifiers')
            finally:
                self.assertTrue(session.close())
        inode = destination['entries']['owned']['device_inode'][1]
        leaf = [event for event in events if event[1] == inode]
        self.assertEqual([event[2] for event in leaf if event[0] == 'flags'], [0, 64, 66])
        mode_index = next(index for index, event in enumerate(leaf) if event[0] == 'mode')
        self.assertEqual(leaf[mode_index][2], 0o6750)
        self.assertLess(next(index for index, event in enumerate(leaf) if event[0] == 'copy_acl'), mode_index)
        self.assertLess(mode_index, max(index for index, event in enumerate(leaf) if event[0] == 'flags'))
        restored = ops.nodes[(7, inode)]['info']
        self.assertEqual(stat.S_IMODE(restored.st_mode), 0o6750)
        self.assertEqual((restored.st_uid, restored.st_gid, restored.st_nlink),
                         (os.geteuid(), os.getegid(), 1))
        self.assertEqual(original, {key: node for key, node in ops.nodes.items() if key[1] < 100})
        self.assertTrue(all(event[1] >= 100 for event in events))

    def test_successful_noop_or_partial_mode_setter_refuses_before_count_and_recovers_on_held_fd(self):
        for applied, recovery in ((0o750, 'normal'), (0o4750, 'normal'), (0o2750, 'normal'),
                                  (0o4750, 'error'), (0o4750, 'noop')):
            with self.subTest(applied=applied, recovery=recovery):
                source, destination = self.modes_fixture()
                ops = model.FakeOps(source, destination)
                original = deepcopy({key: node for key, node in ops.nodes.items() if key[1] < 100})
                mode = ops.mode; fault = []
                def incomplete_mode(fd, value):
                    if value == 0o6750:
                        ops.called('mode', fd, value)
                        info = ops.descriptors[fd]['info']
                        info.st_mode = stat.S_IFMT(info.st_mode) | applied
                        info.st_ctime_ns += 1
                        fault.append((len(ops.calls), fd))
                        return
                    if fault and value == 0o750 and recovery != 'normal':
                        ops.called('mode', fd, value)
                        if recovery == 'error': raise OSError(errno.EIO, 'synthetic mode recovery failure')
                        return
                    return mode(fd, value)
                ops.mode = incomplete_mode
                with mock.patch.object(os, 'fchown', side_effect=AssertionError('ownership writes forbidden')):
                    session = restore.Session('private', 'source', 'parent', source, ops=ops)
                    try:
                        result = session.restore(destination)
                        self.assertEqual((result['status'], result['error'], result['mode_repairs']),
                                         ('incomplete', 'identity_changed', 0))
                        self.assertEqual(result['directory_times'], 0)
                        self.assertEqual(result['recovery'], 'complete' if recovery == 'normal' else 'incomplete')
                    finally:
                        self.assertTrue(session.close())
                self.assertEqual(len(fault), 1)
                index, held = fault[0]
                later = ops.calls[index:]
                self.assertFalse(any(call[0] in ('open', 'unlink', 'link', 'copy_acl', 'times') for call in later))
                self.assertEqual([call for call in ops.calls if call[0] == 'mode' and call[-1] == 0o6750],
                                 [('mode', held, 0o6750)])
                self.assertEqual([call for call in later if call[0] == 'mode'], [('mode', held, 0o750)])
                self.assertEqual([call for call in later if call[0] == 'flags'], [('flags', held, 66)])
                self.assertLess(later.index(('mode', held, 0o750)), later.index(('flags', held, 66)))
                inode = destination['entries']['owned']['device_inode'][1]
                self.assertEqual(ops.nodes[(7, inode)]['info'].st_flags, 66)
                if recovery == 'normal':
                    self.assertEqual(stat.S_IMODE(ops.nodes[(7, inode)]['info'].st_mode), 0o750)
                self.assertEqual(original, {key: node for key, node in ops.nodes.items() if key[1] < 100})
