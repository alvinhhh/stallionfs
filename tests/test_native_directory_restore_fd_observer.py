"""Independent public-Ops ownership observations; no native operations.

The 18-entry metadata model follows the existing first recipe's shape and alias
classes. It does not prepare real payloads or execute its filesystem verifiers.
"""
from collections import Counter
from copy import deepcopy
import errno
import os
import stat
import unittest
from unittest import mock

import test_native_directory_restore as model

restore = model.restore


def first_recipe_model():
    source = model.snapshot({
        '': model.row('directory', 1, mode=0o550, flags=64),
        'a': model.row('directory', 2, mode=0o500, flags=64),
        'a/file': model.row('file', 3, flags=64, links=4),
        'a/link': model.row('symlink', 4, mode=0o777, flags=64, links=4),
        'b': model.row('directory', 5, mode=0o750),
        'b/file': model.row('file', 3, flags=64, links=4),
        'b/link': model.row('symlink', 4, mode=0o777, flags=64, links=4),
        'c': model.row('directory', 6, mode=0o750),
        'c/append': model.row('file', 7, flags=68),
        'c/file': model.row('file', 3, flags=64, links=4),
        'c/immutable': model.row('file', 8, flags=66),
        'c/link': model.row('symlink', 4, mode=0o777, flags=64, links=4),
        'metadata-fixture': model.row('directory', 9, mode=0o750),
        'metadata-fixture/sparse': model.row('file', 10, mode=0o640, links=2, acl='allow-read'),
        'metadata-fixture/subdir': model.row('directory', 11, mode=0o750),
        'metadata-fixture/subdir/alias': model.row('file', 10, mode=0o640, links=2, acl='allow-read'),
        'outside': model.row('symlink', 12, mode=0o777),
        'space \n café 🐎': model.row('file', 13),
    })
    for name in ('metadata-fixture/sparse', 'metadata-fixture/subdir/alias'):
        source['entries'][name].update(size=8 * 1024 * 1024,
            holes={'ranges': [[1024 * 1024, 7 * 1024 * 1024]]},
            xattrs={'636f6d2e6170706c652e5265736f75726365466f726b': '7265736f75726365', '757365722e74657374': '00'})
    destination = deepcopy(source)
    for index, entry in enumerate(destination['entries'].values(), 101):
        entry['device_inode'] = [7, index]
        entry['link_count'] = 1
        entry['flags'] &= ~64
        entry['acl']['text_hex'] = None
        if entry['kind'] == 'directory': entry['mtime_ns'] = 200
    return source, model.snapshot(destination['entries'])


class ReusingFakeOps(model.FakeOps):
    """Make successfully closed descriptor integers available to later opens."""
    def open(self, name, flags, *, dir_fd=None):
        original = super().open(name, flags, dir_fd=dir_fd)
        reusable = next(fd for fd in range(1000, original + 1) if fd == original or fd not in self.descriptors)
        if reusable != original:
            self.descriptors[reusable] = self.descriptors.pop(original)
        return reusable


class OpsObserver:
    """Count handles and explicitly wrapped APIs, not total adapter/syscall cost."""
    def __init__(self, inner):
        self.inner = inner
        self.calls = Counter()
        self.live = {}
        self.serial = 0
        self.open_events = []
        self.close_events = []
        self.events = []
        self.confirmed_closed = set()
        self.uncertain = set()
        self.duplicate_closes = []
        self.invalid_fd_uses = []
        self.anchors = {}
        self.anchor_opens = Counter()
        self.peak = 0
        self.phase = 'admission'
        self.fail_provisional_stat = False
        self.provisional_failure = None
        self.pending_stat = set()
        self.close_error_mode = None
        self.close_error_fd = None
        self.first_uncertain_event = None
        self.cancel_after = None
        self.cancelled = False
        self.cancel_event = None
        self.cleared_blocker = None
        self.cleared_blocking_bits = None
        self.cleared_node = None
        self.fail_tracking_after_clear = False
        self.failed_tracking_fd = None
        self.failed_tracking_event = None

    def __getattr__(self, name):
        return getattr(self.inner, name)

    def event(self, operation, *arguments):
        self.calls[operation] += 1
        self.events.append((operation, *arguments))

    def require_live(self, fd, operation):
        if fd not in self.live or self.live[fd] in self.uncertain:
            self.invalid_fd_uses.append((operation, fd))
            raise AssertionError('operation used a closed or uncertain descriptor')

    def open(self, name, flags, *, dir_fd=None):
        self.event('open_attempt', name, dir_fd)
        fd = self.inner.open(name, flags, dir_fd=dir_fd)
        if fd in self.live: raise AssertionError('open reused a live or uncertain descriptor')
        self.serial += 1
        token = self.serial
        self.live[fd] = token
        self.pending_stat.add(token)
        self.peak = max(self.peak, len(self.live))
        self.open_events.append((fd, token, len(self.events)))
        role = ('base' if dir_fd is None else
                'source' if dir_fd == self.anchors.get('base', (None,))[0] and name == 'source' else
                'parent' if dir_fd == self.anchors.get('base', (None,))[0] and name == 'parent' else
                'destination' if dir_fd == self.anchors.get('parent', (None,))[0] and name == 'output' else None)
        if role is not None:
            self.anchor_opens[role] += 1
            self.anchors[role] = (fd, token)
        return fd

    def close(self, fd):
        self.event('close', fd)
        token = self.live.get(fd)
        if token is None or token in self.uncertain:
            self.duplicate_closes.append((fd, token))
            raise AssertionError('descriptor closed twice or retried after uncertainty')
        self.close_events.append((fd, token, self.phase))
        error_mode, self.close_error_mode = self.close_error_mode, None
        try:
            if error_mode == 'before': raise OSError(errno.EINTR, 'ambiguous descriptor close')
            self.inner.close(fd)
            if error_mode == 'after': raise OSError(errno.EINTR, 'ambiguous descriptor close')
        except BaseException:
            self.uncertain.add(token)
            self.close_error_fd = fd
            if self.first_uncertain_event is None: self.first_uncertain_event = len(self.events)
            raise
        self.confirmed_closed.add(token)
        del self.live[fd]

    def fstat(self, fd):
        self.event('fstat', fd)
        self.require_live(fd, 'fstat')
        token = self.live[fd]
        first_stat = token in self.pending_stat
        self.pending_stat.discard(token)
        if self.fail_provisional_stat and first_stat:
            self.fail_provisional_stat = False
            self.provisional_failure = (fd, token, len(self.live))
            raise OSError(errno.EIO, 'provisional descriptor admission')
        return self.inner.fstat(fd)

    def named(self, parent, name):
        self.event('named', parent, name)
        self.require_live(parent, 'named')
        return self.inner.named(parent, name)

    def unlink(self, parent, name):
        self.event('unlink', parent, name)
        result = self.inner.unlink(parent, name)
        if self.cancel_after == 'unlink': self.cancel()
        return result

    def link(self, parent, name, target, alias):
        self.event('link', parent, name, target, alias)
        return self.inner.link(parent, name, target, alias)

    def flags(self, fd, value):
        self.event('flags', fd, value)
        self.require_live(fd, 'flags')
        before = self.inner.descriptors[fd]['info'].st_flags
        result = self.inner.flags(fd, value)
        if before & 6 and not value & 6:
            self.cleared_blocker = fd
            self.cleared_blocking_bits = before & 6
            self.cleared_node = self.inner.descriptors[fd]
            if self.cancel_after == 'blocker_clear': self.cancel()
        elif self.fail_tracking_after_clear and fd == self.cleared_blocker and value & 64:
            self.fail_tracking_after_clear = False
            self.failed_tracking_fd = fd
            self.failed_tracking_event = len(self.events)
            raise OSError(errno.ENOSPC, 'setter failed after changing held inode')
        return result

    def cancel(self):
        if not self.cancelled:
            self.cancelled = True
            self.cancel_event = len(self.events)


class DescriptorOwnership(unittest.TestCase):
    def setUp(self):
        self.symlink_flag = mock.patch.object(os, 'O_SYMLINK', 0x200000, create=True)
        self.symlink_flag.start()
        self.addCleanup(self.symlink_flag.stop)

    def session(self, *, reuse=False):
        source, destination = first_recipe_model()
        inner = (ReusingFakeOps if reuse else model.FakeOps)(source, destination)
        observer = OpsObserver(inner)
        original = {tuple(row['device_inode']): deepcopy(inner.nodes[tuple(row['device_inode'])])
                    for row in source['entries'].values()}
        session = restore.Session('private', 'source', 'parent', source, ops=observer,
                                  cancelled=lambda: observer.cancelled)
        self.addCleanup(session.close)
        return session, observer, source, destination, original

    def assert_source_unchanged(self, observer, original):
        self.assertEqual({key: observer.inner.nodes[key] for key in original}, original)

    def finish(self, session, observer, *, uncertain=False):
        observer.phase = 'final_close'
        self.assertEqual(session.close(), not uncertain)
        attempts = Counter(token for _, token, _ in observer.close_events)
        self.assertTrue(all(count == 1 for count in attempts.values()))
        self.assertEqual(observer.duplicate_closes, [])
        self.assertEqual(observer.invalid_fd_uses, [])
        self.assertEqual(set(range(1, observer.serial + 1)), observer.confirmed_closed | set(observer.live.values()))
        self.assertFalse(observer.confirmed_closed & observer.uncertain)
        self.assertEqual(set(observer.live.values()), observer.uncertain)
        self.assertLessEqual(observer.peak, 16)
        before = len(observer.close_events)
        self.assertEqual(session.close(), not uncertain)
        self.assertEqual(len(observer.close_events), before)

    def assert_final_model(self, observer, source):
        inner = observer.inner
        root = inner.names[(81, 'output')]
        actual = {}
        for name in sorted(source['entries'], key=lambda value: (value.count('/') + bool(value), value)):
            if not name: node = root
            else:
                parent, leaf = restore.relative(name)
                node = inner.names[(actual[parent]['info'].st_ino, leaf)]
            actual[name] = node
            expected, info = source['entries'][name], node['info']
            self.assertEqual((stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid, info.st_flags, info.st_mtime_ns),
                (expected['mode'], expected['uid'], expected['gid'], expected['flags'], expected['mtime_ns']))
            self.assertEqual(node['row']['acl'], expected['acl'])
            for field in ('size', 'sha256', 'holes', 'xattrs', 'symlink_bytes'):
                self.assertEqual(node['row'].get(field), expected.get(field))
            self.assertEqual(info.st_atime_ns, expected['atime_ns'])
            self.assertNotEqual((info.st_dev, info.st_ino), tuple(expected['device_inode']))
        expected_classes, actual_classes = {}, {}
        for name, expected in source['entries'].items():
            if expected['kind'] != 'directory':
                expected_classes.setdefault(tuple(expected['device_inode']), []).append(name)
                info = actual[name]['info']
                actual_classes.setdefault((info.st_dev, info.st_ino), []).append(name)
        self.assertEqual(sorted(sorted(names) for names in actual_classes.values()),
                         sorted(sorted(names) for names in expected_classes.values()))
        for names in actual_classes.values():
            self.assertTrue(all(actual[name]['info'].st_nlink == len(names) for name in names))
        self.assertTrue(set(actual_classes).isdisjoint(expected_classes))

    def test_full_eighteen_entry_model_bounds_actual_handles_and_balances_borrowed_anchors(self):
        for reuse in (False, True):
            with self.subTest(reuse=reuse):
                session, observer, source, destination, original = self.session(reuse=reuse)
                kinds = Counter(row['kind'] for row in source['entries'].values())
                self.assertEqual(kinds, {'directory': 6, 'file': 8, 'symlink': 4})
                self.assertEqual(max(name.count('/') + bool(name) for name, row in source['entries'].items()
                                     if row['kind'] == 'directory'), 2)
                self.assertEqual(sorted(map(len, source['hardlink_groups'])), [2, 3, 3])
                self.assertEqual({restore.relative(name)[0] for name in source['hardlink_groups'][0]}, {'a', 'b', 'c'})
                observer.phase = 'restore'
                result = session.restore(destination)
                self.assertEqual(result['status'], 'restored_pending_final_verifiers')
                self.assertEqual(observer.anchor_opens, {'base': 1, 'source': 1, 'parent': 1, 'destination': 1})
                self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
                anchor_tokens = {token for _, token in observer.anchors.values()}
                self.assertTrue(all(token not in anchor_tokens for _, token, _ in observer.close_events))
                self.assertEqual((observer.calls['unlink'], observer.calls['link']), (5, 5))
                self.assertGreaterEqual(observer.calls['fstat'], observer.serial)
                self.assertGreater(observer.calls['named'], 0)
                self.assert_final_model(observer, source)
                self.assert_source_unchanged(observer, original)
                self.finish(session, observer)
                if reuse:
                    self.assertLess(len({fd for fd, _, _ in observer.open_events}), observer.serial)

    def test_provisional_returned_descriptor_is_counted_and_closed_on_stat_failure(self):
        session, observer, _, destination, original = self.session()
        observer.phase = 'restore'
        observer.fail_provisional_stat = True
        self.assertEqual(session.restore(destination)['status'], 'incomplete')
        self.assertIsNotNone(observer.provisional_failure)
        _, token, live_at_failure = observer.provisional_failure
        self.assertGreaterEqual(observer.peak, live_at_failure)
        self.finish(session, observer)
        self.assertIn(token, observer.confirmed_closed)
        self.assert_source_unchanged(observer, original)

    def test_uncertain_close_stops_acquisition_and_never_retries_or_claims_zero_unknown_handles(self):
        for error_mode in ('before', 'after'):
            with self.subTest(error_mode=error_mode):
                session, observer, _, destination, original = self.session(reuse=True)
                observer.phase = 'restore'
                observer.close_error_mode = error_mode
                self.assertEqual(session.restore(destination)['status'], 'incomplete')
                self.assertEqual(len(observer.uncertain), 1)
                after_error = observer.events[observer.first_uncertain_event:]
                self.assertFalse(any(event[0] == 'open_attempt' for event in after_error))
                self.finish(session, observer, uncertain=True)
                self.assertEqual(observer.close_error_fd in observer.inner.descriptors, error_mode == 'before')
                self.assert_source_unchanged(observer, original)

    def test_cancel_after_unlink_closes_owned_windows_without_replacement_link(self):
        session, observer, _, destination, original = self.session(reuse=True)
        observer.phase = 'restore'
        observer.cancel_after = 'unlink'
        self.assertEqual(session.restore(destination)['status'], 'incomplete')
        self.assertTrue(observer.cancelled)
        self.assertEqual(observer.calls['unlink'], 1)
        self.assertEqual(observer.calls['link'], 0)
        self.assertFalse(any(event[0] == 'open_attempt' for event in observer.events[observer.cancel_event:]))
        self.finish(session, observer)
        self.assert_source_unchanged(observer, original)

    def test_cancel_after_blocker_clear_recovers_through_still_owned_descriptor(self):
        session, observer, _, destination, original = self.session(reuse=True)
        observer.phase = 'restore'
        observer.cancel_after = 'blocker_clear'
        self.assertEqual(session.restore(destination)['status'], 'incomplete')
        self.assertTrue(observer.cancelled)
        self.assertIsNotNone(observer.cleared_blocker)
        flags = [event[2] for event in observer.events if event[:2] == ('flags', observer.cleared_blocker)]
        self.assertEqual(flags[-1] & 6, observer.cleared_blocking_bits)
        self.assertEqual(observer.cleared_node['info'].st_flags & 6, observer.cleared_blocking_bits)
        self.assertFalse(any(event[0] == 'open_attempt' for event in observer.events[observer.cancel_event:]))
        self.finish(session, observer)
        self.assert_source_unchanged(observer, original)

    def test_partial_tracking_setter_failure_preserves_tracking_during_held_inode_recovery(self):
        session, observer, _, destination, original = self.session(reuse=True)
        observer.phase = 'restore'
        observer.fail_tracking_after_clear = True
        self.assertEqual(session.restore(destination)['status'], 'incomplete')
        self.assertIsNotNone(observer.failed_tracking_fd)
        self.assertFalse(any(event[0] == 'open_attempt' for event in observer.events[observer.failed_tracking_event:]))
        flags = [event[2] for event in observer.events if event[:2] == ('flags', observer.failed_tracking_fd)]
        self.assertEqual(flags[-2:], [64, 64 | observer.cleared_blocking_bits])
        self.assertEqual(observer.cleared_node['info'].st_flags, 64 | observer.cleared_blocking_bits)
        self.finish(session, observer)
        self.assert_source_unchanged(observer, original)

    def read_pass(self, session, *, capture):
        if capture:
            session.capture(session.source_root, session.expected, session.source)
        else:
            session.verify_tree(session.source, session.source_root)

    def after_first_sibling(self, observer, callback):
        close = observer.close; fired = []
        def after_close(fd):
            inode = observer.inner.descriptors[fd]['info'].st_ino
            close(fd)
            if inode == 3 and not fired:
                fired.append(True); callback()
        return mock.patch.object(observer, 'close', side_effect=after_close)

    def test_read_pass_reuses_only_adjacent_parent_and_closes_leaf_before_next_entry(self):
        for capture in (False, True):
            with self.subTest(capture=capture):
                session, observer, _, _, original = self.session(reuse=True)
                baseline = deepcopy(session.source); opened = []; closure_live = []
                open_call = observer.open; verify = session.verify_tree
                observer.phase = 'read_pass'
                def track_open(name, flags, *, dir_fd=None):
                    parent_token = observer.live.get(dir_fd)
                    start = len(observer.events)
                    fd = open_call(name, flags, dir_fd=dir_fd)
                    opened.append((observer.phase, name, dir_fd, parent_token,
                                   observer.live[fd], start, set(observer.confirmed_closed)))
                    return fd
                def closure(records, root):
                    closure_live.append(set(observer.live.values()))
                    observer.phase = 'closure'
                    return verify(records, root)
                with mock.patch.object(observer, 'open', side_effect=track_open):
                    if capture:
                        with mock.patch.object(session, 'verify_tree', side_effect=closure):
                            self.read_pass(session, capture=True)
                    else:
                        self.read_pass(session, capture=False)
                phases = ('read_pass', 'closure') if capture else ('read_pass',)
                parent_tokens = []
                for phase in phases:
                    leaves = [event for event in opened if event[0] == phase and event[1] in ('file', 'link')]
                    first, sibling = leaves[:2]
                    self.assertEqual((first[1], sibling[1]), ('file', 'link'))
                    self.assertEqual(first[3], sibling[3])
                    self.assertIn(first[4], sibling[6])
                    self.assertNotIn(first[3], sibling[6])
                    guards = observer.events[first[5] + 1:sibling[5]]
                    self.assertIn(('fstat', session.source_root), guards)
                    self.assertIn(('fstat', sibling[2]), guards)
                    self.assertIn(('named', session.source_root, 'a'), guards)
                    # The next sibling group must acquire a different allocation.
                    self.assertNotEqual(sibling[3], leaves[2][3])
                    self.assertIn(sibling[3], leaves[2][6])
                    parent_tokens.append(first[3])
                if capture:
                    anchors = {token for _, token in observer.anchors.values()}
                    self.assertEqual(closure_live, [anchors])
                    self.assertNotEqual(*parent_tokens)
                self.assertEqual(session.source, baseline)
                self.assert_source_unchanged(observer, original)
                self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
                self.finish(session, observer)

    def test_read_parent_rechecks_original_full_held_signature_and_named_identity(self):
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_size', 'st_nlink',
                  'st_flags', 'st_mtime_ns', 'st_ctime_ns', 'st_birthtime', 'st_gen')
        for capture in (False, True):
            for change in (*fields, 'held_type', 'root_mode', 'named_directory', 'named_symlink'):
                with self.subTest(capture=capture, change=change):
                    session, observer, _, _, _ = self.session(reuse=True)
                    baseline = deepcopy(session.source); changed_at = []
                    def drift():
                        info = observer.inner.nodes[(7, 2)]['info']
                        if change == 'root_mode':
                            observer.inner.nodes[(7, 1)]['info'].st_mode ^= 0o100
                        elif change == 'held_type':
                            info.st_mode = stat.S_IFLNK | stat.S_IMODE(info.st_mode)
                        elif change.startswith('named_'):
                            kind = change.removeprefix('named_')
                            observer.inner.names[(1, 'a')] = observer.inner.node(model.row(kind, 79))
                        else:
                            setattr(info, change, getattr(info, change, 0) + 1)
                        changed_at.append(len(observer.events))
                    with self.after_first_sibling(observer, drift):
                        with self.assertRaisesRegex(restore.RestoreError, '^source_changed$'):
                            self.read_pass(session, capture=capture)
                    self.assertTrue(changed_at)
                    self.assertFalse(any(event[0] == 'open_attempt' for event in observer.events[changed_at[0]:]))
                    self.assertEqual(session.source, baseline)
                    self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
                    self.finish(session, observer)

        for change in ('healthy', 'outer_held', 'outer_named', 'inner_held', 'inner_named'):
            with self.subTest(depth=2, change=change):
                session, observer, _, _, _ = self.session(reuse=True)
                baseline = deepcopy(session.source)
                parents = restore._ReadParent(session, session.source, session.source_root)
                try:
                    parents.get('metadata-fixture/subdir')
                    self.assertEqual(len(parents.frames), 2)
                    outer, inner = parents.frames
                    tokens = {observer.live[frame['fd']] for frame in parents.frames}
                    if change.endswith('_held'):
                        inode = 9 if change.startswith('outer_') else 11
                        observer.inner.nodes[(7, inode)]['info'].st_ctime_ns += 1
                    elif change.endswith('_named'):
                        binding = (1, 'metadata-fixture') if change.startswith('outer_') else (9, 'subdir')
                        observer.inner.names[binding] = observer.inner.nodes[(7, 2)]
                    start = len(observer.events); serial = observer.serial
                    if change == 'healthy':
                        self.assertEqual(parents.get('metadata-fixture/subdir'), inner['fd'])
                        self.assertEqual(observer.events[start:], [
                            ('fstat', session.source_root), ('fstat', outer['fd']),
                            ('named', session.source_root, 'metadata-fixture'),
                            ('fstat', inner['fd']), ('named', outer['fd'], 'subdir')])
                    else:
                        with self.assertRaisesRegex(restore.RestoreError, '^source_changed$'):
                            parents.get('metadata-fixture/subdir')
                    self.assertEqual(observer.serial, serial)
                    self.assertFalse(any(event[0] == 'open_attempt' for event in observer.events[start:]))
                    self.assertEqual(session.source, baseline)
                finally:
                    parents.close()
                self.assertTrue(tokens <= observer.confirmed_closed)
                self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
                self.finish(session, observer)

    def test_read_parent_cancellation_between_siblings_only_drains_owned_handles(self):
        for capture in (False, True):
            with self.subTest(capture=capture):
                session, observer, _, _, original = self.session(reuse=True)
                with self.after_first_sibling(observer, observer.cancel):
                    with self.assertRaisesRegex(restore.RestoreError, '^restoration_cancelled$'):
                        self.read_pass(session, capture=capture)
                self.assertTrue(observer.cancelled)
                self.assertTrue(all(event[0] == 'close' for event in observer.events[observer.cancel_event:]))
                self.assert_source_unchanged(observer, original)
                self.finish(session, observer)

    def test_read_parent_partial_acquisition_closes_leaf_or_new_ancestor_once(self):
        for capture in (False, True):
            for failure in ('leaf', 'ancestor'):
                with self.subTest(capture=capture, failure=failure):
                    session, observer, _, _, original = self.session(reuse=True)
                    open_call = observer.open; subdirs = []
                    def fail_stat(name, flags, *, dir_fd=None):
                        fd = open_call(name, flags, dir_fd=dir_fd)
                        if name == 'subdir': subdirs.append(fd)
                        if ((failure == 'leaf' and name == 'link') or
                            (failure == 'ancestor' and name == 'subdir' and len(subdirs) == 2)):
                            observer.fail_provisional_stat = True
                        return fd
                    with mock.patch.object(observer, 'open', side_effect=fail_stat):
                        with self.assertRaises(OSError): self.read_pass(session, capture=capture)
                    self.assertIsNotNone(observer.provisional_failure)
                    _, token, _ = observer.provisional_failure
                    self.assertIn(token, observer.confirmed_closed)
                    self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
                    self.assert_source_unchanged(observer, original)
                    self.finish(session, observer)

    def test_read_parent_uncertain_close_detaches_owner_and_only_drains_remaining_handles(self):
        for capture in (False, True):
            for position in ('leaf', 'parent_switch', 'pass_exit'):
                for error_mode in ('before', 'after'):
                    with self.subTest(capture=capture, position=position, error_mode=error_mode):
                        session, observer, _, _, original = self.session(reuse=True)
                        close = observer.close; matches = []
                        inode, occurrence = {'leaf': (3, 1), 'parent_switch': (2, 2), 'pass_exit': (11, 2)}[position]
                        def fail_close(fd):
                            if observer.inner.descriptors[fd]['info'].st_ino == inode:
                                matches.append(fd)
                                if len(matches) == occurrence: observer.close_error_mode = error_mode
                            close(fd)
                        with mock.patch.object(observer, 'close', side_effect=fail_close):
                            # release() preserves an active primary exception; the
                            # read pass must still refuse reuse or success afterward.
                            try: raise RuntimeError('handled caller error')
                            except RuntimeError:
                                with self.assertRaisesRegex(restore.RestoreError, '^restoration_close_failed$'):
                                    self.read_pass(session, capture=capture)
                        self.assertEqual(len(observer.uncertain), 1)
                        after_error = observer.events[observer.first_uncertain_event:]
                        self.assertTrue(all(event[0] == 'close' for event in after_error))
                        self.assertEqual(observer.close_error_fd in observer.inner.descriptors, error_mode == 'before')
                        self.assert_source_unchanged(observer, original)
                        self.finish(session, observer, uncertain=True)

    def test_read_parent_is_drained_before_mutation_classes(self):
        session, observer, _, destination, original = self.session(reuse=True)
        begin = session.begin_class; checked = []
        def begin_without_read_handles(names, canonical):
            self.assertEqual(set(observer.live.values()), {token for _, token in observer.anchors.values()})
            checked.append(canonical)
            return begin(names, canonical)
        with mock.patch.object(session, 'begin_class', side_effect=begin_without_read_handles):
            self.assertEqual(session.restore(destination)['status'], 'restored_pending_final_verifiers')
        self.assertTrue(checked)
        self.assert_source_unchanged(observer, original)
        self.finish(session, observer)
