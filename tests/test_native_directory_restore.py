"""Pure fake-call tests; never launch a helper or invoke native setters."""
from copy import deepcopy
import ctypes
import errno
import importlib.util
import os
from pathlib import Path
import stat
import sys
from types import SimpleNamespace
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('restore_under_test', PERF / 'native_directory_restore.py')
    restore = importlib.util.module_from_spec(spec); spec.loader.exec_module(restore)


def row(kind, inode, *, flags=0, mode=0o640, acl=None, links=1):
    value = {'kind': kind, 'mode': mode, 'uid': os.geteuid(), 'gid': os.getegid(), 'mtime_ns': 100,
             'atime_ns': 71, 'ctime_ns': 50, 'birthtime_ns': None, 'flags': flags,
             'device_inode': [7, inode], 'link_count': links, 'allocated_bytes': 0,
             'acl': {'text_hex': acl, 'unavailable': None}, 'xattrs': {}}
    if kind == 'file': value.update(size=3, sha256='payload', holes={'ranges': []})
    if kind == 'symlink': value['symlink_bytes'] = b'outside-must-never-be-followed'.hex()
    return value


def snapshot(entries):
    groups = {}
    for name, entry in entries.items():
        if entry['kind'] != 'directory': groups.setdefault(tuple(entry['device_inode']), []).append(name)
    return {'entries': entries, 'hardlink_groups': sorted(sorted(names) for names in groups.values() if len(names) > 1),
            'metadata_capabilities': {'platform': 'darwin'}, 'unavailable_fields': []}


def fixtures():
    source = snapshot({'': row('directory', 1, mode=0o550, flags=64),
        'nested': row('directory', 2, mode=0o500),
        'nested/z-file': row('file', 3, flags=64, links=3, acl='allow-read'),
        'nested/a-file': row('file', 3, flags=64, links=3, acl='allow-read'),
        'nested/z-sym': row('symlink', 4, mode=0o777, flags=64, links=3),
        'nested/a-sym': row('symlink', 4, mode=0o777, flags=64, links=3),
        'protected': row('file', 5, flags=66)})
    destination = deepcopy(source)
    for index, entry in enumerate(destination['entries'].values(), 101):
        entry['device_inode'] = [7, index]; entry['link_count'] = 1; entry['flags'] &= ~64
        entry['acl']['text_hex'] = None
        if entry['kind'] == 'directory': entry['mtime_ns'] = 200
    return source, snapshot(destination['entries'])


class FakeOps:
    """In-memory inode/name model, including detached held objects after unlink."""
    def __init__(self, source, destination):
        self.nodes = {}; self.names = {}; self.descriptors = {}; self.next_fd = 1000
        self.calls = []; self.fail = None; self.after = None; self.unsafe_acl = False; self.change_atime = False
        self.root = self.node(row('directory', 80, mode=0o700))
        self.parent = self.node(row('directory', 81, mode=0o700))
        self.names[(80, 'source')] = self.populate(source)
        self.names[(80, 'parent')] = self.parent
        self.names[(81, 'output')] = self.populate(destination)

    def node(self, entry):
        key = tuple(entry['device_inode'])
        if key not in self.nodes:
            self.nodes[key] = {'row': deepcopy(entry), 'info': SimpleNamespace(
                st_dev=key[0], st_ino=key[1], st_mode=entry['mode'] | {'directory': stat.S_IFDIR,
                    'file': stat.S_IFREG, 'symlink': stat.S_IFLNK}[entry['kind']], st_uid=entry['uid'], st_gid=entry['gid'],
                st_size=entry.get('size', 1024 if entry['kind'] == 'directory' else 0),
                st_nlink=entry['link_count'], st_flags=entry['flags'],
                st_mtime_ns=entry['mtime_ns'], st_ctime_ns=entry['ctime_ns'], st_atime_ns=entry['atime_ns'])}
        return self.nodes[key]

    def populate(self, observed):
        nodes = {name: self.node(entry) for name, entry in observed['entries'].items()}
        for name, node in nodes.items():
            if name:
                parent, leaf = restore.relative(name)
                self.names[(nodes[parent]['info'].st_ino, leaf)] = node
        return nodes['']

    def called(self, name, *args):
        self.calls.append((name, *args))
        if self.fail == name:
            self.fail = None
            raise OSError(errno.EIO, 'PRIVATE exception /private/path')
        if self.after:
            self.after(name)

    def open(self, name, flags, *, dir_fd=None):
        self.called('open', name, flags)
        node = self.root if dir_fd is None else self.names[(self.descriptors[dir_fd]['info'].st_ino, name)]
        fd = self.next_fd; self.next_fd += 1; self.descriptors[fd] = node
        return fd

    def close(self, fd):
        self.called('close', fd); del self.descriptors[fd]

    def fstat(self, fd):
        self.called('fstat', fd); return deepcopy(self.descriptors[fd]['info'])

    def named(self, parent, name):
        self.called('named', parent, name)
        key = self.descriptors[parent]['info'].st_ino, name
        if key not in self.names: raise OSError(errno.ENOENT, 'missing')
        return deepcopy(self.names[key]['info'])

    def admit_acl(self, fd, expected):
        self.called('admit_acl', fd)
        restore.need(not self.unsafe_acl and self.descriptors[fd]['row']['acl'] == expected['acl'])

    def payload(self, fd, expected):
        self.called('payload', fd)
        restore.need(all(self.descriptors[fd]['row'].get(key) == expected.get(key)
                         for key in ('size', 'sha256', 'holes', 'xattrs', 'symlink_bytes')))

    def readlink(self, parent, name):
        self.called('readlink', parent, name)
        return self.names[(self.descriptors[parent]['info'].st_ino, name)]['row']['symlink_bytes']

    def flags(self, fd, value):
        self.called('flags', fd, value)
        self.descriptors[fd]['info'].st_flags = value; self.descriptors[fd]['info'].st_ctime_ns += 1

    def mode(self, fd, value):
        self.called('mode', fd, value)
        info = self.descriptors[fd]['info']; info.st_mode = stat.S_IFMT(info.st_mode) | value; info.st_ctime_ns += 1

    def unlink(self, parent, name):
        self.called('unlink', parent, name)
        p = self.descriptors[parent]['info']; restore.need(p.st_mode & 0o300 == 0o300)
        info = self.names.pop((p.st_ino, name))['info']; info.st_nlink -= 1; info.st_ctime_ns += 1
        p.st_size -= 16; p.st_mtime_ns += 1; p.st_ctime_ns += 1

    def link(self, parent, name, target, alias):
        self.called('link', parent, name, target, alias)
        p = self.descriptors[target]['info']; restore.need(p.st_mode & 0o300 == 0o300)
        restore.need((p.st_ino, alias) not in self.names)
        node = self.names[(self.descriptors[parent]['info'].st_ino, name)]
        self.names[(p.st_ino, alias)] = node; node['info'].st_nlink += 1; node['info'].st_ctime_ns += 1
        p.st_size += 16; p.st_mtime_ns += 1; p.st_ctime_ns += 1

    def copy_acl(self, source, destination):
        self.called('copy_acl', source, destination)
        self.descriptors[destination]['row']['acl'] = deepcopy(self.descriptors[source]['row']['acl'])
        self.descriptors[destination]['info'].st_ctime_ns += 1

    def times(self, fd, value):
        self.called('times', fd, value)
        info = self.descriptors[fd]['info']; info.st_mtime_ns = value; info.st_ctime_ns += 1
        if self.change_atime: info.st_atime_ns += 1


class Restoration(unittest.TestCase):
    def setUp(self):
        self.source, self.destination = fixtures()
        self.symlink_flag = mock.patch.object(os, 'O_SYMLINK', 0x200000, create=True)
        self.symlink_flag.start(); self.addCleanup(self.symlink_flag.stop)

    def session(self, source=None, destination=None):
        source = self.source if source is None else source
        destination = self.destination if destination is None else destination
        ops = FakeOps(source, destination)
        session = restore.Session('private', 'source', 'parent', source, ops=ops)
        self.addCleanup(session.close)
        return session, ops

    def mutations(self, ops):
        return [call for call in ops.calls if call[0] in ('flags', 'mode', 'unlink', 'link', 'copy_acl', 'times')]

    def test_metadata_derived_canonicals_include_symlink_classes_and_permit_source_outside_aliases(self):
        derived = restore.plan(self.source, self.destination, os.geteuid())
        self.assertEqual(derived['aliases'], [('nested/a-file', 'nested/z-file'), ('nested/a-sym', 'nested/z-sym')])
        self.assertEqual(derived['acl'], ['nested/a-file'])
        self.assertEqual(len(derived['flags']), 4)
        # Rename every leaf: selection continues to follow metadata, not recipe names.
        changed_source, changed_destination = deepcopy(self.source), deepcopy(self.destination)
        for observed in (changed_source, changed_destination):
            observed['entries'] = {name.replace('file', 'renamed').replace('sym', 'link'): row
                                   for name, row in observed['entries'].items()}
        other = restore.plan(changed_source, changed_destination, os.geteuid())
        self.assertTrue(all('file' not in name and 'sym' not in name for pair in other['aliases'] for name in pair))

    def test_complete_order_permissions_before_aliases_tracking_before_acl_blocking_last_and_atime_preserved(self):
        session, ops = self.session(); source_before = deepcopy({key: value for key, value in ops.nodes.items() if key[1] < 100})
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'restored_pending_final_verifiers')
        self.assertEqual((value['alias_replacements'], value['acl_repairs'], value['tracking_repairs'], value['directory_times']), (2, 1, 4, 2))
        events = self.mutations(ops); kinds = [event[0] for event in events]
        self.assertLess(kinds.index('mode'), kinds.index('unlink'))
        self.assertLess(kinds.index('flags'), kinds.index('copy_acl'))
        self.assertEqual(events[-1][0], 'flags'); self.assertEqual(events[-1][-1], 66)
        protected_fd = session.destination['protected']['fd']
        self.assertEqual([event[-1] for event in events if event[:2] == ('flags', protected_fd)], [0, 64, 66])
        times = [event[1] for event in events if event[0] == 'times']
        self.assertEqual(times, [session.destination['nested']['fd'], session.destination['']['fd']])
        self.assertTrue(all(node['info'].st_atime_ns == 71 for node in ops.nodes.values()))
        self.assertEqual(source_before, {key: value for key, value in ops.nodes.items() if key[1] < 100})
        for first, second in (('nested/a-file', 'nested/z-file'), ('nested/a-sym', 'nested/z-sym')):
            self.assertEqual(restore.identity(session.destination[first]['info']), restore.identity(session.destination[second]['info']))
        self.assertTrue(session.close())

    def test_partial_and_already_correct_destination_classes_use_accounted_names(self):
        for partial in (False, True):
            with self.subTest(partial=partial):
                source, destination = deepcopy(self.source), deepcopy(self.destination)
                if partial:
                    source['entries']['nested/m-file'] = deepcopy(source['entries']['nested/z-file'])
                    for name in ('nested/a-file', 'nested/m-file', 'nested/z-file'):
                        source['entries'][name]['link_count'] = 4
                    destination['entries']['nested/m-file'] = deepcopy(destination['entries']['nested/z-file'])
                    for name in ('nested/m-file', 'nested/z-file'):
                        destination['entries'][name]['link_count'] = 2
                else:
                    destination['entries']['nested/a-file']['device_inode'] = destination['entries']['nested/z-file']['device_inode']
                    for name in ('nested/a-file', 'nested/z-file'):
                        destination['entries'][name]['link_count'] = 2
                session, ops = self.session(source, destination)
                self.assertEqual(session.restore(destination)['status'], 'restored_pending_final_verifiers')
                ids = {restore.identity(record['info']) for name, record in session.destination.items() if name.endswith('file')}
                self.assertEqual(len(ids), 1)
                self.assertEqual(session.summary['alias_replacements'], 3 if partial else 1)

    def test_verified_alias_parent_size_changes_on_both_unlink_and_link_are_admitted(self):
        session, ops = self.session(); changes = []
        initial = ops.nodes[tuple(self.destination['entries']['nested']['device_inode'])]['info'].st_size
        unlink, link = ops.unlink, ops.link
        def removing(parent, name):
            unlink(parent, name); changes.append(ops.fstat(parent).st_size)
        def linking(parent, name, target, alias):
            link(parent, name, target, alias); changes.append(ops.fstat(target).st_size)
        ops.unlink, ops.link = removing, linking
        result = session.restore(self.destination)
        self.assertEqual(result['status'], 'restored_pending_final_verifiers')
        self.assertEqual(changes, [initial - 16, initial] * result['alias_replacements'])
        self.assertGreater(result['alias_replacements'], 0)

    def test_alias_parent_size_admission_does_not_allow_unrelated_size_identity_or_other_parent_drift(self):
        for drift in ('unrelated_size', 'victim_size', 'parent_identity', 'parent_mode', 'parent_nlink'):
            with self.subTest(drift=drift):
                session, ops = self.session(); unlink = ops.unlink
                def removing(parent, name):
                    victim = ops.names[(ops.descriptors[parent]['info'].st_ino, name)]
                    unlink(parent, name)
                    if drift == 'unrelated_size':
                        ops.nodes[tuple(self.destination['entries']['protected']['device_inode'])]['info'].st_size += 1
                    elif drift == 'victim_size': victim['info'].st_size += 1
                    elif drift == 'parent_identity': ops.descriptors[parent]['info'].st_ino += 1
                    elif drift == 'parent_mode': ops.descriptors[parent]['info'].st_mode ^= 0o040
                    else: ops.descriptors[parent]['info'].st_nlink += 1
                ops.unlink = removing
                result = session.restore(self.destination)
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['error'], 'identity_changed')
                self.assertEqual(result['alias_replacements'], 0)
                self.assertFalse(any(call[0] == 'link' for call in ops.calls))

    def test_merged_external_foreign_setid_unknown_field_content_type_and_sparse_mismatches_refuse_before_mutation(self):
        variants = []
        def variant(edit):
            left, right = deepcopy(self.source), deepcopy(self.destination); edit(left, right); variants.append((left, right))
        variant(lambda a, b: b['entries']['protected'].update(device_inode=b['entries']['nested/a-file']['device_inode']))
        variant(lambda a, b: b['entries']['protected'].update(link_count=2))
        variant(lambda a, b: a['entries']['protected'].update(uid=os.geteuid() + 1))
        variant(lambda a, b: a['entries']['protected'].update(mode=0o4640))
        variant(lambda a, b: b['entries']['protected'].update(future_metadata='PRIVATE'))
        variant(lambda a, b: b['entries']['protected'].update(sha256='changed'))
        variant(lambda a, b: b['entries']['protected'].update(kind='symlink'))
        variant(lambda a, b: b['entries']['protected'].update(holes={'ranges': None}))
        variant(lambda a, b: b['entries']['protected'].update(flags=0x80))
        variant(lambda a, b: b['entries']['nested/a-file'].update(flags=2))
        for left, right in variants:
            with self.subTest(entries=right['entries']):
                ops = FakeOps(left, right)
                try:
                    session = restore.Session('private', 'source', 'parent', left, ops=ops)
                except restore.RestoreError:
                    self.assertEqual(self.mutations(ops), [])
                    continue
                self.addCleanup(session.close)
                self.assertEqual(session.restore(right)['status'], 'incomplete')
                self.assertEqual(self.mutations(ops), [])

    def test_stale_named_identity_and_deny_or_inherited_acl_stop_before_mutation(self):
        session, ops = self.session()
        ops.unsafe_acl = True
        self.assertEqual(session.restore(self.destination)['status'], 'incomplete')
        self.assertEqual(self.mutations(ops), [])
        session, ops = self.session()
        original = ops.named
        def replaced(parent, name):
            value = original(parent, name)
            if name == 'output': value.st_ino += 100000
            return value
        ops.named = replaced
        self.assertEqual(session.restore(self.destination)['status'], 'incomplete')
        self.assertEqual(self.mutations(ops), [])

    def test_link_failure_after_unlink_stops_forward_work_and_only_recovers_held_permissions(self):
        session, ops = self.session(); ops.fail = 'link'
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'incomplete'); self.assertEqual(value['alias_replacements'], 0)
        events = self.mutations(ops); index = next(i for i, event in enumerate(events) if event[0] == 'link')
        self.assertTrue(all(event[0] == 'mode' for event in events[index + 1:]))
        self.assertEqual(sum(event[0] == 'unlink' for event in events), 1)
        self.assertEqual(sum(event[0] == 'link' for event in events), 1)
        self.assertNotIn('PRIVATE', str(value)); self.assertNotIn('/private/path', str(value))

    def test_setter_failures_stop_forward_repairs_and_only_recover_held_flags_or_modes(self):
        for setter in ('mode', 'flags', 'copy_acl', 'times', 'unlink'):
            with self.subTest(setter=setter):
                session, ops = self.session(); ops.fail = setter
                value = session.restore(self.destination)
                self.assertEqual(value['status'], 'incomplete')
                self.assertNotEqual(value['error'], 'PRIVATE exception /private/path')
                events = self.mutations(ops); first = next(i for i, event in enumerate(events) if event[0] == setter)
                # Recovery may only use already-held flags/modes, never aliases, ACLs or times.
                self.assertTrue(all(event[0] in ('flags', 'mode') for event in events[first + 1:]))

    def test_failed_acl_repair_preserves_new_tracking_during_blocker_recovery(self):
        session, ops = self.session(); ops.fail = 'copy_acl'
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'incomplete')
        self.assertTrue(session.destination['nested/a-file']['fd'] in session.changed_flags)
        self.assertTrue(ops.fstat(session.destination['nested/a-file']['fd']).st_flags & 64)
        self.assertEqual(ops.fstat(session.destination['protected']['fd']).st_flags, 66)

    def test_descriptor_acl_admission_rejects_deny_and_inheritance_flags(self):
        for tag, inherited, mask in ((1, False, 2), (2, False, 2), (1, True, 2), (1, False, 4)):
            with self.subTest(tag=tag, inherited=inherited, mask=mask):
                ops = restore.DarwinOps.__new__(restore.DarwinOps)
                library = mock.Mock(); ops.libc = library
                library.acl_get_fd_np.return_value = 100
                library.acl_valid.return_value = 0
                def unsupported_context_validator(*_):
                    ctypes.set_errno(errno.ENOTSUP); return -1
                library.acl_valid_fd_np.side_effect = unsupported_context_validator
                library.acl_free.return_value = 0
                ops.acl_text = lambda _: 'allow-read'
                def flagset(_, output): output._obj.value = 300; return 0
                library.acl_get_flagset_np.side_effect = flagset
                library.acl_get_flag_np.side_effect = lambda _, bit: int(inherited and bit == 16)
                def entry(_, index, output):
                    if index == 0: output._obj.value = 200; return 0
                    ctypes.set_errno(errno.EINVAL); return -1
                library.acl_get_entry.side_effect = entry
                def get_tag(_, output): output._obj.value = tag; return 0
                def permissions(_, output): output._obj.value = mask; return 0
                library.acl_get_tag_type.side_effect = get_tag
                library.acl_get_permset_mask_np.side_effect = permissions
                expected = row('file', 10, acl='allow-read')
                if tag == 1 and not inherited and mask == 2:
                    ops.admit_acl(7, expected)
                else:
                    with self.assertRaises(restore.RestoreError): ops.admit_acl(7, expected)
                library.acl_set_fd_np.assert_not_called()
                library.acl_valid.assert_called_once_with(100)
                library.acl_valid_fd_np.assert_not_called()

    def test_copy_acl_uses_object_validation_and_preserves_primary_error_through_free(self):
        for failing in (None, 'validation', 'setter'):
            for free_failure in (False, True):
                with self.subTest(failing=failing, free_failure=free_failure):
                    ops = restore.DarwinOps.__new__(restore.DarwinOps); library = mock.Mock(); ops.libc = library
                    library.acl_get_fd_np.return_value = 100
                    def validate(_):
                        if failing == 'validation': ctypes.set_errno(errno.EINVAL); return -1
                        return 0
                    def setter(*_):
                        if failing == 'setter': ctypes.set_errno(errno.ENOSPC); return -1
                        return 0
                    def free(_):
                        ctypes.set_errno(errno.EBADF)
                        return -1 if free_failure else 0
                    def unsupported(*_): ctypes.set_errno(errno.ENOTSUP); return -1
                    library.acl_valid.side_effect = validate
                    library.acl_set_fd_np.side_effect = setter
                    library.acl_free.side_effect = free
                    library.acl_valid_fd_np.side_effect = unsupported
                    expected = errno.EINVAL if failing == 'validation' else errno.ENOSPC if failing == 'setter' else errno.EBADF if free_failure else None
                    if expected is None:
                        ops.copy_acl(7, 9)
                    else:
                        with self.assertRaises(OSError) as error: ops.copy_acl(7, 9)
                        self.assertEqual(error.exception.errno, expected)
                    library.acl_get_fd_np.assert_called_once_with(7, 0x100)
                    library.acl_valid.assert_called_once_with(100)
                    library.acl_valid_fd_np.assert_not_called()
                    library.acl_free.assert_called_once_with(100)
                    if failing == 'validation': library.acl_set_fd_np.assert_not_called()
                    else: library.acl_set_fd_np.assert_called_once_with(9, 100, 0x100)

    def test_invalid_acl_admission_captures_only_immediate_errno_and_frees_once(self):
        for native_errno in (None, errno.EINVAL):
            with self.subTest(native_errno=native_errno):
                ops = restore.DarwinOps.__new__(restore.DarwinOps); library = mock.Mock(); ops.libc = library
                library.acl_get_fd_np.return_value = 100
                def invalid(_):
                    if native_errno is not None: ctypes.set_errno(native_errno)
                    return -1
                def free(_): ctypes.set_errno(errno.EPERM); return 0
                library.acl_valid.side_effect = invalid; library.acl_free.side_effect = free
                ops.acl_text = mock.Mock()
                ctypes.set_errno(errno.ENOENT)
                with self.assertRaises(OSError) as error: ops.admit_acl(7, row('file', 3))
                self.assertEqual(error.exception.errno, native_errno or errno.EIO)
                library.acl_free.assert_called_once_with(100); ops.acl_text.assert_not_called()
                library.acl_valid_fd_np.assert_not_called()

    def test_absent_acl_uses_empty_object_and_preserves_getter_or_allocator_errno(self):
        for outcome in ('empty', 'init_failure', 'getter_failure'):
            with self.subTest(outcome=outcome):
                ops = restore.DarwinOps.__new__(restore.DarwinOps); library = mock.Mock(); ops.libc = library
                def getter(*_):
                    ctypes.set_errno(errno.EACCES if outcome == 'getter_failure' else errno.ENOENT)
                    return None
                def initialize(_):
                    if outcome == 'init_failure': ctypes.set_errno(errno.ENOMEM); return None
                    return 100
                def flags(_, output): output._obj.value = 300; return 0
                def end(*_): ctypes.set_errno(errno.EINVAL); return -1
                library.acl_get_fd_np.side_effect = getter; library.acl_init.side_effect = initialize
                library.acl_valid.return_value = 0; library.acl_get_flagset_np.side_effect = flags
                library.acl_get_flag_np.return_value = 0; library.acl_get_entry.side_effect = end
                library.acl_free.return_value = 0; ops.acl_text = mock.Mock(return_value='empty')
                if outcome == 'empty':
                    ops.admit_acl(7, row('file', 3))
                    library.acl_valid.assert_called_once_with(100)
                    library.acl_get_entry.assert_called_once(); library.acl_free.assert_called_once_with(100)
                else:
                    with self.assertRaises(OSError) as error: ops.admit_acl(7, row('file', 3))
                    self.assertEqual(error.exception.errno, errno.ENOMEM if outcome == 'init_failure' else errno.EACCES)
                    library.acl_valid.assert_not_called(); library.acl_free.assert_not_called()
                if outcome == 'getter_failure': library.acl_init.assert_not_called()
                else: library.acl_init.assert_called_once_with(0)
                library.acl_set_fd_np.assert_not_called(); library.acl_valid_fd_np.assert_not_called()

    def test_constructor_binding_failure_reports_no_descriptors_without_exception_text(self):
        library = mock.Mock()
        with mock.patch.object(restore.sys, 'platform', 'darwin'), mock.patch.object(restore.ctypes, 'CDLL', return_value=library) as binding:
            restore.DarwinOps()
        binding.assert_called_once_with(None, use_errno=True)
        self.assertEqual(library.acl_valid.argtypes, [ctypes.c_void_p])
        self.assertIs(library.acl_valid.restype, ctypes.c_int)
        with mock.patch.object(restore, 'DarwinOps', side_effect=AttributeError('PRIVATE /private/path')):
            with self.assertRaises(restore.AdmissionError) as caught:
                restore.Session('PRIVATE-base', 'PRIVATE-source', 'PRIVATE-parent', self.source)
        report = caught.exception.report
        self.assertEqual((report['phase'], report['refusal_code'], report['errno']), ('ops_binding', 'api_unavailable', None))
        self.assertEqual(report['close'], {'status': 'not_needed', 'attempts': 0, 'failures': 0, 'errno': None})
        self.assertNotIn('PRIVATE', str(report)); self.assertNotIn('/private/path', str(report))

    def test_constructor_acl_refusal_retains_primary_errno_and_separate_one_time_close_outcome(self):
        for late in (False, True):
            for close_failure in (False, True):
                with self.subTest(late=late, close_failure=close_failure):
                    ops = FakeOps(self.source, self.destination)
                    ops.fail = None if late else 'admit_acl'
                    original_payload = ops.payload
                    def payload(fd, expected):
                        if len(ops.descriptors) > 3:
                            ops.calls.append(('payload', fd))
                            raise OSError(errno.ENOSPC, 'PRIVATE payload /private/path')
                        original_payload(fd, expected)
                    if late: ops.payload = payload
                    original_close = ops.close; first = True
                    def closing(fd):
                        nonlocal first
                        ctypes.set_errno(errno.EPERM)
                        if close_failure and first:
                            first = False; ops.calls.append(('close', fd))
                            raise OSError(errno.EBADF, 'PRIVATE close /private/path')
                        first = False; original_close(fd)
                    ops.close = closing
                    with self.assertRaises(restore.AdmissionError) as caught:
                        restore.Session('private', 'source', 'parent', self.source, ops=ops)
                    report = caught.exception.report; count = 4 if late else 3
                    self.assertEqual((report['phase'], report['refusal_code'], report['errno']),
                        ('payload' if late else 'acl', 'native_error', errno.ENOSPC if late else errno.EIO))
                    self.assertEqual(report['close'], {'status': 'incomplete' if close_failure else 'complete',
                        'attempts': count, 'failures': int(close_failure), 'errno': errno.EBADF if close_failure else None})
                    closed = [call[1] for call in ops.calls if call[0] == 'close']
                    self.assertEqual(set(closed), set(range(1000, ops.next_fd)))
                    self.assertEqual(len(closed), count); self.assertEqual(len(set(closed)), count)
                    self.assertEqual(self.mutations(ops), [])
                    self.assertNotIn('PRIVATE', str(report)); self.assertNotIn('/private/path', str(report))

    def test_successful_admission_is_complete_before_deferred_owned_descriptors_close(self):
        session, ops = self.session(); count = len(session.owned)
        before = session.admission_report()
        self.assertEqual((before['status'], before['phase']), ('complete', 'complete'))
        self.assertEqual(before['close'], {'status': 'deferred', 'attempts': 0, 'failures': 0, 'errno': None})
        self.assertGreater(count, 3); self.assertTrue(session.close())
        after = session.admission_report()
        self.assertEqual((after['status'], after['phase']), ('complete', 'complete'))
        self.assertEqual(after['close'], {'status': 'complete', 'attempts': count, 'failures': 0, 'errno': None})
        self.assertTrue(session.close()); self.assertEqual(session.admission_report(), after)
        self.assertEqual(self.mutations(ops), [])

    def test_unrecognized_admission_error_and_phase_cannot_export_private_values(self):
        report = restore.refusal_report(restore.RestoreError('PRIVATE /private/path ACL contents'), 'PRIVATE phase')
        self.assertEqual((report['phase'], report['refusal_code'], report['errno']), ('unknown', 'admission_error', None))
        self.assertEqual(report['close']['status'], 'unknown')
        self.assertNotIn('PRIVATE', str(report)); self.assertNotIn('/private/path', str(report))

    def test_native_time_argv_preserves_atime_and_encodes_signed_ns_without_native_call(self):
        ops = restore.DarwinOps.__new__(restore.DarwinOps); ops.libc = mock.Mock()
        captured = []
        ops.libc.futimens.side_effect = lambda fd, values: captured.append((fd,
            [(item.seconds, item.nanoseconds) for item in values])) or 0
        ops.times(7, -3)
        self.assertEqual(captured, [(7, [(0, -2), (-1, 999999997)])])

    def test_source_change_during_forward_work_stops_and_never_writes_source(self):
        session, ops = self.session(); fired = False
        def change(name):
            nonlocal fired
            if name == 'mode' and not fired:
                fired = True; ops.nodes[(7, 5)]['info'].st_ctime_ns += 1
        ops.after = change
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'incomplete'); self.assertEqual(value['error'], 'source_changed')
        self.assertFalse(any(call[0] in ('unlink', 'link', 'copy_acl', 'times') for call in ops.calls))
        self.assertTrue(all(ops.descriptors[event[1]]['info'].st_ino >= 100 for event in self.mutations(ops)))

    def test_cancellation_after_unlink_stops_before_link_without_path_recovery(self):
        session, ops = self.session()
        session.cancelled = lambda: any(call[0] == 'unlink' for call in ops.calls)
        value = session.restore(self.destination)
        self.assertEqual(value['error'], 'restoration_cancelled')
        self.assertEqual(sum(call[0] == 'unlink' for call in ops.calls), 1)
        self.assertFalse(any(call[0] in ('link', 'copy_acl', 'times') for call in ops.calls))

    def test_atime_change_and_close_error_remain_incomplete(self):
        session, ops = self.session(); ops.change_atime = True
        self.assertEqual(session.restore(self.destination)['error'], 'atime_changed')
        session, ops = self.session()
        self.assertEqual(session.restore(self.destination)['status'], 'restored_pending_final_verifiers')
        ops.fail = 'close'
        self.assertFalse(session.close()); self.assertEqual(session.summary['status'], 'incomplete')
        self.assertEqual(session.summary['error'], 'restoration_close_failed')


if __name__ == '__main__':
    unittest.main()
