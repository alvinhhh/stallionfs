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
        if entry['kind'] == 'directory':
            entry['link_count'] = 2 + sum(bool(child) and restore.relative(child)[0] == name for child in entries)
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
        node = (self.root if dir_fd is None else self.descriptors[dir_fd] if name == '.' else
                self.names[(self.descriptors[dir_fd]['info'].st_ino, name)])
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
        p.st_nlink -= 1; p.st_size -= 16; p.st_mtime_ns += 1; p.st_ctime_ns += 1

    def link(self, parent, name, target, alias):
        self.called('link', parent, name, target, alias)
        p = self.descriptors[target]['info']; restore.need(p.st_mode & 0o300 == 0o300)
        restore.need((p.st_ino, alias) not in self.names)
        node = self.names[(self.descriptors[parent]['info'].st_ino, name)]
        self.names[(p.st_ino, alias)] = node; node['info'].st_nlink += 1; node['info'].st_ctime_ns += 1
        p.st_nlink += 1; p.st_size += 16; p.st_mtime_ns += 1; p.st_ctime_ns += 1

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

    def test_class_metadata_order_aliases_first_blockers_last_per_inode_and_directories_postorder(self):
        session, ops = self.session(); source_before = deepcopy({key: value for key, value in ops.nodes.items() if key[1] < 100})
        protected_flags, directory_times = [], []
        flags, times = ops.flags, ops.times
        def flagging(fd, value):
            if ops.descriptors[fd]['info'].st_ino == self.destination['entries']['protected']['device_inode'][1]:
                protected_flags.append(value)
            flags(fd, value)
        def timing(fd, value):
            directory_times.append(ops.descriptors[fd]['info'].st_ino)
            times(fd, value)
        ops.flags, ops.times = flagging, timing
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'restored_pending_final_verifiers')
        self.assertEqual((value['alias_replacements'], value['acl_repairs'], value['tracking_repairs'], value['directory_times']), (2, 1, 4, 2))
        events = self.mutations(ops); kinds = [event[0] for event in events]
        self.assertLess(kinds.index('mode'), kinds.index('unlink'))
        self.assertLess(kinds.index('flags'), kinds.index('copy_acl'))
        self.assertEqual(protected_flags, [0, 64, 66])
        self.assertLess(max(i for i, kind in enumerate(kinds) if kind in ('unlink', 'link')), kinds.index('flags'))
        self.assertEqual(directory_times, [session.destination['nested']['info'].st_ino, session.destination['']['info'].st_ino])
        self.assertTrue(all('fd' not in record for record in (*session.source.values(), *session.destination.values())))
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

    def test_verified_alias_parent_size_and_exact_nlink_changes_on_unlink_and_link_are_admitted(self):
        session, ops = self.session(); changes = []
        parent_info = ops.nodes[tuple(self.destination['entries']['nested']['device_inode'])]['info']
        initial, links = parent_info.st_size, parent_info.st_nlink
        unlink, link = ops.unlink, ops.link
        def removing(parent, name):
            unlink(parent, name); info = ops.fstat(parent); changes.append((info.st_size, info.st_nlink))
        def linking(parent, name, target, alias):
            link(parent, name, target, alias); info = ops.fstat(target); changes.append((info.st_size, info.st_nlink))
        ops.unlink, ops.link = removing, linking
        result = session.restore(self.destination)
        self.assertEqual(result['status'], 'restored_pending_final_verifiers')
        self.assertEqual(changes, [(initial - 16, links - 1), (initial, links)] * result['alias_replacements'])
        self.assertEqual(result['alias_replacements'], 2)  # regular and symlink classes
        self.assertNotIn('failure_context', result)
        for name, record in session.destination.items():
            self.assertEqual(record['entry_id'], f'e{sorted(self.destination["entries"]).index(name) + 1:04}')

    def test_alias_parent_nlink_requires_exact_delta_and_reports_only_opaque_failure_context(self):
        for operation, deltas in (('unlink', (0, 1, -2)), ('link', (0, -1, 2))):
            for delta in deltas:
                with self.subTest(operation=operation, delta=delta):
                    session, ops = self.session(); original = getattr(ops, operation)
                    def mutation(*args):
                        parent = args[0] if operation == 'unlink' else args[2]
                        before = ops.descriptors[parent]['info'].st_nlink
                        original(*args)
                        ops.descriptors[parent]['info'].st_nlink = before + delta
                    setattr(ops, operation, mutation)
                    result = session.restore(self.destination)
                    self.assertEqual((result['status'], result['error'], result['alias_replacements']), ('incomplete', 'identity_changed', 0))
                    context = result['failure_context']
                    self.assertEqual(context, {'operation': 'alias_' + operation, 'phase': 'refresh', 'check': 'refresh',
                        'entry_id': 'e0002', 'field': 'nlink'})
                    self.assertEqual(set(context), {'operation', 'phase', 'check', 'entry_id', 'field'})
                    self.assertNotIn('nested', str(context)); self.assertNotIn('before', context); self.assertNotIn('after', context)
                    if operation == 'unlink': self.assertFalse(any(call[0] == 'link' for call in ops.calls))
                    self.assertEqual([call[0] for call in self.mutations(ops)].count(operation), 1)

    def test_active_alias_drift_stops_link_and_inactive_drift_fails_final_inventory(self):
        for drift in ('unrelated_size', 'unrelated_nlink', 'victim_size', 'parent_identity', 'parent_mode', 'parent_nlink'):
            with self.subTest(drift=drift):
                session, ops = self.session(); unlink = ops.unlink
                def removing(parent, name):
                    victim = ops.names[(ops.descriptors[parent]['info'].st_ino, name)]
                    unlink(parent, name)
                    if drift == 'unrelated_size':
                        ops.nodes[tuple(self.destination['entries']['protected']['device_inode'])]['info'].st_size += 1
                    elif drift == 'unrelated_nlink':
                        ops.nodes[tuple(self.destination['entries']['protected']['device_inode'])]['info'].st_nlink += 1
                    elif drift == 'victim_size': victim['info'].st_size += 1
                    elif drift == 'parent_identity': ops.descriptors[parent]['info'].st_ino += 1
                    elif drift == 'parent_mode': ops.descriptors[parent]['info'].st_mode ^= 0o040
                    else: ops.descriptors[parent]['info'].st_nlink += 1
                ops.unlink = removing
                result = session.restore(self.destination)
                self.assertEqual(result['status'], 'incomplete')
                self.assertEqual(result['error'], 'identity_changed')
                if drift not in ('unrelated_size', 'unrelated_nlink'):
                    self.assertEqual(result['alias_replacements'], 0)
                    self.assertFalse(any(call[0] == 'link' for call in ops.calls))
                # Inactive unrelated names are checked on their next lease or
                # final inventory, not continuously pinned across this edit.
                self.assertIn(result['failure_context']['field'], ('identity', 'mode', 'size', 'nlink'))

    def test_merged_external_foreign_setid_unknown_field_content_type_and_sparse_mismatches_refuse_before_mutation(self):
        variants = []
        def variant(edit):
            left, right = deepcopy(self.source), deepcopy(self.destination); edit(left, right); variants.append((left, right))
        variant(lambda a, b: b['entries']['protected'].update(device_inode=b['entries']['nested/a-file']['device_inode']))
        variant(lambda a, b: b['entries']['protected'].update(link_count=2))
        variant(lambda a, b: a['entries']['protected'].update(uid=os.geteuid() + 1))
        variant(lambda a, b: a['entries']['protected'].update(mode=0o4640, gid=os.getegid() + 1))
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

    def test_failed_acl_repair_preserves_tracking_without_starting_later_blocker_classes(self):
        session, ops = self.session(); ops.fail = 'copy_acl'
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'incomplete')
        self.assertTrue(ops.nodes[tuple(self.destination['entries']['nested/a-file']['device_inode'])]['info'].st_flags & 64)
        self.assertEqual(ops.nodes[tuple(self.destination['entries']['protected']['device_inode'])]['info'].st_flags, 2)
        self.assertEqual(session.changed_flags, {})

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

    @unittest.skipUnless(sys.platform == 'darwin', 'Darwin descriptor ABI inspection')
    def test_actual_darwin_adapter_symbols_and_abi_exist_without_native_operations(self):
        self.symlink_flag.stop()
        ops = restore.DarwinOps()
        pointer, integer, size = ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t
        expected = (
            ('fchflags', [integer, ctypes.c_uint32], integer),
            ('acl_get_fd_np', [integer, integer], pointer), ('acl_init', [integer], pointer),
            ('acl_free', [pointer], integer), ('acl_to_text', [pointer, ctypes.POINTER(ctypes.c_ssize_t)], pointer),
            ('acl_size', [pointer], ctypes.c_ssize_t),
            ('acl_copy_ext', [pointer, pointer, ctypes.c_ssize_t], ctypes.c_ssize_t),
            ('acl_valid', [pointer], integer), ('acl_set_fd_np', [integer, pointer, integer], integer),
            ('acl_get_entry', [pointer, integer, ctypes.POINTER(pointer)], integer),
            ('acl_get_tag_type', [pointer, ctypes.POINTER(integer)], integer),
            ('acl_get_flagset_np', [pointer, ctypes.POINTER(pointer)], integer),
            ('acl_get_flag_np', [pointer, integer], integer),
            ('acl_get_permset_mask_np', [pointer, ctypes.POINTER(ctypes.c_uint64)], integer),
            ('flistxattr', [integer, pointer, size, integer], ctypes.c_ssize_t),
            ('fgetxattr', [integer, ctypes.c_char_p, pointer, size, ctypes.c_uint32, integer], ctypes.c_ssize_t))
        for name, arguments, result in expected:
            with self.subTest(symbol=name):
                function = getattr(ops.libc, name)
                self.assertEqual(function.argtypes, arguments); self.assertIs(function.restype, result)
        for name in ('open', 'close', 'fstat', 'stat', 'fchmod', 'unlink', 'link', 'readlink'):
            self.assertTrue(callable(getattr(os, name)), name)
        for name in ('O_RDONLY', 'O_DIRECTORY', 'O_SYMLINK', 'O_NOFOLLOW', 'O_CLOEXEC', 'O_NONBLOCK'):
            self.assertIsInstance(getattr(os, name), int)
        for function in (os.open, os.stat, os.unlink, os.link, os.readlink):
            self.assertIn(function, os.supports_dir_fd)
        for function in (os.stat, os.link): self.assertIn(function, os.supports_follow_symlinks)
        with mock.patch.object(ops, 'call') as call:
            ops.times(7, -1)
        function, descriptor, times = call.call_args.args
        self.assertIs(function, ops.libc.futimens); self.assertEqual(descriptor, 7)
        self.assertIs(function.restype, integer); self.assertIs(function.argtypes[0], integer)
        self.assertEqual(function.argtypes[1]._type_._fields_, [('seconds', ctypes.c_long), ('nanoseconds', ctypes.c_long)])
        self.assertEqual(ctypes.sizeof(times._type_), 16)
        self.assertEqual((times[0].nanoseconds, times[1].seconds, times[1].nanoseconds), (-2, -1, 999999999))

    def test_flags_adapter_uses_libc_without_os_fchflags_and_preserves_immediate_errno(self):
        for outcome in ('success', 'errno', 'no_errno'):
            with self.subTest(outcome=outcome):
                library = mock.Mock()
                def flags(fd, mask):
                    self.assertEqual(ctypes.get_errno(), 0)
                    self.assertEqual((fd, mask), (7, 0x42))
                    if outcome == 'errno': ctypes.set_errno(errno.EPERM)
                    return 0 if outcome == 'success' else -1
                library.fchflags.side_effect = flags
                with mock.patch.object(restore.sys, 'platform', 'darwin'), mock.patch.object(restore.ctypes, 'CDLL', return_value=library), \
                     mock.patch.dict(os.__dict__):
                    os.__dict__.pop('fchflags', None)
                    self.assertFalse(hasattr(os, 'fchflags'))
                    ops = restore.DarwinOps(); ctypes.set_errno(errno.ENOENT)
                    if outcome == 'success': ops.flags(7, 0x42)
                    else:
                        with self.assertRaises(OSError) as caught: ops.flags(7, 0x42)
                        self.assertEqual(caught.exception.errno, errno.EPERM if outcome == 'errno' else errno.EIO)
                    # Recovery uses this same adapter and retains newly set tracking.
                    session = restore.Session.__new__(restore.Session); session.ops = ops; session.summary = {}
                    lease = {'fd': 7}
                    session.changed_flags = {7: (lease, 2)}; session.changed_modes = {}
                    session.recovery_identity = mock.Mock(return_value=SimpleNamespace(st_flags=0x40))
                    ctypes.set_errno(errno.ENOENT); session.recover()
                    self.assertEqual(session.summary['recovery'], 'complete' if outcome == 'success' else 'incomplete')
                    session.recovery_identity.assert_called_once_with(lease)
                self.assertEqual(library.fchflags.argtypes, [ctypes.c_int, ctypes.c_uint32])
                self.assertIs(library.fchflags.restype, ctypes.c_int)
                self.assertEqual(library.fchflags.call_args_list, [mock.call(7, 0x42), mock.call(7, 0x42)])

    def test_missing_fchflags_symbol_refuses_before_acquiring_any_owned_descriptor(self):
        library = mock.Mock(); del library.fchflags
        with mock.patch.object(restore.sys, 'platform', 'darwin'), mock.patch.object(restore.ctypes, 'CDLL', return_value=library), \
             mock.patch.object(restore.os, 'open') as opening:
            with self.assertRaises(restore.AdmissionError) as caught:
                restore.Session('PRIVATE-base', 'PRIVATE-source', 'PRIVATE-parent', self.source)
        report = caught.exception.report
        self.assertEqual((report['phase'], report['refusal_code'], report['errno']), ('ops_binding', 'api_unavailable', None))
        self.assertEqual(report['close'], {'status': 'not_needed', 'attempts': 0, 'failures': 0, 'errno': None})
        opening.assert_not_called(); self.assertNotIn('PRIVATE', str(report))

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
        self.assertEqual(before['close']['status'], 'deferred')
        self.assertGreater(before['close']['attempts'], 0)
        self.assertEqual((before['close']['failures'], before['close']['errno']), (0, None))
        self.assertEqual(count, 3); self.assertTrue(session.close())
        after = session.admission_report()
        self.assertEqual((after['status'], after['phase']), ('complete', 'complete'))
        self.assertEqual(after['close'], {'status': 'complete', 'attempts': before['close']['attempts'] + count, 'failures': 0, 'errno': None})
        self.assertTrue(session.close()); self.assertEqual(session.admission_report(), after)
        self.assertEqual(self.mutations(ops), [])

    def test_fixture_acl_fingerprint_uses_complete_bounded_binary_and_preserves_primary_errno(self):
        library = mock.Mock(); library.acl_get_fd_np.return_value = 100; library.acl_valid.return_value = 0
        library.acl_free.return_value = 0; raw = b'\x00\xff\x80whole-object'
        library.acl_size.return_value = len(raw)
        def copy(buffer, acl, length):
            self.assertEqual((acl, length), (100, len(raw)))
            ctypes.memmove(buffer, raw, length); return length
        library.acl_copy_ext.side_effect = copy
        with mock.patch.object(restore.sys, 'platform', 'darwin'), mock.patch.object(restore.ctypes, 'CDLL', return_value=library):
            ops = restore.DarwinOps()
        self.assertEqual(library.acl_size.argtypes, [ctypes.c_void_p]); self.assertIs(library.acl_size.restype, ctypes.c_ssize_t)
        self.assertEqual(library.acl_copy_ext.argtypes, [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ssize_t])
        self.assertIs(library.acl_copy_ext.restype, ctypes.c_ssize_t)
        self.assertEqual(ops.acl_fingerprint(7), raw)
        library.acl_to_text.assert_not_called(); library.acl_set_fd_np.assert_not_called()
        library.acl_free.assert_called_once_with(100)
        for length in (0, 16385):
            library.reset_mock(); library.acl_size.return_value = length
            with self.assertRaises(restore.RestoreError): ops.acl_fingerprint(7)
            library.acl_copy_ext.assert_not_called(); library.acl_free.assert_called_once_with(100)
        library.reset_mock()
        def size_error(_): ctypes.set_errno(errno.EACCES); return -1
        def free_error(_): ctypes.set_errno(errno.EIO); return -1
        library.acl_size.side_effect = size_error; library.acl_free.side_effect = free_error
        with self.assertRaises(OSError) as failed: ops.acl_fingerprint(7)
        self.assertEqual(failed.exception.errno, errno.EACCES); library.acl_free.assert_called_once_with(100)

    def test_empty_fixture_acl_setter_requires_exact_readback_and_frees_once(self):
        for readback in (b'empty', b'changed'):
            with self.subTest(readback=readback):
                ops = restore.DarwinOps.__new__(restore.DarwinOps); ops.libc = library = mock.Mock()
                library.acl_init.return_value = 100; library.acl_valid.return_value = 0
                library.acl_size.return_value = 5; library.acl_set_fd_np.return_value = 0; library.acl_free.return_value = 0
                def copy(buffer, *_): ctypes.memmove(buffer, b'empty', 5); return 5
                library.acl_copy_ext.side_effect = copy; ops.acl_fingerprint = mock.Mock(return_value=readback)
                if readback == b'empty': ops.clear_fixture_acl(7)
                else:
                    with self.assertRaises(restore.RestoreError): ops.clear_fixture_acl(7)
                library.acl_set_fd_np.assert_called_once_with(7, 100, 0x100)
                library.acl_free.assert_called_once_with(100); ops.acl_fingerprint.assert_called_once_with(7)

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
        for inode, name in ((3, 'nested/a-file'), (5, 'protected')):
            with self.subTest(source_entry=name):
                session, ops = self.session(); fired = False; mutation_inodes = []
                baseline = deepcopy(session.source[name]['info'])
                source_before = deepcopy({key: value for key, value in ops.nodes.items() if key[1] < 100})
                def change(operation):
                    nonlocal fired
                    if operation in ('mode', 'flags', 'copy_acl', 'times', 'unlink', 'link'):
                        event = ops.calls[-1]
                        mutation_inodes.append(ops.descriptors[event[2] if operation == 'copy_acl' else event[1]]['info'].st_ino)
                    if operation == 'mode' and not fired:
                        fired = True; ops.nodes[(7, inode)]['info'].st_ctime_ns += 1
                ops.after = change
                value = session.restore(self.destination)
                self.assertEqual((value['status'], value['error']), ('incomplete', 'source_changed'))
                if inode == 3:
                    self.assertFalse(any(call[0] in ('unlink', 'link', 'copy_acl', 'times') for call in ops.calls))
                # The inactive entry is detected at its next source lease;
                # earlier admitted classes may already have completed work.
                self.assertEqual(session.source[name]['info'], baseline)
                self.assertTrue(mutation_inodes); self.assertTrue(all(value >= 100 for value in mutation_inodes))
                source_before[(7, inode)]['info'].st_ctime_ns += 1
                self.assertEqual({key: value for key, value in ops.nodes.items() if key[1] < 100}, source_before)

    def test_cancellation_after_unlink_stops_before_link_without_path_recovery(self):
        session, ops = self.session()
        session.cancelled = lambda: any(call[0] == 'unlink' for call in ops.calls)
        value = session.restore(self.destination)
        self.assertEqual(value['error'], 'restoration_cancelled')
        self.assertEqual(sum(call[0] == 'unlink' for call in ops.calls), 1)
        self.assertFalse(any(call[0] in ('link', 'copy_acl', 'times') for call in ops.calls))

    def test_reopened_source_uses_original_full_signature_without_refreshing_baseline(self):
        for field in ('st_size', 'st_nlink', 'st_mode', 'st_uid', 'st_gid', 'st_flags', 'st_mtime_ns', 'st_ctime_ns', 'st_gen', 'st_birthtime'):
            with self.subTest(field=field):
                session, ops = self.session()
                before = deepcopy(session.source['nested/a-file']['info'])
                source = ops.nodes[(7, 3)]['info']
                setattr(source, field, getattr(source, field, 0) + 1)
                value = session.restore(self.destination)
                self.assertEqual((value['status'], value['error']), ('incomplete', 'source_changed'))
                self.assertEqual(self.mutations(ops), [])
                self.assertEqual(session.source['nested/a-file']['info'], before)

    def test_removed_victim_remains_held_through_link_and_named_replacement_keeps_opaque_id(self):
        session, ops = self.session(); unlink, link = ops.unlink, ops.link; victims = []
        def removing(parent, name):
            victim = ops.names[(ops.descriptors[parent]['info'].st_ino, name)]
            unlink(parent, name); victims.append(victim)
        def linking(parent, name, target, alias):
            victim = victims[-1]
            self.assertEqual(victim['info'].st_nlink, 0)
            self.assertTrue(any(node is victim for node in ops.descriptors.values()))
            self.assertNotIn((ops.descriptors[target]['info'].st_ino, alias), ops.names)
            link(parent, name, target, alias)
            self.assertTrue(any(node is victim for node in ops.descriptors.values()))
        ops.unlink, ops.link = removing, linking
        value = session.restore(self.destination)
        self.assertEqual(value['status'], 'restored_pending_final_verifiers')
        self.assertEqual(len(victims), 2)
        for name in ('nested/z-file', 'nested/z-sym'):
            self.assertEqual(session.destination[name]['entry_id'], f'e{sorted(self.destination["entries"]).index(name) + 1:04}')

    def test_failed_link_recovery_uses_held_parent_without_reopen_and_reports_failed_undo(self):
        for recovery_fails in (False, True):
            with self.subTest(recovery_fails=recovery_fails):
                session, ops = self.session(); mode, link = ops.mode, ops.link; failed_at = []
                def failing_link(*args):
                    failed_at.append(len(ops.calls)); ops.fail = 'link'; link(*args)
                def restoring_mode(fd, value):
                    if failed_at and recovery_fails: ops.fail = 'mode'
                    mode(fd, value)
                ops.mode, ops.link = restoring_mode, failing_link
                value = session.restore(self.destination)
                self.assertEqual(value['status'], 'incomplete')
                self.assertEqual(value['recovery'], 'incomplete' if recovery_fails else 'complete')
                self.assertTrue(failed_at)
                self.assertFalse(any(call[0] == 'open' for call in ops.calls[failed_at[0]:]))
                modes = [call for call in ops.calls[failed_at[0]:] if call[0] == 'mode']
                self.assertEqual(len(modes), 1)

    def test_primary_operation_error_survives_later_ambiguous_close_without_retry(self):
        session, ops = self.session(); copy_acl, close = ops.copy_acl, ops.close; failed = []
        def failed_acl(*args):
            ops.fail = 'copy_acl'
            try: copy_acl(*args)
            finally: ops.fail = 'close'
        def closing(fd):
            if ops.fail == 'close': failed.append(fd)
            close(fd)
        ops.copy_acl, ops.close = failed_acl, closing
        value = session.restore(self.destination)
        self.assertEqual(value['error'], 'restoration_operation_failed')
        self.assertEqual(value['status'], 'incomplete'); self.assertEqual(len(failed), 1)
        self.assertFalse(session.close())
        self.assertEqual(session.summary['error'], 'restoration_operation_failed')
        self.assertEqual(sum(call == ('close', failed[0]) for call in ops.calls), 1)
        self.assertEqual(session.admission_report()['close']['status'], 'incomplete')

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
