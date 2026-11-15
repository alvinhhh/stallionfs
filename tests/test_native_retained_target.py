"""Pure retained-authority checks; only original writer attestation is mocked."""
import copy
import unittest
from unittest.mock import patch
from stallionfs import core, _native_create_authority as authority, _native_binding as binding


class RetainedTarget(unittest.TestCase):
    def setUp(self):
        self.workspace = '1' * 32
        self.anchor = dict(generation=2, committed_end=16384, root_digest='4' * 64)
        self.target = dict(directory='/fixture/workspaces/' + self.workspace, component='image.sfs',
                           parent=[10, 102], file=[10, 103], uuid='5' * 32)
        native = dict(component='image.sfs', parent=[10, 101], object=[10, 102],
                      file=[10, 103], uuid='5' * 32, anchor=self.anchor)
        origin = dict(id=self.workspace, transaction='2' * 32, native_image=native)
        self.origin_target = dict(parent=[10, 100], object=[10, 102], file=[10, 103], uuid='5' * 32)
        guard = dict(core_consumed=True, status=0, parent_close_errno=0, poisoned=False,
                     transaction_active=False, device=10, inode=103, uuid='5' * 32, **self.anchor)
        installation = dict(operation='native-install', id=self.workspace, transaction='2' * 32,
                            target=self.origin_target, complete=True, guard=guard, previous_installation={})
        self.packet = dict(origin=origin, proof={})
        epoch = dict(schema=1, epoch='3' * 32, authority='installation', workspace=self.workspace,
                     transaction='2' * 32, historical=binding.fingerprint(origin, {}, installation),
                     origin_target=self.origin_target, stable=dict(volume_uuid='12345678-1234-1234-1234-123456789abc',
                     collection=100, object=102, file=103), admitted_target=copy.deepcopy(self.target),
                     anchor=self.anchor, guard=guard, complete=True, publication_file_id=104)
        self.packet['hosting'] = dict(binding=epoch, installation=installation)
        mock = patch.object(authority, 'proof'); mock.start(); self.addCleanup(mock.stop)

    def test_exact_historical_target_accepts_with_or_without_hosting(self):
        authority.retained(self.packet, self.target, self.workspace)
        authority.retained({k: self.packet[k] for k in ('origin', 'proof')}, self.target, self.workspace)

    def test_device_component_inode_and_image_uuid_changes_refuse(self):
        changes = ({'parent': [11, 102]}, {'file': [11, 103]},
                   {'parent': [11, 102], 'file': [11, 103]}, {'component': 'different.sfs'},
                   {'parent': [10, 202]}, {'file': [10, 203]}, {'uuid': '6' * 32})
        for hosting in (False, True):
            packet = self.packet if hosting else {k: self.packet[k] for k in ('origin', 'proof')}
            for change in changes:
                with self.subTest(hosting=hosting, change=change), self.assertRaises(core.StallionError):
                    authority.retained(packet, dict(self.target, **change), self.workspace)

    def test_admitted_current_target_does_not_translate_destructive_authority(self):
        packet = copy.deepcopy(self.packet)
        epoch = packet['hosting']['binding']
        epoch['admitted_target']['parent'][0] = epoch['admitted_target']['file'][0] = 11
        epoch['guard'] = dict(epoch['guard'], device=11)
        for device in (11, 12):
            with self.subTest(device=device), self.assertRaises(core.StallionError):
                authority.retained(packet, dict(self.target, parent=[device, 102], file=[device, 103]), self.workspace)
