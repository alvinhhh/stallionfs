"""Synthetic receipt regressions; no producer, image fixture or syscall fault."""
import copy
import errno
import hashlib
from pathlib import Path
import struct
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from native_reliability import BoundImage, pattern, sha
from native_reliability_regressions import valid_observation
import native_reliability_gaps as gaps
from native_reliability_gaps import (check_stored_payload, classify_focused, one,
                                     run_case, sealed_plan, terminal_result, validate_injection)

IDENTITY = (123, 456)
BINDING = dict(A_generation=3, B_generation=4, A_root="a"*64,
               raw_offset=8192, write_ordinal=1, existing_raw_digest="c"*64)


def encoded_payload_chain():
    """Small memory-only input to the existing fixed-fixture evidence decoder."""
    cell = 4096
    uuid = bytes(range(16))
    data = bytearray(8*cell)

    def ref(kind, at):
        page = data[at:at+cell]
        domain = b"SFSDAT06"+uuid+struct.pack("<IQ", 6, cell) if kind == 6 else b""
        value = bytearray(56)
        struct.pack_into("<I", value, 0, kind)
        struct.pack_into("<QQ", value, 8, at, cell)
        value[24:56] = hashlib.sha256(domain+page).digest()
        return value

    def record(at, kind, mapping=None):
        data[at:at+8] = b"SFSREC06"
        struct.pack_into("<I", data, at+8, kind)
        if mapping is not None:
            struct.pack_into("<IHH", data, at+64, mapping, 0, 1)

    raw, extent, inodes, names, namespace, root = [i*cell for i in range(2, 8)]
    data[raw:raw+cell] = pattern(1, 1, cell)
    record(extent, 5, 3)
    data[extent+648:extent+704] = ref(6, raw)
    record(inodes, 5, 1)
    struct.pack_into("<Q", data, inodes+640, 9)
    data[inodes+672:inodes+728] = ref(5, extent)
    record(names, 5, 2)
    struct.pack_into("<QI", data, names+640, 1, 4)
    data[names+652:names+656] = b"file"
    struct.pack_into("<Q", data, names+907, 9)
    record(namespace, 2)
    data[namespace+64:namespace+120] = ref(5, inodes)
    data[namespace+120:namespace+176] = ref(5, names)
    record(root, 4)
    data[root+64:root+120] = ref(2, namespace)
    data[:8] = b"SFSIMG01"
    struct.pack_into("<I", data, 12, 6)
    data[24:40] = uuid
    struct.pack_into("<Q", data, 40, 4)
    data[48:104] = ref(4, root)
    data[112:144] = hashlib.sha256(data[:cell]).digest()
    binding = BoundImage(data).binding(1, 1, 0)
    binding.update(BINDING, existing_raw_digest=binding["existing_raw_digest"])
    return data, binding


def injection(mode):
    replacement = bytearray(pattern(1, 1, 4096))
    if mode == 2:
        replacement[17] ^= 1
    return dict(event="injection", mode=mode, device=123, inode=456, target_matches=1,
                proof_error=0, requested_count=4096, real_write_count=4096,
                returned_count=4096, caller_unchanged=1, offset=8192, ordinal=1,
                write_hits=int(mode == 2), source_sha256=sha(pattern(1, 1, 4096)),
                replacement_sha256=sha(replacement), fd=8, close_armed=1,
                image_close_attempts=1, real_image_close_result=0, real_image_close_errno=0,
                returned_image_close_result=-1 if mode == 3 else 0,
                returned_image_close_errno=errno.EIO if mode == 3 else 0,
                close_hits=int(mode == 3), parent_close_attempts=1, parent_close_identity_ok=1,
                parent_close_result=0, parent_close_errno=0)


def events(mode, ack=True):
    begun = dict(event="begin", status=0, slot_calls=0, fence_calls=0)
    written = dict(event="write", status=0, slot_calls=0, fence_calls=0)
    operation = dict(event="ack", status=0, generation=4, root_digest="b"*64, phase=0, errno=0,
                     fence_attempted=3, fence_succeeded=3, coverage=2, poisoned=0,
                     transaction_active=0, slot_calls=1, fence_calls=2, hits=0)
    if not ack:
        operation.update(event="result", status=6, generation=3, root_digest="a"*64, phase=5,
                         fence_attempted=0, fence_succeeded=0, poisoned=1, slot_calls=0, fence_calls=0)
        written["status"] = 6
    closed = dict(event="close", status=2 if mode == 3 else 0, phase=15,
                  errno=errno.EIO if mode == 3 else 0, fence_attempted=0, fence_succeeded=0,
                  generation=operation["generation"], root_digest=operation["root_digest"])
    return [begun, written, operation, closed, injection(mode)]


def observation(state=1, corrupt=False):
    value = valid_observation(state, 4 if state else 3)
    root = ("b" if state else "a")*64
    value.update(root_digest=root, open_coverage=2)
    value["independent_verification"].update(root_digest=root, open_coverage=2)
    if corrupt:
        # read_image encounters current/file first. Preserve that CORRUPT;
        # later calls on this same handle merely observe its poisoned state.
        value["objects"] = value["objects"][:4]
        value["objects"][0].update(status=6, read_status=6, count=0, sha256=sha(b""))
        for obj in value["objects"][1:]:
            obj.update(status=9, lookup_status=9, lookup_size=0, lookup_is_file=False,
                       size_attempted=False, size_status=12, size_value=0,
                       read_attempted=False, read_status=12, count=0, length=0, sha256=sha(b""))
        for item in value["metadata"]:
            item.update(lookup_status=9, metadata_attempted=False, metadata_status=12)
        value["symlink"].update(attempted=False, status=12, count=0, target_hex="")
        value["alias_comparison_attempted"] = False
        value["namespaces"] = [dict(view="current", status=9, entries=[])]
        value["catalog"].update(status=9, names_hex=[])
        value.update(baseline_status=9, recovery_status=9, verify_status=9, full_reachable=False)
        value["independent_verification"].update(verify_status=6, full_reachable=False)
    return value


class FocusedRegressions(unittest.TestCase):
    def classify(self, mode, stream=None, observed=None):
        return classify_focused(mode, stream if stream is not None else events(mode),
                                observed if observed is not None else observation(corrupt=mode == 2),
                                BINDING, IDENTITY)

    def test_fixed_six_cases_and_two_actual_parities(self):
        plan = sealed_plan()
        self.assertEqual(len(plan), 6)
        self.assertEqual(len({item["id"] for item in plan}), 6)
        self.assertEqual([(item["parity"], item["mode"]) for item in plan],
                         [(p, m) for p in (0, 1) for m in (1, 2, 3)])

    def test_control(self):
        self.assertEqual(self.classify(1)["classification"], "clean_B")

    def test_ack_then_close_error_preserves_separate_ack(self):
        stream = events(3)
        before = copy.deepcopy(one(stream, "ack"))
        result = self.classify(3, stream)
        self.assertTrue(result["preservation_pass"])
        self.assertEqual(result["classification"], "close_error_after_preserved_ack")
        self.assertEqual(one(stream, "ack"), before)
        self.assertEqual(stream[-1]["event"], "injection")

    def test_payload_detection_is_unavailability_not_preservation(self):
        result = self.classify(2)
        self.assertEqual(result["classification"], "acknowledged_payload_unavailable")
        self.assertFalse(result["preservation_pass"])
        self.assertTrue(result["unresolved_loss_risk"])
        self.assertEqual(result["first_integrity_failure"]["read_status"], 6)

    def test_proven_prepublication_refusal_preserves_A(self):
        result = self.classify(2, events(2, ack=False), observation(state=0))
        self.assertEqual(result["classification"], "prepublication_integrity_refusal")
        self.assertFalse(result["preservation_pass"])

    def test_missing_or_duplicate_injection_and_close(self):
        for name in ("injection", "close", "ack"):
            for duplicate in (False, True):
                with self.subTest(name=name, duplicate=duplicate):
                    stream = events(3)
                    item = one(stream, name)
                    stream.append(copy.deepcopy(item)) if duplicate else stream.remove(item)
                    with self.assertRaises(RuntimeError):
                        self.classify(3, stream)

    def test_injection_proof_rejects_missing_duplicate_wrong_target_or_partial_write(self):
        changes = [dict(target_matches=0), dict(target_matches=2), dict(device=999), dict(inode=999),
                   dict(offset=12288), dict(ordinal=2), dict(real_write_count=19), dict(returned_count=19),
                   dict(write_hits=0), dict(caller_unchanged=0), dict(proof_error=1),
                   dict(replacement_sha256=sha(pattern(1, 1, 4096)))]
        for change in changes:
            with self.subTest(change=change):
                item = injection(2)
                item.update(change)
                with self.assertRaises(RuntimeError):
                    validate_injection(item, 2, BINDING, IDENTITY)

    def test_exactly_once_real_close_and_parent_passthrough_required(self):
        for change in (dict(image_close_attempts=0), dict(image_close_attempts=2),
                       dict(real_image_close_result=-1, real_image_close_errno=errno.EIO),
                       dict(close_hits=0), dict(close_hits=2), dict(parent_close_attempts=2),
                       dict(parent_close_identity_ok=0), dict(parent_close_result=-1)):
            with self.subTest(change=change):
                stream = events(3)
                stream[-1].update(change)
                with self.assertRaises(RuntimeError):
                    self.classify(3, stream)

    def test_close_error_cannot_reuse_commit_fence_receipt(self):
        stream = events(3)
        one(stream, "close")["fence_succeeded"] = 3
        with self.assertRaises(RuntimeError):
            self.classify(3, stream)

    def test_stale_A_after_ack_is_never_preserved(self):
        for mode in (2, 3):
            with self.subTest(mode=mode), self.assertRaises(RuntimeError):
                self.classify(mode, observed=observation(state=0))

    def test_first_wrong_successful_bytes_cannot_hide_behind_later_corruption(self):
        value = observation(corrupt=True)
        value["objects"][0].update(status=0, read_status=0, count=12288, sha256=sha(b"wrong"))
        with self.assertRaises(RuntimeError):
            self.classify(2, observed=value)

    def test_poisoned_followups_are_not_independent_detection(self):
        for change in (dict(verify_status=9), dict(verify_attempted=False),
                       dict(verify_status=0, full_reachable=True), dict(root_digest="d"*64),
                       dict(generation=3)):
            with self.subTest(change=change):
                value = observation(corrupt=True)
                value["independent_verification"].update(change)
                with self.assertRaises(RuntimeError):
                    self.classify(2, observed=value)
        value = observation(corrupt=True)
        value["objects"][0].update(status=9, read_status=9)
        with self.assertRaises(RuntimeError):
            self.classify(2, observed=value)

    def test_lost_ack_or_outcome_unknown_never_proves_prepublication_A(self):
        for change in (dict(status=8), dict(slot_calls=1), dict(fence_attempted=2),
                       dict(phase=10), dict(transaction_active=1), dict(poisoned=0)):
            with self.subTest(change=change):
                stream = events(2, ack=False)
                one(stream, "result").update(change)
                with self.assertRaises(RuntimeError):
                    self.classify(2, stream, observation(state=0))

    def test_disk_bytes_must_prove_one_changed_byte(self):
        data = bytearray(8192) + bytearray(pattern(1, 1, 4096))
        with self.assertRaises(RuntimeError):
            check_stored_payload(data, 2, BINDING, False)
        data[8192+17] ^= 1
        proof = check_stored_payload(data, 2, BINDING, False)
        self.assertEqual(proof["changed_indices"], [17])
        data[8192+18] ^= 1
        with self.assertRaises(RuntimeError):
            check_stored_payload(data, 2, BINDING, False)

    def test_acknowledged_terminal_raw_decode_checks_other_reference_bytes(self):
        data, binding = encoded_payload_chain()
        data[binding["raw_offset"]+17] ^= 1
        unchanged = bytes(data)
        proof = check_stored_payload(data, 2, binding, True)
        self.assertTrue(proof["terminal_raw_digest_mismatch"])
        self.assertEqual(proof["checked_reference_chain"]["target"], "current/file")
        self.assertEqual(bytes(data), unchanged)
        # Metadata content and the external RAW digest are outside the one
        # terminal byte substitution; each must still fail the real decoder.
        for offset in (6*4096+200, 3*4096+648+24, binding["raw_offset"]+18):
            with self.subTest(offset=offset):
                damaged = bytearray(data)
                damaged[offset] ^= 1
                with self.assertRaises((RuntimeError, ValueError)):
                    check_stored_payload(damaged, 2, binding, True)

    def test_last_case_detects_seed_mutation_after_observation(self):
        data, binding = encoded_payload_chain()
        binding["A_sha256"] = sha(b"seed A")
        seed_changed = False
        campaign = mock.Mock()
        campaign.report = {}
        campaign.invoke.return_value = dict(events=events(3))
        stat = SimpleNamespace(st_dev=IDENTITY[0], st_ino=IDENTITY[1])

        def read_bytes(path):
            return (b"changed A" if seed_changed else b"seed A") if path.parent == Path("seed") else bytes(data)

        def observe(*args):
            nonlocal seed_changed
            seed_changed = True
            return observation()

        def case(label, seed, family, action):
            action(Path("specimen"), time.monotonic()+10, dict(id=label))

        campaign.read.side_effect = observe
        campaign.case.side_effect = case
        with mock.patch.object(Path, "stat", return_value=stat), mock.patch.object(Path, "read_bytes", read_bytes):
            with self.assertRaisesRegex(RuntimeError, "A seed changed during"):
                run_case(campaign, Path("seed"), dict(id="gap-0-close_eio", mode=3, family="close_eio"), binding)


class FinalizationRegressions(unittest.TestCase):
    def campaign(self):
        value = mock.Mock()
        value.report = dict(cases=[], case_plan=[], focused_work_completed=True,
                            focused_cases_completed=False, retained_specimens=[])
        value.groups = set()
        value.identity = (1, 2)
        value.deadline = time.monotonic()+10
        value.scratch.stat.return_value = SimpleNamespace(st_dev=1, st_ino=2)
        value.scratch.is_symlink.return_value = False
        return value

    def finish(self, campaign, stdout=None):
        with mock.patch.object(gaps.sys, "stdout", stdout or mock.Mock()), mock.patch.object(gaps.sys, "stderr", mock.Mock()):
            return terminal_result(campaign, False)

    def test_success_requires_checks_after_save_and_flush(self):
        campaign = self.campaign()
        trace = []
        campaign.save.side_effect = lambda: trace.append("save")
        campaign.check_pins.side_effect = lambda: trace.append("pins")
        campaign.bounds.side_effect = lambda: trace.append("bounds")
        output = mock.Mock()
        output.flush.side_effect = lambda: trace.append("flush")
        self.assertEqual(self.finish(campaign, output), 0)
        self.assertEqual(trace, ["save", "pins", "bounds", "save", "flush", "pins", "bounds"])
        self.assertTrue(campaign.report["completion_requires_terminal_exit_zero"])

    def test_unsafe_root_overrides_provisional_completion_and_absent_groups(self):
        for symlink in (False, True):
            with self.subTest(symlink=symlink):
                campaign = self.campaign()
                if symlink:
                    campaign.scratch.is_symlink.return_value = True
                else:
                    campaign.scratch.stat.return_value = SimpleNamespace(st_dev=1, st_ino=999)
                self.assertEqual(self.finish(campaign), 1)
                self.assertFalse(campaign.report["focused_cases_completed"])
                self.assertEqual(campaign.report["cleanup_status"], "unsafe_to_remove")
                self.assertTrue(campaign.report["process_groups_exit_verified"])

    def test_post_save_identity_deadline_pin_or_evidence_failure_cannot_return_zero(self):
        for fault in ("identity", "deadline", "pins", "evidence", "save"):
            with self.subTest(fault=fault):
                campaign = self.campaign()
                saves = 0

                def save():
                    nonlocal saves
                    saves += 1
                    if saves == 2:
                        if fault == "identity":
                            campaign.scratch.stat.return_value = SimpleNamespace(st_dev=1, st_ino=999)
                        elif fault == "deadline":
                            campaign.deadline = time.monotonic()-1
                        elif fault == "pins":
                            campaign.check_pins.side_effect = RuntimeError("late source pin drift")
                        elif fault == "evidence":
                            campaign.bounds.side_effect = RuntimeError("late evidence cap")
                        else:
                            raise OSError("final receipt write failed")

                campaign.save.side_effect = save
                self.assertEqual(self.finish(campaign), 1)
                self.assertFalse(campaign.report["focused_cases_completed"])
                self.assertTrue(campaign.report["terminal_failure"])
                self.assertTrue(campaign.report["finalization_errors"])

    def test_flush_time_failure_and_earlier_error_are_not_lost(self):
        campaign = self.campaign()
        output = mock.Mock()
        output.flush.side_effect = lambda: setattr(campaign, "deadline", time.monotonic()-1)
        self.assertEqual(self.finish(campaign, output), 1)
        self.assertFalse(campaign.report["focused_cases_completed"])
        original = "original producer failure"
        campaign = self.campaign()
        campaign.report["error"] = original
        campaign.save.side_effect = OSError("also failed to save")
        self.assertEqual(self.finish(campaign), 1)
        self.assertEqual(campaign.report["error"], original)
        self.assertTrue(campaign.report["finalization_errors"])


if __name__ == "__main__":
    unittest.main()
