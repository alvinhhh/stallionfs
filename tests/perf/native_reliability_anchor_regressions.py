"""Memory-only anchor classifier checks; no subprocess or filesystem specimen."""
import hashlib
from pathlib import Path
import stat
import struct
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import native_reliability_gaps as gaps
from native_reliability import Campaign
from native_reliability_gap_regressions import encoded_payload_chain, events, injection, observation, IDENTITY


def example(parity=0, mode=5):
    data, _ = encoded_payload_chain()
    b = bytearray(data[:4096])
    data[:8192] = bytes(8192)
    uuid = bytes(range(16)).hex()
    binding = dict(A_generation=3+parity, B_generation=4+parity, B_slot=parity,
                   A_uuid=uuid, A_root="a"*64, A_length=7*4096)
    a = bytearray(b)
    struct.pack_into("<Q", a, 40, binding["A_generation"])
    struct.pack_into("<Q", a, 56, 6*4096)
    a[72:104] = bytes.fromhex(binding["A_root"])
    struct.pack_into("<Q", a, 104, binding["A_length"])
    struct.pack_into("<Q", a, 144, 4*1024*1024)
    a[112:144] = bytes(32); a[112:144] = hashlib.sha256(a).digest()
    data[(1-parity)*4096:(2-parity)*4096] = a
    seed = bytes(data[:binding["A_length"]])
    struct.pack_into("<Q", b, 40, binding["B_generation"])
    struct.pack_into("<Q", b, 104, len(data))
    struct.pack_into("<Q", b, 144, 4*1024*1024)
    b[112:144] = bytes(32); b[112:144] = hashlib.sha256(b).digest()
    if mode == 5:
        b[72] ^= 1
    data[parity*4096:(parity+1)*4096] = b
    stored = gaps.anchor_bytes(data, mode, binding, seed)
    stream = events(1)
    ack = gaps.one(stream, "ack")
    ack.update(generation=binding["B_generation"], root_digest=stored["anchor_root_digest"], committed_end=stored["anchor_end"])
    gaps.one(stream, "close").update(generation=ack["generation"], root_digest=ack["root_digest"],
                                   committed_end=ack["committed_end"], poisoned=0, transaction_active=0)
    injected = injection(1)
    injected.update(mode=mode, offset=parity*4096, write_hits=int(mode == 5), first_fence_succeeded=1,
                    first_fence_fd=8, fences_before_write=1, original_checksum_valid=1)
    for key in ("source_sha256", "replacement_sha256", "anchor_generation", "anchor_uuid", "anchor_root_type",
                "anchor_root_offset", "anchor_root_length", "anchor_root_digest", "anchor_end", "anchor_capacity", "anchor_slot_checksum"):
        injected[key] = stored[key]
    stream[-1] = injected
    observed = observation()
    for item in (observed, observed["independent_verification"]):
        item.update(generation=ack["generation"], root_digest=ack["root_digest"], handle_present=True,
                    open_phase=5, open_errno=0, open_committed_end=ack["committed_end"])
    if mode == 5:
        for item in (observed, observed["independent_verification"]):
            item.update(open_status=7, open_coverage=0, generation=0, root_digest="0"*64,
                        handle_present=False, open_committed_end=0, full_reachable=False)
        observed.update(objects=[], namespaces=[], verify_status=7)
        observed["independent_verification"].update(verify_attempted=False, verify_status=12)
        observed.update(metadata=[dict(name=name, lookup_status=12, metadata_attempted=False, metadata_status=12,
                                       size=0, is_file=False, mode=0, links=0)
                                  for name in ("file", "alias", "companion", "link", "root")],
                        catalog=dict(names_hex=[], status=12, invalid_name_length=False),
                        symlink=dict(attempted=False, status=12, count=0, capacity=4, invalid_count=False, target_hex=""),
                        alias_comparison_attempted=False, alias_equal=False, baseline_status=-1, recovery_status=-1)
    inspection = dict(status=0, phase=5, errno=0, coverage=0, handle_present=True, selection_attempted=False,
                      selected_any_candidate=False, pair_valid=mode == 4, latest_may_be_unknown=True, slots=[])
    for slot in (0, 1):
        bad = slot == parity and mode == 5
        inspection["slots"].append(dict(slot=slot, status=6 if bad else 0, phase=5, errno=0, coverage=0 if bad else 1,
            generation=0 if bad else binding["B_generation"] if slot == parity else binding["A_generation"],
            root_digest="0"*64 if bad else ack["root_digest"] if slot == parity else binding["A_root"],
            committed_end=0 if bad else ack["committed_end"] if slot == parity else binding["A_length"],
            uuid="0"*32 if bad else uuid, full_reachable=not bad))
    return data, seed, binding, stored, stream, observed, inspection


class AnchorRegressions(unittest.TestCase):
    def classify(self, value, mode=5):
        _, _, binding, stored, stream, observed, inspection = value
        return gaps.classify_anchor(mode, stream, observed, inspection, binding, IDENTITY, stored)

    def test_four_selector_and_default_six_unchanged(self):
        self.assertEqual([(r["parity"], r["mode"]) for r in gaps.sealed_anchor_plan()], [(0, 4), (0, 5), (1, 4), (1, 5)])
        self.assertEqual(len(gaps.sealed_plan()), 6)

    def test_clean_and_altered_both_slots_memory_only(self):
        for parity in (0, 1):
            for mode in (4, 5):
                with self.subTest(parity=parity, mode=mode):
                    value = example(parity, mode)
                    unchanged = bytes(value[0])
                    result = self.classify(value, mode)
                    self.assertEqual(result["preservation_pass"], mode == 4)
                    self.assertEqual(result["unresolved_loss_risk"], mode == 5)
                    self.assertEqual(bytes(value[0]), unchanged)

    def test_reject_inert_extra_byte_checksum_or_old_prefix_change(self):
        data, seed, binding, _, _, _, _ = example()
        for offset in (72, 73, 112, 4096+200, 8192):
            with self.subTest(offset=offset):
                changed = bytearray(data); changed[offset] ^= 1
                with self.assertRaises((RuntimeError, ValueError)):
                    gaps.anchor_bytes(changed, 5, binding, seed)

    def test_reject_wrong_ownership_slot_ordinal_counts_and_fence(self):
        for change in (dict(target_matches=0), dict(target_matches=2), dict(device=999), dict(inode=999),
                       dict(offset=4096), dict(ordinal=2), dict(real_write_count=73), dict(returned_count=73),
                       dict(caller_unchanged=0), dict(original_checksum_valid=0), dict(write_hits=0),
                       dict(first_fence_succeeded=0), dict(fences_before_write=0), dict(first_fence_fd=9),
                       dict(source_sha256="e"*64), dict(anchor_slot_checksum="f"*64), dict(proof_error=1)):
            with self.subTest(change=change):
                value = example(); gaps.one(value[4], "injection").update(change)
                with self.assertRaises(RuntimeError): self.classify(value)

    def test_reject_stale_success_missing_fresh_verify_and_inspection_as_preservation(self):
        for target, change in (("read", dict(open_status=0, generation=3, handle_present=True)),
                               ("verify", dict(open_status=0, verify_attempted=True, verify_status=0, full_reachable=True)),
                               ("verify", dict(verify_attempted=True)), ("inspect", dict(pair_valid=True)),
                               ("inspect", dict(selection_attempted=True)), ("inspect", dict(latest_may_be_unknown=False)),
                               ("A", dict(root_digest="e"*64)), ("B", dict(status=0, full_reachable=True)),
                               ("B", dict(generation=4)), ("B", dict(coverage=1))):
            with self.subTest(target=target, change=change):
                value = example()
                item = (value[5] if target == "read" else value[5]["independent_verification"] if target == "verify"
                        else value[6] if target == "inspect" else value[6]["slots"][1 if target == "A" else 0])
                item.update(change)
                with self.assertRaises(RuntimeError): self.classify(value)
        value = example(); del value[5]["independent_verification"]
        with self.assertRaises(RuntimeError): self.classify(value)

    def test_refusal_rejects_every_selected_metadata_catalog_link_alias_or_snapshot_attempt(self):
        for target, change in (("metadata", dict(lookup_status=0)), ("metadata", dict(metadata_attempted=True)),
                               ("metadata", dict(metadata_status=0)), ("metadata", dict(size=1)),
                               ("catalog", dict(status=0)), ("catalog", dict(names_hex=["78"])),
                               ("symlink", dict(attempted=True)), ("symlink", dict(status=0)),
                               ("symlink", dict(count=1, target_hex="78")),
                               ("read", dict(alias_comparison_attempted=True)), ("read", dict(alias_equal=True)),
                               ("read", dict(baseline_status=0)), ("read", dict(recovery_status=0))):
            with self.subTest(target=target, change=change):
                value = example()
                observed = value[5]
                item = observed if target == "read" else observed["metadata"][0] if target == "metadata" else observed[target]
                item.update(change)
                with self.assertRaises(RuntimeError): self.classify(value)

    def test_bridges_reject_same_bytes_new_inode_and_same_inode_changed_bytes(self):
        row = dict(anchor_post_producer_identity=list(IDENTITY), anchor_post_producer_sha256=gaps.sha(b"stable"))
        original = SimpleNamespace(st_dev=123, st_ino=456, st_size=6, st_mode=stat.S_IFREG|0o600)
        replaced = SimpleNamespace(st_dev=123, st_ino=457, st_size=6, st_mode=stat.S_IFREG|0o600)
        stream = mock.MagicMock(); stream.__enter__.return_value.read.return_value = b"stable"
        with mock.patch.object(Path, "lstat", return_value=original), mock.patch.object(Path, "open", return_value=stream):
            gaps.anchor_bridge(Path("synthetic"), row, "before_read")
        self.assertTrue(row["anchor_observation_bridges"][-1]["complete"])
        with mock.patch.object(Path, "lstat", return_value=replaced), mock.patch.object(Path, "open", return_value=stream):
            with self.assertRaises(RuntimeError): gaps.anchor_bridge(Path("synthetic"), row, "before_verify")
        stream.__enter__.return_value.read.return_value = b"change"
        with mock.patch.object(Path, "lstat", return_value=original), mock.patch.object(Path, "open", return_value=stream):
            with self.assertRaises(RuntimeError): gaps.anchor_bridge(Path("synthetic"), row, "before_inspect")
        self.assertFalse(row["anchor_observation_bridges"][-1]["complete"])

    def test_clean_control_final_mismatch_or_read_stat_error_clears_all_preservation_claims(self):
        for fault, stat_calls, read_calls in (("mismatch", 2, 1), ("before_stat", 1, 0),
                                               ("read", 1, 1), ("after_stat", 2, 1), ("read_and_save", 1, 1)):
            with self.subTest(fault=fault):
                campaign = object.__new__(Campaign)
                campaign.deadline = time.monotonic()+10
                campaign.report = dict(cases=[], case_plan=[dict(id="anchor", family="control")], retained_specimens=[])
                campaign.check_pins = mock.Mock()
                campaign.specimen = mock.Mock(return_value=Path("synthetic"))
                campaign.save = mock.Mock()
                if fault == "read_and_save": campaign.save.side_effect = OSError("failure receipt unavailable")
                st = SimpleNamespace(st_dev=123, st_ino=456, st_size=6, st_mode=stat.S_IFREG|0o600)
                expected_error = OSError("final "+fault)

                def action(directory, deadline, row):
                    row.update(outcome="acknowledged_state_preserved", classification="clean_anchor_B",
                               preservation_pass=True, unresolved_loss_risk=False, retain_specimen=True,
                               anchor_post_producer_identity=list(IDENTITY), anchor_post_producer_sha256=gaps.sha(b"stable"))

                with mock.patch.object(Path, "lstat", return_value=st) as observed_stat, \
                     mock.patch.object(Path, "read_bytes", return_value=b"change") as observed_read:
                    if fault == "before_stat": observed_stat.side_effect = expected_error
                    elif fault == "after_stat": observed_stat.side_effect = [st, expected_error]
                    elif fault in ("read", "read_and_save"): observed_read.side_effect = expected_error
                    with self.assertRaises((RuntimeError, OSError)) as caught:
                        campaign.case("anchor", Path("seed"), "control", action)
                    self.assertEqual(observed_stat.call_count, stat_calls)
                    self.assertEqual(observed_read.call_count, read_calls)
                if fault != "mismatch": self.assertIs(caught.exception, expected_error)
                row = campaign.report["cases"][0]
                self.assertEqual(row["outcome"], "unresolved")
                self.assertFalse(row["oracle_passed"])
                self.assertFalse(row["preservation_pass"])
                self.assertFalse(row["acknowledged_data_preservation_established"])
                self.assertTrue(row["unresolved_loss_risk"])
                self.assertTrue(campaign.report["unresolved_loss_risk"])
                self.assertTrue(row["anchor_final_binding_failed"])
                self.assertTrue(row["anchor_final_error"])
                campaign.save.assert_called_once()


def corrective_example(parity=0, mode=5):
    value = example(parity, mode)
    if mode == 5:
        binding, stream = value[2], value[4]
        gaps.one(stream, "ack").update(event="result", status=8, phase=11, errno=0, coverage=0,
            poisoned=1, transaction_active=0, generation=binding["A_generation"],
            root_digest=binding["A_root"], committed_end=binding["A_length"])
        gaps.one(stream, "close").update(poisoned=1, generation=binding["A_generation"],
            root_digest=binding["A_root"], committed_end=binding["A_length"], slot_calls=1, fence_calls=2)
    return value


class CorrectiveAnchorRegressions(unittest.TestCase):
    def classify(self, value, mode=5):
        _, _, binding, stored, stream, observed, inspection = value
        return gaps.classify_corrective_anchor(mode, stream, observed, inspection, binding, IDENTITY, stored)

    def test_four_distinct_corrective_cases_and_original_selector_remains(self):
        plan = gaps.sealed_corrective_anchor_plan()
        self.assertEqual([(row["parity"], row["mode"]) for row in plan], [(0, 4), (0, 5), (1, 4), (1, 5)])
        self.assertFalse({row["id"] for row in plan} & {row["id"] for row in gaps.sealed_anchor_plan()})

    def test_both_parities_distinguish_corrective_expectation_from_preservation(self):
        results = []
        for parity in (0, 1):
            for mode in (4, 5):
                with self.subTest(parity=parity, mode=mode):
                    value = corrective_example(parity, mode)
                    result = self.classify(value, mode)
                    results.append(result)
                    self.assertTrue(result["corrective_expectations_pass"])
                    self.assertEqual(result["preservation_pass"], mode == 4)
                    if mode == 5:
                        self.assertTrue(result["false_ack_prevented"])
                        self.assertFalse(result["ordinary_availability_pass"])
                        self.assertFalse(result["A_preservation_established"])
                        self.assertFalse(result["B_preservation_established"])
                        self.assertTrue(result["unresolved_loss_risk"])
                        self.assertTrue(result["original_acknowledged_loss_finding_retained"])
                        with self.assertRaises(RuntimeError):
                            gaps.classify_anchor(mode, value[4], value[5], value[6], value[2], IDENTITY, value[3])
        self.assertFalse(all(row["preservation_pass"] for row in results))
        self.assertTrue(any(row["unresolved_loss_risk"] for row in results))

    def test_reject_any_ack_event_even_old_or_unrelated_generation(self):
        for generation in (1, 3, 4, 99):
            for append in (False, True):
                with self.subTest(generation=generation, append=append):
                    value = corrective_example()
                    if append:
                        value[4].append(dict(event="ack", status=0, generation=generation))
                    else:
                        gaps.one(value[4], "result").update(event="ack", generation=generation)
                    with self.assertRaises(RuntimeError): self.classify(value)

    def test_require_exact_unknown_publication_phase_errno_masks_and_poison(self):
        for change in (dict(status=0), dict(status=6), dict(status=7), dict(phase=5), dict(phase=7),
                       dict(phase=9), dict(phase=10), dict(errno=5), dict(coverage=2), dict(poisoned=0),
                       dict(transaction_active=1), dict(fence_attempted=1), dict(fence_succeeded=1),
                       dict(slot_calls=0), dict(slot_calls=2), dict(fence_calls=1), dict(fence_calls=3),
                       dict(generation=4), dict(root_digest="e"*64), dict(committed_end=0)):
            with self.subTest(change=change):
                value = corrective_example(); gaps.one(value[4], "result").update(change)
                with self.assertRaises(RuntimeError): self.classify(value)

    def test_reject_missing_duplicate_or_changed_injection_and_close_evidence(self):
        for name in ("result", "injection", "close", "begin", "write"):
            for duplicate in (False, True):
                with self.subTest(name=name, duplicate=duplicate):
                    value = corrective_example(); item = gaps.one(value[4], name)
                    value[4].append(dict(item)) if duplicate else value[4].remove(item)
                    with self.assertRaises(RuntimeError): self.classify(value)
        for name, change in (("injection", dict(real_write_count=17)), ("injection", dict(caller_unchanged=0)),
                             ("injection", dict(write_hits=0)), ("injection", dict(anchor_slot_checksum="e"*64)),
                             ("close", dict(poisoned=0)), ("close", dict(status=2)),
                             ("close", dict(slot_calls=2)), ("close", dict(fence_calls=3))):
            with self.subTest(name=name, change=change):
                value = corrective_example(); gaps.one(value[4], name).update(change)
                with self.assertRaises(RuntimeError): self.classify(value)
        for missing in ("slot_calls", "fence_calls"):
            with self.subTest(missing=missing):
                value = corrective_example(); gaps.one(value[4], "close").pop(missing)
                with self.assertRaises(RuntimeError): self.classify(value)

    def test_unknown_old_result_fields_do_not_admit_old_state_or_incomplete_observers(self):
        for target, change in (("read", dict(open_status=0, generation=3, root_digest="a"*64, handle_present=True)),
                               ("verify", dict(verify_attempted=True, verify_status=0, full_reachable=True)),
                               ("inspection", dict(status=14)), ("inspection", dict(pair_valid=True)),
                               ("A", dict(full_reachable=False)), ("B", dict(status=0)),
                               ("B", dict(generation=4)), ("read", dict(baseline_status=0))):
            with self.subTest(target=target, change=change):
                value = corrective_example()
                item = (value[5] if target == "read" else value[5]["independent_verification"] if target == "verify"
                        else value[6] if target == "inspection" else value[6]["slots"][1 if target == "A" else 0])
                item.update(change)
                with self.assertRaises(RuntimeError): self.classify(value)
        value = corrective_example(); del value[5]["independent_verification"]
        with self.assertRaises(RuntimeError): self.classify(value)

    def test_final_case_failure_clears_corrective_expectations_too(self):
        campaign = object.__new__(Campaign)
        campaign.deadline = time.monotonic()+10
        campaign.report = dict(cases=[], case_plan=[dict(id="corrective", family="altered-success")], retained_specimens=[])
        campaign.check_pins = mock.Mock()
        campaign.specimen = mock.Mock(return_value=Path("synthetic"))
        campaign.save = mock.Mock()
        st = SimpleNamespace(st_dev=123, st_ino=456, st_size=6, st_mode=stat.S_IFREG|0o600)

        def action(directory, deadline, row):
            row.update(outcome="anchor_admission_refusal", corrective_expectations_pass=True,
                       preservation_pass=False, unresolved_loss_risk=True, retain_specimen=True,
                       anchor_post_producer_identity=list(IDENTITY), anchor_post_producer_sha256=gaps.sha(b"stable"))

        with mock.patch.object(Path, "lstat", return_value=st), mock.patch.object(Path, "read_bytes", return_value=b"change"):
            with self.assertRaises(RuntimeError): campaign.case("corrective", Path("seed"), "altered-success", action)
        self.assertFalse(campaign.report["cases"][0]["corrective_expectations_pass"])
        self.assertFalse(campaign.report["cases"][0]["ordinary_availability_pass"])
        self.assertTrue(campaign.report["cases"][0]["unresolved_loss_risk"])


if __name__ == "__main__":
    unittest.main()
