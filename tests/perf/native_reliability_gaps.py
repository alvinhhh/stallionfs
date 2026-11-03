#!/usr/bin/env python3
"""Six disposable-image checks; completion is not an overall preservation pass."""
import argparse
import errno
import json
from pathlib import Path
import shutil
import stat
import struct
import sys
import time

from native_reliability import (BoundImage, Campaign, CASE_SECONDS, REPO,
                                expected, pattern, sha)

CORE_PINS = {
    "filesystem/image.c": "4d82de781c14a168dd64eab402d99004a207adf3401c802b94422f35353923e8",
    "filesystem/image.h": "a335012f3103178baa7229ed405b1b9211a27e3c0b257bbd8f0bf91dc4dd6163",
}
CORRECTIVE_CORE_PINS = {
    "filesystem/image.c": "4d82de781c14a168dd64eab402d99004a207adf3401c802b94422f35353923e8",
    "filesystem/image.h": "a335012f3103178baa7229ed405b1b9211a27e3c0b257bbd8f0bf91dc4dd6163",
}
FAMILIES = (("control", 1), ("acknowledged_payload_success", 2), ("close_eio", 3))


def sealed_plan():
    return [dict(id=f"gap-{parity}-{family}", family=family, parity=parity, mode=mode)
            for parity in (0, 1) for family, mode in FAMILIES]


def sealed_anchor_plan():
    return [dict(id=f"anchor-{parity}-{family}", family=family, parity=parity, mode=mode)
            for parity in (0, 1) for family, mode in (("control", 4), ("altered-success", 5))]


def anchor_bytes(data, mode, binding, seed):
    """Restore the single slot byte only in memory; never repair the specimen."""
    require(mode in (4, 5) and 8192 <= len(seed) < len(data) <= 4*1024*1024,
            "anchor image bounds/mode differ")
    at = binding["B_slot"]*4096
    require(data[:at] == seed[:at] and data[at+4096:len(seed)] == seed[at+4096:],
            "surviving anchor or pre-existing records changed")
    actual = bytes(data[at:at+4096])
    original = bytearray(actual)
    if mode == 5:
        original[72] ^= 1
    cleared = bytearray(original)
    cleared[112:144] = bytes(32)
    require(original[:8] == b"SFSIMG01" and struct.unpack_from("<I", original, 12)[0] == 6 and
            sha(cleared) == original[112:144].hex(), "reconstructed original slot checksum/version invalid")
    root_type, reserved, offset, length = struct.unpack_from("<IIQQ", original, 48)
    generation = struct.unpack_from("<Q", original, 40)[0]
    end = struct.unpack_from("<Q", original, 104)[0]
    capacity = struct.unpack_from("<Q", original, 144)[0]
    require(generation == binding["B_generation"] and generation % 2 == binding["B_slot"] and
            original[24:40].hex() == binding["A_uuid"] and root_type == 4 and reserved == 0 and
            offset >= len(seed) and offset % 4096 == 0 and length == 4096 and
            end == offset+4096 == len(data) and capacity == 4*1024*1024,
            "encoded B identity/end/reference does not match this specimen ledger")
    changed = [i for i in range(4096) if actual[i] != original[i]]
    require(changed == ([72] if mode == 5 else []) and actual[112:144] == original[112:144],
            "slot change differs from the one sealed digest-byte substitution")
    restored = bytearray(data)
    restored[at:at+4096] = original
    chain = BoundImage(restored).binding(1, 1, 0)
    return dict(offset=at, changed_indices=changed, source_sha256=sha(original),
                replacement_sha256=sha(actual), original_checksum_valid=True,
                anchor_generation=generation, anchor_uuid=original[24:40].hex(),
                anchor_root_type=root_type, anchor_root_offset=offset, anchor_root_length=length,
                anchor_root_digest=original[72:104].hex(), anchor_end=end, anchor_capacity=capacity,
                anchor_slot_checksum=original[112:144].hex(), seed_prefix_except_target_unchanged=True,
                reconstructed_memory_only_reference_chain=chain)


def validate_anchor_injection(item, mode, binding, identity, stored):
    wanted = dict(mode=mode, device=identity[0], inode=identity[1], target_matches=1,
                  proof_error=0, requested_count=4096, real_write_count=4096, returned_count=4096,
                  caller_unchanged=1, offset=binding["B_slot"]*4096, ordinal=1, write_hits=int(mode == 5),
                  first_fence_succeeded=1, fences_before_write=1, original_checksum_valid=1,
                  close_armed=1, image_close_attempts=1, real_image_close_result=0, real_image_close_errno=0,
                  returned_image_close_result=0, returned_image_close_errno=0, close_hits=0,
                  parent_close_attempts=1, parent_close_identity_ok=1, parent_close_result=0, parent_close_errno=0)
    for key in ("source_sha256", "replacement_sha256", "anchor_generation", "anchor_uuid",
                "anchor_root_type", "anchor_root_offset", "anchor_root_length", "anchor_root_digest",
                "anchor_end", "anchor_capacity", "anchor_slot_checksum"):
        wanted[key] = stored[key]
    require(all(item.get(key) == value for key, value in wanted.items()),
            "anchor injection/owned close differs from sealed expectations")
    require(isinstance(item.get("fd"), int) and item["fd"] >= 0 and item.get("first_fence_fd") == item["fd"],
            "first successful fence and slot write do not bind the same owned descriptor")


def classify_anchor(mode, events, observation, inspection, binding, identity, stored):
    require(mode in (4, 5), "unsealed anchor mode")
    require([item.get("event") for item in events] == ["begin", "write", "ack", "close", "injection"],
            "anchor case did not retain exactly one ordered B ACK and checked close")
    ack, close = one(events, "ack"), one(events, "close")
    validate_anchor_injection(one(events, "injection"), mode, binding, identity, stored)
    for stage in ("begin", "write"):
        item = one(events, stage)
        require(item.get("status") == 0 and item.get("slot_calls") == item.get("fence_calls") == 0,
                "anchor producer stage failed or published early")
    wanted = dict(status=0, generation=binding["B_generation"], root_digest=stored["anchor_root_digest"],
                  committed_end=stored["anchor_end"], phase=0, errno=0, fence_attempted=3,
                  fence_succeeded=3, coverage=2, poisoned=0, transaction_active=0,
                  slot_calls=1, fence_calls=2, hits=0)
    require(all(ack.get(key) == value for key, value in wanted.items()), "anchor B ACK differs from immutable encoded B")
    wanted_close = dict(status=0, phase=15, errno=0, generation=ack["generation"],
                        root_digest=ack["root_digest"], committed_end=ack["committed_end"],
                        fence_attempted=0, fence_succeeded=0, poisoned=0, transaction_active=0)
    require(all(close.get(key) == value for key, value in wanted_close.items()), "anchor checked close failed or erased B")
    require(inspection.get("status") == 0 and inspection.get("phase") == 5 and inspection.get("errno") == 0 and
            inspection.get("coverage") == 0 and inspection.get("handle_present") is True and
            inspection.get("selection_attempted") is False and inspection.get("selected_any_candidate") is False and
            inspection.get("pair_valid") is (mode == 4) and inspection.get("latest_may_be_unknown") is True,
            "inspection was incomplete, selected a candidate or misreported pair validity")
    slots = inspection.get("slots", [])
    require(len(slots) == 2 and [item.get("slot") for item in slots] == [0, 1], "incomplete inspection slot table")
    for slot, item in enumerate(slots):
        bad = slot == binding["B_slot"] and mode == 5
        wanted_slot = dict(status=6 if bad else 0, errno=0, coverage=0 if bad else 1,
                           generation=0 if bad else binding["B_generation"] if slot == binding["B_slot"] else binding["A_generation"],
                           root_digest="0"*64 if bad else stored["anchor_root_digest"] if slot == binding["B_slot"] else binding["A_root"],
                           committed_end=0 if bad else stored["anchor_end"] if slot == binding["B_slot"] else binding["A_length"],
                           uuid="0"*32 if bad else binding["A_uuid"], full_reachable=not bad)
        require(all(item.get(key) == value for key, value in wanted_slot.items()), "inspection candidate differs from exact A/B ledger")
        require(item.get("phase") == 5, "inspection candidate phase differs")
    if mode == 4:
        check_open_binding(observation, ack["generation"], ack["root_digest"])
        require(Campaign.classify(None, observation, [expected(1)], ack["generation"], True) ==
                "acknowledged_state_preserved", "clean anchor did not preserve exact B manifest")
        for item in (observation, observation["independent_verification"]):
            require(item.get("handle_present") is True and item.get("open_committed_end") == ack["committed_end"] and
                    item.get("open_phase") == 5 and item.get("open_errno") == 0, "clean reader open receipt differs")
        return dict(outcome="acknowledged_state_preserved", classification="clean_anchor_B",
                    preservation_pass=True, acknowledged_payload_unavailable=False, unresolved_loss_risk=False)
    # Ordinary admission must refuse explicitly, never successfully return A or
    # hide a wrong successful payload behind a later error on that same handle.
    for item in (observation, observation.get("independent_verification", {})):
        require(item.get("open_status") == 7 and item.get("open_coverage") == 0 and
                item.get("open_phase") == 5 and item.get("open_errno") == 0 and item.get("generation") == 0 and
                item.get("open_committed_end") == 0 and item.get("root_digest") == "0"*64 and
                item.get("handle_present") is False and item.get("full_reachable") is False,
                "acknowledged altered anchor did not produce the exact fresh ordinary admission refusal")
    independent = observation["independent_verification"]
    require(independent.get("verify_attempted") is False and independent.get("verify_status") == 12 and
            observation.get("verify_status") == 7 and observation.get("objects") == [] and
            observation.get("namespaces") == [], "refused admission nevertheless read or verified selected data")
    metadata = [dict(name=name, lookup_status=12, metadata_attempted=False, metadata_status=12,
                     size=0, is_file=False, mode=0, links=0)
                for name in ("file", "alias", "companion", "link", "root")]
    require(observation.get("metadata") == metadata and
            observation.get("catalog") == dict(names_hex=[], status=12, invalid_name_length=False) and
            observation.get("symlink") == dict(attempted=False, status=12, count=0, capacity=4,
                invalid_count=False, target_hex="") and observation.get("alias_comparison_attempted") is False and
            observation.get("alias_equal") is False and observation.get("baseline_status") == -1 and
            observation.get("recovery_status") == -1,
            "refused admission reports a selected metadata/catalog/symlink/alias/snapshot observation")
    return dict(outcome="anchor_admission_refusal", classification="acknowledged_anchor_unavailable",
                preservation_pass=False, acknowledged_payload_unavailable=True, unresolved_loss_risk=True)


def anchor_bridge(path, row, stage):
    """Bind each fresh native observation to one immutable post-producer image."""
    point = dict(stage=stage, complete=False)
    row.setdefault("anchor_observation_bridges", []).append(point)
    before = path.lstat()
    point["before"] = dict(device=before.st_dev, inode=before.st_ino, bytes=before.st_size)
    require(stat.S_ISREG(before.st_mode) and before.st_size <= 4*1024*1024 and
            [before.st_dev, before.st_ino] == row["anchor_post_producer_identity"],
            "anchor specimen identity changed before " + stage)
    with path.open("rb") as stream:
        data = stream.read(4*1024*1024+1)
    point["sha256"] = sha(data)
    after = path.lstat()
    point["after"] = dict(device=after.st_dev, inode=after.st_ino, bytes=after.st_size)
    require(stat.S_ISREG(after.st_mode) and point["after"] == point["before"] and
            point["sha256"] == row["anchor_post_producer_sha256"] and len(data) == before.st_size,
            "anchor specimen identity/content changed during " + stage)
    point["complete"] = True


def run_anchor_case(campaign, seed, spec, binding):
    def action(directory, deadline, row):
        row["retain_specimen"] = True
        path = directory/"image.sfs"
        before = path.stat()
        identity = (before.st_dev, before.st_ino)
        row["specimen_identity"] = dict(device=identity[0], inode=identity[1])
        seed_data = (seed/"image.sfs").read_bytes()
        require(sha(seed_data) == binding["A_sha256"], "A seed changed before anchor producer")
        row["producer"] = campaign.invoke([campaign.producer, "gap", directory, spec["mode"], binding["B_slot"]*4096, 1],
            row["id"]+"-producer", deadline, manifest=expected(1), ack_generation=binding["B_generation"])
        after = path.stat()
        require((after.st_dev, after.st_ino) == identity, "anchor specimen identity changed")
        with path.open("rb") as stream:
            data = stream.read(4*1024*1024+1)
        row["anchor_post_producer_identity"] = list(identity)
        row["anchor_post_producer_sha256"] = sha(data)
        anchor_bridge(path, row, "post_producer")
        row["stored_anchor"] = anchor_bytes(data, spec["mode"], binding, seed_data)
        validate_anchor_injection(one(row["producer"]["events"], "injection"), spec["mode"], binding, identity, row["stored_anchor"])
        # The existing ordinary read and separate verification helpers are each
        # invoked through the unchanged Campaign supervisor. Their identity and
        # content brackets all compare to the same post-producer baseline.
        for command, event in (("read", "read"), ("verify", "verification")):
            anchor_bridge(path, row, "before_"+command)
            receipt = campaign.invoke([campaign.reader, command, directory], row["id"]+"-"+command, deadline)
            row[command+"_receipt"] = receipt
            anchor_bridge(path, row, "after_"+command)
            observed = one(receipt["events"], event)
            if command == "read":
                row["observation"] = observed
            else:
                row["observation"]["independent_verification"] = observed
        anchor_bridge(path, row, "before_inspection")
        row["inspection"] = campaign.inspect(directory, row["id"]+"-inspection", deadline, binding["B_generation"])
        anchor_bridge(path, row, "after_inspection")
        classification = classify_anchor(spec["mode"], row["producer"]["events"], row["observation"],
                                         row["inspection"], binding, identity, row["stored_anchor"])
        check_seed_unchanged(seed, binding, deadline)
        row["seed_unchanged_after_observation"] = True
        anchor_bridge(path, row, "final_action")
        row.update(classification)
    campaign.case(spec["id"], seed, spec["family"], action)


def sealed_corrective_anchor_plan():
    return [dict(id=f"anchor-corrective-{parity}-{family}", family=family, parity=parity, mode=mode)
            for parity in (0, 1) for family, mode in (("control", 4), ("altered-success", 5))]


def check_corrective_anchor_observers(observation, inspection, binding, stored):
    """Same fresh refusal and unselected inspection gates as the ACK experiment."""
    mode = 5
    require(inspection.get("status") == 0 and inspection.get("phase") == 5 and inspection.get("errno") == 0 and
            inspection.get("coverage") == 0 and inspection.get("handle_present") is True and
            inspection.get("selection_attempted") is False and inspection.get("selected_any_candidate") is False and
            inspection.get("pair_valid") is (mode == 4) and inspection.get("latest_may_be_unknown") is True,
            "inspection was incomplete, selected a candidate or misreported pair validity")
    slots = inspection.get("slots", [])
    require(len(slots) == 2 and [item.get("slot") for item in slots] == [0, 1], "incomplete inspection slot table")
    for slot, item in enumerate(slots):
        bad = slot == binding["B_slot"] and mode == 5
        wanted_slot = dict(status=6 if bad else 0, errno=0, coverage=0 if bad else 1,
                           generation=0 if bad else binding["B_generation"] if slot == binding["B_slot"] else binding["A_generation"],
                           root_digest="0"*64 if bad else stored["anchor_root_digest"] if slot == binding["B_slot"] else binding["A_root"],
                           committed_end=0 if bad else stored["anchor_end"] if slot == binding["B_slot"] else binding["A_length"],
                           uuid="0"*32 if bad else binding["A_uuid"], full_reachable=not bad)
        require(all(item.get(key) == value for key, value in wanted_slot.items()), "inspection candidate differs from exact A/B ledger")
        require(item.get("phase") == 5, "inspection candidate phase differs")
    # Ordinary admission must refuse explicitly, never successfully return A or
    # hide a wrong successful payload behind a later error on that same handle.
    for item in (observation, observation.get("independent_verification", {})):
        require(item.get("open_status") == 7 and item.get("open_coverage") == 0 and
                item.get("open_phase") == 5 and item.get("open_errno") == 0 and item.get("generation") == 0 and
                item.get("open_committed_end") == 0 and item.get("root_digest") == "0"*64 and
                item.get("handle_present") is False and item.get("full_reachable") is False,
                "acknowledged altered anchor did not produce the exact fresh ordinary admission refusal")
    independent = observation["independent_verification"]
    require(independent.get("verify_attempted") is False and independent.get("verify_status") == 12 and
            observation.get("verify_status") == 7 and observation.get("objects") == [] and
            observation.get("namespaces") == [], "refused admission nevertheless read or verified selected data")
    metadata = [dict(name=name, lookup_status=12, metadata_attempted=False, metadata_status=12,
                     size=0, is_file=False, mode=0, links=0)
                for name in ("file", "alias", "companion", "link", "root")]
    require(observation.get("metadata") == metadata and
            observation.get("catalog") == dict(names_hex=[], status=12, invalid_name_length=False) and
            observation.get("symlink") == dict(attempted=False, status=12, count=0, capacity=4,
                invalid_count=False, target_hex="") and observation.get("alias_comparison_attempted") is False and
            observation.get("alias_equal") is False and observation.get("baseline_status") == -1 and
            observation.get("recovery_status") == -1,
            "refused admission reports a selected metadata/catalog/symlink/alias/snapshot observation")


def classify_corrective_anchor(mode, events, observation, inspection, binding, identity, stored):
    """False-ACK prevention is separate from ordinary availability/preservation."""
    require(mode in (4, 5), "unsealed corrective anchor mode")
    if mode == 4:
        classification = classify_anchor(mode, events, observation, inspection, binding, identity, stored)
        classification.update(corrective_expectations_pass=True, ordinary_availability_pass=True,
                              false_ack_prevention_scope="clean control; exact B remains available")
        return classification
    require(not any(item.get("event") == "ack" for item in events),
            "corrective altered-success case must contain no ACK event of any generation")
    require([item.get("event") for item in events] == ["begin", "write", "result", "close", "injection"],
            "need exactly one ordered explicit corrective result with owned close/injection evidence")
    operation, close = one(events, "result"), one(events, "close")
    validate_anchor_injection(one(events, "injection"), mode, binding, identity, stored)
    for stage in ("begin", "write"):
        item = one(events, stage)
        require(item.get("status") == 0 and item.get("slot_calls") == item.get("fence_calls") == 0,
                "corrective anchor stage failed or published before commit")
    wanted = dict(status=8, generation=binding["A_generation"], root_digest=binding["A_root"],
                  committed_end=binding["A_length"], phase=11, errno=0, fence_attempted=3,
                  fence_succeeded=3, coverage=0, poisoned=1, transaction_active=0,
                  slot_calls=1, fence_calls=2, hits=0)
    require(all(operation.get(key) == value for key, value in wanted.items()),
            "not the exact post-publication UNKNOWN/COMMIT_BARRIER corrective outcome")
    wanted_close = dict(status=0, phase=15, errno=0, generation=binding["A_generation"],
                        root_digest=binding["A_root"], committed_end=binding["A_length"],
                        fence_attempted=0, fence_succeeded=0, poisoned=1, transaction_active=0,
                        slot_calls=1, fence_calls=2)
    require(all(close.get(key) == value for key, value in wanted_close.items()),
            "corrective checked close differs from poisoned, unpromoted handle")
    # These old in-memory result fields bind the code path only. Ordinary A and
    # B admission both remain refused; they establish no preserved candidate.
    check_corrective_anchor_observers(observation, inspection, binding, stored)
    return dict(outcome="anchor_admission_refusal", classification="false_ack_prevented_anchor_unavailable",
                corrective_expectations_pass=True, false_ack_prevented=True,
                ordinary_availability_pass=False, preservation_pass=False,
                A_preservation_established=False, B_preservation_established=False,
                intended_B_unavailable=True, unresolved_loss_risk=True,
                original_acknowledged_loss_finding_retained=True,
                false_ack_prevention_scope="post-publication UNKNOWN only; no availability or preservation repair")


def run_corrective_anchor_case(campaign, seed, spec, binding):
    def action(directory, deadline, row):
        row.update(corrective_expectations_pass=False, unresolved_loss_risk=True)
        row["retain_specimen"] = True
        path = directory/"image.sfs"
        before = path.stat()
        identity = (before.st_dev, before.st_ino)
        row["specimen_identity"] = dict(device=identity[0], inode=identity[1])
        seed_data = (seed/"image.sfs").read_bytes()
        require(sha(seed_data) == binding["A_sha256"], "A seed changed before anchor producer")
        row["producer"] = campaign.invoke([campaign.producer, "gap", directory, spec["mode"], binding["B_slot"]*4096, 1],
            row["id"]+"-producer", deadline, manifest=expected(1), ack_generation=binding["B_generation"])
        after = path.stat()
        require((after.st_dev, after.st_ino) == identity, "anchor specimen identity changed")
        with path.open("rb") as stream:
            data = stream.read(4*1024*1024+1)
        row["anchor_post_producer_identity"] = list(identity)
        row["anchor_post_producer_sha256"] = sha(data)
        anchor_bridge(path, row, "post_producer")
        row["stored_anchor"] = anchor_bytes(data, spec["mode"], binding, seed_data)
        validate_anchor_injection(one(row["producer"]["events"], "injection"), spec["mode"], binding, identity, row["stored_anchor"])
        # The existing ordinary read and separate verification helpers are each
        # invoked through the unchanged Campaign supervisor. Their identity and
        # content brackets all compare to the same post-producer baseline.
        for command, event in (("read", "read"), ("verify", "verification")):
            anchor_bridge(path, row, "before_"+command)
            receipt = campaign.invoke([campaign.reader, command, directory], row["id"]+"-"+command, deadline)
            row[command+"_receipt"] = receipt
            anchor_bridge(path, row, "after_"+command)
            observed = one(receipt["events"], event)
            if command == "read":
                row["observation"] = observed
            else:
                row["observation"]["independent_verification"] = observed
        anchor_bridge(path, row, "before_inspection")
        row["inspection"] = campaign.inspect(directory, row["id"]+"-inspection", deadline, binding["B_generation"])
        anchor_bridge(path, row, "after_inspection")
        classification = classify_corrective_anchor(spec["mode"], row["producer"]["events"], row["observation"],
                                         row["inspection"], binding, identity, row["stored_anchor"])
        check_seed_unchanged(seed, binding, deadline)
        row["seed_unchanged_after_observation"] = True
        anchor_bridge(path, row, "final_action")
        row.update(classification)
    campaign.case(spec["id"], seed, spec["family"], action)


def one(events, name, required=True):
    found = [item for item in events if item.get("event") == name]
    if len(found) > 1 or (required and len(found) != 1):
        raise RuntimeError(f"missing or duplicate {name} receipt")
    return found[0] if found else None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_injection(item, mode, binding, identity):
    wanted = dict(mode=mode, device=identity[0], inode=identity[1], target_matches=1,
                  proof_error=0, requested_count=4096, real_write_count=4096,
                  returned_count=4096, caller_unchanged=1, offset=binding["raw_offset"],
                  ordinal=binding["write_ordinal"], write_hits=int(mode == 2),
                  source_sha256=sha(pattern(1, 1, 4096)), close_armed=1,
                  image_close_attempts=1, real_image_close_result=0, real_image_close_errno=0,
                  parent_close_attempts=1, parent_close_identity_ok=1,
                  parent_close_result=0, parent_close_errno=0,
                  close_hits=int(mode == 3), returned_image_close_result=-1 if mode == 3 else 0,
                  returned_image_close_errno=errno.EIO if mode == 3 else 0)
    replacement = bytearray(pattern(1, 1, 4096))
    if mode == 2:
        replacement[17] ^= 1
    wanted["replacement_sha256"] = sha(replacement)
    require(all(item.get(key) == value for key, value in wanted.items()),
            "injection/owned-close evidence differs from sealed expectations")
    require(isinstance(item.get("fd"), int) and item["fd"] >= 0,
            "missing owned image descriptor evidence")
    require(8192 <= binding["raw_offset"] <= 4*1024*1024-4096 and
            binding["raw_offset"] % 4096 == 0 and 1 <= binding["write_ordinal"] <= 1024,
            "invalid sealed RAW binding bounds")


def check_stored_payload(data, mode, binding, acknowledged):
    offset = binding["raw_offset"]
    original = pattern(1, 1, 4096)
    replacement = bytearray(original)
    if mode == 2:
        replacement[17] ^= 1
    actual = bytes(data[offset:offset+4096])
    require(len(data) <= 4*1024*1024 and actual == replacement,
            "stored RAW bytes do not prove the requested successful write")
    evidence = dict(offset=offset, count=4096, actual_sha256=sha(actual),
                    expected_sha256=sha(original), changed=actual != original,
                    changed_indices=[i for i, (a, b) in enumerate(zip(actual, original)) if a != b])
    require(evidence["changed_indices"] == ([17] if mode == 2 else []),
            "payload substitution was inert or changed other bytes")
    if acknowledged:
        # Only the sealed terminal payload is substituted in this memory copy.
        # Nothing is written back. All metadata and the external RAW reference
        # digest are checked by the existing independent fixed-fixture codec.
        checked = bytearray(data)
        checked[offset:offset+4096] = original
        bound = BoundImage(checked).binding(1, 1, 0)
        require(bound["raw_offset"] == offset and bound["target"] == "current/file" and
                bound["existing_raw_digest"] == binding["existing_raw_digest"],
                "stored target is not the sealed B RAW reference")
        evidence["checked_reference_chain"] = bound
        evidence["terminal_raw_digest_mismatch"] = mode == 2
    return evidence


def check_open_binding(observation, generation, root):
    for item in (observation, observation.get("independent_verification", {})):
        require(item.get("open_status") == 0 and item.get("generation") == generation and
                item.get("root_digest") == root and item.get("open_coverage") == 2,
                "fresh ordinary reader/verifier did not select the expected ROOT_ONLY anchor")


def classify_focused(mode, events, observation, binding, identity):
    """Validate semantic JSON receipts; helper exit zero does not mean API success."""
    ack = one(events, "ack", required=False)
    refusal = one(events, "result", required=False)
    close = one(events, "close")
    injected = one(events, "injection")
    begun = one(events, "begin")
    written = one(events, "write")
    require(bool(ack) != bool(refusal), "need exactly one commit ACK or operation refusal")
    operation = ack or refusal
    require([item.get("event") for item in events] ==
            ["begin", "write", "ack" if ack else "result", "close", "injection"],
            "unexpected operation/ACK/close event order")
    require(begun.get("status") == 0 and begun.get("slot_calls") == 0 and
            begun.get("fence_calls") == 0, "begin failed or published unexpectedly")
    validate_injection(injected, mode, binding, identity)
    require(close.get("status") == (2 if mode == 3 else 0) and close.get("phase") == 15 and
            close.get("errno") == (errno.EIO if mode == 3 else 0) and
            close.get("fence_attempted") == close.get("fence_succeeded") == 0,
            "checked close receipt differs from its own invocation contract")
    if ack:
        wanted = dict(status=0, generation=binding["B_generation"], phase=0, errno=0,
                      fence_attempted=3, fence_succeeded=3, coverage=2, poisoned=0,
                      transaction_active=0, slot_calls=1, fence_calls=2, hits=0)
        require(all(ack.get(key) == value for key, value in wanted.items()), "invalid B acknowledgement")
        require(written.get("status") == 0 and written.get("slot_calls") == 0 and
                written.get("fence_calls") == 0, "write-stage trace contradicts ACK")
        require(isinstance(ack.get("root_digest"), str) and len(ack["root_digest"]) == 64,
                "missing acknowledged root digest")
        require(close.get("generation") == ack["generation"] and
                close.get("root_digest") == ack["root_digest"], "close erased the acknowledged state")
        check_open_binding(observation, ack["generation"], ack["root_digest"])
        outcome = Campaign.classify(None, observation, [expected(1)], ack["generation"], mode != 2)
        if mode == 2:
            objects = observation.get("objects", [])
            target = objects[0] if objects else {}
            independent = observation.get("independent_verification", {})
            require(outcome == "integrity_refusal" and target.get("name") == "current/file" and
                    target.get("lookup_status") == 0 and target.get("read_attempted") is True and
                    target.get("read_status") == target.get("status") == 6 and
                    independent.get("verify_attempted") is True and independent.get("verify_status") == 6 and
                    independent.get("full_reachable") is False,
                    "successful-write corruption lacked first-object and independent fresh detection: " + outcome)
            return dict(outcome="integrity_refusal", classification="acknowledged_payload_unavailable",
                        acknowledged_payload_unavailable=True, unresolved_loss_risk=True,
                        preservation_pass=False, first_integrity_failure=target)
        require(outcome == "acknowledged_state_preserved", "acknowledged B not preserved: " + outcome)
        return dict(outcome=outcome, classification="close_error_after_preserved_ack" if mode == 3 else "clean_B",
                    acknowledged_payload_unavailable=False, unresolved_loss_risk=False, preservation_pass=True)
    # Missing ACK alone does not establish that publication was never attempted.
    require(mode == 2 and operation.get("status") == 6 and operation.get("errno") == 0 and
            operation.get("hits") == 0 and operation.get("slot_calls") == 0 and
            operation.get("fence_attempted") == operation.get("fence_succeeded") == 0 and
            operation.get("fence_calls") == 0 and operation.get("poisoned") == 1 and
            operation.get("transaction_active") == 0 and operation.get("phase") in (5, 7) and
            operation.get("generation") == binding["A_generation"] and
            operation.get("root_digest") == binding["A_root"] and
            written.get("status") in (0, 6) and written.get("slot_calls") == 0 and
            written.get("fence_calls") == 0,
            "not proven prepublication CORRUPT refusal; possible publication remains unresolved")
    check_open_binding(observation, binding["A_generation"], binding["A_root"])
    outcome = Campaign.classify(None, observation, [expected(0)], binding["A_generation"], True)
    require(outcome == "acknowledged_state_preserved", "prepublication refusal did not preserve A")
    return dict(outcome="complete_allowed_state", classification="prepublication_integrity_refusal",
                acknowledged_payload_unavailable=False, unresolved_loss_risk=False, preservation_pass=False)


def check_seed_unchanged(seed, binding, deadline):
    require(sha((seed/"image.sfs").read_bytes()) == binding["A_sha256"],
            "A seed changed during the case")
    require(time.monotonic() < deadline, "case deadline expired during final A-seed check")


def run_case(campaign, seed, spec, binding):
    mode = spec["mode"]

    def action(directory, deadline, row):
        row["retain_specimen"] = mode != 1
        path = directory / "image.sfs"
        before = path.stat()
        identity = (before.st_dev, before.st_ino)
        row["specimen_identity"] = dict(device=identity[0], inode=identity[1])
        offset, ordinal = (0, 0) if mode == 1 else (binding["raw_offset"], binding["write_ordinal"])
        row["producer"] = campaign.invoke([campaign.producer, "gap", directory, mode, offset, ordinal],
            row["id"]+"-producer", deadline, manifest=expected(1), ack_generation=binding["B_generation"])
        events = row["producer"]["events"]
        ack = one(events, "ack", required=False)
        injection = one(events, "injection")
        after = path.stat()
        require((after.st_dev, after.st_ino) == identity, "specimen identity changed")
        data = path.read_bytes()
        if mode == 1:
            require(ack is not None, "clean control did not acknowledge B")
            bound = BoundImage(data).binding(1, 1, 0)
            binding.update(bound, write_ordinal=injection.get("ordinal"))
            require(binding["raw_offset"] >= binding["A_length"], "RAW target is not a new append")
        validate_injection(injection, mode, binding, identity)
        row["stored_payload"] = check_stored_payload(data, mode, binding, ack is not None)
        if mode == 1:
            campaign.report["resolved_bindings"][str(spec["parity"])] = dict(binding)
            campaign.report["resolved_bindings_sha256"] = sha(json.dumps(
                campaign.report["resolved_bindings"], sort_keys=True).encode())
            campaign.save()
        row["observation"] = campaign.read(directory, row["id"]+"-read", deadline)
        row.update(classify_focused(mode, events, row["observation"], binding, identity))
        check_seed_unchanged(seed, binding, deadline)
        row["seed_unchanged_after_observation"] = True

    campaign.case(spec["id"], seed, spec["family"], action)


def finish(campaign):
    campaign.report["incomplete_case_ids"] = [spec["id"] for spec in campaign.report["case_plan"]
        if not any(row["id"] == spec["id"] and row["oracle_passed"] for row in campaign.report["cases"])]
    uncertain = campaign.report.get("completion_uncertain", False) or any(
        not campaign.gone(pid) for pid in campaign.groups)
    try:
        current = campaign.scratch.stat()
        unsafe = uncertain or campaign.scratch.is_symlink() or (current.st_dev, current.st_ino) != campaign.identity
    except OSError:
        unsafe = True
    # Keep the bounded fault specimens and all evidence for independent review.
    campaign.report.update(cleanup_verified=False, cleanup_status="unsafe_to_remove" if unsafe else "retained_for_review",
                           retained_scratch=str(campaign.scratch), process_groups_exit_verified=not uncertain,
                           preservation_pass=False)
    campaign.save()


def final_guard(campaign):
    """Recheck existing ownership/input/work bounds after final output I/O."""
    require(not campaign.report.get("error") and not campaign.report.get("finalization_errors"),
            "earlier failure prevents completion")
    require(not campaign.report.get("completion_uncertain") and
            campaign.report.get("cleanup_status") == "retained_for_review",
            "uncertain or unsafe final cleanup state")
    campaign.check_pins()
    try:
        current = campaign.scratch.stat()
        safe = not campaign.scratch.is_symlink() and (current.st_dev, current.st_ino) == campaign.identity
    except OSError:
        safe = False
    if not safe:
        campaign.report.update(cleanup_status="unsafe_to_remove", completion_uncertain=True)
        raise RuntimeError("final scratch identity changed")
    if any(not campaign.gone(pid) for pid in campaign.groups):
        campaign.report["completion_uncertain"] = True
        raise RuntimeError("final owned process-group exit is uncertain")
    campaign.bounds()
    require(time.monotonic() < campaign.deadline, "total deadline expired during final checks")


def terminal_result(campaign, preflight):
    """A saved completion candidate is valid only with a guarded terminal zero."""
    report = campaign.report
    try:
        finish(campaign)
        work_key = "preflight_work_completed" if preflight else "focused_work_completed"
        require(report.get(work_key) is True, "focused work did not complete")
        final_guard(campaign)
        report.update(preflight_completed=preflight, focused_cases_completed=not preflight,
                      campaign_completed=not preflight,
                      completion_requires_terminal_exit_zero=True)
        campaign.save()
        # Output describes provisional work, not a terminal success before the
        # post-write/flush checks have run. No success output follows that guard.
        print(json.dumps({key: report.get(key) for key in
            ("execution_mode", "preflight_work_completed", "focused_work_completed",
             "completion_requires_terminal_exit_zero", "overall_classification", "preservation_pass",
             "unresolved_loss_risk", "retained_scratch", "error")}))
        sys.stdout.flush()
        sys.stderr.flush()
        final_guard(campaign)
        return 0
    except BaseException as error:
        # Keep the original work error. Finalization diagnostics never turn an
        # unsafe identity, late deadline, pin drift or failed write into zero.
        report.setdefault("error", f"{type(error).__name__}: {error}")
        report.setdefault("finalization_errors", []).append(f"{type(error).__name__}: {error}")
        report.update(preflight_completed=False, focused_cases_completed=False, campaign_completed=False,
                      terminal_failure=True, preservation_pass=False, unresolved_loss_risk=True)
        if "corrective_expectations_pass" in report:
            report["corrective_expectations_pass"] = False
        try:
            campaign.save()
        except BaseException as save_error:
            report["finalization_errors"].append(f"failure receipt: {type(save_error).__name__}: {save_error}")
        try:
            print(json.dumps(dict(terminal_failure=True, error=report["error"],
                                  finalization_errors=report["finalization_errors"])), file=sys.stderr, flush=True)
            sys.stdout.flush()
        except BaseException:
            pass
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--preflight", action="store_true", help="compile and synthetic regressions only; no image fixtures")
    parser.add_argument("--anchor-four", action="store_true", help="four direct anchor control/altered-success cases; default six cases unchanged")
    parser.add_argument("--anchor-corrective-four", action="store_true", help="four separate false-ACK prevention cases; no preservation claim")
    args = parser.parse_args()
    if args.anchor_four and args.anchor_corrective_four:
        parser.error("choose one anchor selector")
    root = args.root.resolve(strict=True)
    compiler = shutil.which(args.cc)
    if sys.platform != "darwin" or not root.is_dir() or not compiler:
        parser.error("macOS, existing private scratch root and C compiler required")
    core_pins = CORRECTIVE_CORE_PINS if args.anchor_corrective_four else CORE_PINS
    for name, digest in core_pins.items():
        require(sha((REPO/name).read_bytes()) == digest, "reviewed production core pin changed: " + name)
    args.output.mkdir(mode=0o700, exist_ok=False)
    campaign = Campaign(root, args.output.resolve(), case_plan=sealed_corrective_anchor_plan() if args.anchor_corrective_four
                        else sealed_anchor_plan() if args.anchor_four else sealed_plan())
    campaign.report.update(execution_mode="focused_preflight" if args.preflight else "four_corrective_anchor_cases" if args.anchor_corrective_four
                           else "four_anchor_cases" if args.anchor_four else "six_focused_cases",
                           reviewed_core_sha256=core_pins, resolved_bindings={},
                           focused_cases_completed=False, preservation_pass=False, unresolved_loss_risk=False,
                           metadata_scope="Existing manifest: selected sizes, hashes, names, permissions, links, symlink and snapshots; not complete owners/timestamps/kinds.")
    if args.anchor_corrective_four:
        campaign.report.update(corrective_expectations_pass=False, ordinary_availability_pass=False,
                               preservation_pass=False, unresolved_loss_risk=True,
                               original_acknowledged_loss_finding_retained=True,
                               correction_scope="false-ACK prevention only; availability and preservation unresolved")
    try:
        here = Path(__file__).resolve()
        regression = here.with_name("native_reliability_gap_regressions.py")
        anchor_regression = here.with_name("native_reliability_anchor_regressions.py")
        campaign.compile(str(Path(compiler).resolve()), extra_sources=[here, regression, *([anchor_regression] if args.anchor_four or args.anchor_corrective_four else [])],
                         fault_defines=["-Dclose=campaign_close"], driver_defines=["-DCAMPAIGN_GAPS=1"])
        for script in (here.with_name("native_reliability_regressions.py"), regression, *([anchor_regression] if args.anchor_four or args.anchor_corrective_four else [])):
            campaign.report["setup"].append(campaign.invoke([sys.executable, "-B", script], script.stem,
                min(campaign.deadline, time.monotonic()+CASE_SECONDS), json_lines=False))
        if args.preflight:
            campaign.check_pins()
            campaign.bounds()
            campaign.report["preflight_work_completed"] = True
        else:
            for parity in (0, 1):
                deadline = min(campaign.deadline, time.monotonic()+CASE_SECONDS)
                seed = campaign.scratch/f"gap-seed-{parity}"
                seed.mkdir(mode=0o700)
                setup = campaign.invoke([campaign.reader, "seed", seed, parity], f"gap-seed-{parity}",
                    deadline, manifest=expected(0), ack_generation=3+parity)
                campaign.report["setup"].append(setup)
                ack = one(setup["events"], "ack")
                observation = campaign.read(seed, f"gap-seed-{parity}-read", deadline)
                check_open_binding(observation, 3+parity, ack["root_digest"])
                require(campaign.classify(observation, [expected(0)], 3+parity, True) == "acknowledged_state_preserved",
                        "A seed is not intact")
                path = seed/"image.sfs"
                binding = dict(A_generation=3+parity, B_generation=4+parity,
                               A_root=ack["root_digest"], A_length=path.stat().st_size,
                               A_sha256=sha(path.read_bytes()), B_slot=(4+parity) % 2)
                require(binding["B_slot"] == parity, "publication parity mismatch")
                if args.anchor_four or args.anchor_corrective_four:
                    binding["A_uuid"] = BoundImage(path.read_bytes()).uuid.hex()
                    campaign.report["resolved_bindings"][str(parity)] = dict(binding)
                    campaign.report["resolved_bindings_sha256"] = sha(json.dumps(
                        campaign.report["resolved_bindings"], sort_keys=True).encode())
                    campaign.save()
                for spec in [row for row in campaign.report["case_plan"] if row["parity"] == parity]:
                    require(sha(path.read_bytes()) == binding["A_sha256"], "A seed changed")
                    (run_corrective_anchor_case if args.anchor_corrective_four else
                     run_anchor_case if args.anchor_four else run_case)(campaign, seed, spec, binding)
            campaign.check_pins()
            campaign.bounds()
            require(len(campaign.report["cases"]) == (4 if args.anchor_four or args.anchor_corrective_four else 6) and
                    all(row["oracle_passed"] for row in campaign.report["cases"]), "focused case table incomplete")
            if args.anchor_corrective_four:
                require(all(row.get("corrective_expectations_pass") is True for row in campaign.report["cases"]),
                        "corrective expectation table incomplete")
                campaign.report.update(focused_work_completed=True, corrective_expectations_pass=True, ordinary_availability_pass=False,
                    preservation_pass=False, unresolved_loss_risk=True, original_acknowledged_loss_finding_retained=True,
                    overall_classification="corrective_expectations_completed_false_ack_prevention_only")
            else:
                unavailable = any(row.get("acknowledged_payload_unavailable") for row in campaign.report["cases"])
                campaign.report.update(focused_work_completed=True,
                    unresolved_loss_risk=unavailable, acknowledged_payload_unavailable=unavailable,
                    overall_classification="detection_completed_acknowledged_payload_unavailable" if unavailable
                        else "focused_cases_completed_no_overall_preservation_claim")
            # Do not turn bounded detection into the old overall integrity/pass flag.
            campaign.report["integrity_oracle_passed"] = False
    except BaseException as error:
        campaign.report["error"] = f"{type(error).__name__}: {error}"
        campaign.report["unresolved_loss_risk"] = True
    # Zero means this finite detection/close experiment completed, not data preservation.
    return terminal_result(campaign, args.preflight)


if __name__ == "__main__":
    sys.exit(main())
