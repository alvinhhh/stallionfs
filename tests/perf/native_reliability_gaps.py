#!/usr/bin/env python3
"""Six disposable-image checks; completion is not an overall preservation pass."""
import argparse
import errno
import json
from pathlib import Path
import shutil
import sys
import time

from native_reliability import (BoundImage, Campaign, CASE_SECONDS, REPO,
                                expected, pattern, sha)

CORE_PINS = {
    "filesystem/image.c": "5a125345c2bb9a261ab5ff6879a18aa48f9010f737c1696f7b86153cf1eb4eaf",
    "filesystem/image.h": "a335012f3103178baa7229ed405b1b9211a27e3c0b257bbd8f0bf91dc4dd6163",
}
FAMILIES = (("control", 1), ("acknowledged_payload_success", 2), ("close_eio", 3))


def sealed_plan():
    return [dict(id=f"gap-{parity}-{family}", family=family, parity=parity, mode=mode)
            for parity in (0, 1) for family, mode in FAMILIES]


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
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    compiler = shutil.which(args.cc)
    if sys.platform != "darwin" or not root.is_dir() or not compiler:
        parser.error("macOS, existing private scratch root and C compiler required")
    for name, digest in CORE_PINS.items():
        require(sha((REPO/name).read_bytes()) == digest, "reviewed production core pin changed: " + name)
    args.output.mkdir(mode=0o700, exist_ok=False)
    campaign = Campaign(root, args.output.resolve(), case_plan=sealed_plan())
    campaign.report.update(execution_mode="focused_preflight" if args.preflight else "six_focused_cases",
                           reviewed_core_sha256=CORE_PINS, resolved_bindings={},
                           focused_cases_completed=False, preservation_pass=False, unresolved_loss_risk=False,
                           metadata_scope="Existing manifest: selected sizes, hashes, names, permissions, links, symlink and snapshots; not complete owners/timestamps/kinds.")
    try:
        here = Path(__file__).resolve()
        regression = here.with_name("native_reliability_gap_regressions.py")
        campaign.compile(str(Path(compiler).resolve()), extra_sources=[here, regression],
                         fault_defines=["-Dclose=campaign_close"], driver_defines=["-DCAMPAIGN_GAPS=1"])
        for script in (here.with_name("native_reliability_regressions.py"), regression):
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
                for spec in [row for row in campaign.report["case_plan"] if row["parity"] == parity]:
                    require(sha(path.read_bytes()) == binding["A_sha256"], "A seed changed")
                    run_case(campaign, seed, spec, binding)
            campaign.check_pins()
            campaign.bounds()
            require(len(campaign.report["cases"]) == 6 and all(row["oracle_passed"] for row in campaign.report["cases"]),
                    "six-case table incomplete")
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
