#!/usr/bin/env python3
"""Bounded closed-image acknowledgement and corruption campaign for macOS."""
import argparse
from contextlib import contextmanager
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
MAX_CASES, MAX_BYTES, CASE_SECONDS, TOTAL_SECONDS = 80, 512 * 1024 * 1024, 15, 600
CELL = 4096
CALL_RESERVATION = 48 * 1024 * 1024
CLEANUP_GRACE=2


def request_group_kill(child, receipt, reason):
    """Only an unreaped direct child reserves the PID used as this private PGID.

    The controller is single-threaded: no other waiter may reap this child
    between poll() and killpg(). A cached/reaped PID never authorizes a signal.
    """
    request = dict(reason=reason, pid=child.pid, signal=int(signal.SIGKILL), attempted=False)
    receipt.setdefault("signal_requests", []).append(request)
    try:
        returncode = child.poll()
    except BaseException as error:
        request.update(outcome="skip_poll_error", error=f"{type(error).__name__}: {error}")
        receipt["completion_uncertain"] = True
        return False
    request["poll_returncode"] = returncode
    if returncode is not None:
        request["outcome"] = "skip_already_reaped"
        return False
    request["attempted"] = True
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except BaseException as error:
        request.update(outcome="signal_error", error=f"{type(error).__name__}: {error}",
                       errno=getattr(error, "errno", None))
        receipt["completion_uncertain"] = True
        return False
    request["outcome"] = "signal_sent"
    return True


def cleanup_wait(child, receipt, until):
    wait = dict(attempted=False)
    receipt["cleanup_wait"] = wait
    if child.returncode is not None:
        wait.update(outcome="already_reaped", returncode=child.returncode)
        return
    wait["attempted"] = True
    try:
        child.wait(timeout=max(.001, until-time.monotonic()))
    except BaseException as error:
        wait.update(outcome="wait_error", error=f"{type(error).__name__}: {error}")
        receipt["completion_uncertain"] = True
    else:
        wait.update(outcome="reaped", returncode=child.returncode)


def group_exit_observed(child, receipt):
    """Read-only reconciliation; an existing group after reap is ambiguous."""
    observation = dict(pid=child.pid, signal=0)
    receipt["group_exit_observation"] = observation
    try:
        os.killpg(child.pid, 0)
    except ProcessLookupError:
        observation["outcome"] = "absent"
    except BaseException as error:
        observation.update(outcome="probe_error", error=f"{type(error).__name__}: {error}")
        receipt["completion_uncertain"] = True
    else:
        observation["outcome"] = "exists_after_reap" if child.returncode is not None else "leader_unreaped"
        receipt["completion_uncertain"] = True
    if child.returncode is None:
        receipt["completion_uncertain"] = True
    return observation["outcome"] == "absent" and not receipt.get("completion_uncertain", False)


@contextmanager
def receipt_log(path, receipt_path, receipt, report):
    """A buffered log close must not replace the supervision exception."""
    stream = path.open("wb")
    primary_error = None
    try:
        yield stream
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            stream.close()
        except BaseException as error:
            failure = dict(stage="stderr_log_close", error=f"{type(error).__name__}: {error}")
            receipt.setdefault("cleanup_errors", []).append(failure)
            report.setdefault("cleanup_errors", []).append(failure)
            receipt.update(completion_uncertain=True, process_group_exit_verified=False)
            report["completion_uncertain"] = True
            original = primary_error if primary_error is not None else error
            if primary_error is not None and hasattr(original, "add_note"):
                original.add_note("Buffered stderr log cleanup also failed: " + failure["error"])
            try:
                receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
            except BaseException as save_error:
                if hasattr(original, "add_note"):
                    original.add_note(f"Updated cleanup receipt also failed: {type(save_error).__name__}: {save_error}")
            if primary_error is None:
                raise error


def fault_expectation(name,ordinal):
    error=errno.EIO if name.endswith(("_eio","_zero")) else errno.ENOSPC
    if name.startswith("slot_"): status,attempted,succeeded=8,1,1
    elif name.startswith("fence_"):
        status,attempted,succeeded=(2,1,0) if ordinal==1 else (8,3,1)
    else: status,attempted,succeeded=2,0,0
    return dict(status=status,errno=error,fence_attempted=attempted,fence_succeeded=succeeded,poisoned=1,hits=1)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pattern(state, kind, length):
    return bytes((state * 67 + kind * 31 + i * 17 + (i >> 8)) & 255 for i in range(length))


def expected(state, recovery=False):
    objects = {}
    for view, version in [("current", state), ("baseline", 0)] + ([("recovery", 1)] if recovery else []):
        for name, kind, length in [("file", 1, 12288), ("companion", 2, 8192), ("xattr", 3, 8192), ("resource", 4, 8192)]:
            objects[view + "/" + name] = dict(length=length, sha256=sha(pattern(version, kind, length)))
    return objects


def sealed_plan():
    plan=[]
    def add(label,family,parity,**spec):
        plan.append(dict(id=label,family=family,parity=parity,**spec))
    for parity in range(2):
        for operation in ("write","restore"):
            for repeat in range(4):
                add(f"ack-{parity}-{operation}-{repeat}","post_ack_kill",parity,operation=operation,
                    allowed_state="B" if operation=="write" else "A-with-recovery-B",require_preserved=True)
        for point in range(1,5):
            add(f"cut-{parity}-{point}","pre_ack_cut",parity,cut_point=point,allowed_state="A-or-B-or-integrity-refusal")
        faults=[(f"record_{kind}",nth) for nth in (1,"last_record") for kind in ("eio","enospc","zero","partial")]
        faults += [(f"slot_{kind}",1) for kind in ("eio","enospc","zero","partial","torn73","torn4095")]
        faults += [(f"fence_{kind}",nth) for nth in (1,2) for kind in ("eio","enospc")]
        if parity: faults=[item for item in faults if item[0].startswith("slot_")]
        for index,(fault,nth) in enumerate(faults):
            add(f"fault-{parity}-{index}-{fault}","syscall_failure",parity,fault=fault,ordinal=nth,
                expected_failure=fault_expectation(fault,nth),allowed_state="A-or-B-or-integrity-refusal")
        for name in ("control","slot-checksum","zero-prefix-73","zero-prefix-512","zero-prefix-4095","old-prefix-73","root-byte","truncate-last","truncate-middle","truncate-root"):
            add(f"metadata-{parity}-{name}","acknowledged_metadata_damage",parity,mutation=name,
                allowed_state="B" if name=="control" else "B-or-integrity-refusal")
        for index,(state,kind,page) in enumerate([(1,1,0),(1,1,1),(1,1,2),(1,3,0),(1,4,0),(0,1,0)]):
            add(f"payload-{parity}-{index}","acknowledged_payload_damage",parity,state=state,kind=kind,page=page,allowed_state="B-or-integrity-refusal")
    if len(plan)!=MAX_CASES:
        raise RuntimeError("sealed case count changed")
    return plan


class Campaign:
    def __init__(self, root, output, case_plan=None):
        self.output = output
        self.scratch = Path(tempfile.mkdtemp(prefix="sfs-native-reliability-", dir=root))
        self.identity = (self.scratch.stat().st_dev, self.scratch.stat().st_ino)
        self.deadline = time.monotonic() + TOTAL_SECONDS
        self.groups = set()
        plan=sealed_plan() if case_plan is None else case_plan
        self.report = dict(schema=1, campaign_completed=False, integrity_oracle_passed=False, cases=[], setup=[],
                           case_plan=plan,case_plan_sha256=sha(json.dumps(plan,sort_keys=True).encode()),
                           allowed_manifests={"A":expected(0),"B":expected(1),"A-with-recovery-B":expected(0,True)},
                           storage_accounting="Logical scratch and evidence file lengths plus 48 MiB reserved before each helper call; not sparse physical allocation.",
                           limits=dict(cases=len(plan), logical_evidence_bytes=MAX_BYTES, call_reservation_bytes=CALL_RESERVATION,
                                       cooperative_case_work_seconds=CASE_SECONDS,cooperative_total_work_seconds=TOTAL_SECONDS,
                                       shared_cleanup_grace_seconds=CLEANUP_GRACE), retained_specimens=[],
                           interpretation=["Finite fault testing cannot establish zero data-loss risk or authorize release.",
                           "Integrity refusal detects damage; it does not preserve or reconstruct acknowledged data.",
                           "Object reads and separate-process full reachable verification use independently reopened ordinary handles.",
                           "Injected ENOSPC/EIO are syscall failures, not actual host exhaustion or physical power loss."])
        self.save()

    def save(self):
        (self.output / "result.json").write_text(json.dumps(self.report, indent=2) + "\n")

    def bounds(self, reserve=0):
        used = sum(path.lstat().st_size for root in (self.scratch,self.output)
                   for path in root.rglob("*") if path.is_file())
        self.report["logical_evidence_bytes_observed"] = used
        if used + reserve > MAX_BYTES or time.monotonic() >= self.deadline:
            raise RuntimeError("campaign storage or total-time bound reached")

    @staticmethod
    def gone(pid):
        try:
            os.killpg(pid, 0)
            return False
        except ProcessLookupError:
            return True
        except OSError:
            return False

    def invoke(self, argv, label, deadline, event=None, manifest=None, json_lines=True,
               event_fields=None, ack_generation=None):
        self.bounds(CALL_RESERVATION)
        deadline = min(deadline, self.deadline)
        if time.monotonic() >= deadline:
            raise TimeoutError("work deadline before child launch")
        cleanup_until=deadline+CLEANUP_GRACE
        receipt = dict(label=label, command=Path(str(argv[0])).name, events=[], expected_event=event,
                       timed_out=False, process_group_exit_verified=False)
        log = self.output / (label + ".stderr.log")
        with receipt_log(log, self.output / (label + ".json"), receipt, self.report) as errors:
            child = subprocess.Popen([str(a) for a in argv], cwd=self.scratch, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, start_new_session=True)
            self.groups.add(child.pid)
            selector = None
            pending, matched, captured, error_bytes = b"", False, 0, 0
            primary_error = None
            try:
                selector = selectors.DefaultSelector()
                selector.register(child.stdout, selectors.EVENT_READ)
                selector.register(child.stderr, selectors.EVENT_READ)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        receipt["timed_out"] = True
                        raise TimeoutError("owned child deadline")
                    for key, _ in selector.select(min(remaining, .1)):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        if key.fileobj is child.stderr:
                            error_bytes += len(data)
                            if error_bytes>262144:
                                raise RuntimeError("child stderr exceeded evidence bound")
                            errors.write(data)
                            continue
                        captured += len(data)
                        if captured>262144:
                            raise RuntimeError("child stdout exceeded evidence bound")
                        pending += data
                        if len(pending) > 262144:
                            raise RuntimeError("child receipt exceeded bound")
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            if not json_lines:
                                receipt.setdefault("text", []).append(line.decode(errors="replace"))
                                continue
                            item = json.loads(line)
                            receipt["events"].append(item)
                            if item.get("event") == "ack":
                                if (item.get("status") != 0 or item.get("fence_succeeded") != 3 or
                                    item.get("fence_attempted") != 3 or item.get("poisoned") != 0 or
                                    item.get("transaction_active") != 0 or manifest is None or
                                    (ack_generation is not None and item.get("generation") != ack_generation)):
                                    raise RuntimeError("invalid or unexpected commit acknowledgement")
                                ledger = dict(label=label, receipt=item, expected_manifest=manifest,
                                              expected_manifest_sha256=sha(json.dumps(manifest, sort_keys=True).encode()))
                                with (self.output / "acknowledgements.jsonl").open("a") as stream:
                                    stream.write(json.dumps(ledger, sort_keys=True) + "\n")
                                    stream.flush()
                                    os.fsync(stream.fileno())
                            if item.get("event") == event:
                                if any(item.get(key) != value for key, value in (event_fields or {}).items()):
                                    raise RuntimeError("interruption receipt differs from requested cut")
                                matched = request_group_kill(child, receipt, "requested_" + event)
                                if not matched:
                                    raise RuntimeError("requested interruption was not safely signalled")
                child.wait(timeout=max(.001, deadline - time.monotonic()))
                receipt["returncode"] = child.returncode
                if pending.strip() and json_lines:
                    raise RuntimeError("incomplete child receipt")
                if pending.strip() and not json_lines:
                    receipt.setdefault("text", []).append(pending.decode(errors="replace"))
                if event and not matched:
                    raise RuntimeError("requested interruption event was not observed")
                if child.returncode and not (matched and child.returncode == -signal.SIGKILL):
                    raise RuntimeError("owned child failed; stderr retained")
            except BaseException as error:
                primary_error = error
                receipt["supervision_error"] = f"{type(error).__name__}: {error}"
                request_group_kill(child, receipt, "exception_cleanup")
                cleanup_wait(child, receipt, cleanup_until)
                raise
            finally:
                closes = [("stdout", child.stdout.close), ("stderr", child.stderr.close)]
                if selector is not None:
                    closes.insert(0, ("selector", selector.close))
                for stage, close in closes:
                    try:
                        close()
                    except BaseException as error:
                        receipt.setdefault("cleanup_errors", []).append(dict(stage=stage, error=f"{type(error).__name__}: {error}"))
                        receipt["completion_uncertain"] = True
                receipt["returncode"] = child.returncode
                receipt["process_group_exit_verified"] = group_exit_observed(child, receipt)
                if receipt.get("completion_uncertain"):
                    self.report["completion_uncertain"] = True
                try:
                    (self.output / (label + ".json")).write_text(json.dumps(receipt, indent=2) + "\n")
                except BaseException as error:
                    self.report["completion_uncertain"] = True
                    if primary_error is None:
                        raise
                    if hasattr(primary_error, "add_note"):
                        primary_error.add_note(f"Receipt cleanup also failed: {type(error).__name__}: {error}")
        if not receipt["process_group_exit_verified"]:
            raise RuntimeError("owned process group exit uncertain")
        self.bounds()
        return receipt

    def read(self, directory, label, deadline):
        image = directory / "image.sfs"
        before = sha(image.read_bytes())
        receipt = self.invoke([self.reader, "read", directory], label, deadline)
        if sha(image.read_bytes()) != before:
            raise RuntimeError("non-mutating reader changed specimen")
        events = [e for e in receipt["events"] if e.get("event") == "read"]
        if len(events) != 1:
            raise RuntimeError("missing reader observation")
        verification=self.invoke([self.reader,"verify",directory],label+"-independent-verify",deadline)
        if sha(image.read_bytes()) != before:
            raise RuntimeError("independent verifier changed specimen")
        verified=[e for e in verification["events"] if e.get("event")=="verification"]
        if len(verified)!=1:
            raise RuntimeError("missing independent verification observation")
        if time.monotonic() >= min(deadline,self.deadline):
            raise TimeoutError("work deadline during reader/verifier hashing")
        events[0]["independent_verification"]=verified[0]
        return events[0]

    def classify(self, observation, allowed, min_generation, require_preserved=False):
        """Validate every successful observation before accepting an integrity error."""
        opened=observation["open_status"]==0
        if opened and observation["generation"]<min_generation:
            return "silent_stale_success"
        if opened and observation["generation"]>min_generation+(len(allowed)-1):
            return "silent_wrong_data_success"
        candidates=list(allowed)
        if opened and len(allowed)>1:
            candidates=[allowed[observation["generation"]-min_generation]]
        statuses=[observation["open_status"],observation.get("verify_status",12)]
        wrong="silent_wrong_data_success"
        def restrict(predicate):
            candidates[:]=[manifest for manifest in candidates if predicate(manifest)]
        def views(manifest): return {name.split("/",1)[0] for name in manifest}
        want={name:dict(is_file=regular,size=size,mode=mode,links=links)
              for name,regular,size,mode,links in [("file",True,12288,0o640,2),("alias",True,12288,0o640,2),
              ("companion",True,8192,0o600,1),("link",False,4,0o700,1),("root",False,0,0o700,1)]}
        objects=observation.get("objects",[])
        if len({obj["name"] for obj in objects})!=len(objects): return wrong
        for obj in objects:
            statuses.append(obj["status"])
            target=next((manifest[obj["name"]] for manifest in candidates if obj["name"] in manifest),None)
            if target is None:return wrong
            object_name=obj["name"].split("/")[-1]
            expected_lookup_size=8192 if object_name=="companion" else 12288
            statuses.append(obj["lookup_status"])
            if not obj["lookup_status"] and (obj["lookup_size"]!=expected_lookup_size or not obj["lookup_is_file"]):return wrong
            expected_size_attempted=not obj["lookup_status"] and object_name in ("xattr","resource")
            if obj["size_attempted"]!=expected_size_attempted:return "unresolved"
            prior_status=obj["lookup_status"]
            if obj["size_attempted"]:
                statuses.append(obj["size_status"])
                prior_status=obj["size_status"]
                if not prior_status and obj["size_value"]!=target["length"]:return wrong
            if obj["read_attempted"]:
                statuses.append(obj["read_status"])
                if prior_status or obj["status"]!=obj["read_status"]:return "unresolved"
            elif obj["count"] or obj["status"]!=prior_status or not prior_status:
                return "unresolved"
            if obj.get("invalid_count") or not 0<=obj["count"]<=obj["length"]<=65536:
                return "invalid_checked_prefix"
            if not obj["status"]:
                value=dict(length=obj["length"],sha256=obj["sha256"])
                restrict(lambda m:m.get(obj["name"])==value and obj["count"]==obj["length"])
            elif obj["count"]:
                kind={"file":1,"companion":2,"xattr":3,"resource":4}.get(obj["name"].split("/")[-1])
                def prefix_matches(m):
                    target=m.get(obj["name"])
                    return bool(target and kind and any(sha(pattern(state,kind,target["length"]))==target["sha256"] and
                        sha(pattern(state,kind,target["length"])[:obj["count"]])==obj["sha256"] for state in (0,1)))
                restrict(prefix_matches)
                if not candidates:return "invalid_checked_prefix"
            if not candidates:return wrong
        metadata=observation.get("metadata",[])
        if len({item["name"] for item in metadata})!=len(metadata):return wrong
        for item in metadata:
            statuses.append(item["lookup_status"])
            if item.get("metadata_attempted",item["lookup_status"]==0):statuses.append(item["metadata_status"])
            target=want.get(item["name"])
            if not item["lookup_status"] and (not target or any(item[key]!=target[key] for key in ("is_file","size"))):return wrong
            if not item["metadata_status"] and (not target or any(item[key]!=target[key] for key in ("mode","links"))):return wrong
        if observation.get("alias_comparison_attempted") and not observation.get("alias_equal"):return wrong
        link=observation.get("symlink",dict(status=12,count=0,capacity=4,target_hex=""))
        if link.get("attempted",True):statuses.append(link["status"])
        if link.get("invalid_count") or not 0<=link["count"]<=link["capacity"]<=4096:return "invalid_checked_prefix"
        if not link["status"] and (link["count"]!=4 or link["target_hex"]!=b"file".hex()):return wrong
        if link["status"] and link["count"]:return "invalid_checked_prefix"
        namespaces=observation.get("namespaces",[])
        if len({view["view"] for view in namespaces})!=len(namespaces):return wrong
        for view in namespaces:
            statuses.append(view["status"])
            restrict(lambda m:view["view"] in views(m))
            seen=set()
            for item in view["entries"]:
                name=bytes.fromhex(item["name_hex"]).decode("ascii",errors="replace")
                target=want.get(name)
                if item.get("invalid_name_length") or name in seen or name=="root" or not target:return wrong
                seen.add(name)
                if any(item[key]!=target[key] for key in ("is_file","size")):return wrong
                statuses.append(item["metadata_status"])
                if not item["metadata_status"] and any(item[key]!=target[key] for key in ("mode","links")):return wrong
            if not view["status"] and seen!={"file","alias","companion","link"}:return wrong
        catalog=observation.get("catalog",dict(status=12,names_hex=[]))
        statuses.append(catalog["status"])
        if catalog.get("invalid_name_length") or len(set(catalog["names_hex"]))!=len(catalog["names_hex"]):return wrong
        def catalog_matches(m):
            names={b"baseline".hex()}|({b"recovery".hex()} if "recovery" in views(m) else set())
            actual=set(catalog["names_hex"])
            return actual==names if not catalog["status"] else actual<=names
        restrict(catalog_matches)
        baseline=observation.get("baseline_status",12); recovery=observation.get("recovery_status",12)
        statuses.append(baseline)
        if not recovery:restrict(lambda m:"recovery" in views(m))
        elif recovery==10:restrict(lambda m:"recovery" not in views(m))
        else:statuses.append(recovery)
        if not candidates:return wrong
        independent=observation.get("independent_verification")
        if not independent:return "unresolved"
        independent_opened=independent["open_status"]==0
        if independent.get("verify_attempted")!=independent_opened:return "unresolved"
        if independent_opened:
            if independent["generation"]<min_generation:return "silent_stale_success"
            if independent["generation"]>min_generation+(len(allowed)-1):return wrong
            if opened and independent["generation"]!=observation["generation"]:return "unresolved"
        independent_statuses=[independent["open_status"]]+([independent["verify_status"]] if independent_opened else [])
        if any(status not in (0,6,7) for status in independent_statuses):return "unresolved"
        independent_success=(independent_opened and independent["verify_status"]==0 and independent["full_reachable"])
        if independent["full_reachable"] and not (independent_opened and independent["verify_status"]==0):return "unresolved"
        if independent_opened and not independent["verify_status"] and not independent["full_reachable"]:return "unresolved"
        read_integrity_error=any(status in (6,7) for status in statuses)
        independent_integrity_error=any(status in (6,7) for status in independent_statuses)
        if (read_integrity_error and independent_success) or (
            observation.get("full_reachable") and (read_integrity_error or independent_integrity_error)) or (
            observation.get("full_reachable") and observation.get("verify_status")!=0):
            return "contradictory_integrity_observation"
        statuses.extend(independent_statuses)
        if not opened:
            if objects or namespaces or any(not item["lookup_status"] or not item["metadata_status"] for item in metadata):return "unresolved"
            return "integrity_refusal" if observation["open_status"] in (6,7) and not require_preserved else "unresolved"
        errors=[status for status in statuses if status]
        if errors:
            if any(status not in (6,7,9) for status in errors):return "unresolved"
            return "integrity_refusal" if any(status in (6,7) for status in errors) and not require_preserved else "unresolved"
        if not observation.get("full_reachable") or not independent_success or not observation.get("alias_comparison_attempted"):return "unresolved"
        restrict(lambda m:{obj["name"] for obj in objects}==set(m) and {view["view"] for view in namespaces}==views(m))
        if not candidates or {item["name"] for item in metadata}!=set(want):return wrong
        return "acknowledged_state_preserved" if require_preserved else "complete_allowed_state"

    def inspect(self,directory,label,deadline,floor):
        image=directory/"image.sfs"; before=sha(image.read_bytes())
        receipt=self.invoke([self.reader,"inspect",directory],label,deadline)
        if sha(image.read_bytes())!=before:
            raise RuntimeError("explicit inspection changed specimen")
        observations=[item for item in receipt["events"] if item.get("event")=="inspection"]
        if len(observations)!=1:
            raise RuntimeError("missing explicit recovery inspection")
        result=observations[0]
        result["selected_any_candidate"]=False
        for slot in result["slots"]:
            slot["classification"]=("explicit_stale_candidate" if slot["generation"]<floor else "not_stale_candidate") if slot["full_reachable"] else "unusable_candidate"
        return result

    def specimen(self, seed, label):
        self.bounds(4 * 1024 * 1024)
        directory = self.scratch / label
        directory.mkdir(mode=0o700)
        shutil.copyfile(seed / "image.sfs", directory / "image.sfs")
        (directory / "image.sfs").chmod(0o600)
        if sha((directory/"image.sfs").read_bytes())!=sha((seed/"image.sfs").read_bytes()):
            raise RuntimeError("specimen copy differs from acknowledged seed")
        return directory

    def case(self, label, seed, family, action):
        deadline=min(self.deadline,time.monotonic()+CASE_SECONDS)
        self.check_pins()
        if len(self.report["cases"]) >= len(self.report["case_plan"]):
            raise RuntimeError("case bound reached")
        spec=self.report["case_plan"][len(self.report["cases"])]
        if spec["id"]!=label or spec["family"]!=family:
            raise RuntimeError("execution differs from sealed case table")
        row = dict(id=label, family=family, outcome="unresolved", oracle_passed=False, explicit_recovery="not_attempted")
        self.report["cases"].append(row)
        directory = self.specimen(seed, label)
        if time.monotonic()>=deadline:raise TimeoutError("case work deadline during specimen copy/hash")
        try:
            action(directory, deadline, row)
            if row["outcome"]=="integrity_refusal":
                binding=self.report["resolved_bindings"][str(spec["parity"])]
                floor=binding["B_generation"] if family.startswith("acknowledged_") else binding["A_generation"]
                row["explicit_recovery"]=self.inspect(directory,label+"-inspection",deadline,floor)
            row["oracle_passed"] = row["outcome"] in ("acknowledged_state_preserved", "complete_allowed_state", "integrity_refusal")
            row["acknowledged_data_preservation_established"]=row["outcome"]=="acknowledged_state_preserved"
            if not row["oracle_passed"]:
                raise RuntimeError(label + ": " + row["outcome"])
        finally:
            if self.report.get("completion_uncertain"):
                row["retained_without_further_observation"] = True
                self.report["retained_specimens"].append(label)
                primary_error = sys.exc_info()[1]
                try:
                    self.save()
                except BaseException as error:
                    if primary_error is None:
                        raise
                    if hasattr(primary_error, "add_note"):
                        primary_error.add_note(f"Retention receipt also failed: {type(error).__name__}: {error}")
            else:
                row["image_sha256"] = sha((directory / "image.sfs").read_bytes())
                late=time.monotonic()>=min(deadline,self.deadline)
                if late:row.update(outcome="unresolved",oracle_passed=False,deadline_exceeded=True)
                if not row.get("retain_specimen") and row["oracle_passed"] and row["outcome"] in ("acknowledged_state_preserved", "complete_allowed_state"):
                    shutil.rmtree(directory)
                else:
                    self.report["retained_specimens"].append(label)
                self.save()
                if late:raise TimeoutError("case work deadline before accepting outcome")

    def compile(self, cc, extra_sources=(), fault_defines=(), driver_defines=()):
        tests, core = REPO / "tests", REPO / "filesystem"
        sources = [core / "image.c", core / "image.h", tests / "native_reliability_driver.c",
                   tests / "native_reliability_hooks.c", tests / "fskit_write_hooks.c", tests / "fskit_write_hooks.h",
                   Path(__file__).resolve(),Path(__file__).with_name("native_reliability_regressions.py"), *extra_sources]
        self.pinned_sources=sources
        self.report["source_sha256"] = {str(p.relative_to(REPO)): sha(p.read_bytes()) for p in sources}
        flags = [cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-deprecated-declarations", "-I", core]
        normal, faulted = self.scratch / "ordinary.o", self.scratch / "faulted.o"
        self.reader, self.producer = self.scratch / "reader", self.scratch / "producer"
        commands = [[*flags, "-c", core / "image.c", "-o", normal],
                    [*flags, "-Dpwrite=campaign_pwrite", "-Dfcntl=campaign_fcntl", *fault_defines, "-c", core / "image.c", "-o", faulted],
                    [*flags, tests / "native_reliability_driver.c", normal, "-o", self.reader],
                    [*flags, "-DCAMPAIGN_FAULTS=1", *driver_defines, tests / "native_reliability_driver.c", tests / "native_reliability_hooks.c", faulted, "-o", self.producer]]
        version = self.invoke([cc, "--version"], "compiler-version", min(self.deadline,time.monotonic()+CASE_SECONDS),json_lines=False)
        self.report["setup"].append(version)
        for index, argv in enumerate(commands):
            self.report["setup"].append(self.invoke(argv, f"compile-{index}", min(self.deadline, time.monotonic()+CASE_SECONDS),json_lines=False))
        self.check_pins()
        self.report["binary_sha256"]={"reader":sha(self.reader.read_bytes()),"producer":sha(self.producer.read_bytes())}
        self.report["postcompile_source_sha256"]={str(p.relative_to(REPO)):sha(p.read_bytes()) for p in sources}
        self.save()

    def check_pins(self):
        for path in self.pinned_sources:
            if sha(path.read_bytes())!=self.report["source_sha256"][str(path.relative_to(REPO))]:
                raise RuntimeError("source pin changed; campaign stopped")
        for name,digest in self.report.get("binary_sha256",{}).items():
            if sha(getattr(self,name).read_bytes())!=digest:raise RuntimeError("compiled helper pin changed")


def mutate_metadata(path, name):
    data = bytearray(path.read_bytes())
    generations = [struct.unpack_from("<Q", data, i*CELL+40)[0] for i in range(2)]
    slot = 0 if generations[0] > generations[1] else 1
    offset = slot * CELL
    root = struct.unpack_from("<Q", data, offset+56)[0]
    if root < 8192 or root % CELL or root+CELL > len(data):
        raise RuntimeError("independent anchor bounds failed")
    original = bytes(data)
    changed_offset = offset
    if name == "control":
        return dict(kind=name, changed=False)
    if name == "slot-checksum":
        changed_offset=offset+112; data[changed_offset] ^= 1
    elif name.startswith("zero-prefix-"):
        length=int(name.rsplit("-",1)[1]); data[offset:offset+length]=bytes(length)
    elif name == "old-prefix-73":
        data[offset:offset+73]=data[(1-slot)*CELL:(1-slot)*CELL+73]
    elif name == "root-byte":
        changed_offset=root+64; data[changed_offset] ^= 1
    else:
        retained={"truncate-last":root+CELL-1,"truncate-middle":root+CELL//2,"truncate-root":root}[name]
        changed_offset=retained; del data[retained:]
    with path.open("r+b") as stream:
        stream.write(data); stream.truncate(); stream.flush(); os.fsync(stream.fileno())
    return dict(kind=name, changed=True, offset=changed_offset, before_sha256=sha(original), after_sha256=sha(data),
                original_bytes=original[changed_offset:changed_offset+32].hex(), replacement_bytes=bytes(data[changed_offset:changed_offset+32]).hex())


class BoundImage:
    """Independent bounded leaf codec for the fixed format-0.6 fixture only."""
    def __init__(self,data):
        self.data=bytes(data);self.chain=[]
        if not 8192<=len(data)<=4*1024*1024:raise ValueError("fixture bounds")
        self.slot=max(range(2),key=lambda i:self.u64(i*CELL+40));at=self.slot*CELL
        header=bytearray(data[at:at+CELL]);digest=bytes(header[112:144]);header[112:144]=bytes(32)
        if header[:8]!=b"SFSIMG01" or self.u32(at+12)!=6 or hashlib.sha256(header).digest()!=digest:raise ValueError("anchor digest/version")
        self.uuid=data[at+24:at+40];self.root=self.record(at+48,4,len(data))
    def u32(self,at):return struct.unpack_from("<I",self.data,at)[0]
    def u64(self,at):return struct.unpack_from("<Q",self.data,at)[0]
    def record(self,ref,kind,before):
        if not 0<=ref<=len(self.data)-56:raise ValueError("reference bounds")
        at,length=self.u64(ref+8),self.u64(ref+16)
        if self.u32(ref)!=kind or length!=CELL or at<8192 or at%CELL or at+CELL>len(self.data) or at>=before:raise ValueError("record bounds/type")
        data=self.data[at:at+CELL]
        domain=b"SFSDAT06"+self.uuid+struct.pack("<IQ",6,CELL) if kind==6 else b""
        digest=hashlib.sha256(domain+data).digest()
        if digest!=self.data[ref+24:ref+56]:raise ValueError("reference digest")
        if kind!=6 and (data[:8]!=b"SFSREC06" or self.u32(at+8)!=kind):raise ValueError("record framing")
        self.chain.append(dict(reference_offset=ref,record_offset=at,type=kind,digest=digest.hex()))
        return at
    def rows(self,ref,map_kind,stride,before):
        at=self.record(ref,5,before);level,count=struct.unpack_from("<HH",self.data,at+68)
        if self.u32(at+64)!=map_kind or level!=0 or not 1<=count<=(CELL-640)//stride:raise ValueError("fixture leaf shape")
        return [at+640+i*stride for i in range(count)]
    def binding(self,state,kind,page):
        ns_ref=self.root+64;view="current"
        if state==0:
            catalog=self.rows(self.root+120,4,328,self.root)
            selected=[row for row in catalog if self.data[row+68:row+68+self.u32(row+64)]==b"baseline"]
            if len(selected)!=1:raise ValueError("baseline binding")
            ns_ref=selected[0]+8;view="baseline"
        ns=self.record(ns_ref,2,self.root)
        names=self.rows(ns+120,2,280,ns)
        selected=[row for row in names if self.u64(row)==1 and self.data[row+12:row+12+self.u32(row+8)]==b"file"]
        if len(selected)!=1:raise ValueError("file name binding")
        owner=self.u64(selected[0]+267)
        if kind==1:
            inodes=self.rows(ns+64,1,496,ns);selected=[row for row in inodes if self.u64(row)==owner]
            if len(selected)!=1:raise ValueError("inode binding")
            extent_ref=selected[0]+32;name="file"
        else:
            attribute=b"org.campaign/value" if kind==3 else b"com.apple.ResourceFork"
            rows=self.rows(ns+280,5,352,ns)
            selected=[row for row in rows if self.u64(row)==owner and self.data[row+12:row+12+self.u32(row+8)]==attribute]
            if len(selected)!=1:raise ValueError("xattr binding")
            extent_ref=selected[0]+280;name="xattr" if kind==3 else "resource"
        extents=self.rows(extent_ref,3,72,ns);selected=[row for row in extents if self.u64(row)==page]
        if len(selected)!=1:raise ValueError("extent binding")
        raw=self.record(selected[0]+8,6,self.u64(extent_ref+8))
        wanted=pattern(state,kind,12288 if kind==1 else 8192)[page*CELL:(page+1)*CELL]
        if self.data[raw:raw+CELL]!=wanted:raise ValueError("bound payload differs from expected state")
        return dict(view=view,object=name,logical_page=page,raw_offset=raw,existing_raw_digest=self.chain[-1]["digest"],
                    raw_sha256=sha(wanted),chain=self.chain.copy(),target=view+"/"+name)


def detection_observed(row,target=None):
    if not row.get("mutation",{}).get("changed",False) or row["outcome"]!="integrity_refusal":return False
    observation=row["observation"]
    independent=observation.get("independent_verification",{})
    if target is None:return independent.get("open_status") in (6,7) or (
        independent.get("verify_attempted") and independent.get("verify_status") in (6,7))
    return (observation["open_status"]==0 and independent.get("open_status")==0 and
        independent.get("verify_attempted") and independent.get("verify_status") in (6,7) and any(
        obj["name"]==target and obj["status"]==6 for obj in observation["objects"])
    )


def preflight(campaign,cc):
    campaign.report["execution_mode"]="preflight_only"
    campaign.report["preflight_controls"]=[]
    try:
        campaign.compile(cc)
        campaign.report["regressions"]=campaign.invoke([sys.executable,Path(__file__).with_name("native_reliability_regressions.py")],
            "oracle-regressions",time.monotonic()+CASE_SECONDS,json_lines=False)
        for parity in (0,1):
            directory=campaign.scratch/f"preflight-seed-{parity}";directory.mkdir(mode=0o700)
            receipt=campaign.invoke([campaign.reader,"seed",directory,parity],f"control-seed-{parity}",
                time.monotonic()+CASE_SECONDS,manifest=expected(0),ack_generation=3+parity)
            ack=receipt["events"][-1]
            observation=campaign.read(directory,f"control-read-{parity}",time.monotonic()+CASE_SECONDS)
            outcome=campaign.classify(observation,[expected(0)],3+parity,True)
            bindings=[BoundImage((directory/"image.sfs").read_bytes()).binding(0,kind,page)
                      for kind,page in ((1,0),(1,1),(1,2),(3,0),(4,0))]
            campaign.report["preflight_controls"].append(dict(parity=parity,ack=ack,observation=observation,outcome=outcome,bindings=bindings))
            if outcome!="acknowledged_state_preserved":raise RuntimeError("fresh control oracle failed")
        campaign.check_pins()
        campaign.bounds()
        campaign.report["preflight_passed"]=True
    except BaseException as error:
        campaign.report.update(preflight_passed=False,error=f"{type(error).__name__}: {error}")
    finally:
        campaign.report.update(retained_scratch=str(campaign.scratch),cleanup_status="retained_for_review",cleanup_verified=False,
            incomplete_case_ids=[row["id"] for row in campaign.report["case_plan"]],
            process_groups_exit_verified=all(campaign.gone(pid) for pid in campaign.groups))
        campaign.save()
    print(json.dumps({key:campaign.report.get(key) for key in ("preflight_passed","retained_scratch","process_groups_exit_verified")}))
    return 0 if campaign.report.get("preflight_passed") and campaign.report["process_groups_exit_verified"] else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True,help="new receipt directory")
    parser.add_argument("--cc",default="cc")
    parser.add_argument("--preflight",action="store_true",help="compile, synthetic oracle regressions, fresh seed/read controls only")
    args=parser.parse_args()
    root=args.root.resolve(strict=True)
    cc=shutil.which(args.cc)
    if sys.platform!="darwin" or not root.is_dir() or not cc:
        parser.error("macOS, existing root and C compiler required")
    args.output.mkdir(mode=0o700,exist_ok=False)
    campaign=Campaign(root,args.output.resolve())
    if args.preflight:return preflight(campaign,str(Path(cc).resolve()))
    try:
        campaign.compile(str(Path(cc).resolve()))
        seeds=[]
        for parity in range(2):
            seed=campaign.scratch/f"seed-{parity}"; seed.mkdir(mode=0o700)
            receipt=campaign.invoke([campaign.reader,"seed",seed,parity],f"seed-{parity}",time.monotonic()+CASE_SECONDS,manifest=expected(0),ack_generation=3+parity)
            generation=receipt["events"][-1]["generation"]
            observed=campaign.read(seed,f"seed-{parity}-read",time.monotonic()+CASE_SECONDS)
            if campaign.classify(observed,[expected(0)],generation,True)!="acknowledged_state_preserved":
                raise RuntimeError("seed oracle failed")
            newer=campaign.specimen(seed,f"newer-{parity}")
            calibration=campaign.invoke([campaign.producer,"write",newer,"none",0,0,0],f"calibration-{parity}",time.monotonic()+CASE_SECONDS,manifest=expected(1),ack_generation=4+parity)
            ack=calibration["events"][-1]
            if ack.get("event")!="ack":
                raise RuntimeError("calibration did not commit")
            if generation!=3+parity or ack["generation"]!=4+parity or not ack["record_calls"]:
                raise RuntimeError("fixture generation/parity differs from sealed plan")
            observed=campaign.read(newer,f"newer-{parity}-read",time.monotonic()+CASE_SECONDS)
            if campaign.classify(observed,[expected(1)],ack["generation"],True)!="acknowledged_state_preserved":
                raise RuntimeError("newer seed oracle failed")
            seeds.append((seed,newer,generation,ack["generation"],ack["record_calls"]))
        campaign.report["resolved_bindings"]={str(i):dict(A_generation=oldgen,B_generation=newgen,last_record=last)
            for i,(_,_,oldgen,newgen,last) in enumerate(seeds)}
        campaign.report["resolved_bindings_sha256"]=sha(json.dumps(campaign.report["resolved_bindings"],sort_keys=True).encode())
        campaign.save()
        for parity,(seed,newer,oldgen,newgen,last_record) in enumerate(seeds):
            for operation in ("write","restore"):
                for repeat in range(4):
                    def acknowledged(directory,deadline,row,operation=operation,newgen=newgen,oldgen=oldgen):
                        manifest=expected(1) if operation=="write" else expected(0,True)
                        expected_generation=newgen if operation=="write" else newgen+1
                        row["producer"]=campaign.invoke([campaign.producer,operation,directory,"none",0,0,1],row["id"]+"-producer",deadline,event="ack",manifest=manifest,ack_generation=expected_generation)
                        ack=row["producer"]["events"][-1]
                        row["observation"]=campaign.read(directory,row["id"]+"-read",deadline)
                        row["outcome"]=campaign.classify(row["observation"],[manifest],expected_generation,True)
                    campaign.case(f"ack-{parity}-{operation}-{repeat}",seed if operation=="write" else newer,"post_ack_kill",acknowledged)
            for point in range(1,5):
                def cut(directory,deadline,row,point=point,oldgen=oldgen):
                    row["producer"]=campaign.invoke([campaign.producer,"write",directory,"none",0,point,0],row["id"]+"-producer",deadline,event="cut",manifest=expected(1),event_fields={"point":point})
                    row["observation"]=campaign.read(directory,row["id"]+"-read",deadline)
                    row["outcome"]=campaign.classify(row["observation"],[expected(0),expected(1)],oldgen)
                campaign.case(f"cut-{parity}-{point}",seed,"pre_ack_cut",cut)
            faults=[(f"record_{kind}",nth) for nth in (1,last_record) for kind in ("eio","enospc","zero","partial")]
            faults += [(f"slot_{kind}",1) for kind in ("eio","enospc","zero","partial","torn73","torn4095")]
            faults += [(f"fence_{kind}",nth) for nth in (1,2) for kind in ("eio","enospc")]
            # Record/fence failures need one parity; publication-slot failures cover both.
            if parity: faults=[item for item in faults if item[0].startswith("slot_")]
            for index,(fault,nth) in enumerate(faults):
                def failure(directory,deadline,row,fault=fault,nth=nth,oldgen=oldgen):
                    row["producer"]=campaign.invoke([campaign.producer,"write",directory,fault,nth,0,0],row["id"]+"-producer",deadline,manifest=expected(1))
                    response=row["producer"]["events"][-1]
                    if response.get("event")!="result" or not response.get("hits") or not response.get("status"):
                        raise RuntimeError("requested fault did not fail with an actual injection hit")
                    wanted=fault_expectation(fault,nth)
                    if any(response.get(key)!=value for key,value in wanted.items()) or response.get("generation")!=oldgen:
                        raise RuntimeError("fault response differs from sealed status/errno/publication expectations")
                    row["primary_failure"]={key:response[key] for key in ("status","phase","errno","hits","fence_attempted","fence_succeeded")}
                    row["observation"]=campaign.read(directory,row["id"]+"-read",deadline)
                    row["outcome"]=campaign.classify(row["observation"],[expected(0),expected(1)],oldgen)
                campaign.case(f"fault-{parity}-{index}-{fault}",seed,"syscall_failure",failure)
            names=["control","slot-checksum","zero-prefix-73","zero-prefix-512","zero-prefix-4095","old-prefix-73","root-byte","truncate-last","truncate-middle","truncate-root"]
            for name in names:
                def metadata(directory,deadline,row,name=name,newgen=newgen):
                    row["mutation"]=mutate_metadata(directory/"image.sfs",name)
                    row["observation"]=campaign.read(directory,row["id"]+"-read",deadline)
                    row["outcome"]=campaign.classify(row["observation"],[expected(1)],newgen,name=="control")
                    if name!="control" and row["outcome"] in ("complete_allowed_state","acknowledged_state_preserved","integrity_refusal") and not detection_observed(row):row["outcome"]="coverage_failure"
                campaign.case(f"metadata-{parity}-{name}",newer,"acknowledged_metadata_damage",metadata)
            for index,(state,kind,page) in enumerate([(1,1,0),(1,1,1),(1,1,2),(1,3,0),(1,4,0),(0,1,0)]):
                def payload(directory,deadline,row,state=state,kind=kind,page=page,newgen=newgen):
                    path=directory/"image.sfs"; data=bytearray(path.read_bytes())
                    binding=BoundImage(data).binding(state,kind,page)
                    offset=binding["raw_offset"]+137; original=data[offset]; data[offset]^=1
                    with path.open("r+b") as stream:
                        stream.write(data); stream.flush(); os.fsync(stream.fileno())
                    row["mutation"]=dict(changed=original!=data[offset],offset=offset,original_byte=original,
                        replacement_byte=data[offset],state=state,kind=kind,page=page,binding=binding)
                    row["observation"]=campaign.read(directory,row["id"]+"-read",deadline)
                    row["outcome"]=campaign.classify(row["observation"],[expected(1)],newgen)
                    if row["outcome"] in ("complete_allowed_state","acknowledged_state_preserved","integrity_refusal") and not detection_observed(row,binding["target"]):row["outcome"]="coverage_failure"
                campaign.case(f"payload-{parity}-{index}",newer,"acknowledged_payload_damage",payload)
        campaign.check_pins()
        campaign.bounds()
        if len(campaign.report["cases"])!=MAX_CASES or not all(row["oracle_passed"] for row in campaign.report["cases"]):
            raise RuntimeError("sealed case table is incomplete")
        campaign.report.update(campaign_completed=True,integrity_oracle_passed=True)
    except BaseException as error:
        campaign.report["error"]=f"{type(error).__name__}: {error}"
    finally:
        campaign.report["incomplete_case_ids"]=[spec["id"] for spec in campaign.report["case_plan"]
            if not any(row["id"]==spec["id"] and row["oracle_passed"] for row in campaign.report["cases"])]
        uncertain=campaign.report.get("completion_uncertain",False) or any(not campaign.gone(pid) for pid in campaign.groups)
        try:
            identity=(campaign.scratch.stat().st_dev,campaign.scratch.stat().st_ino)
            unsafe=uncertain or campaign.scratch.is_symlink() or identity!=campaign.identity
        except OSError:
            unsafe=True
        if unsafe or campaign.report["retained_specimens"] or not campaign.report["campaign_completed"]:
            campaign.report.update(cleanup_verified=False,cleanup_status="unsafe_to_remove" if unsafe else "retained_for_review",
                retained_scratch=str(campaign.scratch),process_groups_exit_verified=not uncertain)
        else:
            try:
                shutil.rmtree(campaign.scratch)
                campaign.report.update(cleanup_verified=not campaign.scratch.exists(),cleanup_status="completed",process_groups_exit_verified=True)
            except OSError as error:
                campaign.report.update(cleanup_verified=False,cleanup_status="failed",cleanup_error=str(error),retained_scratch=str(campaign.scratch))
        campaign.save()
    print(json.dumps({key:campaign.report.get(key) for key in ("campaign_completed","integrity_oracle_passed","cleanup_verified","retained_scratch")}))
    return 0 if campaign.report["campaign_completed"] and campaign.report["integrity_oracle_passed"] and campaign.report.get("cleanup_status") not in ("failed","unsafe_to_remove") else 1


if __name__=="__main__":
    sys.exit(main())
