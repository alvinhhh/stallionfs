"""Focused false-positive regressions for the closed-image campaign oracle."""
import copy
import errno
import json
from pathlib import Path
import signal
import subprocess
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import native_reliability as runner
from native_reliability import Campaign, detection_observed, expected, fault_expectation, sha


def valid_observation(state=1,generation=4):
    manifest=expected(state)
    entries=[dict(name_hex=name.encode().hex(),is_file=regular,size=size,metadata_status=0,mode=mode,links=links)
        for name,regular,size,mode,links in [("file",True,12288,0o640,2),("alias",True,12288,0o640,2),
        ("companion",True,8192,0o600,1),("link",False,4,0o700,1)]]
    metadata=[dict(name=bytes.fromhex(item["name_hex"]).decode(),lookup_status=0,**{k:v for k,v in item.items() if k!="name_hex"}) for item in entries]
    metadata.append(dict(name="root",lookup_status=0,metadata_status=0,is_file=False,size=0,mode=0o700,links=1))
    return dict(open_status=0,generation=generation,verify_status=0,full_reachable=True,baseline_status=0,recovery_status=10,
        objects=[dict(name=name,status=0,count=value["length"],invalid_count=False,**value,
            lookup_status=0,lookup_size=8192 if name.endswith("/companion") else 12288,lookup_is_file=True,
            size_attempted=name.endswith(("/xattr","/resource")),
            size_status=0 if name.endswith(("/xattr","/resource")) else 12,
            size_value=value["length"],read_attempted=True,read_status=0) for name,value in manifest.items()],
        metadata=metadata,alias_comparison_attempted=True,alias_equal=True,
        symlink=dict(status=0,count=4,capacity=4,target_hex=b"file".hex(),invalid_count=False),
        namespaces=[dict(view=view,status=0,entries=copy.deepcopy(entries)) for view in ("current","baseline")],
        catalog=dict(status=0,names_hex=[b"baseline".hex()]),
        independent_verification=dict(open_status=0,generation=generation,verify_attempted=True,
                                      verify_status=0,full_reachable=True))


class OracleRegressions(unittest.TestCase):
    def classify(self,row,allowed=None,floor=4,preserved=False):
        return Campaign.classify(None,row,allowed or [expected(1)],floor,preserved)

    def broken_later(self):
        row=valid_observation();row["verify_status"]=6;row["full_reachable"]=False
        row["independent_verification"].update(verify_status=6,full_reachable=False)
        return row

    def test_valid_control(self):
        self.assertEqual(self.classify(valid_observation(),preserved=True),"acknowledged_state_preserved")

    def test_wrong_early_metadata_later_lookup_error(self):
        row=self.broken_later();row["metadata"][0]["mode"]=0o600
        row["metadata"][1].update(lookup_status=9,metadata_status=9)
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_wrong_namespace_metadata_later_verify_error(self):
        row=self.broken_later();row["namespaces"][0]["entries"][0]["mode"]=0o600
        row["namespaces"][0]["status"]=6
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_wrong_successful_symlink_later_verify_error(self):
        row=self.broken_later();row["symlink"]["target_hex"]=b"evil".hex()
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_stale_generation_later_verify_error(self):
        row=self.broken_later();row["generation"]=3
        self.assertEqual(self.classify(row),"silent_stale_success")

    def test_wrong_successful_catalog_later_verify_error(self):
        row=self.broken_later();row["catalog"]["names_hex"]=[b"other".hex()]
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_wrong_lookup_not_hidden_by_stat_error(self):
        row=self.broken_later();row["metadata"][0].update(size=1,metadata_status=9)
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_invalid_return_count_later_verify_error(self):
        row=self.broken_later();row["objects"][0]["count"]+=1
        self.assertEqual(self.classify(row),"invalid_checked_prefix")

    def test_error_prefix_must_match(self):
        row=self.broken_later();row["objects"][0].update(status=6,read_status=6,count=1,sha256=sha(b"wrong"))
        self.assertEqual(self.classify(row),"invalid_checked_prefix")

    def test_mixed_successful_states_later_verify_error(self):
        row=self.broken_later();row["generation"]=3
        self.assertEqual(self.classify(row,[expected(0),expected(1)],3),"silent_wrong_data_success")

    def test_unrelated_io_error_not_hidden_by_corruption(self):
        row=self.broken_later();row["symlink"].update(status=2,count=0,target_hex="")
        self.assertEqual(self.classify(row),"unresolved")

    def test_explicit_corruption_does_not_establish_preservation(self):
        row=self.broken_later();row["objects"][0].update(status=6,read_status=6,count=0,sha256=sha(b""))
        self.assertEqual(self.classify(row),"integrity_refusal")
        self.assertEqual(self.classify(row,preserved=True),"unresolved")

    def test_poisoned_followups_are_not_unattempted_API_errors(self):
        row=self.broken_later();row["objects"]=row["objects"][:1]
        row["objects"][0].update(status=6,read_status=6,count=0,sha256=sha(b""))
        for item in row["metadata"]:item.update(lookup_status=9,metadata_attempted=False,metadata_status=12)
        row["symlink"].update(attempted=False,status=12,count=0,target_hex="")
        row["alias_comparison_attempted"]=False
        row["namespaces"]=[dict(view="current",status=9,entries=[])]
        row["catalog"].update(status=9,names_hex=[])
        row.update(baseline_status=9,recovery_status=9,verify_status=9)
        self.assertEqual(self.classify(row),"integrity_refusal")

    def test_unchanged_B_is_not_corruption_coverage(self):
        row=dict(mutation=dict(changed=True),outcome="complete_allowed_state",observation=valid_observation())
        self.assertFalse(detection_observed(row,"current/file"))
        row["outcome"]="integrity_refusal";row["observation"]["verify_status"]=6
        self.assertFalse(detection_observed(row,"current/file"))

    def test_inert_mutation_is_not_coverage(self):
        row=dict(mutation=dict(changed=False),outcome="integrity_refusal",observation=self.broken_later())
        self.assertFalse(detection_observed(row))

    def test_fault_expectations_distinguish_publication(self):
        for kind,error in [("eio",errno.EIO),("enospc",errno.ENOSPC)]:
            self.assertEqual(fault_expectation("record_"+kind,1)["status"],2)
            self.assertEqual(fault_expectation("slot_"+kind,1)["status"],8)
            self.assertEqual(fault_expectation("fence_"+kind,1)["fence_succeeded"],0)
            self.assertEqual(fault_expectation("fence_"+kind,2)["fence_succeeded"],1)
            self.assertEqual(fault_expectation("fence_"+kind,2)["errno"],error)

    def test_successful_file_size_not_hidden_by_read_corruption(self):
        row=self.broken_later()
        row["objects"][0].update(lookup_size=2048,length=2048,size_value=2048,
            status=6,read_status=6,count=0,sha256=sha(b""))
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_successful_xattr_size_not_hidden_by_read_corruption(self):
        row=self.broken_later()
        row["objects"][2].update(size_value=2048,length=2048,status=6,read_status=6,count=0,sha256=sha(b""))
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_successful_lookup_kind_not_hidden_by_read_corruption(self):
        row=self.broken_later()
        row["objects"][0].update(lookup_is_file=False,status=6,read_status=6,count=0,sha256=sha(b""))
        self.assertEqual(self.classify(row),"silent_wrong_data_success")

    def test_independent_verification_required(self):
        row=valid_observation();del row["independent_verification"]
        self.assertEqual(self.classify(row),"unresolved")

    def test_poisoned_fresh_verifier_is_not_integrity_detection(self):
        row=self.broken_later()
        row["independent_verification"]["verify_status"]=9
        self.assertEqual(self.classify(row),"unresolved")
        self.assertFalse(detection_observed(dict(mutation=dict(changed=True),
            outcome="integrity_refusal",observation=row),"current/file"))

    def test_read_corruption_and_fresh_verification_success_contradict(self):
        row=self.broken_later()
        row["independent_verification"].update(verify_status=0,full_reachable=True)
        self.assertEqual(self.classify(row),"contradictory_integrity_observation")

    def test_same_handle_full_success_does_not_mask_read_corruption(self):
        row=valid_observation()
        row["objects"][0].update(status=6,read_status=6,count=0,sha256=sha(b""))
        row["independent_verification"].update(verify_status=6,full_reachable=False)
        self.assertEqual(self.classify(row),"contradictory_integrity_observation")

    def test_independent_verification_generation_is_checked(self):
        row=valid_observation();row["independent_verification"]["generation"]=3
        self.assertEqual(self.classify(row),"silent_stale_success")

    def test_targeted_read_and_fresh_verification_establish_detection(self):
        row=self.broken_later()
        row["objects"][0].update(status=6,read_status=6,count=0,sha256=sha(b""))
        self.assertEqual(self.classify(row),"integrity_refusal")
        self.assertTrue(detection_observed(dict(mutation=dict(changed=True),
            outcome="integrity_refusal",observation=row),"current/file"))


class SupervisionRegressions(unittest.TestCase):
    """Mock every process, signal and pipe; only disposable receipt files exist."""

    def invoke_mock(self, result=0, expired=False, existing_group=False, signal_error=None,
                    wait_error=None, event=None, already_reaped=False, close_error=False, selector_error=None,
                    log_close_error=None):
        trace = []
        child = mock.Mock(pid=43210, returncode=0 if already_reaped else None)
        child.poll.side_effect = lambda: trace.append('poll') or child.returncode

        def wait(**kwargs):
            trace.append('wait')
            if wait_error:
                raise wait_error
            child.returncode = result
            return result

        child.wait.side_effect = wait
        if close_error:
            child.stdout.close.side_effect = RuntimeError('mock stream close failure')
        selector = mock.Mock()
        selector.get_map.side_effect = ([{1: 1}, {}] if event else None)
        selector.get_map.return_value = {1: 1} if expired else {}
        selector.select.return_value = [(SimpleNamespace(fileobj=child.stdout, fd=42), 1)]
        item = dict(event='ack', status=0, generation=4, fence_attempted=3,
                    fence_succeeded=3, poisoned=0, transaction_active=0)
        clock = iter([1, 101, 101]) if expired else None

        def monotonic():
            return next(clock, 101) if clock else 1

        def killpg(pid, number):
            self.assertEqual(pid, child.pid)
            trace.append('kill' if number else 'probe')
            if number:
                self.assertEqual(number, signal.SIGKILL)
                if signal_error:
                    raise signal_error
            elif not existing_group:
                raise ProcessLookupError()

        with tempfile.TemporaryDirectory() as directory:
            campaign = Campaign.__new__(Campaign)
            campaign.output = campaign.scratch = Path(directory)
            campaign.deadline, campaign.groups, campaign.report = 100, set(), {}
            campaign.bounds = mock.Mock()
            caught, returned = None, None
            original_open = Path.open

            def open_receipt(path, *args, **kwargs):
                stream = original_open(path, *args, **kwargs)
                if path.name.endswith('.stderr.log') and log_close_error is not None:
                    wrapped = mock.Mock(wraps=stream)

                    def fail_close():
                        stream.close()
                        raise log_close_error

                    wrapped.close.side_effect = fail_close
                    return wrapped
                return stream

            with mock.patch.object(runner.subprocess, 'Popen', return_value=child), \
                    mock.patch.object(runner.selectors, 'DefaultSelector', return_value=selector, side_effect=selector_error), \
                    mock.patch.object(runner.os, 'read', return_value=json.dumps(item).encode() + b'\n'), \
                    mock.patch.object(runner.os, 'killpg', side_effect=killpg) as signals, \
                    mock.patch.object(runner.os, 'fsync', side_effect=lambda fd: trace.append('ledger_fsync')), \
                    mock.patch.object(Path, 'open', new=open_receipt), \
                    mock.patch.object(runner.time, 'monotonic', side_effect=monotonic):
                try:
                    returned = campaign.invoke(['mock-command'], 'mock', 100, event=event,
                                               manifest=expected(1) if event else None, ack_generation=4)
                except BaseException as error:
                    caught = error
            receipt = json.loads((Path(directory) / 'mock.json').read_text())
            calls = [call.args for call in signals.call_args_list]
            return returned, caught, receipt, campaign.report, calls, trace

    def test_reaped_leader_with_existing_or_reused_group_is_never_killed(self):
        _, error, receipt, report, calls, _ = self.invoke_mock(result=7, existing_group=True)
        self.assertIn('owned child failed', str(error))
        self.assertTrue(all(number == 0 for _, number in calls))
        self.assertEqual(receipt['signal_requests'][0]['outcome'], 'skip_already_reaped')
        self.assertFalse(receipt['signal_requests'][0]['attempted'])
        self.assertFalse(receipt['process_group_exit_verified'])
        self.assertTrue(report['completion_uncertain'])

    def test_owned_timeout_records_guarded_signal_and_reap(self):
        _, error, receipt, report, calls, trace = self.invoke_mock(result=-signal.SIGKILL, expired=True)
        self.assertIsInstance(error, TimeoutError)
        self.assertTrue(receipt['timed_out'])
        self.assertEqual(receipt['signal_requests'][0]['outcome'], 'signal_sent')
        self.assertTrue(receipt['signal_requests'][0]['attempted'])
        self.assertEqual(receipt['cleanup_wait']['outcome'], 'reaped')
        self.assertTrue(receipt['process_group_exit_verified'])
        self.assertNotIn('completion_uncertain', report)
        self.assertLess(trace.index('poll'), trace.index('kill'))
        self.assertLess(trace.index('kill'), trace.index('wait'))
        self.assertEqual(sum(number != 0 for _, number in calls), 1)

    def test_ack_is_logged_then_guarded_before_kill_and_wait(self):
        result, error, receipt, _, _, trace = self.invoke_mock(result=-signal.SIGKILL, event='ack')
        self.assertIsNone(error)
        self.assertIsNotNone(result)
        self.assertEqual(receipt['signal_requests'][0]['reason'], 'requested_ack')
        self.assertLess(trace.index('ledger_fsync'), trace.index('poll'))
        self.assertLess(trace.index('poll'), trace.index('kill'))
        self.assertLess(trace.index('kill'), trace.index('wait'))

    def test_ack_from_already_reaped_producer_cannot_authorize_kill(self):
        _, error, receipt, _, calls, _ = self.invoke_mock(event='ack', already_reaped=True)
        self.assertIn('not safely signalled', str(error))
        self.assertTrue(all(number == 0 for _, number in calls))
        self.assertTrue(all(request['outcome'] == 'skip_already_reaped' for request in receipt['signal_requests']))

    def test_signal_and_wait_errors_retain_original_timeout(self):
        timeout = subprocess.TimeoutExpired('mock-command', 1)
        _, error, receipt, report, _, _ = self.invoke_mock(expired=True, existing_group=True,
            signal_error=PermissionError(errno.EPERM, 'mock denied'), wait_error=timeout)
        self.assertIsInstance(error, TimeoutError)
        self.assertEqual(str(error), 'owned child deadline')
        self.assertEqual(receipt['signal_requests'][0]['outcome'], 'signal_error')
        self.assertEqual(receipt['cleanup_wait']['outcome'], 'wait_error')
        self.assertTrue(report['completion_uncertain'])
        self.assertFalse(receipt['process_group_exit_verified'])

    def test_cleanup_close_error_does_not_mask_original_command_error(self):
        _, error, receipt, report, calls, _ = self.invoke_mock(result=7, close_error=True)
        self.assertIn('owned child failed', str(error))
        self.assertEqual(receipt['cleanup_errors'][0]['stage'], 'stdout')
        self.assertTrue(report['completion_uncertain'])
        self.assertTrue(all(number == 0 for _, number in calls))

    def test_outer_buffered_log_close_preserves_original_timeout_and_records_failure(self):
        _, error, receipt, report, _, _ = self.invoke_mock(result=-signal.SIGKILL, expired=True,
            log_close_error=OSError('mock buffered log close failure'))
        self.assertIs(type(error), TimeoutError)
        self.assertEqual(str(error), 'owned child deadline')
        self.assertEqual(receipt['supervision_error'], 'TimeoutError: owned child deadline')
        self.assertEqual(receipt['cleanup_errors'][0]['stage'], 'stderr_log_close')
        self.assertTrue(report['completion_uncertain'])
        self.assertFalse(receipt['process_group_exit_verified'])
        self.assertTrue(any('Buffered stderr log' in note for note in error.__notes__))

    def test_poll_error_never_authorizes_destructive_signal(self):
        child = mock.Mock(pid=43210)
        child.poll.side_effect = OSError('mock poll error')
        receipt = {}
        with mock.patch.object(runner.os, 'killpg') as signals:
            self.assertFalse(runner.request_group_kill(child, receipt, 'mock'))
            signals.assert_not_called()
        self.assertEqual(receipt['signal_requests'][0]['outcome'], 'skip_poll_error')
        self.assertTrue(receipt['completion_uncertain'])

    def test_group_probe_error_after_reap_is_read_only_and_uncertain(self):
        child = mock.Mock(pid=43210, returncode=0)
        receipt = {}
        with mock.patch.object(runner.os, 'killpg', side_effect=PermissionError('mock probe denied')) as signals:
            self.assertFalse(runner.group_exit_observed(child, receipt))
            signals.assert_called_once_with(child.pid, 0)
        self.assertEqual(receipt['group_exit_observation']['outcome'], 'probe_error')
        self.assertTrue(receipt['completion_uncertain'])

    def test_selector_setup_error_still_cleans_up_owned_leader(self):
        original = RuntimeError('mock selector unavailable')
        _, error, receipt, _, _, _ = self.invoke_mock(result=-signal.SIGKILL, selector_error=original)
        self.assertIs(error, original)
        self.assertEqual(receipt['signal_requests'][0]['outcome'], 'signal_sent')
        self.assertEqual(receipt['cleanup_wait']['outcome'], 'reaped')
        self.assertTrue(receipt['process_group_exit_verified'])

    def test_uncertain_case_retains_without_read_or_delete_and_preserves_error(self):
        campaign = Campaign.__new__(Campaign)
        campaign.deadline = time.monotonic() + 10
        campaign.check_pins = mock.Mock()
        campaign.specimen = mock.Mock(return_value=Path('/nonexistent-mocked-specimen'))
        campaign.report = dict(cases=[], case_plan=[dict(id='mock', family='post_ack_kill')],
                               retained_specimens=[])
        campaign.save = mock.Mock(side_effect=OSError('mock retention receipt failure'))
        original = RuntimeError('original supervision failure')

        def action(*args):
            campaign.report['completion_uncertain'] = True
            raise original

        with mock.patch.object(Path, 'read_bytes') as read, mock.patch.object(runner.shutil, 'rmtree') as remove:
            with self.assertRaises(RuntimeError) as caught:
                campaign.case('mock', None, 'post_ack_kill', action)
            self.assertIs(caught.exception, original)
            read.assert_not_called()
            remove.assert_not_called()
        self.assertEqual(campaign.report['retained_specimens'], ['mock'])
        self.assertTrue(campaign.report['cases'][0]['retained_without_further_observation'])


if __name__=="__main__":unittest.main()
