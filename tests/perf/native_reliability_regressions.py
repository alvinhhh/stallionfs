"""Focused false-positive regressions for the closed-image campaign oracle."""
import copy
import errno
import unittest
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


if __name__=="__main__":unittest.main()
