"""Small fixture and failure checks for the opt-in file-operation workloads."""
import importlib.util
import json
import os
from pathlib import Path
import platform
import sys
import sysconfig
import tempfile
import unittest
from unittest import mock


spec = importlib.util.spec_from_file_location("fileops_benchmark", Path(__file__).parent / "perf" / "fileops.py")
fileops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fileops)


@unittest.skipUnless(platform.system() == "Darwin", "Requires native macOS clone commands")
class BenchmarkFixtures(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="fileops-check-")
        self.base = Path(self.temporary.name).resolve()
        self.binary = Path(sysconfig.get_path("scripts")) / "stallionfs"

    def tearDown(self):
        self.temporary.cleanup()

    def test_workload_filters_preserve_defaults_and_reject_impossible_selections(self):
        standard = {name: ["clone", "delete", "move"] for name in fileops.SAMPLES}
        large = {name: ["clone", "delete"] for name in fileops.LARGE_PROFILES}
        self.assertEqual(fileops.selected_workloads("standard"), standard)
        self.assertEqual(fileops.selected_workloads("large"), large)
        self.assertEqual(fileops.selected_workloads("all"), standard | large)
        self.assertEqual(fileops.selected_workloads("all", operations=["move"]),
                         {name: ["move"] for name in standard})
        self.assertEqual(fileops.selected_workloads("all", ["tiny_4kib", "dataset_2k_50gb"], ["clone", "move"]),
                         {"tiny_4kib": ["clone", "move"], "dataset_2k_50gb": ["clone"]})
        with self.assertRaisesRegex(RuntimeError, "outside --suite"):
            fileops.selected_workloads("standard", ["dataset_2k_50gb"])
        with self.assertRaisesRegex(RuntimeError, "unavailable"):
            fileops.selected_workloads("all", ["tiny_4kib", "dataset_2k_50gb"], ["move"])
        with self.assertRaisesRegex(RuntimeError, "No fixture"):
            fileops.selected_workloads("large", operations=["move"])
        with self.assertRaisesRegex(RuntimeError, "unavailable across"):
            fileops.selected_workloads("large", operations=["clone", "move"])
        arguments = ["fileops.py", "--binary", "/absent", "--scratch", "/absent", "--output", "/absent/result",
                     "--suite", "large", "--operations", "clone", "move"]
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(fileops, "command") as command, \
                self.assertRaisesRegex(RuntimeError, "unavailable across"):
            fileops.main()
        command.assert_not_called()
        roots = fileops.fixtures(self.base, ["tiny_4kib"])
        self.assertEqual(list(roots), ["tiny_4kib"])
        self.assertEqual(list((self.base / "fixtures").iterdir()), [roots["tiny_4kib"]])
        self.assertEqual(roots["tiny_4kib"].read_bytes(), fileops.random.Random(42).randbytes(1024 * 1024)[:4096])
        self.assertEqual(roots["tiny_4kib"].stat().st_mode & 0o777, 0o640)

    def test_selected_main_skips_unselected_generation_and_records_exact_coverage(self):
        for name in ("tiny_4kib", "docs_5k_100mb"):
            with self.subTest(fixture=name):
                output = self.base / f"{name}.json"
                arguments = ["fileops.py", "--binary", str(self.binary), "--scratch", str(self.base),
                             "--output", str(output), "--suite", "all", "--fixtures", name,
                             "--operations", "delete", "--memory"]
                with mock.patch.object(sys, "argv", arguments), \
                        mock.patch.dict(fileops.LARGE_PROFILES, {"docs_5k_100mb": {"files": 3, "bytes": 1536}}), \
                        mock.patch.object(fileops, "fixtures", wraps=fileops.fixtures) as standard, \
                        mock.patch.object(fileops, "large_fixture", wraps=fileops.large_fixture) as large, \
                        mock.patch.object(fileops, "compare_fixture") as compare:
                    fileops.main()
                self.assertEqual(standard.call_count, int(name == "tiny_4kib"))
                self.assertEqual(large.call_count, int(name == "docs_5k_100mb"))
                self.assertEqual(compare.call_count, 2)
                self.assertEqual([call.args[2] for call in compare.call_args_list], [name, name])
                self.assertEqual([call.args[5] for call in compare.call_args_list], [["delete"], ["delete"]])
                self.assertTrue(compare.call_args_list[1].kwargs["memory"])
                report = json.loads(output.read_text())
                self.assertEqual(report["selection"], {"fixtures_requested": [name], "operations_requested": ["delete"],
                                                       "workloads": {name: ["delete"]}, "full_suite": False})
                self.assertEqual(list(report["fixtures"]), [name])
                self.assertGreater(report["fixture_setup_s"], 0)
                self.assertGreater(report["fixture_validation_s"], 0)
                self.assertTrue(report["cleanup_passed"])

    def test_setup_validation_and_cleanup_do_not_enter_command_timings(self):
        source = self.base / "source"
        source.write_bytes(b"fixture")
        (self.base / "outside-sentinel").write_bytes(b"keep outside linked trees\n")
        expected = fileops.manifest(source)

        def setup_copy(arguments, **kwargs):
            self.assertEqual(arguments[:2], ["/bin/cp", "-cRp"])
            fileops.shutil.copy2(arguments[-2], arguments[-1])

        for operation in fileops.BASELINES:
            for memory in (False, True):
                with self.subTest(operation=operation, memory=memory):
                    def measured(arguments, *args, **kwargs):
                        if operation == "clone":
                            fileops.shutil.copy2(arguments[-2], arguments[-1])
                        elif operation == "delete":
                            arguments[-1].unlink()
                        else:
                            arguments[-2].rename(arguments[-1])
                        row = {"exit_code": 0, "wrapper_wall_s" if memory else "wall_s": 3.0}
                        return (row, None) if memory else row

                    clocks = []
                    for offset in (0, 200):
                        times = ([0, 4] if operation == "clone" else [0, 10, 30, 35])
                        times += [100, 107] if operation == "delete" else [100, 120, 125, 132]
                        clocks.extend(offset + value for value in times)
                    clocks.extend([400, 409])
                    report = {"rows": [], "memory_rows": [], "fixture_validation_s": 0.0}
                    with mock.patch.object(fileops.time, "perf_counter", side_effect=clocks), \
                            mock.patch.object(fileops, "command", side_effect=setup_copy), \
                            mock.patch.object(fileops, "measure", side_effect=measured), \
                            mock.patch.object(fileops, "measure_memory", side_effect=measured), \
                            mock.patch.object(fileops, "no_mounts_below"):
                        fileops.compare_fixture(self.binary, self.base, "tiny_4kib", source, expected,
                                                [operation], 1 if memory else 0, fileops.random.Random(1),
                                                report, lambda: None, memory=memory)
                    rows = report["memory_rows" if memory else "rows"]
                    self.assertEqual(len(rows), 2)
                    for row in rows:
                        self.assertEqual(row["wrapper_wall_s" if memory else "wall_s"], 3.0)
                        self.assertEqual(row["setup_s"], 4.0 if operation == "clone" else 15.0)
                        self.assertEqual(row["setup_validation_s"], 0.0 if operation == "clone" else 20.0)
                        self.assertEqual(row["validation_s"], 7.0 if operation == "delete" else 27.0)
                        self.assertEqual(row["cleanup_s"], 0.0 if operation == "delete" else 5.0)
                        self.assertTrue(row["validated"])
                    self.assertEqual(report["fixture_validation_s"], 9.0)
                    self.assertEqual(fileops.manifest(source), expected)

    def test_scaled_profiles_have_exact_materialized_source_and_independent_clones(self):
        for name in fileops.LARGE_PROFILES:
            with self.subTest(profile=name):
                source = fileops.large_fixture(self.base, name, {"files": 13, "bytes": 13 * 512 + 7})
                expected = fileops.manifest(source)
                totals = fileops.fixture_totals(source, expected)
                self.assertEqual(totals["source_regular_files"], 13)
                self.assertEqual(totals["source_logical_bytes"], 13 * 512 + 7)
                self.assertGreaterEqual(totals["allocated_bytes"], totals["logical_bytes"])
                if name.startswith("git_"):
                    self.assertGreater(totals["git_files"], 0)
                    self.assertEqual(fileops.git_command(source, "ls-files", "-z").stdout.count(b"\0"), 13)
                destination = self.base / "copy"
                fileops.command([self.binary, "clone", source, destination])
                fileops.verify_clone(source, destination, expected)
                relative = next(path for path, row in expected.items() if row["kind"] == "file" and not path.startswith(".git/"))
                (destination / relative).write_bytes(b"changed clone")
                self.assertEqual(fileops.manifest(source), expected)
                fileops.remove_fixture(destination)
                fileops.remove_fixture(source)

    def test_atomic_checkpoint_retains_failed_rows_and_refuses_other_files(self):
        path = self.base / "result.partial"
        report = {"status": "running", "rows": [{"wall_s": 0.1, "warmup": True}]}
        identity = fileops.write_json(path, report)
        report.update(status="failed", error="injected validation failure")
        identity = fileops.write_json(path, report, identity)
        self.assertEqual(json.loads(path.read_text()), report)
        with self.assertRaises(FileExistsError):
            fileops.write_new_json(path, {"unrelated": True})
        other = self.base / "other"
        other.write_text("preserve unrelated contents")
        os.replace(other, path)
        with self.assertRaisesRegex(RuntimeError, "Checkpoint path changed"):
            fileops.write_json(path, report, identity)
        self.assertEqual(path.read_text(), "preserve unrelated contents")

    def test_failed_timed_command_saves_raw_row_without_complete_result(self):
        def tiny_fixture(base, names=None):
            root = base / "fixtures"
            root.mkdir()
            source = root / "tiny"
            source.write_bytes(b"fixture")
            return {"tiny_4kib": source}

        output = self.base / "failed.json"
        arguments = ["fileops.py", "--binary", str(self.binary), "--scratch", str(self.base), "--output", str(output)]
        row = {"exit_code": 1, "wall_s": 0.01, "error": "injected command failure"}
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(fileops, "fixtures", tiny_fixture), \
                mock.patch.object(fileops, "measure", return_value=row), \
                self.assertRaisesRegex(RuntimeError, "injected command failure"):
            fileops.main()
        self.assertFalse(output.exists())
        report = json.loads(output.with_name(output.name + ".partial").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["passed"])
        self.assertTrue(report["cleanup_passed"])
        self.assertEqual(len(report["rows"]), 1)
        self.assertTrue(report["rows"][0]["warmup"])
        self.assertFalse(report["rows"][0]["validated"])
        self.assertEqual(list(self.base.glob("fileops-*")), [])

    def test_uncertain_wrapper_retains_fixture_and_memory_values_are_child_bytes(self):
        metrics = self.base / "memory.txt"
        metrics.write_text("real 0.01\n 1048576 maximum resident set size\n 2097152 peak memory footprint\n")
        completed = fileops.subprocess.CompletedProcess([], 0, b"", b"")
        with mock.patch.object(fileops, "command", return_value=completed):
            row, returned = fileops.measure_memory(["unused"], metrics)
        self.assertIs(returned, completed)
        self.assertEqual((row["rss_bytes"], row["footprint_bytes"]), (1048576, 2097152))
        self.assertNotIn("wall_s", row)
        output = self.base / "uncertain.json"
        arguments = ["fileops.py", "--binary", str(self.binary), "--scratch", str(self.base), "--output", str(output)]

        def interrupted_setup(base, names=None):
            raise fileops.ChildCompletionUnknown("injected wrapper interruption")

        with mock.patch.object(sys, "argv", arguments), mock.patch.object(fileops, "fixtures", interrupted_setup), \
                self.assertRaises(fileops.ChildCompletionUnknown):
            fileops.main()
        report = json.loads(output.with_name(output.name + ".partial").read_text())
        retained = Path(report["retained_fixture"])
        self.assertTrue(retained.is_relative_to(self.base))
        self.assertEqual((retained / "outside-sentinel").read_bytes(), b"keep outside linked trees\n")
        self.assertFalse(report.get("cleanup_passed", False))
        self.assertFalse(output.exists())

    def test_checkpoint_failure_cannot_clear_unknown_child_retention(self):
        output = self.base / "checkpoint-failure.json"
        arguments = ["fileops.py", "--binary", str(self.binary), "--scratch", str(self.base),
                     "--output", str(output), "--memory"]
        compare, write = fileops.compare_fixture, fileops.write_json

        def tiny_fixture(base, names=None):
            root = base / "fixtures"
            root.mkdir()
            source = root / "tiny"
            source.write_bytes(b"keep source")
            return {"tiny_4kib": source}

        def only_memory(*args, **kwargs):
            if kwargs.get("memory"):
                return compare(*args, **kwargs)

        def fail_after_uncertain_row(path, report, previous=None):
            if report["memory_rows"]:
                raise OSError("injected checkpoint disk full")
            return write(path, report, previous)

        row = {"exit_code": 1, "wrapper_wall_s": 0.01, "completion_uncertain": True}
        with mock.patch.object(sys, "argv", arguments), mock.patch.object(fileops, "fixtures", tiny_fixture), \
                mock.patch.object(fileops, "compare_fixture", only_memory), \
                mock.patch.object(fileops, "measure_memory", return_value=(row, None)), \
                mock.patch.object(fileops, "write_json", fail_after_uncertain_row), \
                self.assertRaisesRegex(OSError, "checkpoint disk full"):
            fileops.main()
        retained = list(self.base.glob("fileops-*"))
        self.assertEqual(len(retained), 1)
        self.assertEqual((retained[0] / "fixtures" / "tiny").read_bytes(), b"keep source")
        self.assertEqual((retained[0] / "outside-sentinel").read_bytes(), b"keep outside linked trees\n")
        self.assertFalse(output.exists())

    def test_direct_interrupt_through_measure_retains_fixture(self):
        output = self.base / "interrupted.json"
        arguments = ["fileops.py", "--binary", str(self.binary), "--scratch", str(self.base),
                     "--output", str(output)]
        failure = KeyboardInterrupt()

        def tiny_fixture(base, names=None):
            root = base / "fixtures"
            root.mkdir()
            source = root / "tiny"
            source.write_bytes(b"keep source")
            return {"tiny_4kib": source}

        def fake_subprocess(command, **kwargs):
            if "clone" in command or (command[0] == "/bin/cp" and "-cRp" in command):
                raise failure
            stdout = b"[{}]" if "volumes" in command else b"mock metadata"
            return fileops.subprocess.CompletedProcess(command, 0, stdout, b"")

        with mock.patch.object(sys, "argv", arguments), mock.patch.object(fileops, "fixtures", tiny_fixture), \
                mock.patch.object(fileops.subprocess, "run", side_effect=fake_subprocess), \
                mock.patch.object(fileops, "no_mounts_below"), \
                mock.patch.object(fileops, "scratch_volume", return_value={"filesystem": "apfs", "readonly": False}), \
                mock.patch.object(fileops.shutil, "disk_usage", return_value=mock.Mock(free=3 * 1024**3)), \
                self.assertRaises(fileops.ChildCompletionUnknown) as caught:
            fileops.main()
        self.assertIs(caught.exception.__cause__, failure)
        report = json.loads(output.with_name(output.name + ".partial").read_text())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["phase"]["operation"], "clone")
        self.assertFalse(report.get("cleanup_passed", False))
        self.assertEqual(report["rows"], [], "Uncertainty became an ordinary failed timing row")
        retained = Path(report["retained_fixture"])
        self.assertEqual((retained / "fixtures/tiny").read_bytes(), b"keep source")
        self.assertEqual((retained / "outside-sentinel").read_bytes(), b"keep outside linked trees\n")
        self.assertFalse(output.exists())

    def test_memory_report_errors_preserve_original_cause(self):
        completed = fileops.subprocess.CompletedProcess(["time"], -9, b"", b"wrapper interrupted")
        for failure in (OSError("injected report read failure"),
                        UnicodeDecodeError("utf-8", b"\xff", 0, 1, "injected corrupt report")):
            with self.subTest(error=type(failure).__name__):
                metrics = mock.Mock(spec=Path)
                metrics.exists.return_value = True
                metrics.read_text.side_effect = failure
                with mock.patch.object(fileops, "command", return_value=completed), \
                        self.assertRaises(fileops.ChildCompletionUnknown) as caught:
                    fileops.measure_memory(["unused"], metrics)
                self.assertIs(caught.exception.__cause__, failure)
        metrics = mock.Mock(spec=Path)
        metrics.exists.return_value = True
        metrics.read_text.return_value = "real 0.01\n"
        completed.returncode = 0
        with mock.patch.object(fileops, "command", return_value=completed), \
                self.assertRaises(fileops.ChildCompletionUnknown) as caught:
            fileops.measure_memory(["unused"], metrics)
        self.assertIsInstance(caught.exception.__cause__, RuntimeError)
        self.assertIn("peak RSS", str(caught.exception.__cause__))

    def test_existing_uncertainty_propagates_without_double_wrapping(self):
        failure = fileops.ChildCompletionUnknown("injected unknown child completion")
        for operation in (lambda: fileops.measure(["unused"]),
                          lambda: fileops.measure_memory(["unused"], mock.Mock(spec=Path))):
            with mock.patch.object(fileops, "command", side_effect=failure), \
                    self.assertRaises(fileops.ChildCompletionUnknown) as caught:
                operation()
            self.assertIs(caught.exception, failure)

    def test_scan_deep_fixture_counts_and_uncertain_child_retention(self):
        spec = importlib.util.spec_from_file_location('scan_benchmark', Path(__file__).parent / 'perf/scan.py')
        scan = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'fileops': fileops}):
            spec.loader.exec_module(scan)
        for count in (3, 41):
            with self.subTest(files=count):
                path = self.base / f'deep-{count}'
                expected = scan.fixture(path, count, 'deep40')
                self.assertEqual((expected['files'], expected['directories']), (count + 3, 41))
                parent = path
                for _ in range(40):
                    directories = [child for child in parent.iterdir() if child.is_dir() and not child.is_symlink()]
                    self.assertEqual([child.name for child in directories], ['d'])
                    parent = parent / 'd'
                self.assertTrue((parent / 'empty').is_dir())
                for method, jobs in scan.METHODS.items():
                    self.assertEqual(scan._scan.scan(path, bulk=method != 'posix', jobs=jobs), expected)
                fileops.remove_fixture(path)
        output = self.base / 'scan-memory.json'
        arguments = ['scan.py', '--scratch', str(self.base), '--output', str(output),
                     '--files', '1', '--samples', '1', '--memory']
        completed = fileops.subprocess.CompletedProcess([], 0, b'24', b'')
        failure = fileops.ChildCompletionUnknown('injected scanner child interruption')
        installed_native = self.base / Path(scan._scan.__file__).name
        installed_native.write_bytes(Path(scan._scan.__file__).read_bytes())
        with mock.patch.object(sys, 'argv', arguments), mock.patch.object(fileops, 'command', return_value=completed), \
                mock.patch.object(scan._scan, '__file__', str(installed_native)), \
                mock.patch.object(fileops, 'scratch_volume', return_value={'filesystem': 'apfs'}), \
                mock.patch.object(fileops, 'measure_memory', side_effect=failure), \
                mock.patch.object(fileops, 'remove_fixture') as cleanup, self.assertRaises(fileops.ChildCompletionUnknown):
            scan.main()
        cleanup.assert_not_called()
        report = json.loads(output.with_name(output.name + '.partial').read_text())
        retained = Path(report['retained_fixture'])
        self.assertTrue(retained.is_relative_to(self.base))
        self.assertTrue((retained / 'flat/file-0').is_file())
        self.assertEqual(report['status'], 'failed')
        self.assertFalse(report.get('cleanup_passed', False))
        self.assertFalse(output.exists())
        rows = report['workloads']['flat']['sample_rows']
        self.assertEqual(len(rows), 9)
        self.assertEqual(sum(row['warmup'] for row in rows), 6)
        self.assertTrue(all(set(row['order']) == set(scan.METHODS) for row in rows))

    def test_workspace_report_helpers_preserve_files_and_hash_loaded_modules(self):
        spec = importlib.util.spec_from_file_location('workspace_benchmark', Path(__file__).parent / 'perf/run.py')
        workspace = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {'fileops': fileops}):
            spec.loader.exec_module(workspace)
        checkpoint = self.base / 'workspace.partial.json'
        identity = workspace.f.write_json(checkpoint, {'status': 'incomplete'})
        replacement = self.base / 'other-report'
        replacement.write_text('preserve this report')
        os.replace(replacement, checkpoint)
        with self.assertRaisesRegex(RuntimeError, 'Checkpoint path changed'):
            workspace.f.write_json(checkpoint, {'status': 'complete'}, identity)
        with self.assertRaises(FileExistsError):
            workspace.f.write_new_json(checkpoint, {'status': 'complete'})
        self.assertEqual(checkpoint.read_text(), 'preserve this report')
        modules = {}
        for name in ('stallionfs', 'core', 'images'):
            path = self.base / f'installed-{name}.py'
            path.write_text('version one')
            modules[name] = mock.Mock(__file__=str(path))
        loaded = Path(modules['core'].__file__)
        with mock.patch.multiple(workspace, **modules):
            before = workspace.runtime_fingerprints()
            self.assertEqual(before['core.py'], fileops.digest(loaded))
            loaded.write_text('version two')
            self.assertNotEqual(workspace.runtime_fingerprints()['core.py'], before['core.py'])
            checkout = Path(workspace.__file__).resolve().parents[2] / 'stallionfs/core.py'
            with mock.patch.object(workspace, 'core', mock.Mock(__file__=str(checkout))), \
                    self.assertRaisesRegex(RuntimeError, 'outside the source checkout'):
                workspace.runtime_fingerprints()


    def test_cli_unknown_completion_retains_fixture(self):
        spec = importlib.util.spec_from_file_location("cli_benchmark", Path(__file__).parent / "perf" / "cli.py")
        cli = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"fileops": fileops}):
            spec.loader.exec_module(cli)
        baseline, candidate = self.base / "baseline", self.base / "candidate"
        baseline.touch()
        candidate.touch()

        def tiny_fixture(base):
            tiny = base / "tiny"
            tiny.write_bytes(b"keep source")
            (base / "outside-sentinel").write_bytes(b"keep outside linked trees\n")
            return {"tiny_4kib": tiny}, {}

        def runtime(binary):
            return {"binary": binary, "version": "test", "python_version": "test"}

        def metadata(arguments, **kwargs):
            return fileops.subprocess.CompletedProcess(arguments, 0, b"[{}]", b"")

        for failure in (fileops.ChildCompletionUnknown("injected unknown completion"), KeyboardInterrupt()):
            with self.subTest(error=type(failure).__name__):
                scratch = self.base / type(failure).__name__
                scratch.mkdir()
                output = scratch / "result.json"
                arguments = ["cli.py", "--baseline", str(baseline), "--candidate", str(candidate),
                             "--scratch", str(scratch), "--output", str(output)]
                with mock.patch.object(sys, "argv", arguments), mock.patch.object(cli, "installed", side_effect=runtime), \
                        mock.patch.object(cli, "runtime_hashes", return_value={}), \
                        mock.patch.object(cli, "source_hashes", return_value={}), mock.patch.object(cli, "digest", return_value="test"), \
                        mock.patch.object(cli, "command", side_effect=metadata), mock.patch.object(cli, "no_mounts_below"), \
                        mock.patch.object(cli, "scratch_volume", return_value={"filesystem": "apfs", "readonly": False}), \
                        mock.patch.object(cli.shutil, "disk_usage", return_value=mock.Mock(free=3 * 1024**3)), \
                        mock.patch.object(cli, "make_fixtures", side_effect=tiny_fixture), \
                        mock.patch.object(cli, "measure", side_effect=failure), mock.patch.object(cli.shutil, "rmtree") as cleanup, \
                        self.assertRaises(type(failure)) as caught:
                    cli.main()
                self.assertIs(caught.exception, failure)
                cleanup.assert_not_called()
                retained = list(scratch.glob("stallionfs-cli-*"))
                self.assertEqual(len(retained), 1)
                self.assertEqual((retained[0] / "tiny").read_bytes(), b"keep source")
                self.assertEqual((retained[0] / "outside-sentinel").read_bytes(), b"keep outside linked trees\n")
                self.assertFalse(output.exists())


    def test_cli_paired_plain_effects_require_complete_pairs_and_wall_target(self):
        spec = importlib.util.spec_from_file_location("cli_benchmark", Path(__file__).parent / "perf" / "cli.py")
        cli = importlib.util.module_from_spec(spec)
        with mock.patch.dict(sys.modules, {"fileops": fileops}):
            spec.loader.exec_module(cli)
        rows = []
        for operation in cli.APPLE:
            case = f"{operation}/tiny_4kib/plain"
            for number in range(1, 32):
                saving = number * 0.000002 if operation == "clone" else 0.000005 if operation == "move" else -0.0001
                wall = 0.01 + number * 0.001
                for method in ("apple", "candidate"):
                    rows.append({"case": case, "method": method, "round": number, "warmup": False,
                                 "wall_s": wall if method == "apple" else wall - saving,
                                 "cpu_children_s": 0.001 if method == "apple" else 0.002})
            rows += [{"case": case, "method": "apple", "round": 0, "warmup": True,
                      "wall_s": 999, "cpu_children_s": 999},
                     {"case": f"{operation}/tiny_4kib/json", "method": "candidate", "round": 1,
                      "warmup": False, "wall_s": 999, "cpu_children_s": 999}]
        shuffled = [row for row in rows if row["method"] == "apple"]
        shuffled += list(reversed([row for row in rows if row["method"] != "apple"]))
        effects, method = cli.paired_plain_effects(shuffled)
        clone = effects["clone/tiny_4kib/plain"]
        self.assertEqual(clone["pairs"], 31)
        self.assertEqual(clone["lower_order_statistic"], 10)
        self.assertEqual(clone["interval_coverage"], 0.9705506265163422)
        self.assertAlmostEqual(clone["wall_s"]["median_saving_s"], 0.000032)
        for actual, expected in zip(clone["wall_s"]["median_saving_interval_s"], (0.000020, 0.000044)):
            self.assertAlmostEqual(actual, expected)
        self.assertTrue(clone["wall_target_demonstrated"])
        self.assertFalse(effects["move/tiny_4kib/plain"]["wall_target_demonstrated"])
        self.assertGreater(effects["move/tiny_4kib/plain"]["wall_s"]["median_saving_s"], 0)
        self.assertEqual(clone["required_wall_saving_s"], 0.00001)
        self.assertEqual(clone["cpu_children_s"]["pairs_with_lower_candidate_value"], 0)
        self.assertIn("unpaired", method["scope"])
        rows[0]["cpu_children_s"] = None
        unavailable, _ = cli.paired_plain_effects(rows)
        self.assertIsNone(unavailable["clone/tiny_4kib/plain"]["cpu_children_s"])
        self.assertEqual(unavailable["clone/tiny_4kib/plain"]["wall_s"], clone["wall_s"])
        for invalid, message in ((rows[1:], "missing measured pair"), (rows + [rows[0]], "duplicate measured pair")):
            with self.subTest(error=message), self.assertRaisesRegex(RuntimeError, message):
                cli.paired_plain_effects(invalid)


if __name__ == "__main__":
    unittest.main()
