"""Diagnostic qualification and privacy; the document clone is mocked here."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('phase_probe_under_test', PERF / 'native_phase_probe.py')
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    import fileops, native_correctness, native_fixtures


def report():
    slots = [{'slot': i, 'total_cpu_ns': 100,
              'fclonefileat': {'calls': i, 'failures': 0, 'cpu_ns': i * 10},
              'directory_metadata': {'calls': 1, 'failures': 0, 'cpu_ns': 20}} for i in range(3)]
    counters = {'total_cpu_ns': 300}
    for phase in probe.PHASES:
        counters[phase] = {key: sum(row[phase][key] for row in slots) for key in ('calls','failures','cpu_ns')}
    return {'schema': 2, 'marker': probe.MARKER, 'status': 'available', 'scope': probe.SCOPE,
            'workers_requested': 2, 'workers_started': 2, 'main_fallback': False, 'counters': counters, 'slots': slots}


class PhaseProbe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-phase-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.binary = self.root / 'stallionfs'; self.binary.write_bytes(probe.MARKER.encode()); self.binary.chmod(0o700)
        self.wheel = self.root / 'package.whl'; self.wheel.write_bytes(b'not installed')
        self.native = report(); self.commands = []; self.fail_capture = False

    def run_probe(self, source_unchanged=True, sharing=True, changed_pin=None, snapshot_failure=False):
        snapshot_count = fingerprint_count = 0
        def snapshot(*args, **kwargs):
            nonlocal snapshot_count
            snapshot_count += 1
            if snapshot_failure and snapshot_count == 3:
                raise RuntimeError('PRIVATE post-copy snapshot failure')
            return {'entries': {}}
        snapshots = mock.Mock(side_effect=snapshot)
        def fingerprints():
            nonlocal fingerprint_count
            fingerprint_count += 1
            return {'stallionfs/_tree.c': ('c' if changed_pin == 'source' and fingerprint_count > 1 else 'a') * 64}
        product = types.ModuleType('stallionfs'); product.__file__ = '/private/tmp/installed/stallionfs/__init__.py'
        budget = types.ModuleType('stallionfs._benchmark_budget')
        def command(argv, **options):
            self.commands.append((argv, options))
            options['receipt'].update(pid=1234, exit_code=0, completion_uncertain=False)
            if argv[1] == 'clone':
                self.assertEqual(argv[1:4], ['clone','--jobs','2']); self.assertEqual(options['timeout'], 60)
                if self.fail_capture: raise RuntimeError('PRIVATE raw failure /Users/private')
                if changed_pin == 'cli': self.binary.write_bytes(b'changed executable')
                if changed_pin == 'wheel': self.wheel.write_bytes(b'changed wheel')
                if self.native is not None:
                    path = Path(os.environ['STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT'])
                    path.write_text(json.dumps(self.native)); path.chmod(0o600)
            return subprocess.CompletedProcess(argv, 0, b'[]', b'PRIVATE raw output')
        budget.command = command
        def fixture(base, name, spec):
            self.assertEqual((name,spec), ('docs_5k_100mb',{'files':5000,'bytes':100000000}))
            source = base / name; source.mkdir(); return source
        output = self.root / 'status.json'
        equal = {'strict_equal':True,'sparse_preserved':True,'independent_clone':True}
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'stallionfs':product,'stallionfs._benchmark_budget':budget}))
            stack.enter_context(mock.patch.dict(os.environ))
            stack.enter_context(mock.patch.object(sys,'platform','darwin'))
            stack.enter_context(mock.patch.object(fileops,'scratch_volume'))
            self.mount_checks = stack.enter_context(mock.patch.object(fileops,'no_mounts_below'))
            self.removals = stack.enter_context(mock.patch.object(probe.shutil,'rmtree',wraps=shutil.rmtree))
            stack.enter_context(mock.patch.object(fileops,'fingerprint_sources',side_effect=fingerprints))
            stack.enter_context(mock.patch.object(fileops,'large_fixture',side_effect=fixture))
            stack.enter_context(mock.patch.object(native_fixtures,'enrich_metadata'))
            stack.enter_context(mock.patch.object(native_fixtures,'verify_metadata_coverage',return_value={'populated':True}))
            stack.enter_context(mock.patch.object(native_correctness,'snapshot',snapshots))
            stack.enter_context(mock.patch.object(native_correctness,'compare',return_value=equal))
            stack.enter_context(mock.patch.object(native_correctness,'verify_clone',return_value=equal))
            stack.enter_context(mock.patch.object(native_correctness,'verify_source',return_value={'unchanged':source_unchanged}))
            stack.enter_context(mock.patch.object(native_correctness,'clone_sharing',return_value={'full_data_stream_sharing':sharing}))
            stdout,stderr = io.StringIO(),io.StringIO()
            with redirect_stdout(stdout),redirect_stderr(stderr):
                code = probe.probe(self.binary,self.wheel,self.root,output,'b'*40)
            self.assertEqual(stdout.getvalue()+stderr.getvalue(),'')
        return code,json.loads(output.read_text()),snapshots

    def test_complete_direct_capture_retains_main_phase_and_excludes_raw_data(self):
        code,value,snapshots = self.run_probe()
        self.assertEqual(code,0); self.assertTrue(value['correctness']['passed'])
        self.assertEqual(value['schema'],2)
        self.assertEqual(value['counter_status'],'available'); self.assertEqual(value['clone_attempts'],1)
        self.assertEqual(snapshots.call_count,4); self.assertEqual(value['cleanup'],'complete')
        self.assertEqual(value['cpu_composition']['slots'][0]['directory_metadata']['calls'],1)
        self.assertEqual(value['cpu_composition']['counters']['total_cpu_ns'],300)
        self.assertEqual(value['benchmark_verdict'],'not_applicable')
        self.assertNotIn('PRIVATE',json.dumps(value)); self.assertNotIn(str(self.root),json.dumps(value))
        self.assertEqual(sum(argv[1]=='clone' for argv,_ in self.commands),1)

    def test_missing_or_unavailable_counter_does_not_erase_copy_correctness(self):
        self.native = None
        code,value,_ = self.run_probe()
        self.assertEqual(code,1); self.assertTrue(value['correctness']['passed'])
        self.assertEqual(value['target_completion'],'complete'); self.assertNotIn('cpu_composition',value)
        self.assertEqual(value['counter_status'],'unavailable')
        self.assertEqual(value['cleanup'],'complete'); self.assertEqual(self.removals.call_count,1)
        self.assertEqual(self.mount_checks.call_count,2)

    def test_clock_failure_is_unavailable_with_no_zero_or_partial_counter(self):
        self.native.update(status='clock_read_invalid',counters=None,slots=[])
        code,value,_ = self.run_probe()
        self.assertEqual(code,1); self.assertTrue(value['correctness']['passed'])
        self.assertEqual(value['counter_status'],'clock_read_invalid'); self.assertNotIn('cpu_composition',value)

    def test_unknown_completion_stops_before_post_snapshots_cleanup_and_retry(self):
        self.fail_capture = True
        code,value,snapshots = self.run_probe()
        self.assertEqual(code,1); self.assertEqual(value['target_completion'],'unknown')
        self.assertIsNone(value['correctness']); self.assertEqual(snapshots.call_count,2)
        self.assertEqual(value['cleanup'],'retained_ephemeral'); self.assertNotIn('PRIVATE',json.dumps(value))
        self.assertEqual(sum(argv[1]=='clone' for argv,_ in self.commands),1)

    def test_missing_installed_marker_prevents_clone(self):
        self.binary.write_bytes(b'production binary')
        code,value,snapshots = self.run_probe()
        self.assertEqual(code,1); self.assertEqual(value['clone_attempts'],0)
        self.assertEqual(value['error'],'profile_not_compiled'); self.assertEqual(snapshots.call_count,0)

    def test_changed_source_prevents_cpu_publication(self):
        code,value,_ = self.run_probe(source_unchanged=False)
        self.assertEqual(code,1); self.assertFalse(value['correctness']['passed'])
        self.assertEqual(value['cleanup'],'retained_ephemeral'); self.assertNotIn('cpu_composition',value)

    def test_unproven_sharing_prevents_cpu_publication(self):
        code,value,_ = self.run_probe(sharing=None)
        self.assertEqual(code,1); self.assertFalse(value['correctness']['passed'])
        self.assertEqual(value['cleanup'],'retained_ephemeral'); self.assertNotIn('cpu_composition',value)

    def test_post_copy_snapshot_failure_retains_root_without_cleanup_commands(self):
        code,value,snapshots = self.run_probe(snapshot_failure=True)
        self.assertEqual(code,1); self.assertEqual(value['target_completion'],'complete')
        self.assertIsNone(value['correctness']); self.assertEqual(snapshots.call_count,3)
        self.assertEqual(value['cleanup'],'retained_ephemeral'); self.assertNotIn('cpu_composition',value)
        self.assertEqual(self.mount_checks.call_count,1); self.removals.assert_not_called()
        self.assertNotIn('PRIVATE',json.dumps(value))

    def test_changed_source_cli_or_wheel_retains_root_without_using_changed_binary(self):
        for pin in ('source','cli','wheel'):
            with self.subTest(pin=pin):
                output = self.root/'status.json'
                if output.exists(): output.unlink()
                self.binary.write_bytes(probe.MARKER.encode()); self.wheel.write_bytes(b'not installed')
                code,value,_ = self.run_probe(changed_pin=pin)
                self.assertEqual(code,1); self.assertTrue(value['correctness']['passed'])
                self.assertEqual(value['error'],'source_changed'); self.assertEqual(value['cleanup'],'retained_ephemeral')
                self.assertNotIn('cpu_composition',value); self.assertEqual(self.mount_checks.call_count,1)
                self.removals.assert_not_called()

    def test_rejects_unknown_fields_double_count_overflow_and_failed_phases(self):
        cases = []
        for location,key,value in [([], 'private_path','/Users/private'), (['slots',0], 'slot',True),
                                  (['counters'],'total_cpu_ns',True), (['counters'],'total_cpu_ns',1<<64),
                                  (['counters','fclonefileat'],'cpu_ns',301), (['counters','fclonefileat'],'failures',1),
                                  (['counters','directory_metadata'],'calls',0), ([], 'workers_started',1),
                                  ([], 'schema',1), ([], 'marker','stallionfs-thread-cpu-v1')]:
            item = report(); target = item
            for part in location: target = target[part]
            target[key] = value; cases.append(item)
        for item in cases:
            with self.subTest(item=item),self.assertRaises(probe.ProbeError): probe.validate_report(item)
        for status in probe.STATUSES[1:]:
            item = report(); item.update(status=status,counters=None,slots=[])
            self.assertIsNone(probe.validate_report(item))

    def test_old_inclusive_leaf_label_is_rejected(self):
        item = report()
        for row in [item['counters'], *item['slots']]:
            row['clone_leaf'] = row.pop('fclonefileat')
        with self.assertRaises(probe.ProbeError): probe.validate_report(item)

    def test_report_and_publication_reject_partial_duplicate_unsafe_or_replaced_files(self):
        path = self.root/'report.json'; path.write_text('{"schema":1,"schema":1}'); path.chmod(0o600)
        with self.assertRaises(probe.ProbeError): probe.read_report(path)
        path.chmod(0o644)
        with self.assertRaises(probe.ProbeError): probe.read_report(path)
        output = self.root/'published.json'; probe.publish(output,{'status':'incomplete'})
        with self.assertRaises(FileExistsError): probe.publish(output,{})
        self.assertEqual(json.loads(output.read_text()),{'status':'incomplete'})
        self.assertFalse(list(self.root.glob('.phase-status-*')))


class NativePhaseCounters(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin' and (os.environ.get('GITHUB_ACTIONS') == 'true' or
                         os.environ.get('STALLIONFS_TEST_PHASE_COUNTERS') == '1'), 'tiny native fault harness requires CI or explicit build admission')
    def test_counter_faults_errno_main_fallback_tls_and_report_publication(self):
        tree = PERF.parents[1]/'stallionfs/_tree.c'
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            installed = shutil.which('stallionfs')
            self.assertIsNotNone(installed)
            self.assertNotIn(probe.MARKER.encode(),Path(installed).read_bytes())
        source = r'''
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <copyfile.h>
#include <sys/clonefile.h>
#include <stdio.h>
static int fake_clock(clockid_t, struct timespec *);
static int fake_copy(int, int, copyfile_state_t, copyfile_flags_t);
static int fake_clone(int, int, const char *, uint32_t);
static int fake_flush(FILE *);
#define clock_gettime fake_clock
#define fcopyfile fake_copy
#define fclonefileat fake_clone
#define fflush fake_flush
#define STALLIONFS_DIAGNOSTIC_THREAD_CPU 1
#include "TREE_PATH"
#undef fflush
static int mode, ticks, sink_fail, clone_result, clone_error, clone_calls;
static int fake_flush(FILE *stream) { if (sink_fail) { errno = EIO; return EOF; } return fflush(stream); }
static int fake_clock(clockid_t id, struct timespec *value) {
    assert(id == CLOCK_THREAD_CPUTIME_ID); errno = EIO;
    if (mode == 1) return -1;
    value->tv_sec = mode == 3 ? (time_t)(UINT64_MAX / 1000000000ULL + 1) : 0;
    value->tv_nsec = mode == 2 ? 1000000000L : mode == 4 ? (ticks++ % 2 ? 10 : 20) : ticks++ * 10;
    return 0;
}
static int fake_copy(int a, int b, copyfile_state_t s, copyfile_flags_t f) {
    (void)a; (void)b; (void)s; assert(f == COPYFILE_METADATA); errno = EACCES; return 0;
}
static int fake_clone(int input, int parent, const char *name, uint32_t flags) {
    assert(input == 12 && parent == 34 && !strcmp(name, "leaf"));
    assert(flags == (CLONE_NOFOLLOW | CLONE_ACL));
    clone_calls++; errno = clone_error; return clone_result;
}
int main(int argc, char **argv) {
    assert(argc == 2); uint64_t value; errno = ENOSPC;
    for (mode = 1; mode <= 3; mode++) { assert(!cpu_now(&value)); assert(errno == ENOSPC); }
    mode = 0; ticks = 0;
    struct cpu_slot slot = {0}; cpu_current = &slot; cpu_start(&slot);
    struct tree tree = {.operation = CLONING}; struct job job = {0};
    struct stat identity = {0};
    assert(!directory_metadata(&tree, &job, -1, -1, NULL, NULL)); assert(errno == EACCES);
    assert(slot.phase[CPU_DIRECTORY].calls == 1); assert(slot.phase[CPU_DIRECTORY].ns == 10);
    clone_result = 0; clone_error = EACCES;
    assert(!first_inode(CLONING, &tree, 12, 34, "leaf", &identity, NULL, NULL));
    assert(errno == EACCES && clone_calls == 1 && slot.active == 0);
    assert(slot.phase[CPU_FCLONEFILEAT].calls == 1 && slot.phase[CPU_FCLONEFILEAT].failures == 0);
    assert(slot.phase[CPU_FCLONEFILEAT].ns == 10);
    clone_result = -1; clone_error = ENOSPC;
    assert(first_inode(CLONING, &tree, 12, 34, "leaf", &identity, NULL, NULL) == -1);
    assert(errno == ENOSPC && clone_calls == 2 && slot.active == 0);
    assert(slot.phase[CPU_FCLONEFILEAT].calls == 2 && slot.phase[CPU_FCLONEFILEAT].failures == 1);
    assert(slot.phase[CPU_FCLONEFILEAT].ns == 20);
    job.source = -1; assert(clone_leaf(&tree, &job, "absent", DT_REG, 0) == -1); assert(errno == EBADF);
    assert(clone_calls == 2 && slot.phase[CPU_FCLONEFILEAT].calls == 2);
    assert(slot.phase[CPU_FCLONEFILEAT].failures == 1 && slot.phase[CPU_FCLONEFILEAT].ns == 20);
    slot = (struct cpu_slot){0}; mode = 1; clone_result = 0; clone_error = EACCES;
    assert(!first_inode(CLONING, &tree, 12, 34, "leaf", &identity, NULL, NULL));
    assert(errno == EACCES && slot.status == CPU_CLOCK && slot.active == 0);
    assert(slot.phase[CPU_FCLONEFILEAT].calls == 1 && !slot.phase[CPU_FCLONEFILEAT].failures && !slot.phase[CPU_FCLONEFILEAT].ns);
    slot = (struct cpu_slot){0}; clone_result = -1; clone_error = ENOSPC;
    assert(first_inode(CLONING, &tree, 12, 34, "leaf", &identity, NULL, NULL) == -1);
    assert(errno == ENOSPC && slot.status == CPU_CLOCK && slot.active == 0);
    assert(slot.phase[CPU_FCLONEFILEAT].calls == 1 && slot.phase[CPU_FCLONEFILEAT].failures == 1 && !slot.phase[CPU_FCLONEFILEAT].ns);
    slot = (struct cpu_slot){0}; mode = 1;
    assert(!directory_metadata(&tree, &job, -1, -1, NULL, NULL)); assert(errno == EACCES && slot.status == CPU_CLOCK);
    mode = 0; slot = (struct cpu_slot){0};
    struct cpu_token outer = cpu_enter(CPU_FCLONEFILEAT), inner = cpu_enter(CPU_DIRECTORY);
    cpu_leave(inner, 0); assert(slot.active == CPU_FCLONEFILEAT + 1); cpu_leave(outer, 0); assert(slot.status == CPU_NESTED);
    slot = (struct cpu_slot){0}; slot.phase[0].calls = UINT64_MAX;
    outer = cpu_enter(CPU_FCLONEFILEAT); cpu_leave(outer, 0); assert(slot.status == CPU_OVERFLOW);
    slot = (struct cpu_slot){0}; mode = 4; ticks = 0;
    outer = cpu_enter(CPU_FCLONEFILEAT); cpu_leave(outer, 0); assert(slot.status == CPU_RANGE);
    mode = 0; ticks = 0; slot = (struct cpu_slot){0}; cpu_start(&slot);
    struct tree idle = {.mutex = PTHREAD_MUTEX_INITIALIZER, .available = PTHREAD_COND_INITIALIZER};
    struct cpu_worker_context context = {.state = &idle, .slot = &slot, .main_fallback = 1};
    worker(&context); assert(cpu_current == &slot && slot.total == 0); cpu_stop(&slot);
    pthread_mutex_destroy(&idle.mutex); pthread_cond_destroy(&idle.available);
    setenv("STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT", argv[1], 1);
    errno = ENOSPC; struct cpu_profile profile = cpu_open(CLONING, 2); assert(profile.enabled && errno == ENOSPC);
    profile.status = CPU_JOIN; cpu_report(&profile, 2, 2, 0); assert(errno == ENOSPC);
    char saved[PATH_MAX]; snprintf(saved, sizeof(saved), "%s.join", argv[1]); assert(!rename(argv[1], saved));
    profile = cpu_open(CLONING, 2); sink_fail = 1; cpu_report(&profile, 2, 2, 0); sink_fail = 0;
    assert(access(argv[1], F_OK) == -1);
    profile = cpu_open(CLONING, 2); profile.slots[0].total = UINT64_MAX; profile.slots[1].total = 1;
    cpu_report(&profile, 2, 2, 0); snprintf(saved, sizeof(saved), "%s.overflow", argv[1]); assert(!rename(argv[1], saved));
    profile = cpu_open(CLONING, 2);
    for (unsigned i = 0; i < 3; i++) profile.slots[i].total = 100;
    profile.slots[0].phase[CPU_DIRECTORY] = (struct cpu_counter){.calls = 1, .ns = 10};
    profile.slots[1].phase[CPU_FCLONEFILEAT] = profile.slots[2].phase[CPU_FCLONEFILEAT] = (struct cpu_counter){.calls = 1, .ns = 10};
    cpu_report(&profile, 2, 2, 0); snprintf(saved, sizeof(saved), "%s.valid", argv[1]); assert(!rename(argv[1], saved));
    profile = cpu_open(CLONING, CPU_WORKERS + 1); assert(!profile.enabled && profile.status == CPU_BOUND);
    cpu_report(&profile, CPU_WORKERS + 1, 0, 0); unlink(argv[1]);
    char error_path[PATH_MAX];
    assert(run_tree(-1, -1, -1, "absent", &identity, CLONING, STALLION_COPY_MATERIALIZED, 0, NULL, NULL, error_path, sizeof(error_path)) == -1);
    assert(cpu_current == &slot && errno == EBADF); cpu_current = NULL;
    return 0;
}
'''.replace('TREE_PATH',str(tree))
        with tempfile.TemporaryDirectory(prefix='phase-counter-native-') as temporary:
            root = Path(temporary); code = root/'faults.c'; code.write_text(source)
            binary = root/'faults'
            compiled = subprocess.run(['/usr/bin/xcrun','clang','-std=c11','-O0',str(code),'-o',str(binary)],capture_output=True,timeout=45)
            self.assertEqual(compiled.returncode,0,compiled.stderr.decode(errors='replace'))
            child = subprocess.run([str(binary),str(root/'report.json')],capture_output=True,timeout=10)
            self.assertEqual(child.returncode,0,child.stderr.decode(errors='replace'))
            self.assertEqual(json.loads((root/'report.json').read_text())['status'],'operation_failed')
            for suffix,status in (('join','join_failed'),('overflow','counter_overflow')):
                value = json.loads((root/('report.json.'+suffix)).read_text())
                self.assertEqual(value['status'],status); self.assertIsNone(value['counters']); self.assertEqual(value['slots'],[])
            self.assertEqual(probe.validate_report(json.loads((root/'report.json.valid').read_text()))['counters']['directory_metadata']['cpu_ns'],10)


if __name__ == '__main__': unittest.main()
