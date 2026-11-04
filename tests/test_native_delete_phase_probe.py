"""Fixed-delete diagnostic contracts; heavy fixture and product calls are mocked."""
from contextlib import ExitStack
import ast
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

PERF = Path(__file__).parent / 'perf'
with mock.patch.object(sys, 'path', [str(PERF), *sys.path]):
    spec = importlib.util.spec_from_file_location('delete_phase_under_test', PERF / 'native_delete_phase_probe.py')
    probe = importlib.util.module_from_spec(spec); spec.loader.exec_module(probe)
    import fileops, native_correctness, native_fixtures, native_suite

COUNTS = {'entry_unlinkat': 200002, 'directory_unlinkat': 204}


def report(started=4):
    slots = [{'slot': i, 'total_cpu_ns': 100,
              'entry_unlinkat': {'calls': COUNTS['entry_unlinkat'] if i == 0 else 0, 'failures': 0, 'cpu_ns': 20},
              'directory_unlinkat': {'calls': COUNTS['directory_unlinkat'] if i == 0 else 0, 'failures': 0, 'cpu_ns': 10}}
             for i in range(started + 1)]
    total = {'total_cpu_ns': sum(s['total_cpu_ns'] for s in slots)}
    for phase in probe.PHASES:
        total[phase] = {field: sum(s[phase][field] for s in slots) for field in ('calls', 'failures', 'cpu_ns')}
    return {'schema': 1, 'marker': probe.MARKER, 'status': 'available',
            'scope': 'instrumented run_tree main and worker spans', 'workers_requested': 4,
            'workers_started': started, 'main_fallback': started == 0, 'slots': slots, 'counters': total}


class DeleteContracts(unittest.TestCase):
    def test_workflow_routes_first_recipe_and_delete_to_their_own_drivers(self):
        workflow = (PERF.parents[1] / '.github/workflows/checks.yml').read_text()
        def arguments(step):
            block = workflow.split('- name: ' + step, 1)[1].split('      - name:', 1)[0]
            code = textwrap.dedent(block.split("<<'PY'\n", 1)[1].rsplit('\n          PY', 1)[0])
            tree = ast.parse(code)
            assignment = next(node for node in ast.walk(tree) if isinstance(node, ast.Assign)
                              and any(isinstance(target, ast.Name) and target.id == 'argv' for target in node.targets))
            return [node.value for node in ast.walk(assignment.value) if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        directory = arguments('Collect hosted directory feasibility')
        deletion = arguments('Collect fixed-cache delete CPU phases')
        self.assertIn('--first-recipe-only', directory)
        self.assertNotIn('--first-recipe-only', deletion)
        self.assertIn('tests/perf/native_directory_clone_probe.py', directory)
        self.assertIn('tests/perf/native_delete_phase_probe.py', deletion)
        self.assertIn("if: inputs.mode == 'thread-cpu'", workflow)
        self.assertIn("if: inputs.mode == 'compare'", workflow)

    def test_names_include_symlinks_aliases_and_root(self):
        entries = {'': {'kind': 'directory'}, 'sub': {'kind': 'directory'},
                   'a': {'kind': 'file', 'device_inode': [1, 2]},
                   'b': {'kind': 'file', 'device_inode': [1, 2]}, 'link': {'kind': 'symlink'}}
        self.assertEqual(probe.expected_calls({'entries': entries}), {'entry_unlinkat': 3, 'directory_unlinkat': 2})
        entries['special'] = {'kind': 'fifo'}
        with self.assertRaises(probe.ProbeError): probe.expected_calls({'entries': entries})

    def test_one_inherited_deadline_caps_commands_and_preserves_reserve(self):
        with mock.patch.object(probe.time, 'monotonic', return_value=1000), mock.patch.dict(os.environ, {probe.DEADLINE: '1900'}):
            budget = probe.Deadline(os.environ[probe.DEADLINE])
            self.assertEqual(budget.timeout(700), 600)
            with mock.patch.object(probe.time, 'monotonic', return_value=1865): self.assertEqual(budget.timeout(), 5)
            with mock.patch.object(probe.time, 'monotonic', return_value=1870), self.assertRaises(TimeoutError): budget.timeout()
            self.assertTrue(budget.expired); self.assertEqual(os.environ[probe.DEADLINE], '1900')
            for value in (None, 'nan', 'inf', '1901', '999'):
                with self.subTest(value=value), self.assertRaises(probe.ProbeError): probe.Deadline(value)

    def test_counter_sums_actual_workers_fallback_and_unavailability(self):
        for started in (0, 1, 4):
            execution, composition = probe.validate_report(report(started), COUNTS)
            self.assertEqual(execution['workers_requested'], 4)
            self.assertEqual(execution['workers_started'], started)
            self.assertEqual(execution['main_fallback'], started == 0)
            self.assertEqual(len(composition['slots']), started + 1)
        value = report(0); value.update(status='clock_read_invalid', counters=None, slots=[])
        execution, composition = probe.validate_report(value, COUNTS)
        self.assertTrue(execution['main_fallback']); self.assertIsNone(composition)
        for field, invalid in (('calls', 200001), ('failures', 1), ('cpu_ns', 1 << 64)):
            value = report(); value['counters']['entry_unlinkat'][field] = invalid
            with self.subTest(field=field), self.assertRaises(probe.ProbeError): probe.validate_report(value, COUNTS)
        value = report(); value['slots'][1]['entry_unlinkat']['cpu_ns'] = 101
        with self.assertRaises(probe.ProbeError): probe.validate_report(value, COUNTS)


class DeleteDriver(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='delete-phase-mock-'); self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve(); self.scratch = self.root / 'scratch'; self.scratch.mkdir()
        self.binary = self.root / 'stallionfs'; self.binary.write_bytes(probe.MARKER.encode()); self.binary.chmod(0o700)
        self.wheel = self.root / 'package.whl'; self.wheel.write_bytes(b'package pin')
        self.now = 1000; self.commands = []; self.setup_commands = []; self.snapshot_paths = []; self.native = report()

    def invoke(self, fault=None):
        product = types.ModuleType('stallionfs'); product.__file__ = '/private/tmp/installed/stallionfs/__init__.py'
        budget = types.ModuleType('stallionfs._benchmark_budget')
        def command(argv, **options):
            self.commands.append((argv, options))
            self.assertLessEqual(options['timeout'], min(600, 1870 - self.now))
            options['receipt'].update(pid=1234, exit_code=0, completion_uncertain=False)
            if argv[1] == '--json': return subprocess.CompletedProcess(argv, 0, b'[]', b'')
            if argv[0] == '/usr/bin/ditto': Path(argv[-1]).mkdir(); return subprocess.CompletedProcess(argv, 0, b'', b'')
            self.assertEqual(argv[1:3], ['delete', '--recursive']); self.assertNotIn('--jobs', argv)
            if fault == 'unknown': raise RuntimeError('private capture failure')
            Path(argv[-1]).rmdir()
            if fault == 'expires_after_delete': self.now = 1871
            if fault == 'changed_pin': self.binary.write_bytes(b'changed')
            output = Path(os.environ['STALLIONFS_DIAGNOSTIC_THREAD_CPU_REPORT'])
            output.write_text(json.dumps(self.native)); output.chmod(0o600)
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        budget.command = command
        def fixture(base, name, spec):
            self.assertEqual(name, 'cache_200k_10gb'); self.assertEqual(spec, {'files': 200000, 'bytes': 10000000000})
            path = base / name; path.mkdir(); return path
        def snapshot(path, **_):
            self.snapshot_paths.append(Path(path).name)
            return {'entries': {'': {'kind': 'directory'}}}
        def warm(mode, timeout):
            self.assertEqual(mode, 'warm'); self.assertLessEqual(timeout, 600)
            if fault == 'expires_before_delete': self.now = 1871
            if fault == 'reset_deadline': os.environ[probe.DEADLINE] = '1901'
        def setup_command(argv, **options):
            self.setup_commands.append((argv, options))
            self.assertLessEqual(options['timeout'], min(600, 1870 - self.now))
            return subprocess.CompletedProcess(argv, 0, b'', b'')
        def enrich(*_, **__):
            if fault == 'helper_budget':
                self.now = 1865
                fileops.command(['/synthetic/setup'], timeout=999)
        def mounts(*_):
            if fault == 'expires_in_cleanup' and len(self.snapshot_paths) == 6: self.now = 1871
        output = self.root / 'status.json'
        equal = {'strict_equal': True, 'sparse_preserved': True, 'independent_clone': True}
        coverage = {'populated': True, 'regular_files': 200002, 'directories': 204, 'logical_bytes': 10016777216}
        inherited = '1030' if fault == 'initial_budget' else '1900'
        original_setup = fileops.command
        with ExitStack() as stack:
            stack.enter_context(mock.patch.dict(sys.modules, {'stallionfs': product, 'stallionfs._benchmark_budget': budget}))
            stack.enter_context(mock.patch.dict(os.environ, {probe.DEADLINE: inherited, 'RUNNER_TEMP': str(self.root),
                                    'GITHUB_ACTIONS': 'true', 'STALLIONFS_DELETE_CPU_HOSTED': '1'}))
            stack.enter_context(mock.patch.object(probe.sys, 'platform', 'darwin'))
            stack.enter_context(mock.patch.object(probe.time, 'monotonic', side_effect=lambda: self.now))
            stack.enter_context(mock.patch.object(probe.Deadline, 'start'))
            stack.enter_context(mock.patch.object(probe.Deadline, 'close'))
            stack.enter_context(mock.patch.object(probe, 'pins', return_value={'source': 'a' * 64}))
            stack.enter_context(mock.patch.object(probe, 'expected_calls', return_value=COUNTS))
            if fault == 'report_timeout': stack.enter_context(mock.patch.object(probe, 'read_report', side_effect=TimeoutError))
            stack.enter_context(mock.patch.object(fileops, 'scratch_volume', return_value={'ignore_ownership': False}))
            stack.enter_context(mock.patch.object(fileops, 'command', side_effect=setup_command))
            stack.enter_context(mock.patch.object(fileops, 'no_mounts_below', side_effect=mounts))
            stack.enter_context(mock.patch.object(fileops, 'large_fixture', side_effect=fixture))
            stack.enter_context(mock.patch.object(probe.shutil, 'disk_usage', return_value=types.SimpleNamespace(free=0 if fault == 'space' else 100000000000)))
            self.remove = stack.enter_context(mock.patch.object(probe.shutil, 'rmtree', wraps=shutil.rmtree))
            stack.enter_context(mock.patch.object(native_fixtures, 'enrich_metadata', side_effect=enrich))
            stack.enter_context(mock.patch.object(native_fixtures, 'verify_metadata_coverage', return_value=coverage))
            stack.enter_context(mock.patch.object(native_correctness, 'snapshot', side_effect=snapshot))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_clone', return_value=equal))
            stack.enter_context(mock.patch.object(native_correctness, 'verify_source', return_value={'unchanged': True}))
            stack.enter_context(mock.patch.object(native_suite, 'restore_setup_symlink_times'))
            stack.enter_context(mock.patch.object(native_suite, 'cache_prepare', side_effect=warm))
            code = probe.probe(self.binary, self.wheel, self.scratch, output, 'b' * 40)
            self.assertEqual(os.environ[probe.DEADLINE], '1901' if fault == 'reset_deadline' else inherited)
        self.assertIs(fileops.command, original_setup)
        return code, json.loads(output.read_text())

    def test_success_keeps_default_command_fixed_recipe_pins_and_one_attempt(self):
        code, value = self.invoke()
        self.assertEqual(code, 0); self.assertEqual(value['delete_attempts'], 1)
        self.assertEqual(value['cleanup'], 'complete'); self.assertTrue(value['correctness']['passed'])
        self.assertEqual(value['execution']['workers_requested'], 4)
        self.assertEqual(value['expected_calls'], COUNTS)
        self.assertEqual(sum(argv[1] == 'delete' for argv, _ in self.commands), 1)
        self.assertNotIn(str(self.root), json.dumps(value))

    def test_existing_setup_helpers_receive_the_remaining_usable_budget(self):
        code, value = self.invoke('helper_budget')
        self.assertEqual(code, 0)
        self.assertEqual(self.setup_commands[0][1]['timeout'], 5)
        self.assertEqual(value['budget']['outer_reserve_seconds'], 30)

    def test_no_usable_budget_or_capacity_prevents_deletion(self):
        for fault in ('space', 'initial_budget', 'expires_before_delete', 'reset_deadline'):
            with self.subTest(fault=fault):
                self.setUp(); code, value = self.invoke(fault)
                self.assertEqual(code, 1); self.assertEqual(value['delete_attempts'], 0)
                self.assertFalse(any(argv[1] == 'delete' for argv, _ in self.commands)); self.remove.assert_not_called()

    def test_unknown_completion_or_timeout_stops_followup_scans_and_cleanup(self):
        for fault in ('unknown', 'expires_after_delete'):
            with self.subTest(fault=fault):
                self.setUp(); code, value = self.invoke(fault)
                self.assertEqual(code, 1); self.assertEqual(value['delete_attempts'], 1)
                self.assertEqual(len(self.snapshot_paths), 4); self.remove.assert_not_called()
                self.assertEqual(value['cleanup'], 'retained_ephemeral'); self.assertIsNone(value['correctness'])

    def test_changed_pin_or_cleanup_deadline_cannot_publish_success(self):
        for fault in ('changed_pin', 'expires_in_cleanup', 'report_timeout'):
            with self.subTest(fault=fault):
                self.setUp(); code, value = self.invoke(fault)
                self.assertEqual(code, 1); self.assertNotEqual(value['cleanup'], 'complete'); self.remove.assert_not_called()


class NativeDeleteCounters(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin' and (os.environ.get('GITHUB_ACTIONS') == 'true' or
                         os.environ.get('STALLIONFS_TEST_DELETE_COUNTERS') == '1'), 'tiny fake-call harness requires separate admission')
    def test_delete_calls_refusals_errno_clocks_and_cancel(self):
        if os.environ.get('GITHUB_ACTIONS') == 'true':
            installed = shutil.which('stallionfs'); self.assertIsNotNone(installed)
            self.assertNotIn(probe.MARKER.encode(), Path(installed).read_bytes())
        tree = PERF.parents[1] / 'stallionfs/_tree.c'
        source = r'''
#include <assert.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <copyfile.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
static int fake_clock(clockid_t, struct timespec *);
static int fake_unlink(int, const char *, int);
static int fake_stat(int, const char *, struct stat *, int);
static int fake_fcntl(int, int, ...);
static int fake_close(int);
static DIR *fake_fdopendir(int);
static struct dirent *fake_readdir(DIR *);
static int fake_closedir(DIR *);
#define clock_gettime fake_clock
#define unlinkat fake_unlink
#define fstatat fake_stat
#define fcntl fake_fcntl
#define close fake_close
#define fdopendir fake_fdopendir
#define readdir fake_readdir
#define closedir fake_closedir
#define STALLIONFS_DIAGNOSTIC_THREAD_CPU 1
#define STALLIONFS_DIAGNOSTIC_DELETE_CPU 1
#include "TREE_PATH"
static int mode, ticks, entries, calls;
static int fake_clock(clockid_t id, struct timespec *out) {
    assert(id == CLOCK_THREAD_CPUTIME_ID); errno = EIO;
    if (mode == 1) return -1;
    out->tv_sec = 0; out->tv_nsec = ticks++ * 10; return 0;
}
static int fake_unlink(int fd, const char *name, int flags) {
    calls++; assert((fd == 7 && !strcmp(name, "leaf") && flags == 0) ||
                    (fd == 9 && !strcmp(name, "root") && flags == AT_REMOVEDIR));
    if ((mode == 2 && !flags) || (mode == 3 && flags)) { errno = EACCES; return -1; }
    errno = ENOSPC; return 0;
}
static int fake_stat(int fd, const char *name, struct stat *out, int flags) {
    assert(fd == 9 && !strcmp(name, "root") && flags == AT_SYMLINK_NOFOLLOW);
    memset(out, 0, sizeof(*out)); out->st_dev = 100; out->st_ino = mode == 4 ? 999 : 123;
    out->st_mode = S_IFDIR; return 0;
}
static int fake_fcntl(int fd, int command, ...) {
    assert(fd == 7 || fd == 9); if (command == F_DUPFD_CLOEXEC) { assert(fd == 7); return 8; }
    assert(command == F_GETPATH); va_list args; va_start(args, command);
    strcpy(va_arg(args, char *), "/synthetic"); va_end(args); return 0;
}
static int fake_close(int fd) { assert(fd == 7 || fd == 8); return 0; }
static DIR *fake_fdopendir(int fd) { assert(fd == 8); return (DIR *)(uintptr_t)1; }
static struct dirent *fake_readdir(DIR *dir) {
    assert(dir == (DIR *)(uintptr_t)1); if (entries++) return NULL;
    static struct dirent entry; memset(&entry, 0, sizeof(entry)); entry.d_type = DT_REG;
    strcpy(entry.d_name, "leaf"); return &entry;
}
static int fake_closedir(DIR *dir) { assert(dir == (DIR *)(uintptr_t)1); return 0; }
int main(void) {
    for (mode = 0; mode <= 5; mode++) {
        ticks = entries = calls = 0;
        struct cpu_slot slot = {0}; cpu_current = &slot; cpu_start(&slot);
        struct tree state = {.operation = DELETING, .device = 100, .parent_fd = 9, .live = 1,
            .mutex = PTHREAD_MUTEX_INITIALIZER, .available = PTHREAD_COND_INITIALIZER};
        atomic_init(&state.error, mode == 5 ? EINTR : 0);
        struct job *job = calloc(1, sizeof(*job)); assert(job);
        job->source = 7; job->destination = -1; job->name = strdup("root");
        job->inode = 123; job->pending = 1;
        process(&state, job); cpu_stop(&slot);
        if (mode == 0 || mode == 1) {
            assert(!atomic_load(&state.error) && calls == 2);
            assert(errno == ENOSPC);
            assert(slot.phase[CPU_UNLINK_ENTRY].calls == 1 && slot.phase[CPU_UNLINK_DIRECTORY].calls == 1);
            assert(slot.status == (mode == 1 ? CPU_CLOCK : CPU_OK));
        } else if (mode == 2) {
            assert(atomic_load(&state.error) == EACCES && calls == 1);
            assert(slot.phase[CPU_UNLINK_ENTRY].failures == 1 && !slot.phase[CPU_UNLINK_DIRECTORY].calls);
        } else if (mode == 3) {
            assert(atomic_load(&state.error) == EACCES && calls == 2);
            assert(slot.phase[CPU_UNLINK_DIRECTORY].failures == 1);
        } else if (mode == 4) {
            assert(atomic_load(&state.error) == ESTALE && calls == 1 && !slot.phase[CPU_UNLINK_DIRECTORY].calls);
        } else assert(calls == 0 && atomic_load(&state.error) == EINTR);
        assert(!slot.active); pthread_mutex_destroy(&state.mutex); pthread_cond_destroy(&state.available);
    }
    cpu_current = NULL; return 0;
}
'''.replace('TREE_PATH', str(tree))
        with tempfile.TemporaryDirectory(prefix='delete-counter-fake-') as temporary:
            root = Path(temporary); code = root / 'fake.c'; code.write_text(source); binary = root / 'fake'
            compiled = subprocess.run(['/usr/bin/xcrun', 'clang', '-std=c11', '-O0', str(code), '-o', str(binary)], capture_output=True, timeout=45)
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode(errors='replace'))
            child = subprocess.run([str(binary)], capture_output=True, timeout=10)
            self.assertEqual(child.returncode, 0, child.stderr.decode(errors='replace'))


if __name__ == '__main__': unittest.main()
