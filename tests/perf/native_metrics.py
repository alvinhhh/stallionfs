"""Native macOS command receipts and conservative paired comparison statistics.

Resources runs under /usr/bin/time -lp; timing executes the command directly
with blocking reaping and an owned alarm deadline. Both include process startup.
Timing CPU is the serialized RUSAGE_CHILDREN delta, excluding harness CPU. The
microsecond representation floor is not a guarantee of accounting accuracy.
Resource CPU has 0.01s precision per component and a 0.02s sum floor. RSS
is the command's reported peak in bytes, not simultaneous descendant memory.
Block I/O counts are OS operations, not bytes or physical device traffic.

A win requires at least ten complete, validated pairs and no excluded pairs.
For savings d = native - candidate, both mean(d) and median(d) must exceed
max(minimum_gain, measurement_floor, native_stddev, candidate_stddev,
paired_stddev, 3*paired_standard_error). Loss uses the
same rule on -d. This is a variance-based screening rule, not a confidence
interval. Rounded-zero CPU samples cannot establish a CPU win or loss. Pairing,
fixture validation and warmup exclusion belong to the calling harness.
"""
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import math
import os
from pathlib import Path
import re
import resource
import signal
import statistics
import subprocess
import threading
import time


TIME = '/usr/bin/time'
METRICS = ('wall_s', 'user_s', 'system_s', 'cpu_s', 'rss_bytes',
           'io_input_blocks', 'io_output_blocks')
TIME_PRECISION = {'user_s': 0.01, 'system_s': 0.01, 'cpu_s': 0.02}
TIMING_PRECISION = {'user_s': 0.000002, 'system_s': 0.000002, 'cpu_s': 0.000004}
PHASE_METRICS = {'resources': METRICS, 'timing': ('wall_s', 'user_s', 'system_s', 'cpu_s')}


class _DeadlineExpired(Exception):
    pass


class _Alarm:
    """Exclusive, main-thread alarm ownership; never arm during Popen creation."""
    def __init__(self):
        if threading.current_thread() is not threading.main_thread() or threading.active_count() != 1:
            raise RuntimeError('Timing requires an otherwise single-threaded main thread')
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        if (signal.getsignal(signal.SIGALRM) != signal.SIG_DFL
                or any(signal.getitimer(signal.ITIMER_REAL))
                or signal.SIGALRM in mask or signal.SIGALRM in signal.sigpending()):
            raise RuntimeError('Timing requires exclusive ownership of an idle, unblocked SIGALRM')
        self.active = self.closed = self.expired = False
        signal.signal(signal.SIGALRM, self._expired)

    def _expired(self, _signal, _frame):
        if self.active:
            self.active = False
            self.expired = True
            raise _DeadlineExpired()

    def arm(self, remaining):
        if remaining <= 0:
            raise _DeadlineExpired()
        self.active = True
        signal.setitimer(signal.ITIMER_REAL, remaining)

    def close(self):
        if self.closed:
            return
        self.active = False
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGALRM})
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            if signal.SIGALRM in signal.sigpending():
                self.expired = True
                signal.sigwait({signal.SIGALRM})
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            self.closed = True
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, mask)


def _child_cpu():
    try:
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        result = {'user_s': usage.ru_utime, 'system_s': usage.ru_stime}
        if any(not math.isfinite(value) or value < 0 for value in result.values()):
            raise ValueError(f'Invalid child CPU counters: {result!r}')
        return result, None
    except (OSError, ValueError) as error:
        return None, f'{type(error).__name__}: {error}'


class ChildCompletionUnknown(RuntimeError):
    """The caller must retain the fixture and this receipt for inspection."""
    def __init__(self, receipt):
        self.receipt = receipt
        super().__init__('Command completion is uncertain; preserve its fixture')


@contextmanager
def _retain_on_failure(receipt, child, alarm, grace_s):
    """Unexpected collector/restore failures must never permit fixture cleanup."""
    try:
        yield
    except BaseException as error:
        receipt.update(ok=False, completion_uncertain=True,
                       error=f'{type(error).__name__}: {error}')
        if alarm is not None:
            try: alarm.close()
            except BaseException as cleanup_error:
                receipt['alarm_cleanup_error'] = f'{type(cleanup_error).__name__}: {cleanup_error}'
        process = child()
        if process is not None:
            try:
                stdout, stderr = _stop_group(process, receipt, grace_s)
                receipt.update(stdout_b64=base64.b64encode(_bytes(stdout)).decode('ascii'),
                               stderr_b64=base64.b64encode(_bytes(stderr)).decode('ascii'),
                               stdout=_bytes(stdout).decode('utf-8', errors='replace'),
                               stderr=_bytes(stderr).decode('utf-8', errors='replace'),
                               exit_code=process.returncode)
            except BaseException as cleanup_error:
                receipt['termination_error'] = f'{type(cleanup_error).__name__}: {cleanup_error}'
        raise ChildCompletionUnknown(receipt) from error


def time_diagnostics(stderr):
    """Return lines outside the supported native time -lp numeric footer."""
    text = stderr.decode('utf-8', errors='replace') if isinstance(stderr, bytes) else stderr
    labels = (
        'maximum resident set size', 'average shared memory size',
        'average unshared data size', 'average unshared stack size',
        'page reclaims', 'page faults', 'swaps', 'block input operations',
        'block output operations', 'messages sent', 'messages received',
        'signals received', 'voluntary context switches', 'involuntary context switches',
        'instructions retired', 'cycles elapsed', 'peak memory footprint',
    )
    counter = r'\s*\d+\s+(?:' + '|'.join(re.escape(label) for label in labels) + r')\s*'
    timing = r'(?:real|user|sys)\s+\d+(?:\.\d+)?\s*'
    return [line for line in text.splitlines() if line.strip()
            and not re.fullmatch(timing, line) and not re.fullmatch(counter, line)]


def parse_time(stderr):
    """Parse anchored, unique native time fields; absent/malformed is None."""
    text = stderr.decode('utf-8', errors='replace') if isinstance(stderr, bytes) else stderr
    fields = {
        'time_wall_s': (r'^real\s+(\d+(?:\.\d+)?)\s*$', float),
        'user_s': (r'^user\s+(\d+(?:\.\d+)?)\s*$', float),
        'system_s': (r'^sys\s+(\d+(?:\.\d+)?)\s*$', float),
        'rss_bytes': (r'^\s*(\d+)\s+maximum resident set size\s*$', int),
        'io_input_blocks': (r'^\s*(\d+)\s+block input operations\s*$', int),
        'io_output_blocks': (r'^\s*(\d+)\s+block output operations\s*$', int),
    }
    result, errors = {}, []
    for key, (pattern, convert) in fields.items():
        matches = re.findall(pattern, text, flags=re.MULTILINE)
        try:
            value = convert(matches[0]) if len(matches) == 1 else None
            if value is not None and not math.isfinite(value): value = None
            if key == 'rss_bytes' and value == 0: value = None
        except (ValueError, OverflowError): value = None
        result[key] = value
        if value is None: errors.append(key)
    result['cpu_s'] = (result['user_s'] + result['system_s']
                       if result['user_s'] is not None and result['system_s'] is not None else None)
    result['parse_errors'] = errors
    return result


def _bytes(value):
    return value if isinstance(value, bytes) else (value or '').encode('utf-8', errors='replace')


def _stop_group(process, receipt, grace_s):
    """Bound termination and collection. Never infer all descendants exited."""
    receipt['termination'] = []
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(process.pid, sig)
            receipt['termination'].append({'signal': sig.name, 'sent': True})
        except ProcessLookupError:
            receipt['termination'].append({'signal': sig.name, 'sent': False, 'reason': 'group absent'})
        except OSError as error:
            receipt['termination'].append({'signal': sig.name, 'sent': False, 'error': str(error)})
        try:
            output = process.communicate(timeout=grace_s)
            try: os.killpg(process.pid, 0)
            except ProcessLookupError: return output
            except OSError as error: receipt['group_probe_error'] = str(error)
            if sig == signal.SIGKILL: return output
            # A reaped leader does not prove its original process group is gone.
        except subprocess.TimeoutExpired as error:
            receipt['partial_stdout_b64'] = base64.b64encode(_bytes(error.output)).decode('ascii')
            receipt['partial_stderr_b64'] = base64.b64encode(_bytes(error.stderr)).decode('ascii')
    # Do not perform an unbounded final communicate or unlink any fixture.
    for stream in (process.stdout, process.stderr):
        if stream is not None: stream.close()
    try: process.wait(timeout=grace_s)
    except subprocess.TimeoutExpired: receipt['leader_reap_timed_out'] = True
    return (base64.b64decode(receipt.get('partial_stdout_b64', '')),
            base64.b64decode(receipt.get('partial_stderr_b64', '')))


def collect(argv, *, timeout_s, cwd=None, env=None, termination_grace_s=1.0, phase='resources'):
    """Return a JSON-safe receipt. A failed/uncertain row is never a valid sample.

    Resource stderr also contains time's report; both phases retain bytes as
    base64 alongside display text. No shell interpolation or fixture cleanup.
    A timeout always sets completion_uncertain, even after the leader is reaped:
    detached descendants cannot be ruled out. Interruptions raise with receipt.
    Timing requires sole subprocess ownership: no other child may be reaped
    between its CPU snapshots. CPU includes descendant usage credited to the
    waited-for child, not independent services. Process creation itself cannot
    be safely interrupted before Popen returns its handle; startup counts toward
    the timing deadline, but this is not a hard bound on a stalled spawn.
    """
    arguments = [os.fspath(value) for value in argv]
    if not arguments or not all(isinstance(value, str) and '\0' not in value for value in arguments):
        raise ValueError('argv must contain non-NUL strings')
    if not math.isfinite(timeout_s) or timeout_s <= 0 or not math.isfinite(termination_grace_s) or termination_grace_s <= 0:
        raise ValueError('timeouts must be positive and finite')
    if phase not in PHASE_METRICS:
        raise ValueError('Unknown measurement phase')
    environment = dict(os.environ if env is None else env)
    environment['LC_ALL'] = 'C'
    wrapped = [TIME, '-lp', *arguments] if phase == 'resources' else None
    executed = wrapped if wrapped is not None else arguments
    precision = TIME_PRECISION if phase == 'resources' else TIMING_PRECISION
    receipt = {'phase': phase, 'argv': arguments, 'wrapped_argv': wrapped, 'executed_argv': executed,
               'cwd': str(Path(cwd or os.getcwd()).resolve()),
               'started_utc': datetime.now(timezone.utc).isoformat(), 'timeout_s': timeout_s,
               'exit_code': None, 'timed_out': False, 'completion_uncertain': False, 'ok': False,
               'precision_floor': {**precision, 'wall_s': time.get_clock_info('perf_counter').resolution,
                                   'rss_bytes': 0, 'io_input_blocks': 0, 'io_output_blocks': 0},
               'cpu_scope': ('command CPU reported by time -p, rounded per component' if phase == 'resources'
                             else 'serialized RUSAGE_CHILDREN delta; excludes harness and independent services'),
               'wall_scope': ('elapsed wrapper and command including startup' if phase == 'resources'
                              else 'direct command startup, pipe collection and blocking reap; includes deadline arming'),
               'parse_errors': [],
               **{key: None for key in METRICS}}
    alarm = _Alarm() if phase == 'timing' else None  # Reject unsuitable signal ownership before spawning.
    process = None
    interrupted = False
    stdout = stderr = b''
    start = None
    with _retain_on_failure(receipt, lambda: process, alarm, termination_grace_s):
        try:
            if alarm is not None:
                receipt['child_cpu_before'], receipt['cpu_error'] = _child_cpu()
            start = time.perf_counter()
            process = subprocess.Popen(executed, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, cwd=cwd, env=environment, start_new_session=True)
            receipt['pid'] = process.pid
            try:
                if alarm is not None:
                    try:
                        alarm.arm(timeout_s - (time.perf_counter() - start))
                        stdout, stderr = process.communicate()
                        receipt['wall_s'] = time.perf_counter() - start
                        if receipt['wall_s'] >= timeout_s:
                            raise _DeadlineExpired()
                    finally:
                        alarm.close()
                    if alarm.expired:
                        raise _DeadlineExpired()
                else:
                    stdout, stderr = process.communicate(timeout=timeout_s)
            except (subprocess.TimeoutExpired, _DeadlineExpired):
                if alarm is not None: alarm.close()
                receipt['timed_out'] = receipt['completion_uncertain'] = True
                stdout, stderr = _stop_group(process, receipt, termination_grace_s)
            except (KeyboardInterrupt, SystemExit) as error:
                if alarm is not None: alarm.close()
                interrupted = True
                receipt['completion_uncertain'] = True
                receipt['interruption'] = type(error).__name__
                stdout, stderr = _stop_group(process, receipt, termination_grace_s)
            receipt['exit_code'] = process.returncode
        except OSError as error:
            if alarm is not None: alarm.close()
            receipt['error'] = f'{type(error).__name__}: {error}'
            if process is not None:
                receipt['completion_uncertain'] = True
                stdout, stderr = _stop_group(process, receipt, termination_grace_s)
        except (KeyboardInterrupt, SystemExit) as error:
            # Popen may have created a child even if interrupted before returning it.
            interrupted = receipt['completion_uncertain'] = True
            receipt['interruption'] = type(error).__name__
            if alarm is not None: alarm.close()
            if process is not None:
                stdout, stderr = _stop_group(process, receipt, termination_grace_s)
        finally:
            if alarm is not None:
                alarm.close()
                receipt['child_cpu_after'], error = _child_cpu()
                receipt['cpu_error'] = receipt.get('cpu_error') or error
                before, after = receipt.get('child_cpu_before'), receipt['child_cpu_after']
                if before is not None and after is not None:
                    delta = {key: after[key] - before[key] for key in before}
                    delta['cpu_s'] = sum(delta.values())
                    if any(not math.isfinite(value) or value < 0 for value in delta.values()):
                        receipt['cpu_error'] = f'Invalid child CPU delta: {delta!r}'
                    else:
                        receipt.update(delta)
                        # Account for floating-point spacing if cumulative counters grow large.
                        for key in before:
                            receipt['precision_floor'][key] = max(precision[key], math.ulp(before[key]) + math.ulp(after[key]))
                        receipt['precision_floor']['cpu_s'] = sum(receipt['precision_floor'][key] for key in before)
            if receipt['wall_s'] is None and process is not None:
                receipt['wall_s'] = time.perf_counter() - start
            receipt['stdout_b64'] = base64.b64encode(_bytes(stdout)).decode('ascii')
            receipt['stderr_b64'] = base64.b64encode(_bytes(stderr)).decode('ascii')
            receipt['stdout'] = _bytes(stdout).decode('utf-8', errors='replace')
            receipt['stderr'] = _bytes(stderr).decode('utf-8', errors='replace')
            if phase == 'resources': receipt.update(parse_time(_bytes(stderr)))
            receipt['ok'] = (receipt['exit_code'] == 0 and not receipt['completion_uncertain']
                             and not receipt['parse_errors'] and not receipt.get('cpu_error') and 'error' not in receipt)
    if interrupted: raise ChildCompletionUnknown(receipt)
    return receipt


def summarize(samples):
    """Median, nearest-rank p95 and unbiased sample variance; ten samples minimum."""
    values = list(samples)
    if len(values) < 10 or any(isinstance(v, bool) or not isinstance(v, (int, float))
                              or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('Need at least ten finite, nonnegative measurements')
    ordered = sorted(values)
    return {'n': len(values), 'median': statistics.median(values),
            'p95': ordered[math.ceil(0.95 * len(values)) - 1],
            'mean': statistics.mean(values), 'sample_variance': statistics.variance(values),
            'minimum': ordered[0], 'maximum': ordered[-1]}


def compare_paired(native, candidate, metric, *, minimum_gain=0.0):
    """Compare rows with unique matching pair_id, ok and validated=True.

    Retain incomplete pair reasons. Any excluded pair prevents a win/loss claim;
    complete-case descriptive summaries are still returned when n>=10.
    """
    if metric not in METRICS or not math.isfinite(minimum_gain) or minimum_gain < 0:
        raise ValueError('Invalid metric or minimum gain')
    def keyed(rows):
        result = {}
        for row in rows:
            key = row.get('pair_id')
            if key is None or key in result: raise ValueError('Missing or duplicate pair_id')
            result[key] = row
        return result
    left, right = keyed(native), keyed(candidate)
    phases = {row.get('phase', 'resources') for row in [*left.values(), *right.values()]}
    if len(phases) > 1 or not phases <= PHASE_METRICS.keys():
        raise ValueError('Cannot compare mixed or unknown measurement phases')
    phase = next(iter(phases), 'resources')
    if metric not in PHASE_METRICS[phase]:
        raise ValueError('Metric is not collected in this phase')
    precision = TIME_PRECISION if phase == 'resources' else TIMING_PRECISION
    keys = list(left) + [key for key in right if key not in left]
    a, b, floors, excluded = [], [], [], []
    for key in keys:
        pair = (left.get(key), right.get(key))
        reason = None
        for row in pair:
            if row is None: reason = 'missing pair'; break
            value = row.get(metric)
            if row.get('ok') is not True or row.get('validated') is not True or row.get('completion_uncertain'):
                reason = 'failed, uncertain or unvalidated run'; break
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                reason = 'unavailable or invalid metric'; break
            if metric == 'rss_bytes' and value <= 0:
                reason = 'unavailable or invalid metric'; break
        if reason:
            excluded.append({'pair_id': key, 'reason': reason}); continue
        a.append(pair[0][metric]); b.append(pair[1][metric])
        for row in pair:
            floor = row.get('precision_floor', {}).get(metric, precision.get(metric, 0))
            if not isinstance(floor, (int, float)) or not math.isfinite(floor) or floor < 0:
                raise ValueError('Invalid precision floor')
            floors.append(max(floor, precision.get(metric, 0)))
    result = {'phase': phase, 'metric': metric, 'complete_pairs': len(a), 'excluded_pairs': excluded,
              'decision': 'insufficient_samples', 'native': None, 'candidate': None,
              'criterion': 'mean and median paired savings both exceed max(minimum_gain, precision_floor, native_stddev, candidate_stddev, paired_stddev, 3*paired_standard_error); no excluded pairs; n>=10'}
    if len(a) < 10: return result
    result.update(native=summarize(a), candidate=summarize(b))
    differences = [x-y for x,y in zip(a,b)]
    variance = statistics.variance(differences)
    native_stddev = math.sqrt(statistics.variance(a))
    candidate_stddev = math.sqrt(statistics.variance(b))
    paired_stddev = math.sqrt(variance)
    paired_standard_error = math.sqrt(variance / len(differences))
    uncertainty = max(native_stddev, candidate_stddev, paired_stddev, 3 * paired_standard_error)
    threshold = max(minimum_gain, max(floors, default=0), uncertainty)
    mean, median = statistics.mean(differences), statistics.median(differences)
    result.update(paired_mean_savings=mean, paired_median_savings=median,
                  paired_sample_variance=variance, native_stddev=native_stddev, candidate_stddev=candidate_stddev,
                  paired_stddev=paired_stddev, paired_standard_error=paired_standard_error, variance_threshold=uncertainty,
                  required_gap=threshold, decision='inconclusive')
    if excluded: result['decision'] = 'incomplete_pairs'
    elif metric in TIME_PRECISION and any(v == 0 for v in a+b): result['decision'] = 'below_resolution'
    elif mean > threshold and median > threshold: result['decision'] = 'candidate_faster' if metric == 'wall_s' else 'candidate_lower'
    elif -mean > threshold and -median > threshold: result['decision'] = 'candidate_slower' if metric == 'wall_s' else 'candidate_higher'
    return result
