"""Run one Python build tool with the existing bounded process collector."""
import argparse
import importlib.util
import os
from pathlib import Path
import sys


def require_capture(capture):
    state = capture._command_state
    if (state.get('failure') is not None or state.get('active') is not None
            or state.get('first_signal') is not None or state.get('signal_count', 0) != 0):
        raise RuntimeError('Owned command capture failed or remains incomplete: ' + repr(state))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--timeout', type=int, required=True)
    parser.add_argument('--stem', type=Path, required=True)
    parser.add_argument('tool', type=Path)
    parser.add_argument('arguments', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 600: raise ValueError('Build deadline exceeds policy')
    path = Path(__file__).with_name('_git_capture.py')
    spec = importlib.util.spec_from_file_location('_ci_owned_capture', path)
    capture = importlib.util.module_from_spec(spec); spec.loader.exec_module(capture)
    capture._COMMAND_ENV = {name: os.environ[name] for name in ('HOME', 'USER', 'LOGNAME', 'PATH', 'TMPDIR') if name in os.environ}
    capture._COMMAND_ENV.update(PYTHONDONTWRITEBYTECODE='1', LANG='C', LC_ALL='C', MAKEFLAGS='-j1',
                               CMAKE_BUILD_PARALLEL_LEVEL='1', MAX_JOBS='1')
    previous = capture._install_command_handlers()
    try:
        result = capture._owned_command([sys.executable, '-I', '-B', str(args.tool.absolute()), *args.arguments],
            cwd=Path.cwd(), timeout=args.timeout, stem=args.stem.absolute())
        result.check_returncode()
        require_capture(capture)
    finally:
        capture._restore_command_handlers(previous)
    require_capture(capture)


if __name__ == '__main__': main()
