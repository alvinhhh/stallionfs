"""Subprocess checks of managed run output, without a macOS workspace."""
import json
from pathlib import Path
import select
import subprocess
import sys
import textwrap
import unittest


CLI_SCRIPT = textwrap.dedent('''\
    import contextlib
    from pathlib import Path
    import sys
    import types

    native = types.ModuleType('stallionfs._scan')
    native._private_directory = lambda path: None
    sys.modules['stallionfs._scan'] = native
    from stallionfs import core
    from stallionfs.__main__ import main

    class FolderStore(core.Store):
        def __init__(self, root):
            self.root = Path.cwd()
        def _lease(self, workspace):
            return contextlib.nullcontext(None)
        def _reconcile(self, workspace):
            pass
        def object(self, kind, workspace):
            return self.root, {'backend': 'folder'}
        def _open(self, workspace, path, meta):
            return {}
        def _mount(self, path, meta):
            return {'path': str(path)}
        def opportunistic_cleanup(self):
            pass

    core.Store = FolderStore
    core.lock = lambda *args, **kwargs: contextlib.nullcontext()
    sys.exit(main())
''')


class ManagedRunOutput(unittest.TestCase):
    def command(self, code, *, json_output=True):
        return subprocess.run(
            [sys.executable, '-c', CLI_SCRIPT,
             *(['--json'] if json_output else []), 'run', 'workspace', '--',
             sys.executable, '-c', code],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=15,
        )

    def test_json_child_stdout_is_not_part_of_document(self):
        child = self.command("print('child stdout')")
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), {'workspace': 'workspace', 'returncode': 0})
        self.assertEqual(child.stderr, 'child stdout\n')

    def test_json_empty_child_stdout(self):
        child = self.command('pass')
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), {'workspace': 'workspace', 'returncode': 0})
        self.assertEqual(child.stderr, '')

    def test_json_in_process_caller_with_stringio_stderr(self):
        script = CLI_SCRIPT.replace('sys.exit(main())', textwrap.dedent('''\
            import io
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream):
                status = main()
            assert stream.getvalue() == ''
            sys.exit(status)
        '''))
        child = subprocess.run(
            [sys.executable, '-c', script, '--json', 'run', 'workspace', '--',
             sys.executable, '-c', "print('child stdout')"],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(child.returncode, 0, child.stderr)
        self.assertEqual(json.loads(child.stdout), {'workspace': 'workspace', 'returncode': 0})
        self.assertEqual(child.stderr, 'child stdout\n')

    def test_json_failed_child_keeps_receipt_and_status(self):
        child = self.command("import sys; print('child stdout'); print('child stderr', file=sys.stderr); sys.exit(7)")
        self.assertEqual(child.returncode, 7, child.stderr)
        self.assertEqual(json.loads(child.stdout), {'workspace': 'workspace', 'returncode': 7})
        self.assertEqual(sorted(child.stderr.splitlines()), ['child stderr', 'child stdout'])

    def test_human_child_stdout_streams_before_exit(self):
        with subprocess.Popen(
            [sys.executable, '-c', CLI_SCRIPT, 'run', 'workspace', '--',
             sys.executable, '-c', "import sys; print('child stdout', flush=True); sys.stdin.readline()"],
            cwd=Path(__file__).resolve().parents[1],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        ) as child:
            try:
                self.assertTrue(select.select([child.stdout], [], [], 10)[0], 'stdout was not streamed')
                self.assertEqual(child.stdout.readline(), 'child stdout\n')
                self.assertIsNone(child.poll())
            finally:
                stdout, stderr = child.communicate('\n', timeout=15)
            self.assertEqual(child.returncode, 0, stderr)
            self.assertEqual(stdout, '')
            self.assertEqual(stderr, '')
