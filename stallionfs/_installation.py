"""Read-only installation observations, not release qualification."""
import json
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import sysconfig
from xml.parsers.expat import ExpatError

from . import __version__, _command

APP = Path('/Applications/StallionFS.app')
QUALIFICATION = 'Passing these checks does not imply release qualification or extension enablement.'
REMOVAL_PLAN = [
    'Before removal: retain independently authenticated recovery archives and installation history outside the app; stop all writers and helpers normally and normally unmount owned workspaces. Busy, pending or unknown activity stops removal. Do not purge data to proceed.',
    'First remove only your owned CLI link with sfs command remove while the admitted app is intact. Preserve foreign links/files; other users manage their own links. If the app was deleted first, restore the same exact artifact before normal link removal.',
    'Quit the app normally and disable its File System Extension in System Settings. Recheck actual enablement and activity; this diagnostic does not establish a safe maintenance window.',
    'Use Finder to move only /Applications/StallionFS.app to Trash after the required maintenance observations. Do not empty Trash or reset registrations globally.',
    'Preserve all workspace stores (including custom --root paths), snapshots, sidecars, external references, recovery archives and retained installation history.',
]


def _probe(tool, arguments):
    executable = shutil.which(tool)
    if executable is None:
        return {'state': 'unavailable', 'error': tool + ' is not available'}
    try:
        result = subprocess.run([executable, *arguments], capture_output=True,
                                text=True, timeout=10, check=False)
        return {'state': 'completed', 'returncode': result.returncode,
                'stdout': result.stdout, 'stderr': result.stderr}
    except subprocess.TimeoutExpired:
        return {'state': 'timeout', 'error': tool + ' timed out after 10 seconds'}
    except (OSError, UnicodeError) as error:
        return {'state': 'error', 'error': str(error)}


def _command_status():
    home = _command._home()
    target = APP / 'Contents/Resources/Runtime/CLI/bin/sfs'
    with _command._bin(home, create=False) as held:
        entry = None if held is None else _command._link(held[-1][2])
        if held is not None:
            _command._check_directories(held)
        result = _command._result(home, entry, target)
        result['dangling'] = _command._ours(entry, target) and not target.exists()
        return result


def inspect(root):
    root = Path(root).expanduser().absolute()
    app = {'path': str(APP), 'present': APP.is_dir(),
           'extension_present': (APP / 'Contents/Extensions/StallionFS.appex').is_dir()}
    try:
        with (APP / 'Contents/Info.plist').open('rb') as source:
            info = plistlib.load(source)
        version, build = info.get('CFBundleShortVersionString'), info.get('CFBundleVersion')
        if not isinstance(version, str) or not isinstance(build, str):
            raise ValueError('Missing or invalid bundle version fields')
        app.update(version=version, bundle_version=build, version_matches_cli=version == __version__)
    except (OSError, ValueError, TypeError, AttributeError, plistlib.InvalidFileException, ExpatError) as error:
        app.update(version=None, bundle_version=None, version_matches_cli=False, error=str(error))
    try:
        command = _command_status()
    except (OSError, ValueError, KeyError, TypeError) as error:
        command = {'state': 'error', 'error': str(error)}
    if app['present']:
        verify = _probe('codesign', ['--verify', '--deep', '--strict', str(APP)])
        details = _probe('codesign', ['-dv', str(APP)])
        assessment = _probe('spctl', ['--assess', '--type', 'execute', str(APP)])
    else:
        verify = {'state': 'skipped', 'error': 'App is absent'}
        details = dict(verify)
        assessment = dict(verify)
    signature = {'state': 'unknown', 'verify': verify, 'details': details}
    authorities = [line.removeprefix('Authority=') for line in
                   (details.get('stdout', '') + '\n' + details.get('stderr', '')).splitlines()
                   if line.startswith('Authority=')]
    signature['authorities'] = authorities
    if verify['state'] != 'completed' or details['state'] != 'completed':
        signature['state'] = 'unknown'
    else:
        diagnostic = verify['stderr'] + '\n' + details['stderr']
        if 'not signed at all' in diagnostic:
            signature['state'] = 'unsigned'
        elif verify['returncode'] != 0:
            signature['state'] = 'invalid'
        elif details['returncode'] != 0:
            signature['state'] = 'unknown'
        elif 'Signature=adhoc' in diagnostic:
            signature['state'] = 'ad-hoc'
        elif any(authority.startswith('Developer ID Application:') for authority in authorities):
            signature['state'] = 'Developer ID'
        else:
            signature['state'] = 'other'
    gatekeeper = {'state': ('accepted' if assessment['returncode'] == 0 else 'rejected')
                  if assessment['state'] == 'completed' else assessment['state'], 'probe': assessment}
    checks = {
        'app_present': app['present'], 'extension_present': app['extension_present'],
        'version_matches_cli': app['version_matches_cli'],
        'command_installed': command['state'] == 'installed' and not command.get('dangling', False),
        'command_on_path': command.get('on_path', False),
        'developer_id_signature': signature['state'] == 'Developer ID',
        'gatekeeper_accepted': gatekeeper['state'] == 'accepted',
        'store_root_exists': root.is_dir(),
    }
    invoked = Path(sys.argv[0]).absolute()
    helper = (invoked.with_name('stallionfs-python') if invoked.name in ('sfs', 'stallionfs', 'stallionfs-python')
              else Path(sysconfig.get_path('scripts')) / 'stallionfs-python')
    return {'ready': all(checks.values()), 'checks': checks, 'cli_version': __version__,
            'python_helper': str(helper), 'command': command,
            'app': app, 'signature': signature, 'gatekeeper': gatekeeper,
            'store_root': {'path': str(root), 'exists': checks['store_root_exists']},
            'removal_plan': list(REMOVAL_PLAN), 'qualification': QUALIFICATION}


def describe(result):
    lines = ['Installation: ' + ('ready' if result['ready'] else 'not ready'),
             result['qualification'], 'CLI version: ' + result['cli_version'],
             'Python helper: ' + result['python_helper']]
    for label in ('command', 'app', 'signature', 'gatekeeper', 'store_root'):
        lines.append(label.replace('_', ' ').capitalize() + ': ' + json.dumps(result[label], sort_keys=True))
    lines.append('Checks: ' + json.dumps(result['checks'], sort_keys=True))
    lines.append('Removal plan (instructions only; nothing has been changed):')
    lines.extend(str(index) + '. ' + step for index, step in enumerate(result['removal_plan'], 1))
    return '\n'.join(lines)
