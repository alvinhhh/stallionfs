"""Read-only installation observations, not release qualification."""
import os
from pathlib import Path
import plistlib
import shutil
import stat
import subprocess
import sys
import sysconfig
from xml.parsers.expat import ExpatError

from . import __version__, _command

APP = Path('/Applications/StallionFS.app')
INFORMATIONAL = frozenset({'store_root_exists', 'developer_id_signature', 'gatekeeper_accepted'})
QUALIFICATION = 'Passing these checks does not imply release qualification or extension enablement.'
REMOVAL_PLAN = [
    'Stop processes using workspaces and unmount them normally. Stop if anything is busy, pending or uncertain; do not force unmount or delete data to proceed. Keep verified recovery archives and installation history outside the app.',
    'Run {cli} command remove (by absolute path, so PATH cannot pick another sfs) while the app is still installed. If it was already deleted, reinstall the same version from your verified recovery copy first. Remove only your owned link; leave other files and other users\' links alone.',
    'Quit the app and turn off its File System Extension in System Settings. Check that it is off and no processes are using workspaces before continuing.',
    'Move only /Applications/StallionFS.app to the Trash using Finder. Do not empty the Trash or reset system registrations.',
    'Your workspaces, snapshots and recovery data in {root} are kept — delete them yourself only if you no longer need them. Other stores, external files and recovery archives are also kept.',
]


def _is_dir(path):
    try:
        return path.is_dir()
    except OSError:
        return False


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


def _path_command(name):
    """First executable `name` on PATH, and whether a ~ entry precedes it.

    Shells disagree on ~ in PATH (bash and sh expand ~, ~+, ~-, ~N and ~user; zsh
    expands none), so the result is ambiguous when such an entry is searched first.
    """
    for directory in os.environ.get('PATH', os.defpath).split(os.pathsep):
        if directory.startswith('~'):
            return None, True
        candidate = Path(directory or '.') / name
        try:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate, False
        except OSError:
            continue
    return None, False


def _same_directory(left, right):
    try:
        return os.path.samefile(left, right)
    except OSError:
        return False


def _command_status():
    home = _command._home()
    target = APP / 'Contents/Resources/Runtime/CLI/bin/sfs'
    with _command._bin(home, create=False) as held:
        entry = None if held is None else _command._link(held[-1][2])
        if held is not None:
            _command._check_directories(held)
        result = _command._result(home, entry, target)
        result['dangling'] = _command._ours(entry, target) and not target.exists()
        result['executable'] = target.is_file() and os.access(target, os.X_OK)
        resolved, result['path_ambiguous'] = _path_command('sfs')
        result['path_command'] = None if resolved is None else str(resolved)
        result['on_path'] = (resolved is not None and not result['path_ambiguous']
                             and _same_directory(resolved.parent, home / '.local/bin')
                             and _command._ours(entry, target) and result['executable'])
        return result


def _app_info():
    path = APP / 'Contents/Info.plist'
    if not stat.S_ISREG(path.lstat().st_mode):
        raise ValueError('Info.plist must be a regular file')
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('Info.plist must be a regular file')
        return plistlib.load(source)


def inspect(root):
    root = Path(root).expanduser().absolute()
    app = {'path': str(APP), 'present': _is_dir(APP),
           'extension_present': _is_dir(APP / 'Contents/Extensions/StallionFS.appex')}
    try:
        info = _app_info()
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
        assessment = _probe('spctl', ['--assess', '--no-cache', '--type', 'execute', str(APP)])
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
        'command_installed': command['state'] == 'installed' and command.get('executable', False)
                             and not command.get('dangling', False),
        'command_on_path': command.get('on_path', False),
        'developer_id_signature': signature['state'] == 'Developer ID',
        'gatekeeper_accepted': gatekeeper['state'] == 'accepted',
        'store_root_exists': _is_dir(root),
    }
    invoked = Path(sys.argv[0]).absolute()
    helper = (invoked.with_name('stallionfs-python') if invoked.name in ('sfs', 'stallionfs', 'stallionfs-python')
              else Path(sysconfig.get_path('scripts')) / 'stallionfs-python')
    return {'ready': all(value for name, value in checks.items() if name not in INFORMATIONAL),
            'informational': sorted(INFORMATIONAL),
            'checks': checks, 'cli_version': __version__,
            'python_helper': str(helper), 'command': command,
            'app': app, 'signature': signature, 'gatekeeper': gatekeeper,
            'store_root': {'path': str(root), 'exists': checks['store_root_exists']},
            'removal_plan': [step.format(root=root, cli=APP / 'Contents/Resources/Runtime/CLI/bin/sfs') for step in REMOVAL_PLAN], 'qualification': QUALIFICATION}


def describe(result):
    lines = ['Installation: ' + ('ready' if result['ready'] else 'not ready'),
             result['qualification'], 'CLI version: ' + result['cli_version'],
             'Python helper: ' + result['python_helper']]
    command = result['command']
    command_text = command['state']
    if command.get('command'):
        command_text += ' at ' + command['command']
        command_text += ', on PATH' if command['on_path'] else ', not on PATH'
    if command.get('dangling'):
        command_text += ', broken link (target is missing)'
    elif command.get('state') == 'installed' and not command.get('executable'):
        command_text += ', target is not executable'
    if command.get('path_ambiguous'):
        command_text += (', PATH has a ~ entry before any sfs, which shells resolve differently;'
                         ' replace ~ with $HOME or an absolute path')
    elif command.get('path_command') and not command['on_path']:
        command_text += ', PATH selects ' + command['path_command']
    if command.get('error'):
        command_text += ': ' + command['error']
    lines.append('Command: ' + command_text)
    app = result['app']
    app_text = app['path']
    if app['present']:
        if app['version'] is not None:
            app_text += ', version ' + app['version']
            app_text += ' (matches CLI)' if app['version_matches_cli'] else ' (does not match CLI)'
            app_text += ', build ' + app['bundle_version']
        else:
            app_text += ', version unavailable'
        app_text += ', extension present' if app['extension_present'] else ', extension missing'
    else:
        app_text += ', missing'
    if app.get('error'):
        app_text += ': ' + app['error']
    lines.append('App: ' + app_text)
    signature = result['signature']
    signature_text = signature['state']
    if signature['authorities']:
        signature_text += ' (' + '; '.join(signature['authorities']) + ')'
    if signature['state'] == 'unknown':
        reasons = []
        for probe in (signature['verify'], signature['details']):
            reason = probe.get('error')
            if not reason and probe.get('returncode', 0) != 0:
                reason = probe.get('stderr', '').strip() or 'codesign exited ' + str(probe['returncode'])
            if reason and reason not in reasons:
                reasons.append(reason)
        if reasons:
            signature_text += ': ' + '; '.join(reasons)
    lines.append('Signature: ' + signature_text)
    gatekeeper = result['gatekeeper']
    gatekeeper_text = gatekeeper['state']
    if gatekeeper['probe'].get('error'):
        gatekeeper_text += ': ' + gatekeeper['probe']['error']
    lines.append('Gatekeeper: ' + gatekeeper_text)
    store = result['store_root']
    lines.append('Store root: ' + store['path'] + (', exists' if store['exists'] else ', not created yet (informational)'))
    lines.append('Removal plan (instructions only; nothing has been changed):')
    lines.extend(str(index) + '. ' + step for index, step in enumerate(result['removal_plan'], 1))
    names = {'app_present': 'app missing', 'extension_present': 'extension missing',
             'version_matches_cli': 'app version must match CLI',
             'command_installed': 'command link must be installed', 'command_on_path': 'command must be on PATH'}
    signing = {'developer_id_signature': 'no Developer ID signature', 'gatekeeper_accepted': 'not accepted by Gatekeeper'}
    unsigned = [label for name, label in signing.items() if not result['checks'][name]]
    if unsigned:
        lines.append('Release signing (informational, not part of readiness): ' + '; '.join(unsigned) + '.')
    failed = [label for name, label in names.items() if not result['checks'][name]]
    if failed:
        lines.append('Not ready: ' + '; '.join(failed) + '.')
    return '\n'.join(lines)
