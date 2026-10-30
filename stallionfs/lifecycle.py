"""Cooperative workspace snapshots, recovery, and protected retirement."""
from __future__ import annotations

import contextlib
import fcntl
import math
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import time
import uuid

RETENTION_COUNT = 32
STALE_SECONDS = 7 * 86400


def replace_json(path, value):
    """Replace mutable state atomically; write_json remains create-only."""
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            core.json.dump({'format': 1, **value}, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.lexists(temporary):
            os.unlink(temporary)


def identity(path):
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode):
        raise core.StallionError(f'Unexpected symlink: {path}')
    return [info.st_dev, info.st_ino]


def finite_time(value):
    return (type(value) is int or (type(value) is float and math.isfinite(value))) and value > 0



class Lifecycle:
    @contextlib.contextmanager
    def _lease(self, workspace):
        core.identifier(workspace, 32)
        path = self.root / 'locks' / f'use-{workspace}'
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise core.StallionError(f'Unsafe workspace lease: {path}')
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise core.StallionError(f'Workspace is in managed use: {workspace}') from exc
            yield fd
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _workspace_lock(self, workspace, *, reconcile=True):
        # Acquisition order: managed-use lease, workspace lock, retention lock.
        with self._lease(workspace), core.lock(self.root / 'locks' / f'workspace-{workspace}', blocking=False):
            if reconcile:
                self._reconcile(workspace)
            yield

    def _payload(self, path, meta):
        return path / ('workspace.sparseimage' if meta.get('backend') == 'image' else 'repo')

    def _state(self, workspace):
        return self.root / 'lifecycle' / f'{workspace}.json'

    def _open(self, workspace, path, meta, *, enrolled=None):
        state_path = self._state(workspace)
        previous = core.read_json(state_path) if state_path.exists() else {}
        state = {'id': workspace, 'generation': uuid.uuid4().hex, 'status': 'open',
                 'enrolled': previous.get('enrolled') is True if enrolled is None else enrolled,
                 'object': identity(path), 'payload': identity(self._payload(path, meta))}
        replace_json(state_path, state)
        protection = self.root / 'protected' / f'{workspace}.json'
        if path.parent == self.root / 'workspaces' and os.path.lexists(protection):
            try:
                retired = core.read_json(protection)
                if (retired.get('id') == workspace and retired.get('object') == identity(path) and
                        core.re.fullmatch('[0-9a-f]{32}', str(retired.get('generation', ''))) and
                        not os.path.lexists(self.root / 'trash' / workspace)):
                    protection.unlink()
            except (core.StallionError, OSError):
                pass  # Uncertain protection remains; reopening never authorizes deletion.
        return state

    def _no_mounts(self, path):
        from ._scan import mounts
        root = path.resolve()
        if any(Path(row['path']).is_relative_to(root) for row in mounts()):
            raise core.StallionError(f'Workspace contains a mounted volume: {path}')

    def _standalone_git(self, repo):
        gitdir = repo / '.git'
        if (not gitdir.is_dir() or gitdir.is_symlink() or
                any(os.path.lexists(gitdir / name) for name in
                    ('commondir', 'objects/info/alternates', 'objects/info/http-alternates', 'worktrees', 'modules')) or
                any(gitdir.rglob('*.lock'))):
            raise core.StallionError('Workspace requires standalone Git storage without active Git locks')
        core.validate_tree(gitdir)
        if Path(core.git(repo, 'rev-parse', '--absolute-git-dir')).resolve() != gitdir.resolve():
            raise core.StallionError('Workspace uses external Git storage')
        for config in (gitdir / 'config', gitdir / 'config.worktree'):
            if not config.exists():
                continue
            values = core.git(repo, 'config', '--file', config, '--no-includes', '--list').splitlines()
            for line in values:
                key = line.partition('=')[0].lower()
                if key == 'core.worktree' or key == 'include.path' or key.startswith('includeif.'):
                    raise core.StallionError('Workspace Git configuration contains external worktree or include references')

    def _closed_payload(self, path, meta, *, quiescent):
        payload = self._payload(path, meta)
        if meta.get('backend') == 'image':
            from . import images
            attached = images.mounted(payload)
            if attached is not None and attached['mountpoint'] != str(path / 'volume'):
                raise core.StallionError('Image is not mounted at its managed mountpoint; unmount it before capture')
            repo = Path(self._mount(path, meta)['path']) if attached is None else path / 'volume' / 'repo'
            self._standalone_git(repo)
            images.detach(payload, path / 'volume')
            images.flush(payload)
            self._no_mounts(path)
            return payload, attached is not None
        if not quiescent:
            raise core.StallionError('Folder capture requires --quiescent after stopping all external writers')
        self._no_mounts(path)
        core.validate_tree(payload)
        self._standalone_git(payload)
        return payload, False

    def _clone_payload(self, source, target, meta):
        if meta.get('backend') == 'image':
            from . import images
            images.clone(source, target)
        else:
            core.clone_tree(source, target)

    @contextlib.contextmanager
    def _retention(self):
        with core.lock(self.root / 'locks' / 'retention', blocking=False):
            import itertools
            entries = [p for kind in ('snapshots', 'recovery', 'protected')
                       for p in itertools.islice((self.root / kind).iterdir(), RETENTION_COUNT + 1)]
            if len(entries) >= RETENTION_COUNT:
                raise core.StallionError('Recovery retention limit reached; explicitly purge unneeded retained data')
            yield

    def snapshot(self, workspace, *, quiescent=False, name=''):
        if not isinstance(name, str) or len(name) > 128:
            raise core.StallionError('Snapshot name must be at most 128 characters')
        with self._workspace_lock(workspace):
            path, meta = self.object('workspaces', workspace)
            self._open(workspace, path, meta)
            payload, remount = self._closed_payload(path, meta, quiescent=quiescent)
            value = uuid.uuid4().hex
            with self._retention(), self.staging() as stage:
                self._clone_payload(payload, stage / payload.name, meta)
                record = {'id': value, 'workspace': workspace, 'name': name, 'created': time.time(),
                          'backend': meta.get('backend', 'folder'), 'payload': identity(stage / payload.name)}
                core.write_json(stage / 'meta.json', record)
                stage.rename(self.root / 'snapshots' / value)
            if remount:
                self._mount(path, meta)
            return record

    def snapshots(self, workspace):
        core.identifier(workspace, 32)
        result = []
        for path in sorted((self.root / 'snapshots').iterdir()):
            core.private_directory(path)
            record = core.read_json(path / 'meta.json')
            if record.get('workspace') == workspace:
                self._snapshot(record['id'], workspace)
                result.append(record)
        return result

    def _snapshot(self, value, workspace):
        core.identifier(value, 32)
        path = self.root / 'snapshots' / value
        core.private_directory(path)
        record = core.read_json(path / 'meta.json')
        if (record.get('id') != value or record.get('workspace') != workspace or
                record.get('backend') not in ('folder', 'image') or
                identity(self._payload(path, record)) != record.get('payload')):
            raise core.StallionError('Snapshot identity does not match its record')
        return path, record

    def _reconcile(self, workspace):
        journal = self.root / 'journals' / f'{workspace}.json'
        if not os.path.lexists(journal):
            return
        record = core.read_json(journal)
        core.identifier(record.get('recovery'), 32)
        if record.get('workspace') != workspace or record.get('backend') not in ('folder', 'image'):
            raise core.StallionError('Uncertain rollback journal; retained without changes')
        current = self._payload(self.root / 'workspaces' / workspace, record)
        recovery = self._payload(self.root / 'recovery' / record['recovery'], record)
        pair = [identity(current), identity(recovery)]
        if pair == [record.get('old'), record.get('candidate')]:
            outcome = 'not-exchanged'
        elif pair == [record.get('candidate'), record.get('old')]:
            outcome = 'exchanged'
        else:
            raise core.StallionError('Uncertain rollback identities; current and recovery retained without changes')
        record['outcome'] = outcome
        replace_json(recovery.parent / 'meta.json', record)
        path, meta = self.object('workspaces', workspace)
        self._open(workspace, path, meta)
        journal.unlink()

    def rollback(self, workspace, snapshot, *, quiescent=False):
        with self._workspace_lock(workspace):
            path, meta = self.object('workspaces', workspace)
            source, saved = self._snapshot(snapshot, workspace)
            if saved['backend'] != meta.get('backend', 'folder'):
                raise core.StallionError('Snapshot backend does not match workspace')
            self._open(workspace, path, meta)
            payload, remount = self._closed_payload(path, meta, quiescent=quiescent)
            recovery = uuid.uuid4().hex
            slot = self.root / 'recovery' / recovery
            with self._retention():
                source, saved = self._snapshot(snapshot, workspace)
                slot.mkdir(mode=0o700)
                candidate = slot / payload.name
                # This permanent slot must never enter staging's automatic deleter.
                self._clone_payload(self._payload(source, saved), candidate, saved)
                record = {'id': recovery, 'workspace': workspace, 'recovery': recovery,
                          'snapshot': snapshot, 'backend': saved['backend'], 'created': time.time(),
                          'old': identity(payload), 'candidate': identity(candidate), 'outcome': 'intent'}
                journal = self.root / 'journals' / f'{workspace}.json'
                try:
                    core.write_json(slot / 'meta.json', record)
                    core.write_json(journal, record)
                    from ._scan import move
                    move(payload, candidate, exchange=True)
                    self._reconcile(workspace)
                except BaseException as original:
                    try:
                        self._reconcile(workspace)
                    except BaseException as recovery_error:
                        original.add_note(f'Rollback reconciliation failed; retain {slot}: {recovery_error}')
                    raise
            if remount:
                self._mount(path, meta)
            return {'workspace': workspace, 'snapshot': snapshot, 'recovery': recovery}

    def enroll(self, workspace, *, enabled=True):
        with self._workspace_lock(workspace):
            path, meta = self.object('workspaces', workspace)
            return self._open(workspace, path, meta, enrolled=enabled)

    def close(self, workspace, *, quiescent=False):
        if not quiescent:
            raise core.StallionError('Close requires --quiescent after stopping all writers')
        with self._workspace_lock(workspace):
            path, meta = self.object('workspaces', workspace)
            state = self._open(workspace, path, meta)
            self._closed_payload(path, meta, quiescent=True)
            state.update(status='closed', closed_at=time.time(), payload=identity(self._payload(path, meta)))
            replace_json(self._state(workspace), state)
            return state

    def run(self, workspace, command, *, auto_retire=False):
        if not command:
            raise core.StallionError('Supply a command after --')
        if auto_retire and not self.cleanup_config()['enabled']:
            raise core.StallionError('Enable cleanup before using --auto-retire')
        generation = None
        try:
            with self._lease(workspace) as lease_fd:
                with core.lock(self.root / 'locks' / f'workspace-{workspace}', blocking=False):
                    if auto_retire:
                        self._no_pending_rollback(workspace)
                    else:
                        self._reconcile(workspace)
                    path, meta = self.object('workspaces', workspace)
                    if auto_retire:
                        if meta.get('backend', 'folder') != 'folder':
                            raise core.StallionError('--auto-retire supports folder workspaces only')
                        previous = core.read_json(self._state(workspace))
                        if not self._valid_state(workspace, path, meta, previous, time.time()):
                            raise core.StallionError('--auto-retire requires valid cleanup enrollment')
                    state = self._open(workspace, path, meta)
                    if auto_retire:
                        state['auto_retire'] = {'generation': state['generation']}
                        replace_json(self._state(workspace), state)
                        generation = state['generation']
                    repo = self._mount(path, meta)['path']
                options = {}
                if auto_retire:
                    options = {'pass_fds': (lease_fd,), 'env': {
                        **os.environ, 'STALLIONFS_LEASE_FD': str(lease_fd),
                        'STALLIONFS_LEASE_GENERATION': generation}}
                result = subprocess.run(command, cwd=repo, **options)
        finally:
            # Closing our descriptor must not unlock the shared lease held by descendants.
            if generation is not None:
                self._observe_idle(workspace, generation)
        return {'workspace': workspace, 'returncode': result.returncode}

    def _policy(self):
        path = self.root / 'cleanup.json'
        value = core.read_json(path) if path.exists() else {'enabled': False}
        cursor = value.get('cursor')
        if (type(value.get('enabled')) is not bool or
                (cursor is not None and (not isinstance(cursor, str) or not core.re.fullmatch('[0-9a-f]{32}', cursor)))):
            raise core.StallionError('Invalid cleanup setting')
        return value

    def cleanup_config(self, *, enabled=None):
        with core.lock(self.root / '.lock', blocking=enabled is not None):
            value = self._policy()
            if enabled is not None:
                value = {**value, 'enabled': bool(enabled)}
                replace_json(self.root / 'cleanup.json', value)
            return value

    def _no_pending_rollback(self, workspace):
        if os.path.lexists(self.root / 'journals' / f'{workspace}.json'):
            raise core.StallionError('Pending rollback requires an explicit workspace operation')

    def _valid_state(self, workspace, path, meta, state, now):
        if (not finite_time(now) or state.get('id') != workspace or state.get('enrolled') is not True or
                state.get('status') not in ('open', 'closed') or
                not isinstance(state.get('generation'), str) or
                not core.re.fullmatch('[0-9a-f]{32}', state['generation']) or
                state.get('object') != identity(path) or state.get('payload') != identity(self._payload(path, meta))):
            return False
        if state['status'] == 'closed':
            closed = state.get('closed_at')
            return ('auto_retire' not in state and finite_time(closed) and closed <= now)
        if 'closed_at' in state:
            return False
        if 'auto_retire' in state:
            session = state['auto_retire']
            if (meta.get('backend', 'folder') != 'folder' or not isinstance(session, dict) or
                    session.get('generation') != state['generation']):
                return False
            if 'idle_since' in session and (not finite_time(session['idle_since']) or session['idle_since'] > now):
                return False
        return True

    def _eligible(self, workspace, now, *, observe=False, generation=None):
        path, meta = self.object('workspaces', workspace)
        state = core.read_json(self._state(workspace))
        if not self._valid_state(workspace, path, meta, state, now):
            return None
        if generation is not None and state['generation'] != generation:
            return None
        if state['status'] == 'closed':
            since = state['closed_at']
        else:
            session = state.get('auto_retire')
            if session is None:
                return None
            since = session.get('idle_since')
            if since is None:
                if not observe:
                    return None
                self._no_mounts(path)
                state['auto_retire'] = {**session, 'idle_since': now}
                replace_json(self._state(workspace), state)
                since = now
        if now - since < STALE_SECONDS:
            return None
        self._no_mounts(path)
        if meta.get('backend') == 'image':
            from . import images
            if images.mounted(self._payload(path, meta)) is not None:
                return None
        return path, meta, state

    def _observe_idle(self, workspace, generation):
        try:
            with core.lock(self.root / '.lock', shared=True, blocking=False):
                if not self._policy()['enabled']:
                    return
                with self._workspace_lock(workspace, reconcile=False):
                    self._no_pending_rollback(workspace)
                    self._eligible(workspace, time.time(), observe=True, generation=generation)
        except (core.StallionError, OSError, ValueError, TypeError):
            pass  # A later apply can observe the exact still-enrolled session.

    def _advance_cursor(self, observed, last):
        with core.lock(self.root / '.lock', blocking=False):
            current = self._policy()
            if current['enabled'] and current.get('cursor') == observed:
                replace_json(self.root / 'cleanup.json', {**current, 'cursor': last})

    def cleanup(self, *, apply=False, limit=None):
        result = {'retired' if apply else 'would_retire': [], 'skipped': []}
        policy = self.cleanup_config()
        if not policy['enabled']:
            result['enabled'] = False
            return result
        names = sorted(p.name for p in (self.root / 'workspaces').iterdir()
                       if core.re.fullmatch('[0-9a-f]{32}', p.name))
        cursor = policy.get('cursor')
        if limit is not None:
            if cursor is not None:
                names = [name for name in names if name > cursor] + [name for name in names if name <= cursor]
            names = names[:limit]
        for workspace in names:
            try:
                with core.lock(self.root / '.lock', shared=True, blocking=False):
                    if not self._policy()['enabled']:
                        result['enabled'] = False
                        return result
                    with self._workspace_lock(workspace, reconcile=False):
                        self._no_pending_rollback(workspace)
                        now = time.time()
                        eligible = self._eligible(workspace, now, observe=apply)
                        if eligible is None:
                            continue
                        path, meta, state = eligible
                        if apply:
                            with self._retention():
                                protection = self.root / 'protected' / f'{workspace}.json'
                                if os.path.lexists(protection):
                                    raise core.StallionError('Existing protection requires explicit restore or purge')
                                core.write_json(protection, {'id': workspace, 'object': identity(path),
                                                            'generation': state['generation'], 'retired_at': now})
                                # Protection precedes rename, including when rename succeeds then raises.
                                from ._scan import move
                                move(path, self.root / 'trash' / workspace)
                        result['retired' if apply else 'would_retire'].append(workspace)
            except (core.StallionError, OSError, ValueError, TypeError) as error:
                result['skipped'].append({'id': workspace, 'reason': str(error)})
        if apply and limit is not None and names:
            self._advance_cursor(cursor, names[-1])
        return result

    def opportunistic_cleanup(self):
        try:
            return self.cleanup(apply=True, limit=8)
        except (core.StallionError, OSError, ValueError, TypeError):
            return None  # A successful requested operation stays successful if maintenance cannot run.

    def retained(self):
        return {kind: [p.name for p in (self.root / kind).iterdir()]
                for kind in ('snapshots', 'recovery', 'protected')}

    def purge(self, kind, value, *, yes=False):
        if kind not in ('snapshots', 'recovery', 'trash'):
            raise core.StallionError('Purge accepts snapshots, recovery, or trash')
        core.identifier(value, 32)
        path = self.root / kind / value
        # Purge is explicit permanent deletion, never called by automatic maintenance.
        workspace_lock = self._workspace_lock(value) if kind == 'trash' else contextlib.nullcontext()
        with workspace_lock, core.lock(self.root / 'locks' / 'retention'):
            core.private_directory(path)
            if next((self.root / 'journals').iterdir(), None) is not None:
                raise core.StallionError('Resolve pending rollback before purging retained data')
            self._no_mounts(path)
            image = path / 'workspace.sparseimage'
            if os.path.lexists(image):
                from . import images
                if images.mounted(image) is not None:
                    raise core.StallionError('Retained image is still attached')
            if yes:
                with self.staging() as stage:
                    if kind == 'trash':
                        protection = self.root / 'protected' / f'{value}.json'
                        if os.path.lexists(protection):
                            protection.unlink()
                    expired = stage / 'expired'
                    path.rename(expired)
                    core.remove_tree(expired)
                    stage.rmdir()
            return {'deleted' if yes else 'would_delete': str(path)}


# Store imports this class; defer the helper module until the class is defined.
from . import core
