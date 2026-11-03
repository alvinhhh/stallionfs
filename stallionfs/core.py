"""No daemon, database, shell evaluation, shared Git index, or source-linked workspace files."""

from __future__ import annotations

from ._scan import _private_directory

import contextlib
import errno
import fcntl
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time


class StallionError(Exception):
    """An actionable user or filesystem error."""


def native_target(metadata):
    target = metadata.get('native_image')
    if metadata.get('ownership') != 'external-reference' or not isinstance(target, dict):
        raise StallionError('Invalid native image registration')
    directory, component = target.get('directory'), target.get('component')
    if (not isinstance(directory, str) or not os.path.isabs(directory) or '\0' in directory or
            not isinstance(component, str) or component in ('', '.', '..') or '/' in component or '\0' in component):
        raise StallionError('Invalid native image path')
    for key in ('parent', 'file'):
        pair = target.get(key)
        if not isinstance(pair, list) or len(pair) != 2 or any(type(n) is not int or n < 0 for n in pair):
            raise StallionError('Invalid native image identity')
    if not re.fullmatch('[0-9a-f]{32}', str(target.get('uuid', ''))):
        raise StallionError('Invalid native image UUID')
    return target


def owned_native_target(path, metadata):
    """Resolve a completed retained candidate; this grants no workspace readiness."""
    from .lifecycle import identity
    path = Path(path)
    private_directory(path)
    if (metadata.get('ownership') != 'store-created' or metadata.get('backend') != 'native-image' or
            metadata.get('state') != 'candidate' or metadata.get('creation_proof') != 'native-create.json' or
            path.name != 'owned' or path.parent.parent.name != 'staging'):
        raise StallionError('Invalid owned native candidate')
    target = metadata.get('native_image')
    if not isinstance(target, dict) or set(target) != {'component', 'parent', 'object', 'file', 'uuid', 'anchor'}:
        raise StallionError('Invalid owned native target')
    if target['component'] != 'image.sfs' or target['parent'] != identity(path.parent) or target['object'] != identity(path):
        raise StallionError('Native candidate directory identity changed')
    info = (path / 'image.sfs').lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or
            target['file'] != [info.st_dev, info.st_ino]):
        raise StallionError('Native candidate backing identity changed')
    proof = read_json(path / 'native-create.json')
    identifier(metadata.get('id'), 32)
    identifier(metadata.get('seed'), 64)
    identifier(metadata.get('transaction'), 32)
    result = proof.get('result')
    if not isinstance(result, dict) or not isinstance(result.get('identity'), dict):
        raise StallionError('Invalid native candidate result')
    anchor = target.get('anchor')
    if (not isinstance(anchor, dict) or set(anchor) != {'generation', 'root_digest', 'committed_end'} or
            type(anchor.get('generation')) is not int or anchor['generation'] <= 0 or
            type(anchor.get('committed_end')) is not int or anchor['committed_end'] < 16384 or
            anchor['committed_end'] % 4096 or not re.fullmatch('[0-9a-f]{64}', str(anchor.get('root_digest', '')))):
        raise StallionError('Invalid native candidate committed anchor')
    for operation in ('creation', 'commit', 'verify', 'close', 'reopen', 'reopen_close'):
        receipt = result.get(operation)
        if (not isinstance(receipt, dict) or receipt.get('status') != 0 or
                receipt.get('uuid') != target['uuid'] or [receipt.get('device'), receipt.get('inode')] != target['file'] or
                receipt.get('poisoned') is not False or receipt.get('transaction_active') is not False):
            raise StallionError('Incomplete native candidate operation receipt')
        if operation != 'creation' and any(receipt.get(key) != value for key, value in anchor.items()):
            raise StallionError('Native candidate receipt anchor mismatch')
    if (result['commit'].get('generation') != result['creation'].get('generation') + 1 or
            result['commit'].get('fence_attempted') != 3 or result['commit'].get('fence_succeeded') != 3 or
            result['verify'].get('coverage') != 1 or proof.get('import_contract') != 'prepared-tree-v1'):
        raise StallionError('Native candidate lacks complete import verification')
    if (proof.get('operation') != 'native-create' or proof.get('id') != metadata.get('id') or
            proof.get('transaction') != metadata.get('transaction') or proof.get('seed') != metadata.get('seed') or
            proof.get('native_image') != target or result.get('candidate_complete') is not True or
            result.get('import_committed') is not True or result.get('verified') is not True or
            result.get('creation_disposition') != 'known_created' or result.get('outcome') != 'candidate-created' or
            result.get('identity', {}).get('file') != target['file'] or
            result.get('identity', {}).get('uuid') != target['uuid'] or result.get('anchor') != target['anchor'] or
            any(result.get(key, {}).get('status') != 0 for key in ('close', 'reopen', 'reopen_close'))):
        raise StallionError('Native candidate lacks matching completed creation proof')
    # Reuse the unchanged external target validator only for its identity schema.
    resolved = {'directory': str(path), 'component': 'image.sfs', 'parent': target['object'],
                'file': target['file'], 'uuid': target['uuid']}
    native_target({'ownership': 'external-reference', 'native_image': resolved})
    return resolved


def native_retention_reason(path):
    """Observe protected native stage shapes without following directory aliases."""
    path = Path(path)
    def failed(error):
        raise error
    for parent, directories, files in os.walk(path, followlinks=False, onerror=failed):
        parent = Path(parent)
        names = set(directories) | set(files)
        if names & {'native-create', 'native-create.json'}:
            return 'native creation marker'
        if 'image.sfs' in names and (parent == path or parent.name == 'owned'):
            return 'possible native backing image'
        if parent == path and 'meta.json' in names:
            metadata = read_json(parent / 'meta.json')
            if metadata.get('backend') == 'native-image' or metadata.get('ownership') == 'store-created':
                return 'native object metadata'
    return None


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def native_operation(target, operation, *names):
    # This checks the immediate canonical parent's ACL, not every ancestor.
    private_directory(target['directory'])
    from . import _image
    result = getattr(_image, operation)(target, *names)
    try:
        if not result['ok']:
            committed = result.get('committed', False)
            outcome = result.get('outcome')
            suffix = ('; the change committed' if committed else
                      '; publication outcome is unknown' if outcome == 'unknown' else '')
            error = StallionError(f"Native image {operation} failed: {os.strerror(result['error_code'])}{suffix}")
            error.native_image_result = result
            raise error
    except MemoryError as error:
        try:
            error.native_image_result = result
        except MemoryError:
            pass  # Permanent exhaustion cannot guarantee delivery; never retry the operation.
        raise
    return result


def native_failure_details(error):
    """Recover the fixed receipt carrier after a transient response allocation failure."""
    current = error
    # An outer Store receipt contains location/cleanup facts in addition to
    # the bridge result. Find it before returning an earlier raw carrier.
    for _ in range(3):
        candidate = getattr(current, 'native_candidate_result', None)
        if isinstance(candidate, dict):
            return candidate
        current = getattr(current, '__context__', None)
        if current is None:
            break
    current = error
    for _ in range(3):
        details = getattr(current, 'native_image_result', None)
        if isinstance(details, dict):
            return details
        carrier = getattr(current, 'native_image_carrier', None)
        if isinstance(carrier, dict):
            try:
                details = json.loads(bytes(carrier['data']).split(b'\0', 1)[0])
                details.update(snapshot=carrier['snapshot'], recovery=carrier['recovery'])
                if 'failure_path' in carrier:
                    details['failure_path'] = carrier['failure_path']
                return details
            except (MemoryError, ValueError, TypeError, KeyError):
                return None  # The exception still owns its carrier if memory remains exhausted.
        current = getattr(current, '__context__', None)
        if current is None:
            break
    return None


def run(args, cwd=None, *, capture=True):
    # Inherited Git routing variables must never redirect an operation elsewhere.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
    if os.environ.get('STALLIONFS_BENCHMARK_DEADLINE'):
        from ._benchmark_budget import command
        result = command(args, cwd=cwd, environment=env, persist_success=False)
        if result.returncode:
            raise StallionError(f'{args[0]} failed ({result.returncode}): '
                                + result.stderr.decode(errors='replace').strip())
        if not capture:
            sys.stderr.write(result.stdout.decode(errors='replace'))
            sys.stderr.write(result.stderr.decode(errors='replace'))
            return None
        return result.stdout.decode(errors='replace').strip()
    result = subprocess.run(
        [str(a) for a in args], cwd=cwd, env=env, text=True,
        stdout=subprocess.PIPE if capture else sys.stderr,
        stderr=subprocess.PIPE if capture else sys.stderr,
    )
    if result.returncode:
        raise StallionError(
            f"{args[0]} failed ({result.returncode}): "
            + ((result.stderr or "").strip() if capture else "see stderr")
        )
    return result.stdout.strip() if capture else None


def git(repo, *args):
    return run(["git", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
                "-c", "maintenance.autoDetach=false", "-c", "gc.autoDetach=false",
                "-C", repo, *args])


def identifier(value, length):
    if not isinstance(value, str) or not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise StallionError(f"Expected a {length}-character lowercase hexadecimal ID")
    return value


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise StallionError(f"Missing or unsafe metadata: {path}")
    try:
        value = json.loads(path.read_text())
        if not isinstance(value, dict) or value.get("format") != 1:
            raise ValueError("unsupported format")
        return value
    except (ValueError, UnicodeError) as exc:
        raise StallionError(f"Invalid metadata: {path}: {exc}") from exc


def write_json(path, value):
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump({"format": 1, **value}, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Publish a complete file without replacing an existing marker.
        os.link(temporary, path, follow_symlinks=False)
    finally:
        os.unlink(temporary)


def private_directory(path):
    try:
        _private_directory(path)
    except OSError as exc:
        if exc.errno not in (errno.EPERM, errno.EACCES, errno.ENOTDIR, errno.ELOOP):
            raise
        raise StallionError(f"Storage must be an owned, real directory with mode 0700 and no ACL access for other users: {path}") from exc


def remove_tree(path, *, jobs=4):
    from ._scan import delete, mounts
    root = path.resolve()
    if any(Path(mount["path"]).is_relative_to(root) for mount in mounts()):
        raise StallionError(f"Directory contains a mounted volume; retained at {path}")
    delete(path, recursive=True, jobs=jobs)


@contextlib.contextmanager
def lock(path, *, shared=False, blocking=True):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise StallionError(f"Unsafe lock file: {path}")
        fcntl.flock(fd, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | (0 if blocking else fcntl.LOCK_NB))
        yield
    finally:
        os.close(fd)


def clone_tree(source, destination, *, jobs=4):
    """Clone prepared files using descriptor-relative native filesystem operations."""
    if sys.platform != "darwin":
        raise StallionError("stallionfs requires macOS and an APFS volume")
    try:
        from ._scan import _clone_tree
    except ImportError as exc:
        raise StallionError("Install stallionfs first to build its native filesystem tools: python3 -m pip install .") from exc
    _clone_tree(source, destination, jobs=jobs)


def validate_tree(root):
    """Only regular files, directories, and relocatable internal symlinks are supported."""
    device = root.stat().st_dev
    def failed(error):
        raise error
    for parent, dirs, files in os.walk(root, followlinks=False, onerror=failed):
        for name in dirs + files:
            item = Path(parent, name)
            info = item.lstat()
            if name == ".git" and Path(parent) != root:
                raise StallionError(f"Nested Git repositories are unsupported: {item.relative_to(root)}")
            if info.st_dev != device:
                raise StallionError(f"Nested mount is unsupported: {item.relative_to(root)}")
            if stat.S_ISLNK(info.st_mode):
                target = os.readlink(item)
                try:
                    resolved = item.resolve()
                except (RuntimeError, OSError) as exc:
                    raise StallionError(f"Invalid symlink: {item.relative_to(root)}") from exc
                if os.path.isabs(target) or not resolved.is_relative_to(root):
                    raise StallionError(f"Symlink must be relative and stay inside the workspace: {item.relative_to(root)}")
            elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise StallionError(f"Special file is unsupported: {item.relative_to(root)}")


from .lifecycle import Lifecycle


class Store(Lifecycle):
    def __init__(self, root):
        raw = Path(root).expanduser().absolute()
        if raw.is_symlink():
            raise StallionError("Storage root cannot be a symlink")
        raw.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.root = raw.resolve()
        private_directory(self.root)
        with lock(self.root / ".lock"):
            marker = self.root / "store.json"
            if not marker.exists():
                if set(p.name for p in self.root.iterdir()) != {".lock"}:
                    raise StallionError("Refusing to adopt nonempty storage without store.json")
                write_json(marker, {"application": "stallionfs"})
            if read_json(marker).get("application") != "stallionfs":
                raise StallionError("This is not a stallionfs store")
            for name in ("seeds", "workspaces", "trash", "staging", "locks", "snapshots", "recovery", "lifecycle", "journals", "protected"):
                child = self.root / name
                child.mkdir(mode=0o700, exist_ok=True)
                private_directory(child)

    @contextlib.contextmanager
    def staging(self, *, retain_native=False):
        path = Path(tempfile.mkdtemp(prefix="build-", dir=self.root / "staging"))
        try:
            yield path
        except BaseException as exc:
            try:
                exc.add_note(f"Unfinished files retained at {path}")
            except (AttributeError, MemoryError):
                pass  # Retention must not replace the primary failure.
            raise
        else:
            if path.exists():
                reason = native_retention_reason(path)
                if reason:
                    if retain_native:
                        return
                    raise StallionError(f'Staging contains {reason}; retained at {path}')
                for journal in (self.root / 'journals').iterdir():
                    record = read_json(journal)
                    if record.get('operation') == 'native-create' and record.get('stage') == str(path):
                        raise StallionError(f'Native creation intent protects staging at {path}')
                image = path / "workspace.sparseimage"
                if os.path.lexists(image):
                    from . import images
                    # Inspection errors also retain staging: absence of a mount is
                    # insufficient proof that the backing image is unused.
                    if images.mounted(image) is not None:
                        raise StallionError(f"Staging image is still attached; retained at {path}")
                remove_tree(path)

    def object(self, kind, value):
        identifier(value, 64 if kind == "seeds" else 32)
        path = self.root / kind / value
        private_directory(path)
        metadata = read_json(path / "meta.json")
        if metadata.get("id") != value:
            raise StallionError(f"Metadata ID mismatch: {path}")
        if metadata.get('backend') == 'native-image':
            if kind != 'workspaces':
                raise StallionError('Native image registrations are not seeds or trash')
            native_target(metadata)
            return path, metadata
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(metadata.get("commit", ""))):
            raise StallionError(f"Invalid commit in metadata: {path}")
        backend = metadata.get("backend", "folder")
        if backend == "image":
            info = (path / "workspace.sparseimage").lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise StallionError(f"Missing or unsafe workspace image: {path}")
            if kind != "seeds" and ((path / "volume").is_symlink() or not (path / "volume").is_dir()):
                raise StallionError(f"Missing or unsafe mount directory: {path}")
        elif backend != "folder" or (path / "repo").is_symlink() or not (path / "repo").is_dir():
            raise StallionError(f"Missing or unsafe repository: {path}")
        return path, metadata

    def _guard_native_tree(self, path):
        """Call under the store lock before moving or deleting managed data."""
        reason = native_retention_reason(path)
        if reason:
            raise StallionError(f'Native data must remain at {path}: {reason}')
        references = []
        for registration in (self.root / 'workspaces').iterdir():
            private_directory(registration)
            metadata = read_json(registration / 'meta.json')
            if metadata.get('backend') != 'native-image':
                continue
            target = native_target(metadata)
            references.append(tuple(target['file']))
            try:
                parent = Path(target['directory']).lstat()
                backing = (Path(target['directory']) / target['component']).lstat()
            except OSError as error:
                raise StallionError('Uncertain native reference prevents managed data removal') from error
            if (not stat.S_ISDIR(parent.st_mode) or [parent.st_dev, parent.st_ino] != target['parent'] or
                    not stat.S_ISREG(backing.st_mode) or [backing.st_dev, backing.st_ino] != target['file']):
                raise StallionError('Changed native reference prevents managed data removal')
        if not references:
            return
        def failed(error):
            raise error
        for directory, directories, files in os.walk(path, followlinks=False, onerror=failed):
            for name in directories + files:
                item = Path(directory) / name
                info = item.lstat()
                if (info.st_dev, info.st_ino) in references:
                    raise StallionError(f'Registered native backing must remain at {item}')

    def register_native_image(self, source, *, name=''):
        with lock(self.root / '.lock'):
            return self._register_native_image(source, name=name)

    def _refuse_owned_native_reference(self, target):
        expected = target['file']
        for stage in (self.root / 'staging').iterdir():
            private_directory(stage)
            if os.path.lexists(stage / 'owned'):
                private_directory(stage / 'owned')
            for candidate in (stage / 'owned' / 'image.sfs', stage / 'image.sfs'):
                try:
                    info = candidate.lstat()
                except FileNotFoundError:
                    continue
                if [info.st_dev, info.st_ino] == expected:
                    raise StallionError('A retained native candidate cannot be registered as an external image')
        for journal in (self.root / 'journals').iterdir():
            record = read_json(journal)
            if record.get('operation') != 'native-create':
                continue
            if record.get('creation_attempted') is not False and record.get('native_image', {}).get('file') is None:
                raise StallionError('Resolve uncertain native creation before registering an external image')
            if record.get('native_image', {}).get('file') == expected:
                raise StallionError('Native creation intent protects this backing image')

    def _register_native_image(self, source, *, name=''):
        import uuid
        if not isinstance(name, str) or len(name) > 128:
            raise StallionError('Registration name must be at most 128 characters')
        raw = Path(source).expanduser().absolute()
        if raw.is_symlink() or raw.name in ('', '.', '..'):
            raise StallionError('Native image must be a real backing file')
        # Intermediate aliases are allowed here; later operations bind this
        # canonical parent and the core-opened backing inode independently.
        parent = raw.parent.resolve(strict=True)
        private_directory(parent)
        identity = parent.stat()
        target = {'directory': str(parent), 'component': raw.name,
                  'parent': [identity.st_dev, identity.st_ino], 'file': None, 'uuid': None}
        observed = native_operation(target, 'inspect')
        target.update(file=observed['identity']['file'], uuid=observed['identity']['uuid'])
        self._refuse_owned_native_reference(target)
        workspace = uuid.uuid4().hex
        metadata = {'id': workspace, 'name': name, 'backend': 'native-image',
                    'ownership': 'external-reference', 'native_image': target, 'created': time.time()}
        with self._workspace_lock(workspace):
            with self.staging() as stage:
                write_json(stage / 'meta.json', metadata)
                stage.rename(self.root / 'workspaces' / workspace)
        return {**metadata, 'path': str(parent / raw.name)}

    @contextlib.contextmanager
    def _native_creation_scope(self, seed, result, carrier):
        primary = None
        try:
            with lock(self.root / '.lock'), lock(self.root / 'locks' / f'seed-{seed}', shared=True):
                try:
                    yield
                except BaseException as error:
                    primary = error
                    raise
        except BaseException as closing_error:
            error = primary if primary is not None else closing_error
            receipt, fallback = carrier
            if receipt is not None and (primary is None or error is not closing_error):
                receipt['lock_close_errno'] = getattr(closing_error, 'errno', None)
            try:
                if result[0] is not None:
                    error.native_image_result = result[0]
                if receipt is not None:
                    error.native_candidate_result = receipt
            except (AttributeError, MemoryError):
                if fallback is not None:
                    # The exception and its location receipt were allocated
                    # before creation; exception context slots need no dict.
                    fallback.__context__ = error.__context__
                    error.__context__ = fallback
                    if error is not closing_error:
                        closing_error.__context__ = fallback
            if error is not closing_error:
                raise error from closing_error
            raise

    def _build_owned_native_candidate(self, seed, *, name='', jobs=4, native_capacity_gib, native_verification_budget=None):
        """Produce a retained verified image; public workspace creation is unchanged."""
        import uuid
        from . import _image
        from .lifecycle import identity, replace_json
        identifier(seed, 64)
        if type(native_capacity_gib) is not int or not 1 <= native_capacity_gib <= 65536:
            raise StallionError('Native image capacity must be an integer between 1 and 65536 GiB')
        if type(jobs) is not int or not 1 <= jobs <= 4:
            raise StallionError('jobs must be between 1 and 4')
        if not isinstance(name, str) or (name and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,63}', name)):
            raise StallionError('Name must be 1–64 letters, digits, dots, underscores or hyphens')
        if native_verification_budget is not None:
            dimensions = {'raw_cells', 'metadata_read_bytes', 'metadata_hash_bytes', 'checks', 'auxiliary_bytes', 'auxiliary_io_bytes'}
            if (not isinstance(native_verification_budget, dict) or set(native_verification_budget) != dimensions or
                    any(type(value) is not int or not 0 < value < 1 << 64 for value in native_verification_budget.values())):
                raise StallionError('Verification budget requires six positive uint64 dimensions')
            native_verification_budget = native_verification_budget.copy()
        native_result, carrier = [None], [None, None]
        with self._native_creation_scope(seed, native_result, carrier):
            base, seed_meta = self.object('seeds', seed)
            if seed_meta.get('backend', 'folder') != 'folder':
                error = StallionError('Native candidate creation requires a folder seed')
                error.native_reason = 'source-backend'
                raise error
            workspace, transaction = uuid.uuid4().hex, uuid.uuid4().hex
            final = self.root / 'workspaces' / workspace
            journal = self.root / 'journals' / f'{workspace}.json'
            if os.path.lexists(final) or os.path.lexists(journal):
                raise StallionError('Native candidate destination is already reserved')
            with self.staging(retain_native=True) as stage:
                host, owned = stage / 'input', stage / 'owned'
                host.mkdir(mode=0o700)
                owned.mkdir(mode=0o700)
                response = {'candidate_created': False, 'image_verified': False,
                            'candidate': str(owned), 'retained_stage': str(stage), 'journal': str(journal),
                            'host_input': str(host), 'host_cleanup_complete': None, 'host_cleanup_error': None,
                            'host_cleanup_errno': None, 'lock_close_errno': None, 'metadata': None,
                            'native_image_result': None, 'outcome': 'preparing'}
                fallback = StallionError(f'Native creation receipt retained; stage {stage}; intent {journal}')
                fallback.native_candidate_result = response
                carrier[:] = [response, fallback]
                intent = {'operation': 'native-create', 'transaction': transaction, 'workspace': workspace,
                          'seed': seed, 'stage': str(stage), 'stage_identity': identity(stage),
                          'candidate': str(owned), 'object': identity(owned), 'final': str(final),
                          'creation_attempted': False, 'outcome': 'preparing',
                          'native_image': {'component': 'image.sfs', 'file': None, 'uuid': None, 'anchor': None}}
                write_json(stage / 'native-create', intent)
                sync_directory(stage)
                write_json(journal, intent)
                sync_directory(journal.parent)
                sync_directory(stage.parent)
                if read_json(journal).get('transaction') != transaction:
                    raise StallionError('Native candidate intent ownership changed')
                with self._workspace_lock(workspace, reconcile=False, native_result=native_result):
                    repo = host / 'repo'
                    clone_tree(base / 'repo', repo, jobs=jobs)
                    branch = f"stallionfs/{name + '-' if name else ''}{workspace}"
                    git(repo, 'checkout', '-b', branch)
                    self._standalone_git(repo)
                    validate_tree(repo)

                    def before_create():
                        current = read_json(journal)
                        if (current != {'format': 1, **intent} or current.get('transaction') != transaction or
                                identity(stage) != intent['stage_identity'] or identity(owned) != intent['object'] or
                                os.path.lexists(final)):
                            raise StallionError('Native candidate intent or directory changed')
                        intent.update(creation_attempted=True, outcome='creation-attempted')
                        replace_json(journal, intent)
                        sync_directory(journal.parent)
                        replace_json(stage / 'native-create', intent)
                        sync_directory(stage)

                    source = {'directory': str(repo), 'root': identity(repo)}
                    destination = {'directory': str(owned), 'parent': identity(owned), 'component': 'image.sfs',
                                   'before_create': before_create}
                    try:
                        result = _image.create_from_tree(source, destination, native_capacity_gib * (1 << 30),
                            *((native_verification_budget,) if native_verification_budget is not None else ()))
                    except BaseException as error:
                        details = native_failure_details(error)
                        if details is not None:
                            native_result[0] = details
                            response['native_image_result'] = details
                            response['outcome'] = details.get('outcome', 'unknown')
                            try:
                                error.native_image_result = details
                            except (AttributeError, MemoryError):
                                pass  # The preallocated Store receipt owns the same details.
                        try:
                            error.add_note(f'Native candidate and host input retained at {stage}; intent {journal}')
                        except (AttributeError, MemoryError):
                            pass
                        raise
                    native_result[0] = result
                    response['native_image_result'] = result
                    response['image_verified'] = result.get('candidate_complete') is True
                    response['outcome'] = 'image-verified' if response['image_verified'] else result['outcome']
                    intent.update(outcome=result['outcome'], result=result)
                    if result.get('identity') is not None:
                        intent['native_image'].update(result['identity'])
                    intent['native_image']['anchor'] = result.get('anchor')
                    replace_json(journal, intent)
                    sync_directory(journal.parent)
                    replace_json(stage / 'native-create', intent)
                    sync_directory(stage)
                    if not result.get('candidate_complete'):
                        error = StallionError(f"Native candidate creation failed: {result.get('reason', 'publication-unknown')}; retained at {stage}")
                        error.native_image_result = result
                        raise error
                    target = {'component': 'image.sfs', 'parent': identity(stage), 'object': identity(owned),
                              'file': result['identity']['file'], 'uuid': result['identity']['uuid'], 'anchor': result['anchor']}
                    metadata = {'id': workspace, 'seed': seed, 'transaction': transaction, 'name': name,
                                'branch': branch, 'commit': seed_meta['commit'], 'created': time.time(),
                                'backend': 'native-image', 'ownership': 'store-created', 'state': 'candidate',
                                'capacity_gib': native_capacity_gib, 'native_image': target, 'creation_proof': 'native-create.json'}
                    write_json(owned / 'native-create.json', {'operation': 'native-create', 'id': workspace,
                               'transaction': transaction, 'seed': seed, 'native_image': target,
                               'import_contract': 'prepared-tree-v1', 'result': result})
                    write_json(owned / 'meta.json', metadata)
                    sync_directory(owned)
                    owned_native_target(owned, metadata)
                    response['candidate_created'] = True
                    response['metadata'] = metadata
                    response['outcome'] = 'candidate-created'
                    response['host_cleanup_complete'] = False
                    try:
                        remove_tree(host, jobs=jobs)
                        sync_directory(stage)
                    except (OSError, StallionError) as error:
                        response['host_cleanup_errno'] = getattr(error, 'errno', None)
                        response['host_cleanup_error'] = str(error)
                    else:
                        response['host_cleanup_complete'] = True
                    # The intent remains an observational hold, never an exchange journal.
                    return response

    def prepare(self, source, *, ref="HEAD", key, command=(), image_size=None):
        import hashlib
        import platform
        if sys.platform != "darwin":
            raise StallionError("stallionfs requires macOS and an APFS volume")
        source = Path(source).expanduser().resolve(strict=True)
        if not key.strip():
            raise StallionError("Supply a cache key describing the toolchain (for example node22-npm10-v1)")
        if image_size is not None and (type(image_size) is not int or not 1 <= image_size <= 65536):
            raise StallionError("Image capacity must be an integer between 1 and 65536 GiB")
        if self.root.is_relative_to(source) or source.is_relative_to(self.root):
            raise StallionError("Source and stallionfs storage must not overlap")
        if Path(git(source, "rev-parse", "--show-toplevel")).resolve() != source:
            raise StallionError("Source must be the root of a Git checkout")
        if git(source, "status", "--porcelain", "--untracked-files=normal"):
            raise StallionError("Commit or stash source changes before preparing a seed")
        commit = git(source, "rev-parse", "--verify", "--end-of-options", f"{ref}^{{commit}}")
        if any(line.startswith("160000 ") for line in git(source, "ls-tree", "-r", commit).splitlines()):
            raise StallionError("Submodules are not supported")
        remotes = git(source, "remote").splitlines()
        origin = git(source, "remote", "get-url", "origin") if "origin" in remotes else str(source)
        # Avoid persisting token-bearing HTTP URLs in every workspace's Git config.
        if re.match(r"https?://[^/]*@", origin) or "?" in origin or "\n" in origin:
            raise StallionError("Use an origin URL without embedded credentials or query parameters")
        spec = {"source": str(source), "commit": commit, "origin": origin, "key": key,
                "command": list(command), "system": platform.system(),
                "release": platform.release(), "machine": platform.machine(), "format": 1}
        if image_size is not None:
            spec.update(backend="image", capacity_gib=image_size)
        seed = hashlib.sha256(json.dumps(spec, sort_keys=True).encode()).hexdigest()
        with lock(self.root / "locks" / f"seed-{seed}"):
            final = self.root / "seeds" / seed
            if final.exists():
                _, existing = self.object("seeds", seed)
                return {**existing, "cached": True}
            with self.staging() as stage:
                repo = stage / "repo"
                git(source, "clone", "--no-local", "--no-checkout", "--template=", "--", str(source), str(repo))
                # A linked or detached source may name a commit absent from advertised branches.
                git(repo, "fetch", "--no-tags", "--", str(source), commit)
                git(repo, "checkout", "--detach", commit)
                git(repo, "remote", "set-url", "origin", origin)
                if command:
                    run(command, repo, capture=False)
                if not (repo / ".git").is_dir() or (repo / ".git").is_symlink():
                    raise StallionError("Preparation replaced the standalone Git directory")
                if any((repo / ".git" / name).exists() for name in ("commondir", "objects/info/alternates", "worktrees")):
                    raise StallionError("Preparation created shared Git storage or linked worktrees")
                if any(line.lower().startswith("core.worktree=") for line in git(repo, "config", "--local", "--list").splitlines()):
                    raise StallionError("Preparation set core.worktree; cloned Git directories must be relocatable")
                if git(repo, "rev-parse", "HEAD") != commit or git(repo, "diff", "HEAD", "--"):
                    raise StallionError("Preparation changed tracked files or HEAD; commit those changes in the source first")
                if any((repo / ".git").rglob("*.lock")):
                    raise StallionError("Preparation left a Git lock; stop background processes before preparing")
                validate_tree(repo)
                if image_size is not None:
                    from . import images
                    images.build(repo, stage / "workspace.sparseimage", image_size)
                    remove_tree(repo)
                metadata = {"id": seed, **spec, "created": time.time()}
                write_json(stage / "meta.json", metadata)
                # Publish only a fully prepared tree; a failed command never becomes a cache hit.
                stage.rename(final)
                return {**metadata, "cached": False}

    def forget(self, seed, *, yes=False):
        identifier(seed, 64)
        with lock(self.root / ".lock"), lock(self.root / "locks" / f"seed-{seed}"):
            path, metadata = self.object("seeds", seed)
            self._guard_native_tree(path)
            if yes:
                if metadata.get("backend") == "image":
                    from . import images
                    if images.mounted(path / "workspace.sparseimage") is not None:
                        raise StallionError("Prepared image is still attached; detach it before deleting the seed")
                # Existing workspaces own their Git objects and retain their cloned blocks.
                with self.staging() as stage:
                    path.rename(stage / "expired")
            return {"deleted" if yes else "would_delete": seed}

    def create(self, seed, *, name="", jobs=4):
        import uuid
        identifier(seed, 64)
        if type(jobs) is not int or not 1 <= jobs <= 4:
            raise StallionError("jobs must be between 1 and 4")
        if name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise StallionError("Name must be 1–64 letters, digits, dots, underscores or hyphens")
        with lock(self.root / "locks" / f"seed-{seed}", shared=True):
            base, seed_meta = self.object("seeds", seed)
            workspace = uuid.uuid4().hex
            final = self.root / "workspaces" / workspace
            with self._workspace_lock(workspace):
                with self.staging() as stage:
                    branch = f"stallionfs/{name + '-' if name else ''}{workspace}"
                    metadata = {"id": workspace, "seed": seed, "name": name, "branch": branch,
                                "commit": seed_meta["commit"], "created": time.time()}
                    if seed_meta.get("backend") == "image":
                        from . import images
                        images.clone(base / "workspace.sparseimage", stage / "workspace.sparseimage")
                        (stage / "volume").mkdir(mode=0o700)
                        metadata.update(backend="image", capacity_gib=seed_meta["capacity_gib"])
                    else:
                        clone_tree(base / "repo", stage / "repo", jobs=jobs)
                        git(stage / "repo", "checkout", "-b", branch)
                    write_json(stage / "meta.json", metadata)
                    stage.rename(final)
                self._open(workspace, final, metadata)
                return self._mount(final, metadata)

    def _mount(self, path, metadata):
        if metadata.get('backend') == 'native-image':
            raise StallionError('Mounted native image sessions are not supported by this command')
        repo = path / "repo"
        if metadata.get("backend") == "image":
            from . import images
            try:
                repo = images.attach(path / "workspace.sparseimage", path / "volume")
                ready = path / "ready.json"
                if ready.exists():
                    if read_json(ready).get("id") != metadata["id"]:
                        raise StallionError("Invalid image initialization marker")
                else:
                    if git(repo, "branch", "--show-current") != metadata["branch"]:
                        if git(repo, "rev-parse", "HEAD") != metadata["commit"]:
                            raise StallionError("Uninitialized image has an unexpected Git commit")
                        git(repo, "checkout", "-b", metadata["branch"])
                    write_json(ready, {"id": metadata["id"]})
            except (OSError, StallionError) as exc:
                raise StallionError(f"Workspace {metadata['id']} retained; retry with mount: {exc}") from exc
        return {**metadata, "path": str(repo)}

    def mount(self, workspace):
        identifier(workspace, 32)
        with self._workspace_lock(workspace):
            path, metadata = self.object("workspaces", workspace)
            self._open(workspace, path, metadata)
            return self._mount(path, metadata)

    def unmount(self, workspace):
        identifier(workspace, 32)
        with self._workspace_lock(workspace):
            path, metadata = self.object("workspaces", workspace)
            if metadata.get('backend') == 'native-image':
                raise StallionError('Mounted native image sessions are not supported by this command')
            if metadata.get("backend") != "image":
                raise StallionError("This workspace is an ordinary folder")
            self._open(workspace, path, metadata)
            from . import images
            images.detach(path / "workspace.sparseimage", path / "volume")
            return {"unmounted": workspace}

    def list(self, kind="workspaces"):
        if kind not in ("workspaces", "trash", "seeds"):
            raise StallionError("Invalid object collection")
        values = []
        for path in sorted((self.root / kind).iterdir()):
            try:
                _, meta = self.object(kind, path.name)
                target = path / "repo"
                if meta.get("backend") == "image":
                    target = path / ("workspace.sparseimage" if kind == "seeds" else "volume/repo")
                elif meta.get('backend') == 'native-image':
                    native = native_target(meta)
                    target = Path(native['directory']) / native['component']
                values.append({**meta, "path": str(target)})
            except FileNotFoundError:
                continue  # An object can be moved by another process while listing.
        return values

    def move(self, workspace, *, restore=False):
        identifier(workspace, 32)
        source, destination = ("trash", "workspaces") if restore else ("workspaces", "trash")
        with lock(self.root / ".lock"), self._workspace_lock(workspace):
            path, metadata = self.object(source, workspace)
            if metadata.get('backend') == 'native-image':
                raise StallionError('External native image registrations cannot be removed or retired')
            self._guard_native_tree(path)
            target = self.root / destination / workspace
            if target.exists() or target.is_symlink():
                raise StallionError("Destination already exists")
            if metadata.get("backend") == "image":
                from . import images
                images.detach(path / "workspace.sparseimage", path / "volume")
            self._open(workspace, path, metadata)
            path.rename(target)
            self._open(workspace, target, metadata)
            # Directory mtime records trash age without an extra metadata transaction.
            os.utime(target, None, follow_symlinks=False)
            if restore:
                return self._mount(target, metadata)
            return {**metadata, "path": str(target / ("workspace.sparseimage" if metadata.get("backend") == "image" else "repo"))}

    def gc(self, *, older_than=86400, yes=False, jobs=4):
        if type(jobs) is not int or not 1 <= jobs <= 4:
            raise StallionError("jobs must be between 1 and 4")
        if older_than < 0 or not float(older_than) < float("inf"):
            raise StallionError("Trash age must be finite and nonnegative")

        def collect(entry):
            identifier(entry.name, 32)
            with lock(self.root / ".lock"), self._workspace_lock(entry.name):
                if os.path.lexists(self.root / "protected" / f"{entry.name}.json"):
                    return None
                if not entry.exists() and not entry.is_symlink():
                    return None
                path, metadata = self.object("trash", entry.name)
                if time.time() - path.stat().st_mtime < older_than:
                    return None
                self._guard_native_tree(path)
                if yes:
                    if metadata.get("backend") == "image":
                        from . import images
                        if images.mounted(path / "workspace.sparseimage") is not None:
                            raise StallionError("Trashed image is still attached; detach it before collection")
                    # Keep partial deletion out of the restorable trash collection.
                    with self.staging() as stage:
                        expired = stage / "expired"
                        path.rename(expired)
                        remove_tree(expired, jobs=tree_jobs)
                        stage.rmdir()
                return entry.name

        entries = list((self.root / "trash").iterdir())
        tree_jobs = max(1, jobs // max(1, len(entries)))
        if not yes or len(entries) < 2:
            return [value for value in map(collect, entries) if value is not None]
        from concurrent.futures import ThreadPoolExecutor
        # Share the worker budget across trees instead of multiplying it per tree.
        with ThreadPoolExecutor(max_workers=min(jobs, len(entries))) as pool:
            return [value for value in pool.map(collect, entries) if value is not None]

    def doctor(self):
        import platform
        with self.staging() as stage:
            source = stage / "source"
            source.mkdir()
            (source / "probe").write_bytes(b"stallionfs\n")
            clone_tree(source, stage / "clone")
            (stage / "clone" / "probe").write_bytes(b"changed\n")
            if (source / "probe").read_bytes() != b"stallionfs\n":
                raise StallionError("Copy-on-write isolation check failed")
        return {"backend": "apfs-clonefile", "isolation": "passed", "root": str(self.root),
                "git": run(["git", "--version"]), "python": platform.python_version(),
                "staging_entries": [p.name for p in (self.root / "staging").iterdir()]}
