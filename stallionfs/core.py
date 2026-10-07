"""No daemon, database, shell evaluation, shared Git index, or hard-linked files."""

from __future__ import annotations

import contextlib
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid


class StallionError(Exception):
    """An actionable user or filesystem error."""


def run(args, cwd=None, *, capture=True):
    # Inherited Git routing variables must never redirect an operation elsewhere.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_TERMINAL_PROMPT"] = "0"
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
    with path.open("x", encoding="utf-8") as stream:
        json.dump({"format": 1, **value}, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())


def private_directory(path):
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise StallionError(f"Storage must be an owned, real directory with mode 0700: {path}")


@contextlib.contextmanager
def lock(path, *, shared=False):
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
            raise StallionError(f"Unsafe lock file: {path}")
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def clone_tree(source, destination):
    """Native recursive copyfile, accepting only successful copy-on-write clones."""
    if sys.platform != "darwin":
        raise StallionError("stallionfs requires macOS and an APFS volume")
    lib = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    lib.copyfile_state_alloc.restype = ctypes.c_void_p
    lib.copyfile_state_set.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    lib.copyfile_state_get.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
    lib.copyfile_state_free.argtypes = [ctypes.c_void_p]
    lib.copyfile.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                    ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p,
                                    ctypes.c_void_p, use_errno=True)
    failure = []

    @callback_type
    def check_clone(what, stage, state, src, dst, context):
        if stage == 3:  # COPYFILE_ERR: abort rather than skipping an entry.
            failure.append((ctypes.get_errno() or errno.EIO, os.fsdecode(src)))
            return 2  # COPYFILE_QUIT
        if what == 1 and stage == 2:  # COPYFILE_RECURSE_FILE / COPYFILE_FINISH
            cloned = ctypes.c_bool()
            if lib.copyfile_state_get(state, 10, ctypes.byref(cloned)) or not cloned.value:
                failure.append((errno.ENOTSUP, os.fsdecode(src)))
                return 2
        return 0

    state = lib.copyfile_state_alloc()
    if not state:
        raise OSError(errno.ENOMEM, "Unable to allocate native copy state")
    try:
        no_cross_mount = ctypes.c_bool(True)
        for option, value in ((6, check_clone), (14, ctypes.byref(no_cross_mount))):
            if lib.copyfile_state_set(state, option, value):
                number = ctypes.get_errno()
                raise OSError(number, os.strerror(number))
        # COPYFILE_RECURSIVE | COPYFILE_CLONE | COPYFILE_NOFOLLOW_DST.
        # COPYFILE_CLONE alone allows fallback; the callback rejects it before publication.
        result = lib.copyfile(os.fsencode(source), os.fsencode(destination), state,
                              (1 << 15) | (1 << 24) | (1 << 19))
        if result or failure:
            number, path = failure[0] if failure else (ctypes.get_errno() or errno.EIO, str(source))
            raise OSError(number, os.strerror(number), path)
    finally:
        lib.copyfile_state_free(state)


def validate_tree(root):
    """Only regular files, directories, and relocatable internal symlinks are supported."""
    device = root.stat().st_dev
    for parent, dirs, files in os.walk(root, followlinks=False):
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


class Store:
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
            for name in ("seeds", "workspaces", "trash", "staging", "locks"):
                child = self.root / name
                child.mkdir(mode=0o700, exist_ok=True)
                private_directory(child)

    @contextlib.contextmanager
    def staging(self):
        path = Path(tempfile.mkdtemp(prefix="build-", dir=self.root / "staging"))
        try:
            yield path
        finally:
            if path.exists():
                shutil.rmtree(path)

    def object(self, kind, value):
        identifier(value, 64 if kind == "seeds" else 32)
        path = self.root / kind / value
        private_directory(path)
        metadata = read_json(path / "meta.json")
        if metadata.get("id") != value:
            raise StallionError(f"Metadata ID mismatch: {path}")
        if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(metadata.get("commit", ""))):
            raise StallionError(f"Invalid commit in metadata: {path}")
        if (path / "repo").is_symlink() or not (path / "repo").is_dir():
            raise StallionError(f"Missing or unsafe repository: {path}")
        return path, metadata

    def prepare(self, source, *, ref="HEAD", key, command=()):
        if sys.platform != "darwin":
            raise StallionError("stallionfs requires macOS and an APFS volume")
        source = Path(source).expanduser().resolve(strict=True)
        if not key.strip():
            raise StallionError("Supply a cache key describing the toolchain (for example node22-npm10-v1)")
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
                metadata = {"id": seed, **spec, "created": time.time()}
                write_json(stage / "meta.json", metadata)
                # Publish only a fully prepared tree; a failed command never becomes a cache hit.
                stage.rename(final)
                return {**metadata, "cached": False}

    def forget(self, seed, *, yes=False):
        identifier(seed, 64)
        with lock(self.root / "locks" / f"seed-{seed}"):
            path, _ = self.object("seeds", seed)
            if yes:
                # Existing workspaces own their Git objects and retain their cloned blocks.
                with self.staging() as stage:
                    path.rename(stage / "expired")
            return {"deleted" if yes else "would_delete": seed}

    def create(self, seed, *, name=""):
        identifier(seed, 64)
        if name and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name):
            raise StallionError("Name must be 1–64 letters, digits, dots, underscores or hyphens")
        with lock(self.root / "locks" / f"seed-{seed}", shared=True):
            base, seed_meta = self.object("seeds", seed)
            workspace = uuid.uuid4().hex
            final = self.root / "workspaces" / workspace
            with self.staging() as stage:
                clone_tree(base / "repo", stage / "repo")
                branch = f"stallionfs/{name + '-' if name else ''}{workspace}"
                git(stage / "repo", "checkout", "-b", branch)
                metadata = {"id": workspace, "seed": seed, "name": name, "branch": branch,
                            "commit": seed_meta["commit"], "created": time.time()}
                write_json(stage / "meta.json", metadata)
                stage.rename(final)
                return {**metadata, "path": str(final / "repo")}

    def list(self, kind="workspaces"):
        if kind not in ("workspaces", "trash", "seeds"):
            raise StallionError("Invalid object collection")
        values = []
        for path in sorted((self.root / kind).iterdir()):
            try:
                _, meta = self.object(kind, path.name)
                values.append({**meta, "path": str(path / "repo")})
            except FileNotFoundError:
                continue  # An object can be moved by another process while listing.
        return values

    def move(self, workspace, *, restore=False):
        identifier(workspace, 32)
        source, destination = ("trash", "workspaces") if restore else ("workspaces", "trash")
        with lock(self.root / "locks" / f"workspace-{workspace}"):
            path, metadata = self.object(source, workspace)
            target = self.root / destination / workspace
            if target.exists() or target.is_symlink():
                raise StallionError("Destination already exists")
            path.rename(target)
            # Directory mtime records trash age without an extra metadata transaction.
            os.utime(target, None, follow_symlinks=False)
            return {**metadata, "path": str(target / "repo")}

    def gc(self, *, older_than=86400, yes=False):
        if older_than < 0 or not float(older_than) < float("inf"):
            raise StallionError("Trash age must be finite and nonnegative")
        removed = []
        for entry in (self.root / "trash").iterdir():
            identifier(entry.name, 32)
            with lock(self.root / "locks" / f"workspace-{entry.name}"):
                if not entry.exists():
                    continue
                path, _ = self.object("trash", entry.name)
                if time.time() - path.stat().st_mtime < older_than:
                    continue
                if yes:
                    # Only an owned, validated object in trash is ever recursively deleted.
                    shutil.rmtree(path)
                removed.append(entry.name)
        return removed

    def doctor(self):
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
