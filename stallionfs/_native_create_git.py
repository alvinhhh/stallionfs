"""Finite, receipted Git operations over a private prepared clone.

This boundary is conditional on the qualified runtime, exact commands and
admitted repository layout. It is not a sandbox for arbitrary Git programs.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import stat

from . import core, _native
from ._native_create_recovery import require, pair

INPUT_CAP = 1024 * 1024
OUTPUT_CAP = 2 * 1024 * 1024
ENTRY_CAP = 4096
TREE_CAP = 262144
POLICY = 'native-git-empty-environment-v3'
PSEUDO = {'MERGE_HEAD', 'AUTO_MERGE', 'MERGE_AUTOSTASH', 'CHECKOUT_AUTOSTASH_HEAD',
          'CHERRY_PICK_HEAD', 'REVERT_HEAD', 'REBASE_HEAD', 'BISECT_HEAD', 'BISECT_EXPECTED_REV'}
TRANSIENT = PSEUDO | {'MERGE_RR', 'MERGE_MSG', 'MERGE_MODE', 'SQUASH_MSG', 'sequencer', 'rebase-merge',
    'rebase-apply', 'BISECT_LOG', 'BISECT_NAMES', 'BISECT_START', 'BISECT_ANCESTORS_OK', 'BISECT_RUN',
    'BISECT_TERMS', 'BISECT_FIRST_PARENT', 'BISECT_RESET_WHEN_FOUND'}
UNSUPPORTED = {'commondir', 'gitdir', 'worktrees', 'modules', 'config.worktree', 'shallow',
               'objects/info/alternates', 'objects/info/http-alternates', 'info/grafts'}
FIXED = ('core.hooksPath=/dev/null', 'core.fsmonitor=false', 'maintenance.auto=false',
         'maintenance.autoDetach=false', 'gc.auto=0', 'gc.autoDetach=false', 'branch.autoSetupMerge=false',
         'branch.autoSetupRebase=never', 'hook.post-checkout.enabled=false', 'hook.reference-transaction.enabled=false')
PREFIX = ['--no-pager', '--no-lazy-fetch', '--no-replace-objects', *[part for setting in FIXED for part in ('-c', setting)]]


def read_at(parent, name, cap):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.getuid()
                and before.st_size <= cap, 'unsafe-git-file')
        data = bytearray()
        while len(data) <= cap:
            block = os.read(fd, min(65536, cap + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(len(data) <= cap and (pair(before), before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (pair(after), after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'git-file-changed')
        return bytes(data), {'file': pair(before), 'sha256': hashlib.sha256(data).hexdigest()}
    finally:
        os.close(fd)


def structure(repo, *, branch=None):
    """No-follow structure admission. Detached inputs and resulting HEAD differ."""
    repo = Path(repo)
    require(repo.resolve() == repo, 'aliased-repository')
    root = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    gitdir = None
    try:
        gitdir = os.open('.git', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        device, count = os.fstat(gitdir).st_dev, [0]
        def walk(fd, prefix=''):
            with os.scandir(fd) as entries:
                for entry in entries:
                    count[0] += 1
                    require(count[0] <= TREE_CAP, 'git-entry-budget')
                    name = prefix + entry.name
                    info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                    require(info.st_uid == os.getuid() and info.st_dev == device, 'unsafe-git-owner')
                    require(not entry.name.endswith('.lock') and not entry.name.endswith('.promisor'), 'git-active-state')
                    require(name not in UNSUPPORTED and name.split('/')[0] not in TRANSIENT
                            and not name.startswith('refs/bisect/'), 'git-transient-state')
                    if stat.S_ISDIR(info.st_mode):
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                        try:
                            require(pair(os.fstat(child)) == pair(info), 'git-directory-changed')
                            walk(child, name + '/')
                        finally:
                            os.close(child)
                    elif name == 'HEAD' and branch is not None and stat.S_ISLNK(info.st_mode):
                        target = os.readlink(entry.name, dir_fd=fd)
                        require(target.startswith('refs/heads/') and '..' not in target and not target.endswith('/')
                                and (branch is True or target == 'refs/heads/' + branch), 'unsafe-head-link')
                    else:
                        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe-git-entry')
                    require(pair(os.stat(entry.name, dir_fd=fd, follow_symlinks=False)) == pair(info), 'git-entry-changed')
        walk(gitdir)
        data, config_identity = read_at(gitdir, 'config', INPUT_CAP)
        if 'reftable' in os.listdir(gitdir):
            table = os.open('reftable', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=gitdir)
            try:
                listing, _ = read_at(table, 'tables.list', INPUT_CAP)
                names = listing.decode().splitlines()
                require((not listing or listing.endswith(b'\n')) and len(names) <= ENTRY_CAP
                        and len(set(names)) == len(names), 'invalid-reftable-list')
                for name in names:
                    require(re.fullmatch(r'0x[0-9a-f]{12,16}-0x[0-9a-f]{12,16}-[0-9a-f]{8}\.ref', name), 'reftable-path')
                    info = os.stat(name, dir_fd=table, follow_symlinks=False)
                    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, 'unsafe-reftable')
            finally:
                os.close(table)
        return {'repository': pair(os.fstat(root)), 'git': pair(os.fstat(gitdir)), 'config': config_identity}
    finally:
        if gitdir is not None:
            os.close(gitdir)
        os.close(root)


def parse_config(data):
    require(not data or data.endswith(b'\0'), 'truncated-config')
    result = []
    for record in data.split(b'\0'):
        if not record:
            continue
        key, sep, value = record.partition(b'\n')
        require(len(result) < ENTRY_CAP and 0 < len(key) <= 4096 and len(value) <= 65536, 'config-budget')
        result.append((key.decode().lower(), value.decode() if sep else None))
    return result


def bindings(repo):
    """Recheck actor routing/config without repeating a whole .git traversal.

    The full structure was admitted before the inspector. Until checkout, the
    serialized qualified actors are read-only; no other managed writer runs.
    """
    root = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        directory = os.open('.git', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=root)
        try:
            _, config = read_at(directory, 'config', INPUT_CAP)
            return {'repository': pair(os.fstat(root)), 'git': pair(os.fstat(directory)), 'config': config}
        finally:
            os.close(directory)
    finally:
        os.close(root)


def config_gate(entries):
    exact = {'core.repositoryformatversion', 'core.bare', 'core.filemode', 'core.logallrefupdates',
        'core.ignorecase', 'core.precomposeunicode', 'core.hookspath', 'core.fsmonitor', 'core.autocrlf',
        'core.safecrlf', 'core.eol', 'core.symlinks', 'core.trustctime', 'core.checkstat', 'core.quotepath',
        'core.ignorestat', 'core.fsync', 'core.fsyncmethod', 'core.fsyncobjectfiles', 'core.sharedrepository',
        'core.prefersymlinkrefs', 'core.abbrev', 'core.compression', 'core.loosecompression', 'core.packedgitlimit',
        'core.packedgitwindowsize', 'core.bigfilethreshold', 'core.packedgitmmap', 'core.deltabasecachelimit',
        'core.untrackedcache', 'core.sparsecheckout', 'core.sparsecheckoutcone', 'core.splitindex',
        'extensions.objectformat', 'extensions.refstorage'}
    families = ('user.', 'author.', 'committer.', 'hook.', 'filter.', 'diff.', 'merge.', 'branch.', 'remote.',
        'push.', 'pull.', 'fetch.', 'credential.', 'url.', 'http.', 'https.', 'advice.', 'color.', 'i18n.',
        'maintenance.', 'gc.', 'reftable.', 'pack.')
    for key, value in entries:
        require(key in exact or key.startswith(families), 'unqualified-git-config')
    config = dict(entries)
    require(config.get('core.bare', 'false') in ('false', 'no', '0', 'off')
            and config.get('extensions.objectformat', 'sha1') in ('sha1', 'sha256')
            and config.get('extensions.refstorage', 'files') in ('files', 'reftable')
            and config.get('core.repositoryformatversion') in ('0', '1'), 'unsupported-git-format')
    return config


def environment(directory, runtime):
    return {'PATH': str(Path(runtime['executable']).parent) + ':/usr/bin:/bin',
        'HOME': str(directory / 'home'), 'XDG_CONFIG_HOME': str(directory / 'xdg'),
        'TMPDIR': str(directory / 'tmp'), 'GIT_EXEC_PATH': runtime['exec_path'],
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': str(directory / 'empty-config'),
        'GIT_CONFIG_GLOBAL': str(directory / 'empty-config'), 'GIT_TERMINAL_PROMPT': '0',
        'GIT_ATTR_NOSYSTEM': '1', 'LC_ALL': 'C', 'LANG': 'C', 'TZ': 'UTC',
        'GIT_ALLOW_PROTOCOL': '', 'GIT_PROTOCOL_FROM_USER': '0',
        'GIT_CEILING_DIRECTORIES': str(directory)}


def checkout(repo, commit, branch, stage, record, persist, runtime):
    """Exactly five roles; durable pending receipts precede every launch."""
    admitted = structure(repo)
    actors = stage / 'actors'
    actors.mkdir(mode=0o700)
    directory = actors / 'environment'
    directory.mkdir(mode=0o700)
    for name in ('home', 'xdg', 'tmp', 'inspect'):
        (directory / name).mkdir(mode=0o700)
    fd = os.open(directory / 'empty-config', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    core.sync_directory(directory)
    core.sync_directory(actors)
    core.sync_directory(stage)
    env = environment(directory, runtime)
    record['actors'] = []
    persist()
    def actor(role, args, *, code=0):
        if 'check' in runtime:
            runtime['check']()
        current = bindings(repo)
        require(current == admitted, 'git-input-changed')
        log = actors / role
        log.mkdir(mode=0o700)
        core.sync_directory(actors)
        receipt = {'role': role, 'cwd': str(directory / 'inspect'), 'environment': POLICY,
                   'runtime': runtime['contract'], 'input': admitted,
                   'executable': {'path': runtime['executable'],
                                  'sha256': runtime['contract']['executable_sha256']}}
        record['actors'].append(receipt)
        result = _native.execute_owned([runtime['executable'], *PREFIX, *args], receipt, persist, log,
                                      cwd=directory / 'inspect', env=env, output_limit=OUTPUT_CAP)
        require(result['returncode'] == code and result.get('streams_durable') is True
                and result.get('streams_eof') is True and result.get('reaped') is True, 'git-actor-failed')
        return (log / 'stdout').read_bytes()
    entries = parse_config(actor('00-config', ['config', '--file', str(repo / '.git/config'), '--no-includes', '--null', '--list']))
    config = config_gate(entries)
    for field in ('NAME', 'EMAIL'):
        key = field.lower()
        env['GIT_COMMITTER_' + field] = config.get('committer.' + key, config.get('user.' + key,
                                                  'StallionFS' if field == 'NAME' else 'stallionfs@localhost'))
    prefix = ['--git-dir=' + str(repo / '.git'), '--work-tree=' + str(repo)]
    refs = actor('01-refs', [*prefix, 'for-each-ref', '--include-root-refs', '--format=%(refname)']).decode().splitlines()
    require(not any(name in PSEUDO or name.startswith('refs/bisect/') for name in refs), 'git-transient-ref')
    target = 'refs/heads/' + branch
    require(not any(name == target or name.startswith(target + '/') or target.startswith(name + '/') for name in refs), 'branch-conflict')
    require(actor('02-head', [*prefix, 'rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}']).decode().strip() == commit, 'head-pin')
    actor('03-head-state', [*prefix, 'symbolic-ref', '--quiet', 'HEAD'], code=1)
    actor('04-checkout', [*prefix, 'checkout', '-b', branch])
    # core.preferSymlinkRefs intentionally changes HEAD to a contained symlink.
    after = structure(repo, branch=branch)
    require(after == admitted, 'git-config-changed')


def _inspect(repo, *, branch=None, structure_required=True, references=False, runtime=None):
    """Read a standalone repository's config as data, with no ambient startup."""
    import tempfile
    from . import _bundle
    admit = (lambda: structure(repo, branch=branch)) if structure_required else (lambda: bindings(repo))
    admitted = admit()
    if runtime is None:
        runtime = _bundle.product_git()
    executable = runtime['executable']
    with tempfile.TemporaryDirectory(prefix='sfs-git-inspect-') as temporary:
        directory = Path(temporary).resolve()
        for name in ('home', 'xdg', 'tmp', 'inspect'):
            (directory / name).mkdir(mode=0o700)
        (directory / 'empty-config').touch(mode=0o600)
        env = environment(directory, runtime)
        env.update(GIT_TRACE2='0', GIT_TRACE2_EVENT='0', GIT_TRACE2_PERF='0')
        def query(log, args):
            runtime['check']()
            receipt = {}
            _native.execute_owned([executable, *PREFIX, *args], receipt, lambda: None, log,
                                  cwd=directory / 'inspect', env=env, output_limit=OUTPUT_CAP)
            require(receipt.get('returncode') == 0 and receipt.get('outcome') == 'success'
                    and receipt.get('child_pending') is False and type(receipt.get('pid')) is int and receipt['pid'] > 0
                    and type(receipt.get('output_bytes')) is int and 0 <= receipt['output_bytes'] <= OUTPUT_CAP
                    and all(receipt.get(key) is True
                    for key in ('reaped', 'streams_eof', 'streams_durable'))
                    and not any(key in receipt for key in ('collector_error', 'stream_close_errors', 'receipt_error',
                                                          'interrupted', 'stop_errors')), 'config-inspector-failed')
            return (log / 'stdout').read_bytes()
        config = {}
        for name in ('config', 'config.worktree'):
            path = repo / '.git' / name
            if name != 'config' and not os.path.lexists(path):
                continue
            fd = os.open(repo / '.git', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                _, before = read_at(fd, name, INPUT_CAP)
                log = directory / name; log.mkdir(mode=0o700)
                values = dict(parse_config(query(log, ['config', '--file', str(path),
                    '--no-includes', '--null', '--list'])))
                require('core.worktree' not in values, 'Preparation set core.worktree; cloned Git directories must be relocatable')
                require(not any(key == 'include.path' or key.startswith('includeif.') for key in values),
                        'Workspace Git configuration contains external worktree or include references')
                require(read_at(fd, name, INPUT_CAP)[1] == before, 'git-config-changed')
                if name == 'config': config = values
            finally:
                os.close(fd)
        refs = []
        if references:
            require(bindings(repo) == admitted, 'git-input-changed')
            log = directory / 'refs'; log.mkdir(mode=0o700)
            data = query(log, ['--git-dir=' + str(repo / '.git'), '--work-tree=' + str(repo),
                'for-each-ref', '--include-root-refs', '--format=%(refname)'])
            require(not data or data.endswith(b'\n'), 'truncated-refs')
            refs = data.decode().splitlines()
            require(len(refs) <= TREE_CAP, 'git-entry-budget')
    require(admit() == admitted, 'git-input-changed')
    return config, refs


def inspect_standalone(repo, *, branch=None, structure_required=True, runtime=None):
    return _inspect(repo, branch=branch, structure_required=structure_required, runtime=runtime)[0]


def inspect_refs(repo):
    return _inspect(repo, references=True)[1]


def qualified_runtime(native_host=None):
    """Static companion admission; the producer separately receipts signature verification."""
    from . import _bundle
    bundle = _bundle.from_host(native_host or _native.HOST)
    metadata = bundle['metadata']
    value = metadata.get('git')
    require(metadata['schema'] == 2 and type(value) is dict
            and set(value) == set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256', 'payload_entries', 'payload_sha256'}
            and all(value.get(key) == expected for key, expected in _bundle.GIT_CONTRACT.items())
            and type(value['payload_entries']) is int and 0 < value['payload_entries'] <= 4096
            and re.fullmatch('[0-9a-f]{64}', str(value['payload_sha256'])), 'unqualified-git-runtime')
    _bundle.git_contract({key: value[key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}})
    root = bundle['git'].parent.parent
    payload = _bundle.git_payload(root)
    require(payload['entries'] == value['payload_entries'] and payload['sha256'] == value['payload_sha256'], 'git-payload-mismatch')
    descriptor = bundle['app'] / _bundle.DESCRIPTOR
    descriptor_bytes = _bundle._file(descriptor, read=True)
    import json
    require(json.loads(descriptor_bytes) == metadata, 'runtime-descriptor-changed')
    contract = {**value, 'descriptor_sha256': hashlib.sha256(descriptor_bytes).hexdigest(),
                'executable_sha256': payload['executable_sha256'], 'source_build_id': metadata['source_build_id'],
                'publisher': _bundle.PUBLISHER_TEAM}
    descriptor_identity = _bundle._identity(descriptor.lstat())
    def check():
        fd = _bundle._directory(root)
        try:
            require(_bundle._identity(os.fstat(fd)) == payload['root_identity'], 'runtime-substitution')
        finally:
            os.close(fd)
        require(_bundle._identity(descriptor.lstat()) == descriptor_identity, 'runtime-substitution')
        for relative, expected in payload['identities'].items():
            require(_bundle._identity((root / relative).lstat()) == expected, 'runtime-substitution')
    check()
    return {'executable': str(bundle['git']), 'exec_path': str(bundle['git_exec_path']), 'contract': contract, 'check': check}


def readiness(repo, metadata):
    """Qualified bounded read-only queries for an already installed workspace."""
    import tempfile
    runtime = qualified_runtime(metadata.get('native_host'))
    admitted = structure(repo, branch=True)
    with tempfile.TemporaryDirectory(prefix='sfs-native-readiness-') as temporary:
        directory = Path(temporary).resolve()
        for name in ('home', 'xdg', 'tmp', 'inspect'):
            (directory / name).mkdir(mode=0o700)
        (directory / 'empty-config').touch(mode=0o600)
        env = environment(directory, runtime)
        def query(name, args):
            runtime['check']()
            log = directory / name; log.mkdir(mode=0o700)
            receipt = {}
            _native.execute_owned([runtime['executable'], *PREFIX, *args], receipt, lambda: None, log,
                cwd=directory / 'inspect', env=env, output_limit=OUTPUT_CAP)
            require(receipt['returncode'] == 0 and receipt.get('streams_durable') is True, 'git-readiness-query')
            return (log / 'stdout').read_bytes()
        config_gate(parse_config(query('config', ['config', '--file', str(repo / '.git/config'), '--no-includes', '--null', '--list'])))
        prefix = ['--git-dir=' + str(repo / '.git'), '--work-tree=' + str(repo)]
        commit = query('head', [*prefix, 'rev-parse', '--verify', '--end-of-options', 'HEAD^{commit}']).decode().strip()
        branch = query('branch', [*prefix, 'symbolic-ref', '--quiet', 'HEAD']).decode().strip().removeprefix('refs/heads/')
        require(structure(repo, branch=True) == admitted, 'git-input-changed')
        return commit, branch
