"""Enforce one verified Git cache return during an owned wheel build."""
import hashlib
import json
import os
from pathlib import Path
import sys


class CacheOnlyGuard:
    def __init__(self, destination, manifest_sha256, temporary, identity_check):
        self.destination = Path(destination).absolute()
        self.temporary = Path(temporary).absolute()
        self.manifest_sha256 = manifest_sha256
        self.identity_check = identity_check
        self.active = False
        self.calls = 0
        self.observations = []
        self.effects = []
        self.wrapped = set()

    def audit(self, event, args):
        if not self.active:
            return
        forbidden = event in {
            'subprocess.Popen', 'os.system', 'os.posix_spawn', 'os.fork',
            'os.exec', 'socket.__new__', 'socket.connect', 'socket.bind',
            'os.mkdir', 'os.remove', 'os.rmdir', 'os.rename', 'os.link',
            'os.symlink', 'os.chmod', 'os.chown', 'os.truncate', 'os.utime',
        } or event.startswith(('urllib.', 'http.client.'))
        if event == 'open':
            _, mode, flags = args
            forbidden = (isinstance(mode, str) and any(c in mode for c in 'wax+'))
            forbidden = forbidden or bool(flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND))
        if forbidden:
            self.effects.append(event)
            raise RuntimeError('Git cache-only boundary refused: ' + event)

    def wrap(self, builder):
        if id(builder) in self.wrapped:
            raise RuntimeError('Builder module was wrapped twice')
        original = builder.build
        self.wrapped.add(id(builder))

        def cache_only(destination, temporary, **options):
            self.calls += 1
            if self.calls != 1:
                raise RuntimeError('One cache consumption attempt permitted')
            if (Path(destination).absolute() != self.destination
                    or Path(temporary).absolute() != self.temporary or options):
                raise RuntimeError('Unexpected Git cache destination or inputs')
            if os.path.lexists(self.temporary):
                raise RuntimeError('Git build root already exists')
            self.identity_check()
            path = self.destination / 'manifest.json'
            before = path.read_bytes()
            if hashlib.sha256(before).hexdigest() != self.manifest_sha256:
                raise RuntimeError('Frozen Git manifest differs')
            self.active = True
            try:
                result = original(destination, temporary)
            finally:
                self.active = False
            if self.effects or os.path.lexists(self.temporary):
                raise RuntimeError('Git cache-return boundary was not preserved')
            if result != json.loads(before) or path.read_bytes() != before:
                raise RuntimeError('Git cache-return manifest differs')
            self.identity_check()
            self.observations.append({'cache_return': True, 'calls': self.calls})
            return result

        builder.build = cache_only

    def install_audit(self):
        sys.addaudithook(self.audit)

    def require_complete(self):
        if self.active or self.effects or self.calls != 1 or len(self.observations) != 1:
            raise RuntimeError('Cache consumption was not proved')
