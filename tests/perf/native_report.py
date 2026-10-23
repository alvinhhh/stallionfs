"""Append-only benchmark evidence with an atomic committed-prefix manifest."""
from array import array
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile

import fileops

KINDS = ('rows', 'preparation', 'metadata_preparation', 'comparisons', 'unavailable')
ENCODER = json.JSONEncoder(ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(',', ':'))
MAX_MANIFEST_BYTES = 16 * 1024 * 1024


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _identity(info):
    return info.st_dev, info.st_ino


def _object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, 'Duplicate journal JSON key')
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError('Nonfinite journal JSON value: ' + value)


def _load(raw):
    return json.loads(raw, object_pairs_hook=_object, parse_constant=_invalid_constant)


class ReportJournal:
    """One writer; read-only reopen never resumes or truncates an incomplete run.

    Offsets occupy eight bytes per distinct ID. Historical payloads live only on
    disk. An event and the active validation snapshot may still be large.
    """
    def __init__(self, output):
        self._initialize(output)
        for path in (self.output, self.journal_path, self.manifest_path):
            _require(not os.path.lexists(path), 'Report output already exists')
        fd = os.open(self.journal_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self._stream = os.fdopen(fd, 'w+b', buffering=65536)
        self._journal_identity = _identity(os.fstat(fd))
        self._readonly = False
        self._digest = hashlib.sha256()
        self._bytes = self._events = 0
        self._manifest_identity = None
        self._manifest = None
        try:
            self.checkpoint({})
        except BaseException:
            self.close()
            raise

    def _initialize(self, output):
        self.output = Path(output).absolute()
        self.journal_path = self.output.with_name(self.output.name + '.journal')
        self.manifest_path = self.output.with_name(self.output.name + '.manifest')
        self._offsets = {kind: array('Q') for kind in KINDS}
        self._stream = None
        self._poisoned = False
        self._finished = False

    def _owned(self):
        _require(self._stream is not None and not self._stream.closed, 'Journal is closed')
        info = self.journal_path.lstat()
        _require(stat.S_ISREG(info.st_mode) and _identity(info) == self._journal_identity
                 and _identity(os.fstat(self._stream.fileno())) == self._journal_identity,
                 'Journal path changed')
        if self._manifest_identity is not None:
            info = self.manifest_path.lstat()
            _require(stat.S_ISREG(info.st_mode) and _identity(info) == self._manifest_identity,
                     'Manifest path changed')

    def _writable(self):
        _require(not self._readonly and not self._finished and not self._poisoned,
                 'Journal is read-only, finished or has an uncommitted failure')
        self._owned()

    def append(self, kind, id, payload):
        self._writable()
        _require(kind in KINDS and type(id) is int and 0 <= id <= len(self._offsets[kind]),
                 'Invalid journal kind or noncontiguous ID')
        _require(isinstance(payload, dict), 'Journal payload must be an object')
        self._stream.seek(0, os.SEEK_END)
        _require(self._stream.tell() == self._bytes, 'Journal length changed')
        start, digest, count = self._bytes, self._digest.copy(), 0
        event = {'sequence': self._events, 'kind': kind, 'id': id, 'payload': payload}
        try:
            for piece in ENCODER.iterencode(event):
                raw = piece.encode('utf-8')
                self._stream.write(raw); digest.update(raw); count += len(raw)
            self._stream.write(b'\n'); digest.update(b'\n'); count += 1
        except BaseException:
            self._poisoned = True
            raise
        offsets = self._offsets[kind]
        if id == len(offsets): offsets.append(start)
        else: offsets[id] = start
        self._bytes += count; self._events += 1; self._digest = digest

    def checkpoint(self, state):
        self._writable()
        _require(isinstance(state, dict) and not set(state).intersection(KINDS),
                 'Checkpoint state must exclude journal-owned arrays')
        # Freeze the small base state rather than retaining caller-owned objects.
        state = _load(ENCODER.encode(state))
        try:
            manifest = {'storage_schema': 1, 'journal': self.journal_path.name,
                        'committed_bytes': self._bytes, 'event_count': self._events,
                        'prefix_sha256': self._digest.hexdigest(), 'state': state}
            # Match fileops.write_json's indented, sorted UTF-8 JSON and newline.
            encoded_bytes = 1
            manifest_digest = hashlib.sha256()
            for piece in json.JSONEncoder(indent=2, sort_keys=True).iterencode(manifest):
                raw = piece.encode('utf-8')
                encoded_bytes += len(raw)
                manifest_digest.update(raw)
                _require(encoded_bytes <= MAX_MANIFEST_BYTES, 'Oversized journal manifest')
            manifest_digest.update(b'\n')
            self._stream.flush()
            _require(os.fstat(self._stream.fileno()).st_size == self._bytes, 'Journal length changed')
            os.fsync(self._stream.fileno())
            identity = fileops.write_json(self.manifest_path, manifest, self._manifest_identity)
        except BaseException:
            self._poisoned = True
            raise
        self._manifest_identity, self._manifest = identity, manifest
        self._manifest_sha256 = manifest_digest.hexdigest()

    @classmethod
    def open_existing(cls, output):
        self = cls.__new__(cls)
        self._initialize(output)
        self._readonly = True
        fd = os.open(self.manifest_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            _require(stat.S_ISREG(info.st_mode), 'Manifest must be a regular file')
            self._manifest_identity = _identity(info)
            with os.fdopen(fd, 'rb') as stream:
                fd = -1
                raw = stream.read(MAX_MANIFEST_BYTES + 1)
                _require(len(raw) <= MAX_MANIFEST_BYTES, 'Oversized journal manifest')
                self._manifest = _load(raw)
                self._manifest_sha256 = hashlib.sha256(raw).hexdigest()
        finally:
            if fd >= 0: os.close(fd)
        manifest = self._manifest
        _require(isinstance(manifest, dict) and set(manifest) == {'storage_schema', 'journal', 'committed_bytes',
                 'event_count', 'prefix_sha256', 'state'} and type(manifest['storage_schema']) is int
                 and manifest['storage_schema'] == 1 and manifest['journal'] == self.journal_path.name,
                 'Unknown journal manifest schema')
        _require(type(manifest['committed_bytes']) is int and manifest['committed_bytes'] >= 0
                 and type(manifest['event_count']) is int and manifest['event_count'] >= 0
                 and isinstance(manifest['prefix_sha256'], str) and len(manifest['prefix_sha256']) == 64
                 and isinstance(manifest['state'], dict) and not set(manifest['state']).intersection(KINDS),
                 'Invalid journal manifest')
        fd = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        self._stream = os.fdopen(fd, 'rb')
        self._journal_identity = _identity(os.fstat(fd))
        try:
            self._verify(rebuild=True)
        except BaseException:
            self.close()
            raise
        return self

    @property
    def state(self):
        return _load(ENCODER.encode(self._manifest['state']))

    @property
    def provenance(self):
        return {'original_manifest_sha256': self._manifest_sha256,
                'committed_prefix_sha256': self._manifest['prefix_sha256'],
                'committed_bytes': self._manifest['committed_bytes'],
                'event_count': self._manifest['event_count']}

    def verify(self):
        self._verify()

    def _verify(self, rebuild=False):
        self._owned()
        fd = os.open(self.manifest_path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as stream:
            info = os.fstat(stream.fileno())
            _require(stat.S_ISREG(info.st_mode) and _identity(info) == self._manifest_identity,
                     'Manifest path changed')
            raw = stream.read(MAX_MANIFEST_BYTES + 1)
            _require(len(raw) <= MAX_MANIFEST_BYTES, 'Oversized journal manifest')
            _require(hashlib.sha256(raw).hexdigest() == self._manifest_sha256,
                     'Manifest content changed')
        committed = self._manifest['committed_bytes']
        if not self._readonly: self._stream.flush()
        _require(os.fstat(self._stream.fileno()).st_size == committed,
                 'Journal has a torn, missing or uncommitted tail; evidence retained')
        self._stream.seek(0)
        digest, remaining = hashlib.sha256(), committed
        while remaining:
            raw = self._stream.read(min(65536, remaining))
            _require(bool(raw), 'Journal prefix truncated')
            digest.update(raw); remaining -= len(raw)
        _require(digest.hexdigest() == self._manifest['prefix_sha256'], 'Journal prefix digest mismatch')
        if rebuild:
            self._stream.seek(0)
            sequence = 0
            while self._stream.tell() < committed:
                offset = self._stream.tell()
                raw = self._stream.readline(committed - offset)
                _require(raw.endswith(b'\n'), 'Incomplete journal event')
                event = self._event(raw)
                _require(event['sequence'] == sequence, 'Journal event sequence mismatch')
                kind, id = event['kind'], event['id']
                offsets = self._offsets[kind]
                _require(id <= len(offsets), 'Noncontiguous journal ID')
                if id == len(offsets): offsets.append(offset)
                else: offsets[id] = offset
                sequence += 1
            _require(sequence == self._manifest['event_count'], 'Journal event count mismatch')
        self._owned()

    @staticmethod
    def _event(raw):
        event = _load(raw)
        _require(isinstance(event, dict) and set(event) == {'sequence', 'kind', 'id', 'payload'}
                 and type(event['sequence']) is int and event['sequence'] >= 0 and event['kind'] in KINDS
                 and type(event['id']) is int and event['id'] >= 0 and isinstance(event['payload'], dict),
                 'Invalid journal event')
        return event

    def _latest(self, kind):
        _require(kind in KINDS, 'Unknown journal kind')
        for id, offset in enumerate(self._offsets[kind]):
            self._stream.seek(offset)
            raw = self._stream.readline(self._manifest['committed_bytes'] - offset)
            event = self._event(raw)
            _require(event['kind'] == kind and event['id'] == id, 'Journal index disagrees with record')
            yield event['payload']

    def iter_latest(self, kind):
        self._verify()
        yield from self._latest(kind)

    def finish(self, state):
        self.checkpoint(state)
        self._verify()
        fd, temporary = tempfile.mkstemp(prefix='.native-report-', dir=self.output.parent)
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as stream:
                stream.write('{')
                first = True
                for key, value in self._manifest['state'].items():
                    if not first: stream.write(',')
                    first = False
                    stream.write(ENCODER.encode(key) + ':')
                    for piece in ENCODER.iterencode(value): stream.write(piece)
                for kind in KINDS:
                    if not first: stream.write(',')
                    first = False
                    stream.write(ENCODER.encode(kind) + ':[')
                    for index, payload in enumerate(self._latest(kind)):
                        if index: stream.write(',')
                        for piece in ENCODER.iterencode(payload): stream.write(piece)
                    stream.write(']')
                stream.write('}\n'); stream.flush(); os.fsync(stream.fileno())
            self._verify()
            os.link(temporary, self.output)
            self._finished = True
        finally:
            if os.path.lexists(temporary): os.unlink(temporary)

    def close(self):
        if self._stream is not None:
            self._stream.close()
