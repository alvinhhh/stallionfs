"""Decode schema-1 payloads after external process/time/build/load attribution.

Reservation order is not execution or collection order. Even a valid, gapless
prefix cannot establish callback absence, reply delivery, or mount causality.
"""
import re
from collections import defaultdict

_FIELDS = 'b q t e o l c s z m k i v d n'.split()
_HEX = set('q t l c m k i v'.split())
_REPLY_STAGES = {
    1: {1, 8, 9, 10, 15, 16, 17, 18, 19, 20},
    2: {1, 4, 7, 8, 11},
    3: {1, 8, 9, 10, 11, 12, 13, 14},
    4: {1, 2, 3, 4, 5, 6, 7, 8},
}


def _association(row):
    # A partially malformed record can still contradict a known association.
    if all(key in row and 0 <= row[key] < 1 << 64 for key in ('l', 'c', 'o')):
        if row['c'] or row.get('e') in (1, 2, 3):
            return row['l'], row['c'], row['o']
    return None


def _recognizable_callback(line):
    """Recognize only an identity, never an event, from a bounded payload.

    Require the ordered header through c and exactly one of each header key
    anywhere in the payload. In particular, never choose between duplicate
    identity tokens. Other header values can be malformed without hiding a
    clearly named callback; full numeric/shape validation remains separate.
    """
    # Include noncanonical whitespace when looking for duplicate tokens. The
    # full parser below still requires the producer's literal space separators.
    parts = line.split()
    header = _FIELDS[:7]
    names = [part.partition('=')[0] for part in parts[1:]]
    if names[:7] != header or any(names.count(key) != 1 for key in header):
        raise ValueError
    value = parts[7].partition('=')[2]
    if re.fullmatch('[0-9a-f]+', value):
        callback = int(value, 16)
        if 0 < callback < 1 << 64:
            return callback
    return None


def _shape(row):
    """Fixed producer fields, not inferred OS state or collector authority."""
    b, q, e, o, s, z, d, n = (row[k] for k in ('b', 'q', 'e', 'o', 's', 'z', 'd', 'n'))
    if (b != 1 or not 1 <= q <= 64 or not 0 <= e <= 5 or not 0 <= o <= 7
            or not 0 <= s <= 20 or not -1 <= z <= 3 or not 0 <= d <= 2
            or not -(1 << 63) <= n < 1 << 63
            or any(not 0 <= row[k] < 1 << 64 for k in _HEX)):
        return False

    def zero(fields):
        return all(row[k] == 0 for k in fields.split())

    if e in (0, 5):
        return (q == (1 if e == 0 else 64) and z == -1
                and zero('o l c s m k i d n')
                and (row['v'] <= 15 if e == 0 else row['v'] == 0))
    if q == 1 or q == 64 or not row['l']:
        return False
    if e == 4 and o in (5, 6, 7):
        return (zero('c s m i d n') and z == -1
                and (row['k'] == 0 if o != 7 else row['k'] == row['v'] == 4096)
                and (o != 6 or row['v'] in (0x29f, 0x39f)))
    if o not in _REPLY_STAGES or not row['c'] or row['l'] == row['c']:
        return False
    if o != 4 and not zero('m k i'):
        return False
    if e != 3 and not zero('d n'):
        return False
    if e == 1:
        return (s == 0 and z == -1 and (o == 4 or row['k'] == 0)
                and (row['v'] <= 65 if o in (1, 3) else row['v'] == 0))
    if e == 2:
        return (s == 0 and (z == -1 if o == 1 else z >= 0)
                and (4 <= row['v'] <= 7 if o == 1 else row['v'] == 0))
    if e == 4:
        return (zero('d n k') and z == -1
                and ((o == 1 and s == 0 and row['v'] <= 2)
                     or (o == 3 and s == 10 and row['v'] <= 1)))
    if e != 3 or s not in _REPLY_STAGES[o] or (d == 0 and n != 0):
        return False
    if (d == 0) != (s == 8):
        return False
    early = o == 1 or s == 1 or (o == 3 and s == 9)
    if (z == -1) != early:
        return False
    if o != 4 or s not in (7, 8):
        return row['v'] == 0
    # GET prepared-field values are meaningful only with their presence bits.
    v = row['v']
    return (0 < v <= 31 and bool(v & 1)
            and (not v & 8 or bool(v & 2)) and (not v & 16 or bool(v & 4)))


def decode(lines):
    issues, seen, conflicting, invalid = set(), {}, set(), defaultdict(set)
    callbacks, loads = defaultdict(set), defaultdict(set)
    observed_loads = set()
    malformed_callbacks = set()
    previous = 0

    def invalidate(key, issue):
        issues.add(issue)
        if key is not None:
            invalid[key].add(issue)

    for line in lines:
        row = {}
        callback = None
        try:
            if (not isinstance(line, str) or len(line) > 256
                    or len(line.encode('utf-8')) > 256 or not line.startswith('SMT1 ')):
                raise ValueError
            callback = _recognizable_callback(line)
            parts = line.split(' ')
            if len(parts) != len(_FIELDS) + 1:
                raise ValueError
            for key, part in zip(_FIELDS, parts[1:]):
                name, sep, value = part.partition('=')
                if (name == key and sep
                        and re.fullmatch('[0-9a-f]+' if key in _HEX else '-?[0-9]+', value)):
                    row[key] = int(value, 16 if key in _HEX else 10)
            if len(row) != len(_FIELDS):
                raise ValueError
            valid = _shape(row)
        except (ValueError, UnicodeError):
            valid = False
        key = _association(row) if valid or callback is not None else None
        if not valid:
            invalidate(key, 'malformed')
            if callback is not None:
                malformed_callbacks.add(callback)
            else:
                issues.add('malformed-scope-unknown')
        # Getters have no callback association, but their load IDs still come
        # from the same allocator. Keep these roles even if q later conflicts.
        if valid and row['l']:
            observed_loads.add(row['l'])
        if key is not None:
            callbacks[row['c']].add(key)
            loads[row['l']].add(key)
        q = row.get('q')
        if q is None or not 1 <= q <= 64:
            continue
        if q < previous:
            issues.add('reordered')
        previous = q
        if q in seen:
            issues.add('duplicate-sequence')
            old, _ = seen[q]
            if row != old or not valid:
                conflicting.add(q)
                for candidate in (old, row):
                    invalidate(_association(candidate), 'conflicting-sequence')
            continue
        seen[q] = row, valid

    # Sorting is only for reporting and reservation checks; retain reorder evidence.
    records = [r for q, (r, valid) in sorted(seen.items()) if valid and q not in conflicting]
    if not any(r['e'] == 0 for r in records):
        issues.add('missing-startup')
    if seen and set(seen) != set(range(1, max(seen) + 1)):
        issues.add('missing-sequence')
    if any(r['e'] == 5 for r in records):
        issues.add('capped')
    groups = defaultdict(list)
    for r in records:
        key = _association(r)
        if key is not None:
            groups[key].append(r)
            if r['c'] in malformed_callbacks:
                invalidate(key, 'malformed')
    # IDs come from one allocator; a callback cannot change load/operation or
    # reuse a load ID. No gaplessness or numeric allocation order is assumed.
    for identifier, keys in callbacks.items():
        if len(keys) > 1 or identifier in loads or identifier in observed_loads:
            for key in keys | loads.get(identifier, set()):
                invalidate(key, 'conflicting-identifier')

    rejections = []
    for key, rows in groups.items():
        events = defaultdict(list)
        for r in rows:
            events[r['e']].append(r)
        if any(len(values) > 1 for values in events.values()):
            invalidate(key, 'ambiguous-association')
        if not events[1] or not events[3]:
            issues.add('missing-entry-or-reply')
        if len(events[1]) != 1 or len(events[3]) != 1:
            continue
        entry, reply = events[1][0], events[3][0]
        if (entry['q'] >= reply['q']
                or any(not entry['q'] < r['q'] < reply['q']
                       for r in events[2] + events[4])):
            invalidate(key, 'invalid-reservation-order')
        if key[2] == 4 and (any(r['m'] != entry['m'] or r['i'] != entry['i'] for r in rows)
                           or any(r['k'] != reply['k'] for r in events[2])
                           # Zero entry is legacy unspecified, not captured zero.
                           or entry['k'] not in (0, reply['k'])):
            invalidate(key, 'mismatched-get-fields')
        if (key not in invalid and reply['o'] == 4 and reply['s'] == 2
                and reply['d'] == 1 and reply['n'] == 45 and reply['m'] & 0x30000):
            rejections.append({'load': reply['l'], 'callback': reply['c'], 'mask': reply['m'],
                               'other_unsupported_bits': reply['m'] & ~0x33fff})
    return {'records': records, 'issues': sorted(issues), 'policy_rejections': rejections,
            'invalid_associations': [dict(load=l, callback=c, operation=o, issues=sorted(reasons))
                                     for (l, c, o), reasons in sorted(invalid.items())],
            'callback_absence': 'inconclusive', 'reply_delivery': 'unproven'}
