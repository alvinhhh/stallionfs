import itertools
import unittest
from mount_trace_decoder import decode


def row(q, event, op=0, callback=0, stage=0, mask=0, domain=0, code=0, **fields):
    """Schema-1 producer shapes; overrides intentionally permit malformed fixtures."""
    r = dict(b=1, q=q, t=1, e=event, o=op, l=1, c=callback, s=stage,
             z=-1, m=mask, k=0, i=1 if op == 4 else 0, v=0, d=domain, n=code)
    if event in (0, 5):
        r['l'] = 0
        r['v'] = 3 if event == 0 else 0
    if event == 2:
        r['v'] = 4 if op == 1 else 0
        r['z'] = -1 if op == 1 else 1
    if event == 3:
        if op != 1 and stage != 1 and not (op == 3 and stage == 9):
            r['z'] = 1
        if op == 4 and stage in (7, 8):
            r['v'] = 1
    if event == 4 and op == 6:
        r['v'] = 0x29f
    if event == 4 and op == 7:
        r['v'] = r['k'] = 4096
    r.update(fields)
    return 'SMT1 ' + ' '.join(f'{k}={v:x}' if k in 'q t l c m k i v'.split()
                              else f'{k}={v}' for k, v in r.items())


def pair(entry=2, reply=3, callback=2, mask=0x10000, **fields):
    return [row(entry, 1, 4, callback, mask=mask, **fields),
            row(reply, 3, 4, callback, 2, mask, 1, 45, **fields)]


# Startup, load (l=1/c=2), activation (c=3), then GET (c=4).
# Keep this complete producer prefix literal so callback IDs cannot accidentally
# overlap the load callback when adding malformed and getter observations.
_PREFIX = [
    'SMT1 b=1 q=1 t=101 e=0 o=0 l=0 c=0 s=0 z=-1 m=0 k=0 i=0 v=3 d=0 n=0',
    'SMT1 b=1 q=2 t=102 e=1 o=1 l=1 c=2 s=0 z=-1 m=0 k=0 i=0 v=0 d=0 n=0',
    'SMT1 b=1 q=3 t=103 e=2 o=1 l=1 c=2 s=0 z=-1 m=0 k=0 i=0 v=5 d=0 n=0',
    'SMT1 b=1 q=4 t=104 e=4 o=1 l=1 c=2 s=0 z=-1 m=0 k=0 i=0 v=1 d=0 n=0',
    'SMT1 b=1 q=5 t=105 e=3 o=1 l=1 c=2 s=8 z=-1 m=0 k=0 i=0 v=0 d=0 n=0',
    'SMT1 b=1 q=6 t=106 e=1 o=2 l=1 c=3 s=0 z=-1 m=0 k=0 i=0 v=0 d=0 n=0',
    'SMT1 b=1 q=7 t=107 e=2 o=2 l=1 c=3 s=0 z=0 m=0 k=0 i=0 v=0 d=0 n=0',
    'SMT1 b=1 q=8 t=108 e=3 o=2 l=1 c=3 s=8 z=1 m=0 k=0 i=0 v=0 d=0 n=0',
]
_GET = [
    'SMT1 b=1 q=9 t=109 e=1 o=4 l=1 c=4 s=0 z=-1 m=10000 k=0 i=1 v=0 d=0 n=0',
    'SMT1 b=1 q=a t=10a e=2 o=4 l=1 c=4 s=0 z=1 m=10000 k=3fff i=1 v=0 d=0 n=0',
    'SMT1 b=1 q=b t=10b e=3 o=4 l=1 c=4 s=2 z=1 m=10000 k=3fff i=1 v=0 d=1 n=45',
]
_SUCCESS = 'SMT1 b=1 q=c t=10c e=3 o=4 l=1 c=4 s=8 z=1 m=10000 k=3fff i=1 v=1 d=0 n=0'


class MountTraceDecoder(unittest.TestCase):
    def assert_boundary(self, result):
        self.assertEqual(result['callback_absence'], 'inconclusive')
        self.assertEqual(result['reply_delivery'], 'unproven')

    def test_get_entry_sdk_unsigned_and_legacy(self):
        for sdk in (1, 1 << 62, 1 << 63, (1 << 64) - 1):
            for early in (False, True):
                for entry_sdk in (0, sdk, sdk ^ 1):
                    lines = [row(1, 0), row(2, 1, 4, 2, mask=1, k=entry_sdk)]
                    if not early:
                        lines.append(row(3, 2, 4, 2, mask=1, k=sdk))
                    lines.append(row(3 if early else 4, 3, 4, 2,
                                     1 if early else 5, 1, 1, 13, k=sdk))
                    result = decode(lines)
                    self.assertEqual(bool(result['invalid_associations']), entry_sdk not in (0, sdk))
                    self.assertEqual(result['policy_rejections'], [])
                    self.assert_boundary(result)
                    if entry_sdk in (0, sdk):
                        self.assertEqual(result['issues'], [])
            for field in ('m', 'i', 'k'):
                lines = [row(1, 0), row(2, 1, 4, 2, mask=1, k=sdk),
                         row(3, 2, 4, 2, mask=1, k=sdk),
                         row(4, 3, 4, 2, 5, 1, 1, 13, k=sdk)]
                tokens = lines[2].split()
                lines[2] = ' '.join(f'{field}=2' if t.startswith(field + '=') else t for t in tokens)
                self.assertIn('mismatched-get-fields', decode(lines)['issues'])
        for op in (1, 2, 3):
            self.assertIn('malformed', decode([row(1, 0), row(2, 1, op, 2, k=1)])['issues'])

    def test_positive_survives_incomplete_capture(self):
        startup, (entry, reply) = row(1, 0), pair()
        for lines in ([startup, entry, reply], [reply, startup, entry],
                      [entry, reply], [startup, entry, reply, row(64, 5)],
                      [startup, entry, reply, reply], [startup, entry, reply, 'SMT1 b='],
                      [startup, entry, reply, 'x'*257]):
            with self.subTest(lines=lines):
                result = decode(lines)
                self.assertEqual(len(result['policy_rejections']), 1)
                self.assert_boundary(result)
        self.assertIn('missing-startup', decode([entry, reply])['issues'])
        self.assertIn('capped', decode([startup, entry, reply, row(64, 5)])['issues'])
        self.assertIn('duplicate-sequence', decode([entry, reply, reply])['issues'])

    def test_no_synthetic_missing_events_or_errno_attribution(self):
        for lines in ([], [row(1, 0)], [pair()[0]], [pair()[1]],
                      [pair()[0], row(3, 3, 4, 2, 7, 0x10000, 1, 45)],
                      [pair()[0], row(3, 3, 4, 2, 2, 0x20000, 1, 45)],
                      [pair()[0], row(3, 3, 4, 2, 8, 0x10000)]):
            with self.subTest(lines=lines):
                result = decode(lines)
                self.assertEqual(result['policy_rejections'], [])
                self.assert_boundary(result)
        for mask in (0x10000, 0x20000, 0x30040, 0x50000, (1 << 64) - 1):
            with self.subTest(mask=mask):
                observation = decode(pair(mask=mask))['policy_rejections'][0]
                self.assertEqual(observation['mask'], mask)
                self.assertEqual(observation['other_unsupported_bits'], mask & ~0x33fff)
        for mask in (0, 0x40, 0x40000):
            self.assertEqual(decode(pair(mask=mask))['policy_rejections'], [])

    def test_conflicting_sequence_cannot_support_a_positive(self):
        entry, reply = pair()
        conflict = row(3, 3, 4, 2, 7, 0x10000, 1, 45)
        for lines in itertools.permutations([entry, reply, conflict]):
            result = decode(lines)
            self.assertIn('conflicting-sequence', result['issues'])
            self.assertEqual(result['policy_rejections'], [])

    def test_distinct_sequence_entries_and_replies_are_ambiguous(self):
        entry, reply = pair()
        conflicts = [row(4, 1, 4, 2, mask=0x20000), row(4, 1, 4, 2, mask=0x10000),
                     row(4, 3, 4, 2, 8, 0x10000), row(4, 3, 4, 2, 2, 0x10000, 1, 45),
                     row(4, 3, 4, 2, 2, 0x10000, 1, 13)]
        for conflict in conflicts:
            for lines in itertools.permutations([entry, reply, conflict]):
                with self.subTest(lines=lines):
                    result = decode(lines)
                    self.assertEqual(result['policy_rejections'], [])
                    self.assertIn('ambiguous-association', result['issues'])
                    self.assertEqual(result['invalid_associations'][0]['callback'], 2)
        # Neither a larger reservation number nor later collection selects a verdict.
        for success_q, error_q in ((3, 4), (4, 3)):
            lines = [entry, row(success_q, 3, 4, 2, 8, 0x10000),
                     row(error_q, 3, 4, 2, 2, 0x10000, 1, 45)]
            self.assertEqual(decode(lines)['policy_rejections'], [])

    def test_identical_collector_duplicates_keep_positive(self):
        entry, reply = pair()
        result = decode([row(1, 0), entry, entry, reply, reply])
        self.assertEqual(len(result['records']), 3)
        self.assertEqual(len(result['policy_rejections']), 1)
        self.assertEqual(result['issues'], ['duplicate-sequence'])
        self.assertEqual(result['invalid_associations'], [])

    def test_mixed_associations_exclude_only_affected_observations(self):
        entry, reply = pair()
        for conflict in (row(4, 1, 4, 2, mask=0x10000),
                         row(4, 3, 4, 2, 8, 0x10000),
                         row(3, 3, 4, 2, 2, 0x20000, 1, 45),
                         row(4, 3, 4, 2, 2, 0x10000, 1, 45, v=1),
                         row(4, 3, 4, 2, 2, 0x10000, 1, 45, l=1 << 64),
                         row(4, 3, 4, 2, 2, 0x10000, 1, 45).replace('v=0', 'v=false'),
                         row(4, 3, 4, 2, 2, 0x10000, 1, 45).replace('o=4', 'o=false')):
            with self.subTest(conflict=conflict):
                result = decode([entry, reply, conflict] + pair(5, 7, callback=3)
                                + pair(8, 9, callback=5, l=4))
                self.assertEqual({r['callback'] for r in result['policy_rejections']}, {3, 5})
                self.assertEqual({r['callback'] for r in result['invalid_associations']}, {2})
                self.assert_boundary(result)

    def test_callback_identifiers_cannot_change_association(self):
        for conflicting_pair in (pair(4, 5, l=3),
                                 pair(4, 5, l=0), pair(4, 5, o=8),
                                 [row(4, 1, 2, 2), row(5, 3, 2, 2, 8)],
                                 pair(4, 5, callback=4, l=2)):
            result = decode(pair() + conflicting_pair + pair(6, 7, callback=8, l=7))
            self.assertIn('conflicting-identifier', result['issues'])
            self.assertEqual([r['callback'] for r in result['policy_rejections']], [8])

    def test_reservation_order_is_per_callback(self):
        for lines in (pair(3, 2), pair(2, 2),
                      [pair()[0], row(4, 2, 4, 2, mask=0x10000), pair()[1]],
                      [row(2, 2, 4, 2, mask=0x10000)] + pair(3, 4)):
            result = decode(lines + pair(5, 6, callback=3))
            self.assertEqual([r['callback'] for r in result['policy_rejections']], [3])
            self.assertTrue({'invalid-reservation-order', 'conflicting-sequence'} & set(result['issues']))

    def test_valid_concurrent_collection_reordering_keeps_both_positives(self):
        # q is reservation order; neither t nor interleaved collections need increase.
        lines = [row(1, 0), pair(2, 7)[0], pair(3, 5, callback=3)[0],
                 row(4, 2, 4, 3, mask=0x10000, t=900), pair(3, 5, callback=3)[1],
                 row(6, 2, 4, 2, mask=0x10000, t=10), pair(2, 7)[1]]
        result = decode([lines[i] for i in (6, 2, 0, 5, 1, 4, 3)])
        self.assertEqual({r['callback'] for r in result['policy_rejections']}, {2, 3})
        self.assertEqual(result['issues'], ['reordered'])
        self.assert_boundary(result)
        for collection in itertools.permutations([row(1, 0)] + pair()):
            result = decode(collection)
            self.assertEqual(len(result['policy_rejections']), 1)
            self.assertEqual('reordered' in result['issues'], list(collection) != [row(1, 0)] + pair())

    def test_overflow_has_one_exclusive_slot_and_fixed_payload(self):
        for marker in (row(4, 5), row(64, 5, l=1), row(64, 5, v=1),
                       row(64, 5, i=1), row(64, 5, z=0), row(64, 5, n=45),
                       row(64, 5, op=4, callback=8)):
            with self.subTest(marker=marker):
                result = decode(pair() + [marker])
                self.assertIn('malformed', result['issues'])
                self.assertNotIn('capped', result['issues'])
                self.assertEqual(len(result['policy_rejections']), 1)
        for entry_q, reply_q in ((2, 64), (64, 3)):
            self.assertEqual(decode(pair(entry_q, reply_q))['policy_rejections'], [])
        marker = row(64, 5)
        result = decode([marker] + pair() + [marker])
        self.assertTrue({'capped', 'duplicate-sequence', 'reordered', 'missing-sequence'} <= set(result['issues']))
        self.assertEqual(len(result['policy_rejections']), 1)
        # A conflicting slot64 payload invalidates that slot, not another callback.
        result = decode(pair() + [marker, row(64, 5, v=1)])
        self.assertIn('conflicting-sequence', result['issues'])
        self.assertEqual(len(result['policy_rejections']), 1)

    def test_full_capped_capture_keeps_every_unambiguous_positive(self):
        lines = [row(1, 0)]
        for callback in range(2, 33):
            lines.extend(pair(callback*2-2, callback*2-1, callback=callback))
        lines.append(row(64, 5))
        result = decode(lines)
        self.assertEqual(len(result['records']), 64)
        self.assertEqual(len(result['policy_rejections']), 31)
        self.assertEqual(result['issues'], ['capped'])
        self.assert_boundary(result)

    def test_nonzero_distinct_association_ids(self):
        for fields in (dict(l=0), dict(c=0), dict(l=2)):
            with self.subTest(fields=fields):
                result = decode(pair(**fields))
                self.assertEqual(result['policy_rejections'], [])
                self.assertIn('malformed', result['issues'])

    def test_malformed_field_types_and_ranges(self):
        entry, reply = pair()
        bad_values = {
            'b': ['0', '2', 'true', '1.0'], 'q': ['0', '41', '-1', '10000000000000000'],
            't': ['-1', '10000000000000000'], 'e': ['-1', '6', 'true'],
            'o': ['-1', '8', 'null'], 'l': ['-1', '10000000000000000'],
            'c': ['-1', '10000000000000000'], 's': ['-1', '21', '2.0'],
            'z': ['-2', '4', 'false'], 'm': ['-1', '10000000000000000', '0x10000'],
            'k': ['-1', '10000000000000000'], 'i': ['-1', '10000000000000000'],
            'v': ['-1', '10000000000000000'], 'd': ['-1', '3', '1.0'],
            'n': [str(1 << 63), str(-(1 << 63) - 1), 'NaN'],
        }
        for key, values in bad_values.items():
            for value in values:
                parts = reply.split(' ')
                malformed = ' '.join(f'{key}={value}' if part.startswith(key + '=') else part for part in parts)
                with self.subTest(key=key, value=value):
                    result = decode([entry, malformed])
                    self.assertEqual(result['policy_rejections'], [])
                    self.assertIn('malformed', result['issues'])
        for malformed in (None, 1, True, {}, b'SMT1', reply + ' extra=0',
                          reply.replace(' k=0', ' m=0'), reply.replace('SMT1', 'SMT2'),
                          reply[:-5], 'x'*257, '\ud800'):
            with self.subTest(malformed=malformed):
                result = decode([entry, malformed])
                self.assertIn('malformed', result['issues'])
                self.assertEqual(result['policy_rejections'], [])

    def test_event_operation_stage_and_unused_fields(self):
        entry, reply = pair()
        for changes in (dict(e=0), dict(e=2), dict(e=4), dict(e=5), dict(o=0), dict(o=5),
                        dict(s=0), dict(s=9), dict(z=-1), dict(d=0), dict(v=1)):
            with self.subTest(changes=changes):
                result = decode([entry, row(3, 3, 4, 2, 2, 0x10000, 1, 45, **changes)])
                self.assertIn('malformed', result['issues'])
                self.assertEqual(result['policy_rejections'], [])
        for field in ('s', 'k', 'v', 'd', 'n'):
            self.assertEqual(decode([row(2, 1, 4, 2, mask=0x10000, **{field: 1}), reply])['policy_rejections'], [])
        # A profile marker with callback fields is not an authoritative startup.
        self.assertIn('missing-startup', decode([row(1, 0, l=1)] + pair())['issues'])

    def test_supported_producer_shapes_and_sparse_capture(self):
        lines = [row(1, 0, v=11), row(2, 1, 1, 2, v=2), row(3, 2, 1, 2, v=5),
                 row(4, 4, 1, 2, v=1), row(5, 3, 1, 2, 8),
                 row(6, 1, 2, 3), row(7, 2, 2, 3), row(8, 3, 2, 3, 8),
                 row(9, 1, 3, 4), row(10, 2, 3, 4), row(11, 4, 3, 4, 10),
                 row(12, 3, 3, 4, 8), row(13, 4, 5), row(14, 4, 6), row(15, 4, 7)]
        self.assertEqual(decode(lines)['issues'], [])
        sparse = decode(pair(10, 63, t=(1 << 64) - 1))
        self.assertEqual(sparse['issues'], ['missing-sequence', 'missing-startup'])
        self.assertEqual(len(sparse['policy_rejections']), 1)
        self.assert_boundary(sparse)

    def test_body_and_reply_get_fields_match_without_sdk_entry_comparison(self):
        lines = [pair()[0], row(3, 2, 4, 2, mask=0x10000, k=0x3fff),
                 row(4, 3, 4, 2, 2, 0x10000, 1, 45, k=0x3fff)]
        self.assertEqual(len(decode(lines)['policy_rejections']), 1)
        for field in ('m', 'i', 'k'):
            changed = lines.copy()
            changed[1] = row(3, 2, 4, 2, mask=0x10000, **{field: 0})
            result = decode(changed)
            self.assertIn('mismatched-get-fields', result['issues'])
            self.assertEqual(result['policy_rejections'], [])

    def test_complete_producer_prefix_and_reverse_keep_positive(self):
        for lines in (_PREFIX + _GET, list(reversed(_PREFIX + _GET))):
            result = decode(lines)
            self.assertEqual([r['callback'] for r in result['policy_rejections']], [4])
            self.assertEqual(len(result['records']), 11)
            self.assertEqual(result['invalid_associations'], [])
            self.assertEqual(result['issues'], [] if lines[0] == _PREFIX[0] else ['reordered'])
            self.assert_boundary(result)

    def test_malformed_outcome_taints_callback_in_every_collection_order(self):
        malformed = (_SUCCESS + ' x=0', _SUCCESS.rsplit(' ', 1)[0],
                     _SUCCESS.replace('v=1', 'v=true'),
                     ' '.join(_SUCCESS.split(' ')[:8]))
        for conflict in malformed:
            for ordering in itertools.permutations([_GET[0], _GET[2], conflict]):
                with self.subTest(conflict=conflict, ordering=ordering):
                    result = decode(_PREFIX + list(ordering) + pair(13, 14, callback=5))
                    self.assertEqual([r['callback'] for r in result['policy_rejections']], [5])
                    self.assertIn('malformed', result['issues'])
                    self.assertNotIn('malformed-scope-unknown', result['issues'])
                    self.assertEqual({r['callback'] for r in result['invalid_associations']}, {4})
                    self.assertFalse(any(r['q'] == 12 for r in result['records']))
                    self.assert_boundary(result)
        # A recognizable malformed reply never supplies an outcome itself.
        for conflict in malformed:
            result = decode(_PREFIX + [_GET[0], conflict])
            self.assertEqual(result['policy_rejections'], [])

    def test_ambiguous_headers_do_not_choose_an_identity(self):
        conflicts = [
            _SUCCESS + ' c=5', _SUCCESS + ' c=4', _SUCCESS + ' l=5',
            _SUCCESS + ' o=2', _SUCCESS + ' q=d', _SUCCESS + ' b=2',
            _SUCCESS + '\tc=5', _SUCCESS + '\nc=5', _SUCCESS + '\u00a0l=5',
            _SUCCESS.replace(' n=0', ' c=5'),
            _SUCCESS.replace(' c=4', ' l=5'),
            _SUCCESS.replace(' l=1 c=4', ' c=4 l=1'),
            _SUCCESS.replace(' c=4', ''),
        ]
        for conflict in conflicts:
            for lines in (_PREFIX + _GET + [conflict] + pair(13, 14, callback=5),
                          [conflict] + pair(13, 14, callback=5) + _PREFIX + _GET):
                with self.subTest(conflict=conflict):
                    result = decode(lines)
                    self.assertEqual({r['callback'] for r in result['policy_rejections']}, {4, 5})
                    self.assertTrue({'malformed', 'malformed-scope-unknown'} <= set(result['issues']))
                    self.assertEqual(result['invalid_associations'], [])
                    self.assertFalse(any(r['q'] == 12 for r in result['records']))
                    self.assert_boundary(result)

    def test_callback_recognition_bounds_and_unrelated_callbacks(self):
        malformed = _SUCCESS + ' x=0'
        for value in ('0', '10000000000000000', '-1', 'true', '0x4', ''):
            with self.subTest(value=value):
                result = decode(_PREFIX + _GET + [malformed.replace(' c=4', ' c=' + value)]
                                + pair(13, 14, callback=5))
                self.assertEqual({r['callback'] for r in result['policy_rejections']}, {4, 5})
                self.assertIn('malformed-scope-unknown', result['issues'])
                self.assertEqual(result['invalid_associations'], [])
                self.assert_boundary(result)
        for conflict in (malformed.replace(' t=10c', ' t=' + '0' * 257),
                         malformed + 'x' * 257, malformed + '\ud800',
                         malformed + 'é' * 100,
                         _SUCCESS.replace(' c=4', ' c=0').replace(' l=1', ' l=4')):
            result = decode(_PREFIX + _GET + [conflict])
            self.assertEqual([r['callback'] for r in result['policy_rejections']], [4])
            self.assertIn('malformed-scope-unknown', result['issues'])
            self.assert_boundary(result)
        # At the payload bound, recognition still taints; one byte beyond is
        # unscoped. A maximum UInt64 callback remains a valid identity too.
        bounded = malformed + 'x' * (256 - len(malformed))
        for conflict, expected in ((bounded, []), (bounded + 'x', [4])):
            result = decode(_PREFIX + _GET + [conflict])
            self.assertEqual([r['callback'] for r in result['policy_rejections']], expected)
        for callback in (8, (1 << 64) - 1):
            conflict = malformed.replace(' c=4', f' c={callback:x}')
            result = decode(_PREFIX + _GET + pair(13, 14, callback=callback) + [conflict])
            self.assertEqual([r['callback'] for r in result['policy_rejections']], [4])
            self.assertEqual({r['callback'] for r in result['invalid_associations']}, {callback})

    def test_all_getter_load_roles_participate_in_identifier_collisions(self):
        for op in (5, 6, 7):
            for load, expected in ((4, {5}), (6, {4, 5}), (1, {4, 5})):
                getter = row(12, 4, op, l=load)
                for lines in (_PREFIX + _GET + [getter] + pair(13, 14, callback=5),
                              [getter] + pair(13, 14, callback=5) + _PREFIX + _GET):
                    with self.subTest(op=op, load=load):
                        result = decode(lines)
                        self.assertEqual({r['callback'] for r in result['policy_rejections']}, expected)
                        invalid = {r['callback'] for r in result['invalid_associations']}
                        self.assertEqual(invalid, {4} if load == 4 else set())
                        self.assertEqual('conflicting-identifier' in result['issues'], load == 4)
                        self.assertTrue(any(r['e'] == 4 and r['o'] == op and r['c'] == 0
                                            for r in result['records']))
                        self.assert_boundary(result)
            # Also invalidate callbacks using the colliding load. c=5 on l=1
            # remains unrelated; no synthetic getter callback 0 is introduced.
            lines = (_PREFIX + _GET + [row(12, 4, op, l=4)]
                     + pair(13, 14, callback=5) + pair(15, 16, callback=7, l=4))
            for collection in (lines, list(reversed(lines))):
                result = decode(collection)
                self.assertEqual([r['callback'] for r in result['policy_rejections']], [5])
                self.assertEqual({r['callback'] for r in result['invalid_associations']}, {4, 7})
                self.assertIn('conflicting-identifier', result['issues'])
                self.assert_boundary(result)


if __name__ == '__main__':
    unittest.main()
