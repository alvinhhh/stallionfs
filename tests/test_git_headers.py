"""Admission of the actual pinned public-header inventory."""
import copy
import hashlib
import json
from pathlib import Path
import unittest

from stallionfs import _bundle, _git_runtime, _git_sources


class GitHeaders(unittest.TestCase):
    def setUp(self):
        path = Path(__file__).resolve().parents[1] / 'tools/git-inputs/header-manifest.json'
        data = path.read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), _git_sources.INPUTS['header-manifest.json'])
        self.headers = json.loads(data)

    def test_all_real_pinned_headers_are_admitted(self):
        result = _git_runtime._headers(self.headers)
        self.assertEqual(result, self.headers)
        self.assertIn('baseline/include/curl/typecheck-gcc.h', {row['file'] for row in result})

    def test_changed_paths_and_incomplete_or_duplicate_inventories_refuse(self):
        for change in ('escape', 'absolute', 'duplicate', 'missing', 'size', 'hash'):
            headers = copy.deepcopy(self.headers)
            if change == 'escape': headers[0]['file'] = 'baseline/include/curl/../curl.h'
            elif change == 'absolute': headers[0]['file'] = '/curl.h'
            elif change == 'duplicate': headers[0]['file'] = headers[1]['file']
            elif change == 'missing': headers.pop()
            elif change == 'size': headers[0]['bytes'] = True
            else: headers[0]['sha256'] = 'invalid'
            with self.subTest(change=change), self.assertRaises(_bundle.BundleError):
                _git_runtime._headers(headers)
