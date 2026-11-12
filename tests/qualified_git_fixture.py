"""Access the input already admitted by the runner before test discovery."""
import sys


def runtime():
    admission = sys.modules.get('ci_git_input')
    if admission is None:
        raise RuntimeError('Qualified Git input must be initialized before test discovery')
    return admission.runtime()


from contextlib import contextmanager
import copy
import platform
from unittest.mock import patch


@contextmanager
def native_creation(runtime_value=None):
    """Use admitted host Git in controlled tests; this grants no companion authority."""
    from stallionfs import _bundle, _native_create_authority as authority
    from stallionfs import _native_create_git as git, _native_create_request as request
    from stallionfs._native_create_recovery import require
    value = runtime() if runtime_value is None else runtime_value
    expected = copy.deepcopy(value['contract'])
    executable, exec_path, live_check = value['executable'], value['exec_path'], value['check']
    architecture = platform.machine()
    production_current = authority.current
    active = True

    def same_contract(candidate):
        return (type(candidate) is dict and type(expected) is dict and candidate.keys() == expected.keys()
                and all(type(candidate[key]) is type(expected[key]) and candidate[key] == expected[key]
                        for key in expected))

    def checked_runtime(native_host=None):
        require(active, 'fixture-scope-ended')
        require(value['check'] is live_check, 'fixture-runtime-changed')
        live_check()
        admitted = runtime()
        require(same_contract(value['contract']) and same_contract(admitted['contract'])
                and value['executable'] == executable == admitted['executable']
                and value['exec_path'] == exec_path == admitted['exec_path'], 'fixture-runtime-changed')
        _bundle.git_contract({key: value['contract'][key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}},
                             architecture=architecture)
        return value

    def current(spec):
        request.schema(spec)
        require(spec['protocol'] == request.PROTOCOL and spec['method'] == request.METHOD,
                'unverified-writer')
        checked_runtime()
        require(same_contract(spec['runtime']), 'fixture-runtime-changed')
        _bundle.git_contract({key: spec['runtime'][key] for key in set(_bundle.GIT_CONTRACT) | {'input_inventory_sha256'}},
                             architecture=architecture)
        if architecture == 'arm64':
            production_current(spec)

    try:
        checked_runtime()
        with patch.object(git, 'qualified_runtime', checked_runtime), patch.object(authority, 'current', current):
            yield value
    finally:
        active = False
