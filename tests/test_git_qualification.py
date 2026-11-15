"""Exact native input registration and caller architecture boundaries; no actors."""
import ast
import importlib.util
from pathlib import Path
import unittest


SOURCE = Path(__file__).resolve().parents[1]
ARM = '9b9401eaea9d2f2b3e88c8c87509b52414b5522016c505718c050cd562725700'
INTEL = '020c08613be10d2d21d46a4defd6c4c98724b0af61426a9a2096e1bee48d546a'


def bundle():
    spec = importlib.util.spec_from_file_location('qualification_contract', SOURCE / 'stallionfs/_bundle.py')
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


class GitQualification(unittest.TestCase):
    def test_only_two_measured_architecture_profiles_are_registered(self):
        module = bundle()
        self.assertEqual(module.QUALIFIED_GIT_ARCHITECTURES, {ARM: 'arm64', INTEL: 'x86_64'})
        self.assertEqual(module.QUALIFIED_GIT_INPUTS, frozenset((ARM, INTEL)))
        for inventory, architecture in module.QUALIFIED_GIT_ARCHITECTURES.items():
            with self.subTest(architecture=architecture):
                contract = dict(module.GIT_CONTRACT, input_inventory_sha256=inventory)
                self.assertIs(module.git_contract(contract, architecture=architecture), contract)
                with self.assertRaisesRegex(module.BundleError, 'architecture differs'):
                    module.git_contract(contract, architecture='x86_64' if architecture == 'arm64' else 'arm64')

    def test_unknown_changed_source_unsupported_and_raw_architecture_refuse(self):
        module = bundle(); contract = dict(module.GIT_CONTRACT, input_inventory_sha256=INTEL)
        for value, keywords, message in (
                ({**contract, 'input_inventory_sha256': '0' * 64}, {}, 'not been qualified'),
                ({**contract, 'source_sha256': '0' * 64}, {}, 'Unsupported Git provenance'),
                (contract, {'architecture': 'aarch64'}, 'architecture differs'),
                (contract, {'qualified': False, 'architecture': 'x86_64'}, 'architecture differs')):
            with self.subTest(value=value, keywords=keywords), self.assertRaisesRegex(module.BundleError, message):
                module.git_contract(value, **keywords)

    def test_app_admission_stays_arm_and_ci_selects_the_actual_host(self):
        boundaries = {
            ('tools/package_fskit.py', '_prepare_runtime', '_runtime_admit_git'): 'arm64',
            ('tools/package_fskit.py', 'finalize_git_payload', 'git_contract'): 'arm64',
            ('stallionfs/_native_create_git.py', 'qualified_runtime', 'git_contract'): 'arm64',
            ('stallionfs/_native_create_authority.py', 'current', 'git_contract'): 'arm64',
            ('tools/ci_build.py', 'build', '_runtime_admit_git'): 'host',
            ('tools/ci_git_input.py', 'initialize', '_runtime_admit_git'): 'host',
        }
        for (name, function, target), expected in boundaries.items():
            with self.subTest(name=name, function=function):
                tree = ast.parse((SOURCE / name).read_bytes())
                owner = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function)
                calls = [node for node in ast.walk(owner) if isinstance(node, ast.Call)
                         and (isinstance(node.func, ast.Name) and node.func.id == target
                              or isinstance(node.func, ast.Attribute) and node.func.attr == target)]
                self.assertEqual(len(calls), 1)
                architecture = next(keyword.value for keyword in calls[0].keywords if keyword.arg == 'architecture')
                if expected == 'arm64': self.assertEqual(ast.literal_eval(architecture), 'arm64')
                else: self.assertEqual(ast.unparse(architecture), 'platform.machine()')

    def test_shared_admission_refuses_unspecified_or_unsupported_architecture_before_reading(self):
        spec = importlib.util.spec_from_file_location('qualified_architecture_reader', SOURCE / 'tools/package_fskit.py')
        package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)
        for architecture in (None, '', 'aarch64', 'ARM64', 1, True, [], {}):
            with self.subTest(architecture=architecture), self.assertRaisesRegex(ValueError, 'Git build architecture differs'):
                package._runtime_admit_git(object(), {}, architecture=architecture)


if __name__ == '__main__': unittest.main()
