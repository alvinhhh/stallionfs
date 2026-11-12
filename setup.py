import os
import platform as host
import sys

if sys.platform == 'darwin':
    architecture = host.machine()
    if not isinstance(architecture, str) or architecture not in ('arm64', 'x86_64'):
        raise ValueError('Unsupported Darwin architecture')
    os.environ['ARCHFLAGS'] = '-arch ' + architecture

from pathlib import Path
from shutil import copy2
from setuptools import Extension, setup
from setuptools.command.build_py import build_py
import hashlib
import json
import importlib.util
from distutils.ccompiler import new_compiler
from distutils.command.build_scripts import build_scripts
from distutils.sysconfig import customize_compiler
from setuptools.command.bdist_wheel import bdist_wheel

NATIVE = ["stallionfs/_main.c", "stallionfs/_tree.c", "stallionfs/_walk.c"]
HEADER = "stallionfs/_tree.h"
SOURCE_ROOT = Path(__file__).resolve().parent
FLAGS = ["-O2", "-Wall", "-Wextra", "-ffile-prefix-map=" + str(SOURCE_ROOT) + "=/usr/src/stallionfs"]
LINK_FLAGS = ["-Xlinker", "-oso_prefix", "-Xlinker", str(SOURCE_ROOT) + "/"]


class NativeScripts(build_scripts):
    def run(self):
        self.mkpath(self.build_dir)
        if self.dry_run:
            return
        compiler = new_compiler(force=self.force)
        customize_compiler(compiler)
        temporary = str(Path(self.get_finalized_command("build").build_temp) / "native-scripts")
        objects = compiler.compile(NATIVE, output_dir=temporary, extra_postargs=FLAGS,
                                   macros=[("STALLIONFS_VERSION", f'"{self.distribution.get_version()}"')],
                                   depends=[HEADER, "pyproject.toml"])
        compiler.link_executable(objects, "stallionfs", output_dir=self.build_dir, extra_postargs=LINK_FLAGS)
        copy2(Path(self.build_dir) / "stallionfs", Path(self.build_dir) / "sfs")

    def get_outputs(self):
        return [str(Path(self.build_dir) / name) for name in ("stallionfs", "sfs")]

    def get_source_files(self):
        return [*NATIVE, HEADER]


BENCHMARK_MODULES = ('fileops.py', 'native_suite.py', 'native_metrics.py',
                     'native_correctness.py', 'native_fixtures.py', 'native_report.py',
                     'campaign.py', 'scan.py', 'run.py', 'cli.py')
BENCHMARK_FIXTURES = ('package.json', 'package-lock.json', 'check.cjs')
BENCHMARK_INPUTS = [*("tests/perf/" + name for name in BENCHMARK_MODULES),
                    *("tests/perf/fixture/" + name for name in BENCHMARK_FIXTURES)]
GIT_BUILD_INPUTS = ['tools/build_git_runtime.py', 'tools/_git_capture.py',
                    *['tools/git-inputs/' + name for name in
                      ('combined.patch', 'notices.patch', 'config.mak', 'header-manifest.json', 'alias.c')]]


def git_builder():
    spec = importlib.util.spec_from_file_location('_stallionfs_git_build', 'tools/build_git_runtime.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class BenchmarkResources(build_py):
    """Ship the existing collectors, not repository tests or generated reports."""
    def run(self):
        super().run()
        destination = Path('stallionfs') if self.editable_mode else Path(self.build_lib) / 'stallionfs'
        temporary = Path(self.get_finalized_command('build').build_temp) / 'git-dependency'
        git_builder().build(destination / '_git', temporary)
        destination = Path(self.build_lib) / 'stallionfs' / '_benchmark_runtime'
        resources = {}
        for source in BENCHMARK_INPUTS:
            relative = Path(source).relative_to('tests/perf')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copy2(source, target)
            resources[relative.as_posix()] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
        sources = [Path('setup.py'), Path('pyproject.toml'), *map(Path, GIT_BUILD_INPUTS),
                   *(file for file in Path('stallionfs').iterdir()
                     if file.is_file() and file.suffix in ('.py', '.c', '.h'))]
        manifest = {'schema': 1, 'kind': 'build-source provenance', 'resources': resources,
                    'build_source_sha256': {file.as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
                                            for file in sorted(sources)}}
        (destination / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')

    def get_source_files(self):
        return [*super().get_source_files(), *BENCHMARK_INPUTS, *GIT_BUILD_INPUTS]

    def get_outputs(self, include_bytecode=1):
        destination = Path(self.build_lib) / 'stallionfs' / '_benchmark_runtime'
        package = Path('stallionfs') if self.editable_mode else Path(self.build_lib) / 'stallionfs'
        runtime = package / '_git'
        generated = [str(path) for path in runtime.rglob('*') if path.is_file()] if runtime.exists() else []
        return [*super().get_outputs(include_bytecode), *generated,
                *(str(destination / Path(name).relative_to('tests/perf')) for name in BENCHMARK_INPUTS),
                str(destination / 'manifest.json')]


class PayloadWheel(bdist_wheel):
    def get_tag(self):
        python, abi, platform = super().get_tag()
        builder = git_builder()
        build = self.get_finalized_command('build')
        roots = [Path(build.build_lib), Path(self.get_finalized_command('build_scripts').build_dir)]
        architecture = host.machine()
        minimum, architectures = (0, 0, 0), set()
        for root in roots:
            for path in root.rglob('*'):
                if not path.is_file() or path.is_symlink():
                    continue
                slices = builder.macho(path)
                if slices and (len(slices) != 1 or slices[0]['architecture'] != architecture):
                    raise ValueError('Wheel payload architecture differs: ' + str(path))
                for value in slices:
                    minimum = max(minimum, value['minimum']); architectures.add(value['architecture'])
        if not architectures:
            return python, abi, platform
        if architecture not in architectures:
            raise ValueError('Wheel payload architecture is missing')
        floor = (minimum[0], 0) if minimum[0] >= 11 else minimum[:2]
        return python, abi, f'macosx_{floor[0]}_{floor[1]}_{architecture}'


setup(
    ext_modules=[Extension("stallionfs._scan", ["stallionfs/_scan.c", "stallionfs/_tree.c", "stallionfs/_walk.c"],
                           depends=[HEADER], extra_compile_args=FLAGS, extra_link_args=LINK_FLAGS),
                 Extension("stallionfs._image", ["stallionfs/_image.c", "stallionfs/_native_import.c", "filesystem/image.c"],
                           include_dirs=["filesystem"], depends=["filesystem/image.h", "stallionfs/_native_import.h"],
                           extra_compile_args=FLAGS, extra_link_args=LINK_FLAGS)],
    scripts=["stallionfs/_main.c"],
    cmdclass={"build_scripts": NativeScripts, "build_py": BenchmarkResources, "bdist_wheel": PayloadWheel},
)
