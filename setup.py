from pathlib import Path
from shutil import copy2
from setuptools import Extension, setup
from setuptools.command.build_py import build_py
import hashlib
import json
from distutils.ccompiler import new_compiler
from distutils.command.build_scripts import build_scripts
from distutils.sysconfig import customize_compiler

NATIVE = ["stallionfs/_main.c", "stallionfs/_tree.c", "stallionfs/_walk.c"]
HEADER = "stallionfs/_tree.h"
FLAGS = ["-O2", "-Wall", "-Wextra"]


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
        compiler.link_executable(objects, "stallionfs", output_dir=self.build_dir)
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


class BenchmarkResources(build_py):
    """Ship the existing collectors, not repository tests or generated reports."""
    def run(self):
        super().run()
        destination = Path(self.build_lib) / 'stallionfs' / '_benchmark_runtime'
        resources = {}
        for source in BENCHMARK_INPUTS:
            relative = Path(source).relative_to('tests/perf')
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            copy2(source, target)
            resources[relative.as_posix()] = hashlib.sha256(Path(source).read_bytes()).hexdigest()
        sources = [Path('setup.py'), Path('pyproject.toml'),
                   *(file for file in Path('stallionfs').iterdir()
                     if file.is_file() and file.suffix in ('.py', '.c', '.h'))]
        manifest = {'schema': 1, 'kind': 'build-source provenance', 'resources': resources,
                    'build_source_sha256': {file.as_posix(): hashlib.sha256(file.read_bytes()).hexdigest()
                                            for file in sorted(sources)}}
        (destination / 'manifest.json').write_text(json.dumps(manifest, sort_keys=True) + '\n')

    def get_source_files(self):
        return [*super().get_source_files(), *BENCHMARK_INPUTS]

    def get_outputs(self, include_bytecode=1):
        destination = Path(self.build_lib) / 'stallionfs' / '_benchmark_runtime'
        return [*super().get_outputs(include_bytecode),
                *(str(destination / Path(name).relative_to('tests/perf')) for name in BENCHMARK_INPUTS),
                str(destination / 'manifest.json')]


setup(
    ext_modules=[Extension("stallionfs._scan", ["stallionfs/_scan.c", "stallionfs/_tree.c", "stallionfs/_walk.c"],
                           depends=[HEADER], extra_compile_args=FLAGS),
                 Extension("stallionfs._image", ["stallionfs/_image.c", "filesystem/image.c"],
                           include_dirs=["filesystem"], depends=["filesystem/image.h"], extra_compile_args=FLAGS)],
    scripts=["stallionfs/_main.c"],
    cmdclass={"build_scripts": NativeScripts, "build_py": BenchmarkResources},
)
