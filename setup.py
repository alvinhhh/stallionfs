from pathlib import Path
from setuptools import Extension, setup
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
        objects = compiler.compile(NATIVE, output_dir=temporary, extra_postargs=FLAGS, depends=[HEADER])
        compiler.link_executable(objects, "stallionfs", output_dir=self.build_dir)

    def get_outputs(self):
        return [str(Path(self.build_dir) / "stallionfs")]

    def get_source_files(self):
        return [*NATIVE, HEADER]


setup(
    ext_modules=[Extension("stallionfs._scan", ["stallionfs/_scan.c", "stallionfs/_tree.c", "stallionfs/_walk.c"],
                           depends=[HEADER], extra_compile_args=FLAGS)],
    scripts=["stallionfs/_main.c"],
    cmdclass={"build_scripts": NativeScripts},
)
