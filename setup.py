from setuptools import Extension, setup

setup(ext_modules=[Extension("stallionfs._scan", ["stallionfs/_scan.c"],
                             extra_compile_args=["-O2", "-Wall", "-Wextra"])])
