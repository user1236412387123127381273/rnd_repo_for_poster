# pylint: disable=missing-class-docstring
from __future__ import annotations
import glob
import importlib.resources
import os
import platform
import shutil
import subprocess
import sys
from distutils.command.build import build as st_build
from distutils.util import get_platform

from setuptools import Command, setup
from setuptools.command.develop import develop as st_develop
from setuptools.errors import LibError

if sys.platform == "darwin":
    library_file = "bisa_native.dylib"
elif sys.platform in ("win32", "cygwin"):
    library_file = "bisa_native.dll"
else:
    library_file = "bisa_native.so"


def _build_native():
    try:
        importlib.import_module("pyvex")
    except ImportError as e:
        raise LibError("You must install pyvex before building bisa") from e

    env = os.environ.copy()
    env_data = (
        ("PYVEX_INCLUDE_PATH", "pyvex", "include"),
        ("PYVEX_LIB_PATH", "pyvex", "lib"),
        ("PYVEX_LIB_FILE", "pyvex", "lib\\pyvex.lib"),
    )
    for var, pkg, fnm in env_data:
        base = importlib.resources.files(pkg)
        for child in fnm.split("\\"):
            base = base.joinpath(child)
        env[var] = str(base)

    if sys.platform == "win32":
        cmd = ["nmake", "/f", "Makefile-win"]
    elif shutil.which("gmake") is not None:
        cmd = ["gmake"]
    else:
        cmd = ["make"]
    try:
        subprocess.run(cmd, cwd="native", env=env, check=True)
    except FileNotFoundError as err:
        raise LibError("Couldn't find " + cmd[0] + " in PATH") from err
    except subprocess.CalledProcessError as err:
        raise LibError("Error while building bisa_native: " + str(err)) from err

    shutil.rmtree("bisa/lib", ignore_errors=True)
    os.mkdir("bisa/lib")
    shutil.copy(os.path.join("native", library_file), "bisa/lib")


def _clean_native():
    oglob = glob.glob("native/*.o")
    oglob += glob.glob("native/*.obj")
    oglob += glob.glob("native/*.so")
    oglob += glob.glob("native/*.dll")
    oglob += glob.glob("native/*.dylib")
    for fname in oglob:
        os.unlink(fname)


class build(st_build):
    def run(self, *args):
        self.execute(_build_native, (), msg="Building bisa_native")
        super().run(*args)


class clean_native(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.execute(_clean_native, (), msg="Cleaning bisa_native")


class develop(st_develop):
    def run(self):
        self.run_command("build")
        super().run()


cmdclass = {
    "build": build,
    "clean_native": clean_native,
    "develop": develop,
}


try:
    from setuptools.command.editable_wheel import editable_wheel as st_editable_wheel

    class editable_wheel(st_editable_wheel):
        def run(self):
            self.run_command("build")
            super().run()

    cmdclass["editable_wheel"] = editable_wheel
except ModuleNotFoundError:
    pass


if "bdist_wheel" in sys.argv and "--plat-name" not in sys.argv:
    sys.argv.append("--plat-name")
    name = get_platform()
    if "linux" in name:
        sys.argv.append("manylinux2014_" + platform.machine())
    else:
        # https://www.python.org/dev/peps/pep-0425/
        sys.argv.append(name.replace(".", "_").replace("-", "_"))

setup(cmdclass=cmdclass)
