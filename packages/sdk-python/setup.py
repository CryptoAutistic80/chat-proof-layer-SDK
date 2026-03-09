from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from setuptools import setup
from setuptools.command.build_py import build_py as _build_py
try:
    from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
except ImportError:
    from wheel.bdist_wheel import bdist_wheel as _bdist_wheel


def _run_native_build() -> None:
    package_root = Path(__file__).resolve().parent
    script_path = package_root / "scripts" / "build_native.py"
    subprocess.run([sys.executable, str(script_path)], cwd=package_root, check=True)


class build_py(_build_py):
    def run(self) -> None:
        _run_native_build()
        super().run()


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        self.root_is_pure = False


setup(cmdclass={"build_py": build_py, "bdist_wheel": bdist_wheel})
