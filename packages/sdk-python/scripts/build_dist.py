from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


REQUIRED_WHEEL_ENTRIES = (
    "proofsdk/__init__.py",
    "proofsdk/native.py",
    "proofsdk/py.typed",
)


def main() -> None:
    script_path = Path(__file__).resolve()
    package_root = script_path.parents[1]
    dist_dir = package_root / "dist"
    env = os.environ.copy()
    env.setdefault("PROOF_SDK_NATIVE_PROFILE", "release")

    shutil.rmtree(dist_dir, ignore_errors=True)
    dist_dir.mkdir(parents=True)

    subprocess.run(
        [sys.executable, "-m", "build", "--wheel", "--outdir", str(dist_dir)],
        cwd=package_root,
        env=env,
        check=True,
    )

    wheels = sorted(dist_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel artifact in {dist_dir}, found {len(wheels)}")

    wheel_path = wheels[0]
    with zipfile.ZipFile(wheel_path) as wheel:
        members = set(wheel.namelist())
        for entry in REQUIRED_WHEEL_ENTRIES:
            if not any(name.endswith(entry) for name in members):
                raise RuntimeError(f"wheel is missing required entry {entry}")
        if not any("/proofsdk/_native" in name or name.startswith("proofsdk/_native") for name in members):
            raise RuntimeError("wheel is missing the native proofsdk/_native extension module")
        wheel_metadata_name = next(
            (name for name in members if name.endswith(".dist-info/WHEEL")),
            None,
        )
        if wheel_metadata_name is None:
            raise RuntimeError("wheel is missing .dist-info/WHEEL metadata")
        wheel_metadata = wheel.read(wheel_metadata_name).decode("utf-8")
        if "Root-Is-Purelib: false" not in wheel_metadata:
            raise RuntimeError("wheel metadata still marks the package as pure-Python")

    print(
        json.dumps(
            {
                "wheel": str(wheel_path),
                "checked_entries": [
                    *REQUIRED_WHEEL_ENTRIES,
                    "proofsdk/_native*",
                ],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
