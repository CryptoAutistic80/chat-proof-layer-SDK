from __future__ import annotations

import os
import shutil
import subprocess
import sys
import sysconfig
from pathlib import Path


def _built_library_path(target_dir: Path) -> Path:
    if sys.platform.startswith("linux"):
        return target_dir / "libproof_layer_pyo3.so"
    if sys.platform == "darwin":
        return target_dir / "libproof_layer_pyo3.dylib"
    if sys.platform == "win32":
        return target_dir / "proof_layer_pyo3.dll"
    raise RuntimeError(f"unsupported platform: {sys.platform}")


def main() -> None:
    script_path = Path(__file__).resolve()
    package_root = script_path.parents[1]
    repo_root = package_root.parents[1]
    profile = (
        "release"
        if sys.argv[1:] == ["--release"] or os.environ.get("PROOF_SDK_NATIVE_PROFILE") == "release"
        else "debug"
    )
    target_dir = repo_root / "target" / profile

    cargo_cmd = ["cargo", "build", "-p", "proof-layer-pyo3"]
    if profile == "release":
        cargo_cmd.append("--release")
    subprocess.run(
        cargo_cmd,
        cwd=repo_root,
        check=True,
    )

    built_library = _built_library_path(target_dir)
    if not built_library.exists():
        raise FileNotFoundError(f"expected built library at {built_library}")

    ext_suffix = sysconfig.get_config_var("EXT_SUFFIX") or (".pyd" if sys.platform == "win32" else ".so")
    target_dir_python = package_root / "proofsdk"
    target_path = target_dir_python / f"_native{ext_suffix}"

    for stale in target_dir_python.glob("_native*.so"):
        stale.unlink()
    for stale in target_dir_python.glob("_native*.pyd"):
        stale.unlink()

    shutil.copy2(built_library, target_path)
    print(f"copied {built_library} -> {target_path}")


if __name__ == "__main__":
    main()
