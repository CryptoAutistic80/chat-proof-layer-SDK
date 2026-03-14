from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from generate_schemas import build_expected_schema_files


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate release/version metadata for SDK artifacts.")
    parser.add_argument(
        "--expect-version",
        help="Require all package metadata to match this release version (for example, 0.1.0).",
    )
    return parser.parse_args()


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_workspace_version(repo_root: Path) -> str:
    cargo = read_text(repo_root / "Cargo.toml")
    match = re.search(
        r"^\[workspace\.package\]\s+version = \"([^\"]+)\"",
        cargo,
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError("failed to parse workspace.package.version")
    return match.group(1)


def parse_python_version(repo_root: Path) -> str:
    pyproject = read_text(repo_root / "packages" / "sdk-python" / "pyproject.toml")
    match = re.search(r"^\[project\]\s+name = \"[^\"]+\"\s+version = \"([^\"]+)\"", pyproject, re.MULTILINE)
    if match is None:
        raise RuntimeError("failed to parse project.version from packages/sdk-python/pyproject.toml")
    return match.group(1)


def parse_typescript_package(repo_root: Path) -> dict[str, object]:
    return json.loads(read_text(repo_root / "sdks" / "typescript" / "package.json"))


def main() -> None:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]

    workspace_version = parse_workspace_version(repo_root)
    python_version = parse_python_version(repo_root)
    ts_package = parse_typescript_package(repo_root)
    ts_version = str(ts_package["version"])
    schema_manifest = json.loads(read_text(repo_root / "schemas" / "schema_manifest.json"))
    schema_manifest_version = str(schema_manifest["release_version"])

    versions = {
        "workspace": workspace_version,
        "typescript": ts_version,
        "python": python_version,
        "schema_manifest": schema_manifest_version,
    }

    unique_versions = set(versions.values())
    if len(unique_versions) != 1:
        raise SystemExit(
            "release version mismatch: "
            + ", ".join(f"{name}={value}" for name, value in versions.items())
        )

    expected_version = args.expect_version
    if expected_version is not None and workspace_version != expected_version:
        raise SystemExit(
            f"release tag/version mismatch: expected {expected_version}, found {workspace_version}"
        )

    expected_files = build_expected_schema_files(repo_root)
    drifted = []
    for path, contents in expected_files.items():
        current = read_text(path) if path.exists() else None
        if current != contents:
            drifted.append(path.relative_to(repo_root).as_posix())
    if drifted:
        raise SystemExit(
            "schema artifacts are stale: "
            + ", ".join(drifted)
            + ". Run `python3 ./scripts/generate_schemas.py`."
        )

    print(
        json.dumps(
            {
                "version": workspace_version,
                "typescript_package": ts_package["name"],
                "python_package": "proof-layer-sdk-python",
                "schema_manifest": "schemas/schema_manifest.json",
                "schema_files_checked": sorted(
                    path.relative_to(repo_root).as_posix() for path in expected_files
                ),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
