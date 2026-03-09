from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build checked SDK distribution artifacts.")
    parser.add_argument(
        "--profile",
        choices=("debug", "release"),
        default="release",
        help="Native Cargo profile to use for packaged SDK artifacts.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env["PROOF_SDK_NATIVE_PROFILE"] = args.profile

    subprocess.run(
        ["npm", "run", "pack:smoke"],
        cwd=repo_root / "sdks" / "typescript",
        env=env,
        check=True,
    )
    subprocess.run(
        [sys.executable, "./scripts/build_dist.py"],
        cwd=repo_root / "packages" / "sdk-python",
        env=env,
        check=True,
    )

    npm_artifacts = sorted((repo_root / "sdks" / "typescript" / "dist" / "artifacts").glob("*.tgz"))
    python_artifacts = sorted((repo_root / "packages" / "sdk-python" / "dist").glob("*.whl"))

    print(
        json.dumps(
            {
                "profile": args.profile,
                "typescript": [str(path) for path in npm_artifacts],
                "python": [str(path) for path in python_artifacts],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
