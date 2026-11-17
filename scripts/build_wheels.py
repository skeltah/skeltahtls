"""Build the sdist and one wheel per platform into dist/.

    python scripts/build_wheels.py                 # sdist + every platform wheel
    python scripts/build_wheels.py linux-amd64     # just these wheels

Each wheel holds only its own tls-client library; see setup.py for the tags.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from setup import LIBRARY_SUFFIXES, TARGETS  # noqa: E402


def clean() -> None:
    # build/lib keeps the libraries of the previous target otherwise
    shutil.rmtree(ROOT / "build", ignore_errors=True)
    for egg in ROOT.glob("*.egg-info"):
        shutil.rmtree(egg, ignore_errors=True)


def build(*args: str, target: str = "") -> None:
    env = dict(os.environ)
    env.pop("SKELTAHTLS_TARGET", None)
    if target:
        env["SKELTAHTLS_TARGET"] = target
    clean()
    subprocess.run([sys.executable, "-m", "build", "--outdir", "dist", *args], cwd=ROOT, env=env, check=True)


def main() -> int:
    targets = sys.argv[1:] or list(TARGETS)
    unknown = [t for t in targets if t not in TARGETS]
    if unknown:
        sys.exit(f"unknown target(s): {', '.join(unknown)}; pick from {', '.join(TARGETS)}")
    if not sys.argv[1:]:
        build("--sdist")
    for target in targets:
        build("--wheel", target=target)

    # every wheel must hold exactly its own library
    for wheel in sorted((ROOT / "dist").glob("*.whl")):
        with zipfile.ZipFile(wheel) as z:
            libs = [n for n in z.namelist() if n.endswith(LIBRARY_SUFFIXES)]
        tag = wheel.name.rsplit("-", 1)[-1][:-4]
        expected = [lib for lib, plat in TARGETS.values() if plat == tag]
        status = "ok" if [Path(n).name for n in libs] == expected else f"WRONG {libs}"
        print(f"{wheel.name:90s} {wheel.stat().st_size / 1e6:6.1f} MB  {status}")
        if status != "ok":
            return 1
    clean()
    return 0


if __name__ == "__main__":
    sys.exit(main())
