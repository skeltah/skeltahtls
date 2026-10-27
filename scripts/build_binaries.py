"""Build the tls-client shared libraries from source (bogdanfinn/tls-client tag).

Why not just download the GitHub release assets? The upstream cffi_dist/go.mod pins the
*previous* tls-client version, so release binaries lag behind the tagged source (v1.16.0's
DLL does not know the "GREASE"/"MLDSA*" signature-algorithm names that the v1.16.0 source
maps, which breaks custom ja3 clients that mimic Chrome 150+). Building from the tag with
``replace github.com/bogdanfinn/tls-client => ../`` gives binaries that match the source.

Requirements:
  * Go (https://go.dev/dl/) - the version in go.mod or newer
  * zig (https://ziglang.org/download/) for cross compiling C (cgo) - portable zip is fine
    Set ZIG=/path/to/zig if it is not on PATH.
  * git

Usage:
    python scripts/build_binaries.py                     # ref from manifest, all targets
    python scripts/build_binaries.py v1.17.1             # a tag
    python scripts/build_binaries.py master              # a branch
    python scripts/build_binaries.py v1.17.1 linux-amd64 windows-amd64   # a subset

Upstream tags and GitHub releases do not line up: v1.17.0 and v1.17.1 exist as tags with
no release behind them, so the release assets (and update_binaries.py) stop at v1.16.0
while the source has moved on.

macOS targets need the Apple SDK and are skipped unless MACOS_SDK=/path/to/MacOSX.sdk is set
(zig can then link against it); otherwise keep the upstream dylibs from update_binaries.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parent.parent
DEP_DIR = ROOT / "skeltahtls" / "dependencies"
MANIFEST = DEP_DIR / "manifest.json"
REPO = "https://github.com/bogdanfinn/tls-client.git"

# name -> (GOOS, GOARCH, zig target, extra env)
TARGETS = {
    "windows-amd64": ("windows", "amd64", "x86_64-windows-gnu", {}),
    "windows-386": ("windows", "386", "x86-windows-gnu", {}),
    "linux-amd64": ("linux", "amd64", "x86_64-linux-gnu.2.17", {}),
    "linux-musl-amd64": ("linux", "amd64", "x86_64-linux-musl", {}),
    "linux-arm64": ("linux", "arm64", "aarch64-linux-gnu.2.17", {}),
    "linux-armv7": ("linux", "arm", "arm-linux-gnueabihf.2.17", {"GOARM": "7"}),
    "darwin-arm64": ("darwin", "arm64", "aarch64-macos", {}),
    "darwin-amd64": ("darwin", "amd64", "x86_64-macos", {}),
}
EXT = {"windows": ".dll", "linux": ".so", "darwin": ".dylib"}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, cwd=None, env=None, check=True):
    print("   $", " ".join(str(c) for c in cmd))
    return subprocess.run(cmd, cwd=cwd, env=env, check=check, text=True, capture_output=True)


def find_zig() -> Optional[str]:
    zig = os.environ.get("ZIG") or shutil.which("zig")
    if not zig and platform.system() != "Darwin":
        sys.exit("zig not found: install it (https://ziglang.org/download/) or set ZIG=/path/to/zig")
    return zig


def main() -> int:
    args = [a for a in sys.argv[1:]]
    ref = None
    if args and args[0] not in TARGETS:
        ref = args.pop(0)
    if ref is None and MANIFEST.exists():
        recorded = json.loads(MANIFEST.read_text()).get("version")
        ref = f"v{recorded}" if recorded else None
    if ref is None:
        sys.exit("no ref given and no manifest.json to read one from")
    unknown = [a for a in args if a not in TARGETS]
    if unknown:
        sys.exit(f"unknown target(s): {', '.join(unknown)}; pick from {', '.join(TARGETS)}")
    wanted = args or list(TARGETS)

    zig = find_zig()
    go_version = run(["go", "version"]).stdout.strip()
    zig_version = run([zig, "version"]).stdout.strip() if zig else "n/a"
    print(f"ref {ref} | {go_version} | zig {zig_version}")

    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {"files": {}}
    manifest.setdefault("files", {})

    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "tls-client"
        run(["git", "clone", "-q", "--depth", "1", "--branch", ref, REPO, str(src)])
        commit = run(["git", "rev-parse", "HEAD"], cwd=src).stdout.strip()
        # a tag gives its own name, a branch gives "<last tag>-<commits>-g<sha>"
        described = run(["git", "describe", "--tags", "--always"], cwd=src, check=False).stdout.strip()
        version = (described or ref).lstrip("v")
        dist = src / "cffi_dist"
        gomod = dist / "go.mod"
        gomod.write_text(gomod.read_text() + "\n// build against the checked-out source instead of the pinned release\n"
                         "replace github.com/bogdanfinn/tls-client => ../\n")
        run(["go", "mod", "tidy"], cwd=dist)

        for name in wanted:
            goos, goarch, zig_target, extra = TARGETS[name]
            out = DEP_DIR / f"tls-client-{name}{EXT[goos]}"
            print(f"== {name} -> {out.name}")
            env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="1", **extra)
            if zig:
                env["CC"], env["CXX"] = f"{zig} cc -target {zig_target}", f"{zig} c++ -target {zig_target}"
            elif goos != "darwin":
                print("   skipped: zig required for cross compiling this target")
                continue
            if goos == "darwin":
                if platform.system() == "Darwin":
                    # native toolchain (Xcode CLT) handles both arches, no zig needed
                    arch = "arm64" if goarch == "arm64" else "x86_64"
                    env["CC"], env["CXX"] = f"clang -arch {arch}", f"clang++ -arch {arch}"
                else:
                    sdk = os.environ.get("MACOS_SDK")
                    if not sdk:
                        print("   skipped: set MACOS_SDK=/path/to/MacOSX.sdk (or run on macOS) to build darwin targets")
                        continue
                    env["CGO_CFLAGS"] = f"-isysroot {sdk}"
                    env["CGO_LDFLAGS"] = f"-isysroot {sdk} -F{sdk}/System/Library/Frameworks"
            tmp_out = dist / "dist" / out.name
            tmp_out.parent.mkdir(exist_ok=True)
            res = run(["go", "build", "-trimpath", "-ldflags=-s -w", "-buildmode=c-shared", "-o", str(tmp_out), "."],
                      cwd=dist, env=env, check=False)
            if res.returncode != 0:
                print("   FAILED:\n" + "\n".join("   " + l for l in (res.stderr or res.stdout).splitlines()[-15:]))
                continue
            DEP_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tmp_out, out)
            manifest["files"][out.name] = {
                "version": version,
                "source": f"built from {REPO}@{ref} ({commit[:12]}) with {go_version.split()[2]} / zig {zig_version}",
                "sha256": sha256_of(out),
                "size": out.stat().st_size,
                "features": {"custom_client_grease_mldsa_sigalgs": True},
            }
            print(f"   ok {out.stat().st_size / 1e6:.1f} MB")

    manifest["version"] = version
    manifest["source"] = f"https://github.com/bogdanfinn/tls-client/tree/{commit}"
    manifest["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    versions = {entry.get("version", manifest["version"]) for entry in manifest["files"].values()}
    if len(versions) > 1:
        print("NOTE: the bundled libraries are not all the same version: " + ", ".join(sorted(versions)))
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"manifest written: {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
