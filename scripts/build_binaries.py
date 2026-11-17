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
(zig can then link against it), or run on a Mac.

linux-386 is built with gcc inside quay.io/pypa/manylinux2014_i686 (needs docker): the zig
build of it loads and then segfaults in the Go runtime, while the gcc one works (checked in
an i386 container) and needs nothing newer than glibc 2.3.2.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
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
    "linux-386": ("linux", "386", None, {}),  # gcc in DOCKER_IMAGES, see the docstring
    "linux-arm64": ("linux", "arm64", "aarch64-linux-gnu.2.17", {}),
    "linux-armv7": ("linux", "arm", "arm-linux-gnueabihf.2.17", {"GOARM": "7"}),
    "darwin-arm64": ("darwin", "arm64", "aarch64-macos", {}),
    "darwin-amd64": ("darwin", "amd64", "x86_64-macos", {}),
}
EXT = {"windows": ".dll", "linux": ".so", "darwin": ".dylib"}
# targets built natively inside a container instead of with zig
DOCKER_IMAGES = {"linux-386": ("quay.io/pypa/manylinux2014_i686", "linux/386")}


def build_in_docker(name: str, src: Path, tmp: Path, go_version: str, out_name: str) -> subprocess.CompletedProcess:
    """go build inside the target's own image with its own gcc and a Go toolchain for it."""
    image, docker_platform = DOCKER_IMAGES[name]
    goos, goarch = TARGETS[name][:2]
    go_release = go_version.split()[2]  # "go1.27.4"
    toolchain = tmp / f"go-{goos}-{goarch}"
    if not toolchain.exists():
        archive = tmp / f"{go_release}.{goos}-{goarch}.tar.gz"
        url = f"https://go.dev/dl/{archive.name}"
        print(f"   downloading {url}")
        urllib.request.urlretrieve(url, archive)
        toolchain.mkdir()
        with tarfile.open(archive) as t:
            t.extractall(toolchain)
    modcache = run(["go", "env", "GOMODCACHE"]).stdout.strip()
    run(["go", "mod", "download"], cwd=src / "cffi_dist")
    return run([
        "docker", "run", "--rm", "--platform", docker_platform,
        "-v", f"{src}:/w", "-v", f"{toolchain}:/tc", "-v", f"{modcache}:/gomod", "-w", "/w/cffi_dist",
        "-e", "GOMODCACHE=/gomod", "-e", "GOTOOLCHAIN=local", "-e", "GOFLAGS=-mod=mod",
        "-e", "CGO_ENABLED=1", "-e", f"GOOS={goos}", "-e", f"GOARCH={goarch}",
        image, "/tc/go/bin/go", "build", "-buildvcs=false", "-trimpath", "-ldflags=-s -w", "-buildmode=c-shared",
        "-o", f"/w/cffi_dist/dist/{out_name}", ".",
    ], check=False)


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

    failed = []
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "tls-client"
        run(["git", "clone", "-q", "--depth", "1", "--branch", ref, REPO, str(src)])
        commit = run(["git", "rev-parse", "HEAD"], cwd=src).stdout.strip()
        # the shallow clone has no tags; fetch enough history for describe to find the last one
        run(["git", "fetch", "-q", "--deepen", "200", "--tags", "origin"], cwd=src, check=False)
        # a tag gives its own name, a branch gives "<last tag>-<commits>-g<sha>"
        described = run(["git", "describe", "--tags", "--always"], cwd=src, check=False).stdout.strip()
        version = (described or ref).lstrip("v")
        dist = src / "cffi_dist"
        gomod = dist / "go.mod"
        gomod.write_text(gomod.read_text() + "\n// build against the checked-out source instead of the pinned release\n"
                         "replace github.com/bogdanfinn/tls-client => ../\n")
        run(["go", "mod", "tidy"], cwd=dist)
        # go.mod may ask for a newer Go than the one on PATH (GOTOOLCHAIN=auto switches to
        # it); record the toolchain that actually builds
        go_version = run(["go", "version"], cwd=dist).stdout.strip()
        print(f"building with {go_version}")

        for name in wanted:
            goos, goarch, zig_target, extra = TARGETS[name]
            out = DEP_DIR / f"tls-client-{name}{EXT[goos]}"
            print(f"== {name} -> {out.name}")
            env = dict(os.environ, GOOS=goos, GOARCH=goarch, CGO_ENABLED="1", **extra)
            tmp_out = dist / "dist" / out.name
            tmp_out.parent.mkdir(exist_ok=True)
            if name in DOCKER_IMAGES:
                if not shutil.which("docker"):
                    print(f"   skipped: needs docker ({DOCKER_IMAGES[name][0]})")
                    failed.append((name, "skipped: needs docker"))
                    continue
                res = build_in_docker(name, src, Path(tmp), go_version, out.name)
                toolchain_note = f"gcc in {DOCKER_IMAGES[name][0]}"
            elif zig:
                env["CC"], env["CXX"] = f"{zig} cc -target {zig_target}", f"{zig} c++ -target {zig_target}"
            elif goos != "darwin":
                print("   skipped: zig required for cross compiling this target")
                failed.append((name, "skipped: zig required"))
                continue
            if goos == "darwin":
                if platform.system() == "Darwin":
                    # native toolchain (Xcode CLT) handles both arches, no zig needed
                    arch = "arm64" if goarch == "arm64" else "x86_64"
                    # the wheels are tagged macosx_12_0 (Go 1.25+ needs macOS 12 anyway)
                    env["CC"] = f"clang -arch {arch} -mmacosx-version-min=12.0"
                    env["CXX"] = f"clang++ -arch {arch} -mmacosx-version-min=12.0"
                    env["MACOSX_DEPLOYMENT_TARGET"] = "12.0"
                else:
                    sdk = os.environ.get("MACOS_SDK")
                    if not sdk:
                        print("   skipped: set MACOS_SDK=/path/to/MacOSX.sdk (or run on macOS) to build darwin targets")
                        failed.append((name, "skipped: needs MACOS_SDK or a Mac"))
                        continue
                    env["CGO_CFLAGS"] = f"-isysroot {sdk}"
                    env["CGO_LDFLAGS"] = f"-isysroot {sdk} -F{sdk}/System/Library/Frameworks"
            if name not in DOCKER_IMAGES:
                res = run(["go", "build", "-trimpath", "-ldflags=-s -w", "-buildmode=c-shared", "-o", str(tmp_out), "."],
                          cwd=dist, env=env, check=False)
                native_mac = goos == "darwin" and platform.system() == "Darwin"
                toolchain_note = "clang" if native_mac else f"zig {zig_version}"
            if res.returncode != 0:
                tail = (res.stderr or res.stdout).splitlines()[-15:]
                print("   FAILED:\n" + "\n".join("   " + l for l in tail))
                failed.append((name, "\n".join(tail)))
                continue
            DEP_DIR.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tmp_out, out)
            manifest["files"][out.name] = {
                "version": version,
                "source": f"built from {REPO}@{ref} ({commit[:12]}) with {go_version.split()[2]} / {toolchain_note}",
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
    for name, why in failed:
        print(f"NOT BUILT: {name}: {why.splitlines()[0] if why else ''}")
        if os.environ.get("GITHUB_ACTIONS"):
            # an annotation is readable on the run page without the log
            message = why.replace("%", "%25").replace("\n", "%0A")
            print(f"::error title=build {name} failed::{message}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
