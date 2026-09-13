"""Download bogdanfinn/tls-client shared libraries (GitHub release assets).

Prefer scripts/build_binaries.py: upstream release binaries are built against the previous
tls-client version (cffi_dist/go.mod pins it), so they can lag behind the tagged source.
Use this script for platforms you cannot build (e.g. macOS without an SDK).

Usage:
    python scripts/update_binaries.py                 # version from manifest.json, all platforms
    python scripts/update_binaries.py 1.16.0          # explicit version
    python scripts/update_binaries.py latest          # newest GitHub release
    python scripts/update_binaries.py 1.16.0 darwin   # only assets whose shipped name contains "darwin"

Every file is downloaded to a temp path, hashed, and only then moved into
skeltahtls/dependencies/. The manifest records version + sha256 per file so
the package can verify what it ships.
"""
from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEP_DIR = ROOT / "skeltahtls" / "dependencies"
MANIFEST = DEP_DIR / "manifest.json"
RELEASE_URL = "https://github.com/bogdanfinn/tls-client/releases/download/v{version}/{asset}"
LATEST_API = "https://api.github.com/repos/bogdanfinn/tls-client/releases/latest"

# GitHub asset name template -> name we ship under (must match skeltahtls/_platform.py)
ASSETS = {
    "tls-client-windows-64-{v}.dll": "tls-client-windows-amd64.dll",
    "tls-client-windows-32-{v}.dll": "tls-client-windows-386.dll",
    "tls-client-darwin-arm64-{v}.dylib": "tls-client-darwin-arm64.dylib",
    "tls-client-darwin-amd64-{v}.dylib": "tls-client-darwin-amd64.dylib",
    "tls-client-linux-ubuntu-amd64-{v}.so": "tls-client-linux-amd64.so",
    "tls-client-linux-alpine-amd64-{v}.so": "tls-client-linux-musl-amd64.so",
    "tls-client-linux-arm64-{v}.so": "tls-client-linux-arm64.so",
    "tls-client-linux-armv7-{v}.so": "tls-client-linux-armv7.so",
}


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_version(arg: str | None) -> str:
    if arg and arg != "latest":
        return arg.lstrip("v")
    if arg == "latest" or not MANIFEST.exists():
        with urllib.request.urlopen(LATEST_API, timeout=30) as r:
            return json.load(r)["tag_name"].lstrip("v")
    return json.loads(MANIFEST.read_text())["version"]


def download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "skeltahtls-updater"})
    with urllib.request.urlopen(req, timeout=300) as r, dest.open("wb") as f:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            f.write(chunk)


def main() -> int:
    version = resolve_version(sys.argv[1] if len(sys.argv) > 1 else None)
    only = sys.argv[2:] if len(sys.argv) > 2 else []
    print(f"tls-client v{version}")
    DEP_DIR.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST.read_text()) if MANIFEST.exists() else {}
    files: dict[str, dict] = manifest.get("files", {})

    with tempfile.TemporaryDirectory() as tmp:
        for template, shipped in ASSETS.items():
            if only and not any(o in shipped for o in only):
                continue
            asset = template.format(v=version)
            url = RELEASE_URL.format(version=version, asset=asset)
            tmp_path = Path(tmp) / shipped
            print(f"  {asset:45s} -> {shipped} ...", end=" ", flush=True)
            download(url, tmp_path)
            digest = sha256_of(tmp_path)
            size = tmp_path.stat().st_size
            if size < 1_000_000:
                print(f"FAILED (only {size} bytes)")
                return 1
            tmp_path.replace(DEP_DIR / shipped)
            files[shipped] = {
                "source": f"{RELEASE_URL.format(version=version, asset=asset)}",
                "sha256": digest,
                "size": size,
                # release assets are built against the previous tls-client version, see build_binaries.py
                "features": {"custom_client_grease_mldsa_sigalgs": False},
            }
            print(f"{size / 1e6:.1f} MB  {digest[:12]}")

    MANIFEST.write_text(json.dumps({
        "version": version,
        "source": "https://github.com/bogdanfinn/tls-client/releases/tag/v" + version,
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "files": files,
    }, indent=2) + "\n")
    print(f"manifest written: {MANIFEST}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
