"""Pick the bundled tls-client shared library for the running platform."""
from __future__ import annotations

import ctypes
import os
import platform
import sys
from pathlib import Path

DEPENDENCIES_DIR = Path(__file__).resolve().parent / "dependencies"
ENV_OVERRIDE = "SKELTAHTLS_LIBRARY"


def _is_musl() -> bool:
    # glibc reports a version; musl (alpine) reports nothing
    try:
        libc, _ = platform.libc_ver()
        if libc == "glibc":
            return False
    except Exception:  # pragma: no cover
        pass
    return any(Path("/lib").glob("ld-musl-*")) if Path("/lib").exists() else False


def shared_library_name() -> str:
    machine = platform.machine().lower()
    is_64 = ctypes.sizeof(ctypes.c_void_p) == 8

    if sys.platform in ("win32", "cygwin"):
        return "tls-client-windows-amd64.dll" if is_64 else "tls-client-windows-386.dll"

    if sys.platform == "darwin":
        return "tls-client-darwin-arm64.dylib" if machine in ("arm64", "aarch64") else "tls-client-darwin-amd64.dylib"

    # linux / other unix. The machine name is the kernel's, so a 32-bit userland on a
    # 64-bit kernel (Raspberry Pi OS, i386 containers) reports aarch64 / x86_64; the
    # pointer size of this interpreter is what decides which library it can load.
    if machine in ("aarch64", "arm64", "armv8l", "armv8b") or machine.startswith("arm"):
        return "tls-client-linux-arm64.so" if is_64 else "tls-client-linux-armv7.so"
    if machine in ("x86_64", "amd64", "i386", "i486", "i586", "i686", "x86"):
        if not is_64:
            return "tls-client-linux-386.so"
        if _is_musl():
            return "tls-client-linux-musl-amd64.so"
        return "tls-client-linux-amd64.so"
    raise OSError(
        f"skeltahtls has no tls-client library for {sys.platform}/{platform.machine()}; "
        f"build one (scripts/build_binaries.py) and point {ENV_OVERRIDE} at it"
    )


def shared_library_path() -> Path:
    override = os.environ.get(ENV_OVERRIDE)
    if override:
        path = Path(override)
        if not path.is_file():
            raise FileNotFoundError(f"{ENV_OVERRIDE} points to a missing file: {path}")
        return path

    path = DEPENDENCIES_DIR / shared_library_name()
    if not path.is_file():
        raise FileNotFoundError(
            f"No bundled tls-client library for this platform ({sys.platform}/{platform.machine()}): "
            f"expected {path}. Run scripts/update_binaries.py or set {ENV_OVERRIDE}."
        )
    return path
