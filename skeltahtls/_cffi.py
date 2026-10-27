"""ctypes bindings for the bogdanfinn/tls-client shared library.

Every exported function takes a JSON string and returns a JSON string that must
be released with freeMemory(id) once parsed. `call()` wraps that protocol.
"""
from __future__ import annotations

import ctypes
import json
import threading
from typing import Any, Dict

from ._platform import shared_library_path

_lock = threading.Lock()
_lib = None


def _load():
    global _lib
    if _lib is not None:
        return _lib
    with _lock:
        if _lib is None:
            lib = ctypes.cdll.LoadLibrary(str(shared_library_path()))
            for name in ("request", "getCookiesFromSession", "addCookiesToSession", "destroySession"):
                fn = getattr(lib, name)
                fn.argtypes = [ctypes.c_char_p]
                fn.restype = ctypes.c_void_p  # raw pointer: we read it ourselves and never let ctypes free it
            lib.freeMemory.argtypes = [ctypes.c_char_p]
            lib.freeMemory.restype = None
            lib.destroyAll.argtypes = []
            lib.destroyAll.restype = ctypes.c_void_p
            _lib = lib
    return _lib


def call(function_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Call an exported function with a JSON payload and return the parsed JSON response."""
    lib = _load()
    fn = getattr(lib, function_name)
    raw_ptr = fn(json.dumps(payload).encode("utf-8"))
    if not raw_ptr:
        raise RuntimeError(f"tls-client {function_name} returned NULL")
    raw = ctypes.string_at(raw_ptr)
    response = json.loads(raw.decode("utf-8"))
    response_id = response.get("id")
    if response_id:
        lib.freeMemory(response_id.encode("utf-8"))
    return response


def destroy_all() -> None:
    lib = _load()
    raw_ptr = lib.destroyAll()
    if raw_ptr:
        response = json.loads(ctypes.string_at(raw_ptr).decode("utf-8"))
        if response.get("id"):
            lib.freeMemory(response["id"].encode("utf-8"))


def _manifest() -> Dict[str, Any]:
    from ._platform import DEPENDENCIES_DIR
    manifest = DEPENDENCIES_DIR / "manifest.json"
    if manifest.is_file():
        try:
            return json.loads(manifest.read_text())
        except ValueError:
            pass
    return {}


def library_version() -> str:
    """Version of the tls-client library in use, from dependencies/manifest.json.

    Per-file, because the bundled libraries can come from different upstream versions
    (a platform whose binary has to come from a release lags the ones built from source).
    """
    import os
    from ._platform import ENV_OVERRIDE, shared_library_path
    manifest = _manifest()
    if not os.environ.get(ENV_OVERRIDE):
        entry = manifest.get("files", {}).get(shared_library_path().name, {})
        if entry.get("version"):
            return str(entry["version"])
    return manifest.get("version", "unknown")


def library_features() -> Dict[str, bool]:
    """Feature flags recorded for the library file in use (empty for SKELTAHTLS_LIBRARY overrides
    and unknown files - callers should treat missing flags as "supported")."""
    import os
    from ._platform import ENV_OVERRIDE, shared_library_path
    if os.environ.get(ENV_OVERRIDE):
        return {}
    entry = _manifest().get("files", {}).get(shared_library_path().name, {})
    return dict(entry.get("features", {}))
