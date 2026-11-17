"""Load the bundled library on this platform and send one real request.

Used by CI inside alpine / i386 / arm containers, where installing the test suite is more
trouble than it is worth:

    docker run --rm -v "$PWD:/src" -w /src -e PYTHONPATH=/src python:3.12-alpine \
        python scripts/smoke_test.py

Exits non-zero (with the reason) if the library does not load or the request fails.
"""
import ctypes
import platform
import sys

sys.path.insert(0, ".")

from skeltahtls import Session, library_version  # noqa: E402
from skeltahtls import _cffi, _platform  # noqa: E402


def main() -> int:
    print(f"python {platform.python_version()} on {sys.platform}/{platform.machine()}, "
          f"{ctypes.sizeof(ctypes.c_void_p) * 8}-bit, libc {platform.libc_ver()}")
    print(f"library: {_platform.shared_library_name()} ({library_version()})")
    _cffi._load()
    print("loaded")
    with Session() as s:
        r = s.get("https://tls.browserleaks.com/json", timeout=30)
        print(f"status {r.status_code}, {r.http_version}, ja4 {r.json().get('ja4')}")
        return 0 if r.status_code == 200 else 1


if __name__ == "__main__":
    sys.exit(main())
