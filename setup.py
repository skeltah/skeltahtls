"""Per-platform wheels.

Everything else lives in pyproject.toml; this file only exists for the build hook below.

    SKELTAHTLS_TARGET=linux-amd64 python -m build --wheel
        -> skeltahtls-X-py3-none-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
           holding just tls-client-linux-amd64.so (~15 MB instead of all of them)

Without SKELTAHTLS_TARGET (an sdist install, a checkout) the wheel is py3-none-any and
carries every bundled library, which is what the sdist falls back to on a platform with
no wheel of its own.
"""
import os

# target -> (library file, wheel platform tag)
TARGETS = {
    "windows-amd64": ("tls-client-windows-amd64.dll", "win_amd64"),
    "windows-386": ("tls-client-windows-386.dll", "win32"),
    "linux-amd64": ("tls-client-linux-amd64.so", "manylinux_2_17_x86_64.manylinux2014_x86_64"),
    "linux-386": ("tls-client-linux-386.so", "manylinux_2_17_i686.manylinux2014_i686"),
    "linux-arm64": ("tls-client-linux-arm64.so", "manylinux_2_17_aarch64.manylinux2014_aarch64"),
    "linux-armv7": ("tls-client-linux-armv7.so", "manylinux_2_17_armv7l.manylinux2014_armv7l"),
    "darwin-arm64": ("tls-client-darwin-arm64.dylib", "macosx_12_0_arm64"),
    "darwin-amd64": ("tls-client-darwin-amd64.dylib", "macosx_12_0_x86_64"),
}
LIBRARY_SUFFIXES = (".dll", ".so", ".dylib")

TARGET = os.environ.get("SKELTAHTLS_TARGET") or None
if TARGET is not None and TARGET not in TARGETS:
    raise SystemExit(f"SKELTAHTLS_TARGET={TARGET!r} is not one of: {', '.join(TARGETS)}")


def _commands():
    # imported here so scripts/build_wheels.py can read TARGETS without a new setuptools
    from setuptools.command.build_py import build_py

    try:
        from setuptools.command.bdist_wheel import bdist_wheel
    except ImportError:  # setuptools < 70.1
        from wheel.bdist_wheel import bdist_wheel

    class BuildPy(build_py):
        def find_data_files(self, package, src_dir):
            files = super().find_data_files(package, src_dir)
            if TARGET is None or package != "skeltahtls":
                return files
            keep = TARGETS[TARGET][0]
            kept = [f for f in files if not f.endswith(LIBRARY_SUFFIXES) or os.path.basename(f) == keep]
            if not any(os.path.basename(f) == keep for f in kept):
                raise SystemExit(f"{keep} is missing from skeltahtls/dependencies")
            return kept

    class BdistWheel(bdist_wheel):
        def finalize_options(self):
            super().finalize_options()
            if TARGET is not None:
                self.root_is_pure = False

        def get_tag(self):
            if TARGET is None:
                return super().get_tag()
            # ctypes only: any Python 3, no ABI, one platform
            return "py3", "none", TARGETS[TARGET][1]

    return {"build_py": BuildPy, "bdist_wheel": BdistWheel}


if __name__ == "__main__":  # setuptools runs this file as __main__; scripts/build_wheels.py imports it
    from setuptools import setup

    setup(cmdclass=_commands())
