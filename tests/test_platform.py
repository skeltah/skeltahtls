"""Which bundled library a platform gets."""
import pytest

from skeltahtls import _platform


@pytest.fixture
def fake(monkeypatch):
    def apply(system, machine, bits, musl=False):
        monkeypatch.setattr(_platform.sys, "platform", system)
        monkeypatch.setattr(_platform.platform, "machine", lambda: machine)
        monkeypatch.setattr(_platform.ctypes, "sizeof", lambda t: bits // 8)
        monkeypatch.setattr(_platform, "_is_musl", lambda: musl)
        return _platform.shared_library_name()
    return apply


@pytest.mark.parametrize("system,machine,bits,musl,expected", [
    ("win32", "AMD64", 64, False, "tls-client-windows-amd64.dll"),
    ("win32", "AMD64", 32, False, "tls-client-windows-386.dll"),  # 32-bit Python on 64-bit Windows
    ("darwin", "arm64", 64, False, "tls-client-darwin-arm64.dylib"),
    ("darwin", "x86_64", 64, False, "tls-client-darwin-amd64.dylib"),
    ("linux", "x86_64", 64, False, "tls-client-linux-amd64.so"),
    ("linux", "x86_64", 32, False, "tls-client-linux-386.so"),     # i386 container on a 64-bit kernel
    ("linux", "i686", 32, False, "tls-client-linux-386.so"),
    ("linux", "aarch64", 64, False, "tls-client-linux-arm64.so"),
    ("linux", "aarch64", 32, False, "tls-client-linux-armv7.so"),  # 32-bit Raspberry Pi OS, 64-bit kernel
    ("linux", "armv7l", 32, False, "tls-client-linux-armv7.so"),
])
def test_library_choice(fake, system, machine, bits, musl, expected):
    assert fake(system, machine, bits, musl) == expected


def test_musl_says_why_it_cannot_work(fake):
    with pytest.raises(OSError, match="musl libc .Alpine.*glibc-based image"):
        fake("linux", "x86_64", 64, musl=True)


def test_unknown_architecture_says_so(fake):
    with pytest.raises(OSError, match="riscv64"):
        fake("linux", "riscv64", 64)

