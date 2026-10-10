"""Regenerate the identifier list in skeltahtls/profiles.py from bogdanfinn/tls-client source.

    python scripts/gen_profiles.py v1.16.0

Only the generated head (``ClientIdentifiers`` literal, the ``*_LATEST`` constants and the
h3 profile sets) is rewritten; everything below the marker line (Chrome defaults for custom
clients) is kept as is - review it by hand when a new Chrome profile lands
(profiles/internal_browser_profiles.go).
"""
from __future__ import annotations

import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "skeltahtls" / "profiles.py"
MARKER = "# ---------------------------------------------------------------------------------------------"
REPO = "https://github.com/bogdanfinn/tls-client.git"
PROFILE_FILES = (
    "internal_browser_profiles.go",
    "contributed_browser_profiles.go",
    "internal_custom_profiles.go",
    "contributed_custom_profiles.go",
)
GROUPS = ("chrome", "brave", "firefox", "opera", "safari", "okhttp4", "zalando", "nike",
          "mms", "mesh", "confirmed", "cloudscraper")
VAR_SPLIT = re.compile(r"\nvar (\w+) = ClientProfile\{")


def profile_bodies(profiles_dir: Path) -> dict[str, str]:
    """Go variable name -> its ClientProfile literal body."""
    source = "\n".join(
        (profiles_dir / name).read_text(encoding="utf-8")
        for name in PROFILE_FILES if (profiles_dir / name).is_file()
    )
    parts = VAR_SPLIT.split(source)
    return dict(zip(parts[1::2], parts[2::2]))


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else None
    if not tag:
        sys.exit("usage: gen_profiles.py vX.Y.Z")

    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", tag, REPO, tmp + "/src"],
                       check=True, capture_output=True)
        profiles_dir = Path(tmp, "src", "profiles")
        mapped = (profiles_dir / "profiles.go").read_text(encoding="utf-8")
        bodies = profile_bodies(profiles_dir)

    block = re.search(r"var MappedTLSClients = map\[string\]ClientProfile\{(.*?)\n\}", mapped, re.S)
    if not block:
        sys.exit("could not find MappedTLSClients in profiles.go")
    pairs = re.findall(r'"([^"]+)":\s*(\w+)', block.group(1))
    keys = [identifier for identifier, _ in pairs]

    # h3 in ALPN/ALPS -> disable_http3 changes this profile's ClientHello
    h3_alpn = sorted({i for i, var in pairs if '"h3"' in bodies.get(var, "")})
    # carries browser HTTP/3 SETTINGS / pseudo headers / GREASE frames -> h3 is browser-accurate
    h3_settings = sorted({i for i, var in pairs if "http3Settings" in bodies.get(var, "")})

    grouped: dict[str, list[str]] = {}
    for identifier in keys:
        group = next((g for g in GROUPS if identifier.startswith(g)), "custom")
        grouped.setdefault(group, []).append(identifier)

    def newest(prefix: str) -> str:
        found = [k for k in keys if re.fullmatch(prefix + r"_\d+", k)]
        return max(found, key=lambda s: int(s.rsplit("_", 1)[1]))

    chrome, firefox = newest("chrome"), newest("firefox")

    head: list[str] = [
        f'"""Client profiles built into the bundled tls-client library ({tag}).',
        "",
        "Generated from bogdanfinn/tls-client by scripts/gen_profiles.py - do not hand-edit",
        "anything above the marker line.",
        '"""',
        "from typing import FrozenSet, Literal, Tuple",
        "",
        "ClientIdentifiers = Literal[",
    ]
    for group, identifiers in grouped.items():
        head.append(f"    # {group}")
        head += [f'    "{i}",' for i in identifiers]
    head += [
        "]",
        "",
        "ALL_IDENTIFIERS: Tuple[str, ...] = ClientIdentifiers.__args__  # type: ignore[attr-defined]",
        "",
        f'CHROME_LATEST = "{chrome}"',
        f'CHROME_LATEST_PSK = "{chrome}_PSK"',
        f'FIREFOX_LATEST = "{firefox}"',
        "DEFAULT_PROFILE = CHROME_LATEST",
        "",
        "# Profiles whose ClientHello advertises h3 in ALPN/ALPS. disable_http3 (http_version=2)",
        "# strips it and therefore changes their fingerprint.",
        "PROFILES_WITH_H3_ALPN: FrozenSet[str] = frozenset({",
        *[f'    "{i}",' for i in h3_alpn],
        "})",
        "",
        "# Profiles carrying browser HTTP/3 SETTINGS, pseudo-header order and GREASE frames.",
        "# With any other profile an h3 connection (http_version=3) is not browser-accurate:",
        "# the QUIC/h3 layer falls back to the library defaults.",
        "PROFILES_WITH_HTTP3_SETTINGS: FrozenSet[str] = frozenset({",
        *[f'    "{i}",' for i in h3_settings],
        "})",
        "",
        "# pseudo header order hard-wired into every built-in Chrome/Brave/Opera profile",
        'CHROME_PSEUDO_HEADER_ORDER = (":method", ":authority", ":scheme", ":path")',
        'FIREFOX_PSEUDO_HEADER_ORDER = (":method", ":path", ":authority", ":scheme")',
        'SAFARI_PSEUDO_HEADER_ORDER = (":method", ":scheme", ":path", ":authority")',
        "",
        "",
        "def is_known_identifier(identifier: str) -> bool:",
        "    return identifier in ALL_IDENTIFIERS",
        "",
        "",
        "def builtin_pseudo_header_order(identifier: str) -> Tuple[str, ...]:",
        '    """Pseudo header order the Go library uses for a built-in profile."""',
        '    if identifier.startswith("firefox"):',
        "        return FIREFOX_PSEUDO_HEADER_ORDER",
        '    if identifier.startswith("safari"):',
        "        return SAFARI_PSEUDO_HEADER_ORDER",
        "    return CHROME_PSEUDO_HEADER_ORDER",
        "",
        "",
    ]

    current = TARGET.read_text(encoding="utf-8")
    tail = current[current.index(MARKER):] if MARKER in current else ""
    TARGET.write_text("\n".join(head) + tail, encoding="utf-8")

    print(f"{len(keys)} identifiers, CHROME_LATEST={chrome}, FIREFOX_LATEST={firefox} -> {TARGET}")
    print(f"  h3 in ALPN/ALPS:      {', '.join(h3_alpn) or 'none'}")
    print(f"  HTTP/3 settings:      {', '.join(h3_settings) or 'none'}")
    if f'"{chrome}"' not in tail:
        print(f"NOTE: check the Chrome defaults below the marker against the {chrome} Go profile")
    if chrome not in h3_settings:
        print(f"NOTE: {chrome} has no HTTP/3 settings - http_version=3 is not Chrome-accurate with it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
