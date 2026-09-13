"""Regenerate the identifier list in skeltahtls/profiles.py from bogdanfinn/tls-client source.

    python scripts/gen_profiles.py v1.16.0

Only the ``ClientIdentifiers`` literal and the *_LATEST constants are rewritten; everything
below the marker line (Chrome defaults for custom clients) is kept as is - review it by hand
when a new Chrome profile lands (profiles/internal_browser_profiles.go).
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
GROUPS = ("chrome", "brave", "firefox", "opera", "safari", "okhttp4", "zalando", "nike", "mms", "mesh", "confirmed", "cloudscraper")


def main() -> int:
    tag = sys.argv[1] if len(sys.argv) > 1 else None
    if not tag:
        sys.exit("usage: gen_profiles.py vX.Y.Z")
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run(["git", "clone", "-q", "--depth", "1", "--branch", tag,
                        "https://github.com/bogdanfinn/tls-client.git", tmp + "/src"], check=True)
        src = Path(tmp, "src", "profiles", "profiles.go").read_text(encoding="utf-8")

    m = re.search(r"var MappedTLSClients = map\[string\]ClientProfile\{(.*?)\n\}", src, re.S)
    keys = re.findall(r'"([^"]+)":\s*\w+', m.group(1))
    grouped: dict[str, list[str]] = {}
    for k in keys:
        grouped.setdefault(next((g for g in GROUPS if k.startswith(g)), "custom"), []).append(k)

    def newest(prefix: str) -> str:
        found = [k for k in keys if re.fullmatch(prefix + r"_\d+", k)]
        return max(found, key=lambda s: int(s.rsplit("_", 1)[1]))

    chrome, firefox = newest("chrome"), newest("firefox")
    head = [
        f'"""Client profiles built into the bundled tls-client library ({tag}).',
        "",
        "Generated from bogdanfinn/tls-client profiles/profiles.go - do not hand-edit the list,",
        "re-run scripts/gen_profiles.py after updating binaries.",
        '"""',
        "from typing import Literal, Tuple",
        "",
        "ClientIdentifiers = Literal[",
    ]
    for g, ks in grouped.items():
        head.append(f"    # {g}")
        head += [f'    "{k}",' for k in ks]
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
    if f'"{chrome}"' not in tail:
        print(f"NOTE: check the Chrome defaults below the marker against the {chrome} Go profile")
    return 0


if __name__ == "__main__":
    sys.exit(main())
