"""Client profiles built into the bundled tls-client library (v1.16.0).

Generated from bogdanfinn/tls-client by scripts/gen_profiles.py - do not hand-edit
anything above the marker line.
"""
from typing import FrozenSet, Literal, Tuple

ClientIdentifiers = Literal[
    # chrome
    "chrome_103",
    "chrome_104",
    "chrome_105",
    "chrome_106",
    "chrome_107",
    "chrome_108",
    "chrome_109",
    "chrome_110",
    "chrome_111",
    "chrome_112",
    "chrome_116_PSK",
    "chrome_116_PSK_PQ",
    "chrome_117",
    "chrome_120",
    "chrome_124",
    "chrome_130_PSK",
    "chrome_131",
    "chrome_131_PSK",
    "chrome_133",
    "chrome_133_PSK",
    "chrome_144",
    "chrome_144_PSK",
    "chrome_146",
    "chrome_146_PSK",
    "chrome_150",
    "chrome_150_PSK",
    "chrome_152",
    "chrome_152_PSK",
    # brave
    "brave_146",
    "brave_146_PSK",
    # safari
    "safari_15_6_1",
    "safari_16_0",
    "safari_ipad_15_6",
    "safari_ios_15_5",
    "safari_ios_15_6",
    "safari_ios_16_0",
    "safari_ios_17_0",
    "safari_ios_18_0",
    "safari_ios_18_5",
    "safari_ios_26_0",
    # firefox
    "firefox_102",
    "firefox_104",
    "firefox_105",
    "firefox_106",
    "firefox_108",
    "firefox_110",
    "firefox_117",
    "firefox_120",
    "firefox_123",
    "firefox_132",
    "firefox_133",
    "firefox_135",
    "firefox_146_PSK",
    "firefox_147",
    "firefox_147_PSK",
    "firefox_148",
    # opera
    "opera_89",
    "opera_90",
    "opera_91",
    # zalando
    "zalando_android_mobile",
    "zalando_ios_mobile",
    # nike
    "nike_ios_mobile",
    "nike_android_mobile",
    # cloudscraper
    "cloudscraper",
    # mms
    "mms_ios",
    "mms_ios_1",
    "mms_ios_2",
    "mms_ios_3",
    # mesh
    "mesh_ios",
    "mesh_ios_1",
    "mesh_ios_2",
    "mesh_android",
    "mesh_android_1",
    "mesh_android_2",
    # confirmed
    "confirmed_ios",
    "confirmed_android",
    # okhttp4
    "okhttp4_android_7",
    "okhttp4_android_8",
    "okhttp4_android_9",
    "okhttp4_android_10",
    "okhttp4_android_11",
    "okhttp4_android_12",
    "okhttp4_android_13",
]

ALL_IDENTIFIERS: Tuple[str, ...] = ClientIdentifiers.__args__  # type: ignore[attr-defined]

CHROME_LATEST = "chrome_152"
CHROME_LATEST_PSK = "chrome_152_PSK"
FIREFOX_LATEST = "firefox_148"
DEFAULT_PROFILE = CHROME_LATEST

# Profiles whose ClientHello advertises h3 in ALPN/ALPS. disable_http3 (http_version=2)
# strips it and therefore changes their fingerprint.
PROFILES_WITH_H3_ALPN: FrozenSet[str] = frozenset({
    "chrome_133",
    "chrome_133_PSK",
})

# Profiles carrying browser HTTP/3 SETTINGS, pseudo-header order and GREASE frames.
# With any other profile an h3 connection (http_version=3) is not browser-accurate:
# the QUIC/h3 layer falls back to the library defaults.
PROFILES_WITH_HTTP3_SETTINGS: FrozenSet[str] = frozenset({
    "chrome_144",
    "chrome_144_PSK",
    "firefox_147",
    "firefox_147_PSK",
    "firefox_148",
})

# pseudo header order hard-wired into every built-in Chrome/Brave/Opera profile
CHROME_PSEUDO_HEADER_ORDER = (":method", ":authority", ":scheme", ":path")
FIREFOX_PSEUDO_HEADER_ORDER = (":method", ":path", ":authority", ":scheme")
SAFARI_PSEUDO_HEADER_ORDER = (":method", ":scheme", ":path", ":authority")


def is_known_identifier(identifier: str) -> bool:
    return identifier in ALL_IDENTIFIERS


def builtin_pseudo_header_order(identifier: str) -> Tuple[str, ...]:
    """Pseudo header order the Go library uses for a built-in profile."""
    if identifier.startswith("firefox"):
        return FIREFOX_PSEUDO_HEADER_ORDER
    if identifier.startswith("safari"):
        return SAFARI_PSEUDO_HEADER_ORDER
    return CHROME_PSEUDO_HEADER_ORDER

# ---------------------------------------------------------------------------------------------
# Chrome 152 values used to fill in whatever a custom (ja3_string) client does not specify.
# Taken from bogdanfinn/tls-client profiles/internal_browser_profiles.go (Chrome_152).
# ---------------------------------------------------------------------------------------------
CHROME_H2_SETTINGS = {
    "HEADER_TABLE_SIZE": 65536,
    "ENABLE_PUSH": 0,
    "INITIAL_WINDOW_SIZE": 6291456,
    "MAX_HEADER_LIST_SIZE": 262144,
}
CHROME_H2_SETTINGS_ORDER = ["HEADER_TABLE_SIZE", "ENABLE_PUSH", "INITIAL_WINDOW_SIZE", "MAX_HEADER_LIST_SIZE"]
CHROME_CONNECTION_FLOW = 15663105
CHROME_SUPPORTED_VERSIONS = ["GREASE", "1.3", "1.2"]
CHROME_KEY_SHARE_CURVES = ["GREASE", "X25519MLKEM768", "X25519"]
CHROME_SIGNATURE_ALGORITHMS = [
    "GREASE", "MLDSA44", "MLDSA65", "MLDSA87",
    "ECDSAWithP256AndSHA256", "PSSWithSHA256", "PKCS1WithSHA256",
    "ECDSAWithP384AndSHA384", "PSSWithSHA384", "PKCS1WithSHA384",
    "PSSWithSHA512", "PKCS1WithSHA512",
]
CHROME_ALPN = ["h2", "http/1.1"]
CHROME_ALPS = ["h2"]
CHROME_CERT_COMPRESSION = ["brotli"]
# wire bytes of the trust_anchors (51764 / 0xca34) extension as captured from Chrome 152
CHROME_TRUST_ANCHORS_PAYLOAD = (
    "00b80582df13020108839a648c9b2d010c08839a648c9b2d010704d679090c08839a648c9b2d010a04d679090b08839a64"
    "8c9b2d010d0582df13020e08839a648c9b2d010b04d67909050582df13020d0582df13021404d679090404d679090804d6"
    "79090d04d679090a04d679090708839a648c9b2d011204d67909010582df13020608839a648c9b2d01080582df13021208"
    "839a648c9b2d011304d679090f0582df13021308839a648c9b2d01090582df13020f04d6790906"
)

TRUST_ANCHORS_EXTENSION_ID = 51764
KEY_SHARE_EXTENSION_ID = 51
COMPRESS_CERTIFICATE_EXTENSION_ID = 27
ALPN_EXTENSION_ID = 16
ALPS_EXTENSION_IDS = (17513, 17613)
SUPPORTED_VERSIONS_EXTENSION_ID = 43
SIGNATURE_ALGORITHMS_EXTENSION_ID = 13
X25519MLKEM768_GROUP_ID = 4588
