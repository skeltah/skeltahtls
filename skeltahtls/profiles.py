"""Client profiles built into the bundled tls-client library (v1.16.0).

Generated from bogdanfinn/tls-client by scripts/gen_profiles.py - do not hand-edit
anything above the marker line.
"""
import difflib
from typing import FrozenSet, List, Literal, Tuple, Union

try:  # Final narrows these to Literal types, so they satisfy ClientIdentifiers
    from typing import Final
except ImportError:  # pragma: no cover
    from typing_extensions import Final  # type: ignore[assignment]

# Accepted values of Session(client_identifier=...). Editors complete these.
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

# Same thing, permissive: use it for a profile name that only exists at runtime
# (read from a config file, say). Validated against ALL_IDENTIFIERS either way.
ClientIdentifier = Union[ClientIdentifiers, str]

ALL_IDENTIFIERS: Tuple[str, ...] = ClientIdentifiers.__args__  # type: ignore[attr-defined]

CHROME_LATEST: Final = "chrome_152"
CHROME_LATEST_PSK: Final = "chrome_152_PSK"
FIREFOX_LATEST: Final = "firefox_148"
DEFAULT_PROFILE: Final = CHROME_LATEST

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


class Profiles:
    """Every built-in profile as an attribute, so `Profiles.` lists them in any editor.

        Session(client_identifier=Profiles.CHROME_152)
        Session(client_identifier=Profiles.LATEST_CHROME)  # follows the bundled library
    """

    LATEST_CHROME: Final = CHROME_LATEST
    LATEST_CHROME_PSK: Final = CHROME_LATEST_PSK
    LATEST_FIREFOX: Final = FIREFOX_LATEST

    # chrome
    CHROME_103: Final = "chrome_103"
    CHROME_104: Final = "chrome_104"
    CHROME_105: Final = "chrome_105"
    CHROME_106: Final = "chrome_106"
    CHROME_107: Final = "chrome_107"
    CHROME_108: Final = "chrome_108"
    CHROME_109: Final = "chrome_109"
    CHROME_110: Final = "chrome_110"
    CHROME_111: Final = "chrome_111"
    CHROME_112: Final = "chrome_112"
    CHROME_116_PSK: Final = "chrome_116_PSK"
    CHROME_116_PSK_PQ: Final = "chrome_116_PSK_PQ"
    CHROME_117: Final = "chrome_117"
    CHROME_120: Final = "chrome_120"
    CHROME_124: Final = "chrome_124"
    CHROME_130_PSK: Final = "chrome_130_PSK"
    CHROME_131: Final = "chrome_131"
    CHROME_131_PSK: Final = "chrome_131_PSK"
    CHROME_133: Final = "chrome_133"
    CHROME_133_PSK: Final = "chrome_133_PSK"
    CHROME_144: Final = "chrome_144"
    CHROME_144_PSK: Final = "chrome_144_PSK"
    CHROME_146: Final = "chrome_146"
    CHROME_146_PSK: Final = "chrome_146_PSK"
    CHROME_150: Final = "chrome_150"
    CHROME_150_PSK: Final = "chrome_150_PSK"
    CHROME_152: Final = "chrome_152"
    CHROME_152_PSK: Final = "chrome_152_PSK"

    # brave
    BRAVE_146: Final = "brave_146"
    BRAVE_146_PSK: Final = "brave_146_PSK"

    # safari
    SAFARI_15_6_1: Final = "safari_15_6_1"
    SAFARI_16_0: Final = "safari_16_0"
    SAFARI_IPAD_15_6: Final = "safari_ipad_15_6"
    SAFARI_IOS_15_5: Final = "safari_ios_15_5"
    SAFARI_IOS_15_6: Final = "safari_ios_15_6"
    SAFARI_IOS_16_0: Final = "safari_ios_16_0"
    SAFARI_IOS_17_0: Final = "safari_ios_17_0"
    SAFARI_IOS_18_0: Final = "safari_ios_18_0"
    SAFARI_IOS_18_5: Final = "safari_ios_18_5"
    SAFARI_IOS_26_0: Final = "safari_ios_26_0"

    # firefox
    FIREFOX_102: Final = "firefox_102"
    FIREFOX_104: Final = "firefox_104"
    FIREFOX_105: Final = "firefox_105"
    FIREFOX_106: Final = "firefox_106"
    FIREFOX_108: Final = "firefox_108"
    FIREFOX_110: Final = "firefox_110"
    FIREFOX_117: Final = "firefox_117"
    FIREFOX_120: Final = "firefox_120"
    FIREFOX_123: Final = "firefox_123"
    FIREFOX_132: Final = "firefox_132"
    FIREFOX_133: Final = "firefox_133"
    FIREFOX_135: Final = "firefox_135"
    FIREFOX_146_PSK: Final = "firefox_146_PSK"
    FIREFOX_147: Final = "firefox_147"
    FIREFOX_147_PSK: Final = "firefox_147_PSK"
    FIREFOX_148: Final = "firefox_148"

    # opera
    OPERA_89: Final = "opera_89"
    OPERA_90: Final = "opera_90"
    OPERA_91: Final = "opera_91"

    # zalando
    ZALANDO_ANDROID_MOBILE: Final = "zalando_android_mobile"
    ZALANDO_IOS_MOBILE: Final = "zalando_ios_mobile"

    # nike
    NIKE_IOS_MOBILE: Final = "nike_ios_mobile"
    NIKE_ANDROID_MOBILE: Final = "nike_android_mobile"

    # cloudscraper
    CLOUDSCRAPER: Final = "cloudscraper"

    # mms
    MMS_IOS: Final = "mms_ios"
    MMS_IOS_1: Final = "mms_ios_1"
    MMS_IOS_2: Final = "mms_ios_2"
    MMS_IOS_3: Final = "mms_ios_3"

    # mesh
    MESH_IOS: Final = "mesh_ios"
    MESH_IOS_1: Final = "mesh_ios_1"
    MESH_IOS_2: Final = "mesh_ios_2"
    MESH_ANDROID: Final = "mesh_android"
    MESH_ANDROID_1: Final = "mesh_android_1"
    MESH_ANDROID_2: Final = "mesh_android_2"

    # confirmed
    CONFIRMED_IOS: Final = "confirmed_ios"
    CONFIRMED_ANDROID: Final = "confirmed_android"

    # okhttp4
    OKHTTP4_ANDROID_7: Final = "okhttp4_android_7"
    OKHTTP4_ANDROID_8: Final = "okhttp4_android_8"
    OKHTTP4_ANDROID_9: Final = "okhttp4_android_9"
    OKHTTP4_ANDROID_10: Final = "okhttp4_android_10"
    OKHTTP4_ANDROID_11: Final = "okhttp4_android_11"
    OKHTTP4_ANDROID_12: Final = "okhttp4_android_12"
    OKHTTP4_ANDROID_13: Final = "okhttp4_android_13"


def is_known_identifier(identifier: str) -> bool:
    return identifier in ALL_IDENTIFIERS


def find(prefix: str) -> List[str]:
    """Built-in identifiers starting with `prefix`, e.g. find("chrome_15") or find("firefox").

        >>> find("safari_ios")[-1]
        'safari_ios_26_0'
    """
    prefix = prefix.lower()
    return [i for i in ALL_IDENTIFIERS if i.lower().startswith(prefix)]


def suggest(value: str, limit: int = 3) -> List[str]:
    """Built-in identifiers closest to a misspelt one (for error messages)."""
    matches = difflib.get_close_matches(value.lower(), ALL_IDENTIFIERS, n=limit, cutoff=0.6)
    if matches:
        return matches
    # "chrome152", "chrome" -> every chrome_* profile, newest first
    family = "".join(c for c in value.lower() if c.isalpha())
    same_family = [i for i in ALL_IDENTIFIERS if family and i.startswith(family)]
    return list(reversed(same_family))[:limit]


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
