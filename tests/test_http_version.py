"""http_version: the transport protocol knob and the validation that guards it."""
import warnings

import pytest

from conftest import BROWSERLEAKS, CHROME, NO_QUIC_HOST, QUIC_HOST, fetch
from skeltahtls import HTTP_VERSIONS, Response, Session, SessionConfigurationError
from skeltahtls import profiles as P
from skeltahtls.structures import CaseInsensitiveDict

CHROME_JA4_H2 = CHROME["ja4"]
CHROME_JA4_H1 = CHROME["ja4"].replace("h2_", "h1_", 1)  # forcing http/1.1 rewrites ALPN


def test_default_is_auto():
    s = Session()
    assert s.http_version == "auto"
    assert (s.force_http1, s.disable_http3, s.with_protocol_racing) == (False, False, False)


@pytest.mark.parametrize("value,expected", [
    (None, "auto"), ("auto", "auto"),
    (1, "1.1"), (1.1, "1.1"), ("1", "1.1"), ("1.1", "1.1"), ("h1", "1.1"), ("http/1.1", "1.1"),
    (2, "2"), ("2", "2"), ("h2", "2"), ("http/2", "2"),
    (3, "3"), ("3", "3"), ("h3", "3"), ("quic", "3"),
])
def test_aliases_round_trip(value, expected):
    s = Session()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        s.http_version = value
    assert s.http_version == expected
    assert (s.force_http1, s.disable_http3, s.with_protocol_racing) == HTTP_VERSIONS[expected]


def test_low_level_flags_still_report_a_version():
    assert Session(force_http1=True).http_version == "1.1"
    assert Session(disable_http3=True).http_version == "2"
    assert Session(with_protocol_racing=True).http_version == "3"


def test_unknown_value_and_mixing_with_low_level_flags_are_rejected():
    with pytest.raises(SessionConfigurationError, match="unknown http_version"):
        Session(http_version="4")
    with pytest.raises(SessionConfigurationError, match="same setting at a lower level"):
        Session(http_version=3, force_http1=True)


@pytest.mark.parametrize("kwargs,match", [
    (dict(with_protocol_racing=True, force_http1=True), "cannot be combined with force_http1"),
    (dict(with_protocol_racing=True, disable_http3=True), "cannot be combined with disable_http3"),
    (dict(disable_ipv4=True, disable_ipv6=True), "both IPv4 and IPv6"),
    (dict(certificate_pinning={"x": ["y"]}, verify=False), "verify=False"),
    (dict(http_version=3, proxy="http://h:1"), "SOCKS5"),
    (dict(http_version=3, proxy="https://h:1"), "SOCKS5"),
])
def test_configs_the_go_library_refuses_are_caught_in_python(kwargs, match):
    # these used to reach the shared library, which stored a nil client and then panicked
    # inside destroySession - taking the whole process down
    with pytest.raises(SessionConfigurationError, match=match):
        Session(**kwargs)


def test_socks5_proxy_is_allowed_with_h3():
    s = Session(http_version=3, proxy="socks5://user:pass@host:1080")
    assert s.http_version == "3"


def test_per_request_proxy_is_validated_too():
    s = Session(http_version=3)
    with pytest.raises(SessionConfigurationError, match="SOCKS5"):
        s.get("https://example.com/", proxy="http://h:1")


def test_payload_flags():
    for version, (h1, no_h3, racing) in HTTP_VERSIONS.items():
        s = Session()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            s.http_version = version
        payload = s._build_payload("GET", "https://x/", CaseInsensitiveDict(), [], None, [], 30, "", True)
        assert payload["forceHttp1"] is h1
        assert payload["disableHttp3"] is no_h3
        assert payload["withProtocolRacing"] is racing


def test_switching_rebuilds_the_go_client():
    s = Session()
    auto = s._transport_config(30, True)
    s.http_version = 1
    assert s._transport_config(30, True) != auto


def test_warns_when_the_profile_cannot_back_the_choice():
    # chrome_133 advertises h3 in ALPN/ALPS, so disabling h3 changes its ClientHello
    assert "chrome_133" in P.PROFILES_WITH_H3_ALPN
    with pytest.warns(UserWarning, match="changes its ClientHello"):
        Session(client_identifier="chrome_133", http_version=2)
    # chrome_152 has no HTTP/3 settings, so an h3 connection is not browser-accurate
    assert P.CHROME_LATEST not in P.PROFILES_WITH_HTTP3_SETTINGS
    with pytest.warns(UserWarning, match="no HTTP/3 settings"):
        Session(http_version=3)
    # a profile that does carry them is silent
    assert "chrome_144" in P.PROFILES_WITH_HTTP3_SETTINGS
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        Session(client_identifier="chrome_144", http_version=3)
        Session(http_version=2)


@pytest.mark.parametrize("used,expected", [
    ("HTTP/2.0", "2"), ("h2", "2"), ("HTTP/1.1", "1.1"), ("HTTP/3.0", "3"), ("h3", "3"),
    ("HTTP/1.0", "1.0"), ("", None), (None, None),
])
def test_response_http_version(used, expected):
    r = Response()
    r.used_protocol = used
    assert r.http_version == expected


# ------------------------------------------------------------------ network

@pytest.mark.network
def test_http1_and_h2_on_the_wire():
    with Session(http_version=2) as s:
        assert fetch(BROWSERLEAKS, s)["ja4"] == CHROME_JA4_H2
        s.http_version = 1
        d = fetch(BROWSERLEAKS, s)
        # forcing http/1.1 rewrites ALPN in the ClientHello, so JA4 changes with it
        assert d["ja4"] == CHROME_JA4_H1


@pytest.mark.network
def test_h3_is_used_against_a_quic_host_and_falls_back_otherwise():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(client_identifier="chrome_144", http_version=3) as s:
            assert s.get(QUIC_HOST, timeout=30).http_version == "3"
        with Session(http_version=3) as s:
            # no alt-svc there, so HTTP/2 wins the race after the 300 ms head start
            assert s.get(NO_QUIC_HOST, timeout=30).http_version == "2"
