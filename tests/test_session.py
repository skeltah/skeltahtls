"""Unit tests that do not touch the network (payload construction, validation, cookies)."""
import json

import pytest

from skeltahtls import Session, SessionConfigurationError
from skeltahtls import profiles as P
from skeltahtls.structures import CaseInsensitiveDict


def test_default_profile_is_latest_chrome():
    s = Session()
    assert s.client_identifier == P.CHROME_LATEST == P.DEFAULT_PROFILE
    assert s.random_tls_extension_order is True


def test_ja3_without_identifier_means_custom_client():
    s = Session(ja3_string="771,4865,0-23,29,0")
    assert s.client_identifier is None
    payload = s._build_payload("GET", "https://x/", CaseInsensitiveDict(), [], None, [], 30, "", True)
    assert "tlsClientIdentifier" not in payload
    assert payload["customTlsClient"]["ja3String"] == "771,4865,0-23,29,0"


def test_identifier_plus_custom_option_is_rejected():
    with pytest.raises(SessionConfigurationError):
        Session(client_identifier="chrome_152", ja3_string="771,4865,0,29,0")
    with pytest.raises(SessionConfigurationError):
        Session(client_identifier="chrome_999")
    with pytest.raises(SessionConfigurationError):
        Session(client_identifier=None)


def test_pseudo_header_order_must_match_builtin_profile():
    Session(pseudo_header_order=[":method", ":authority", ":scheme", ":path"])  # chrome order: fine
    with pytest.raises(SessionConfigurationError):
        Session(pseudo_header_order=[":method", ":path", ":authority", ":scheme"])
    Session(client_identifier="firefox_148", pseudo_header_order=[":method", ":path", ":authority", ":scheme"])


def test_custom_client_gets_chrome_defaults_only_for_listed_extensions():
    ja3 = "771,4865-4866,51764-27-65037-65281-11-23-16-18-0-35-17613-5-45-51-10-13-43,4588-29-23-24,0"
    c = Session(ja3_string=ja3)._custom_tls_client()
    assert c["supportedVersions"] == P.CHROME_SUPPORTED_VERSIONS
    assert c["keyShareCurves"] == P.CHROME_KEY_SHARE_CURVES
    assert c["alpnProtocols"] == P.CHROME_ALPN and c["alpsProtocols"] == P.CHROME_ALPS
    assert c["certCompressionAlgos"] == ["brotli"]
    assert c["trustAnchorsPayload"] == P.CHROME_TRUST_ANCHORS_PAYLOAD
    assert c["h2Settings"] == P.CHROME_H2_SETTINGS and c["connectionFlow"] == P.CHROME_CONNECTION_FLOW
    assert c["pseudoHeaderOrder"] == list(P.CHROME_PSEUDO_HEADER_ORDER)

    # extensions absent from the ja3 -> no defaults injected for them
    c2 = Session(ja3_string="771,4865,0-23-43,29,0")._custom_tls_client()
    assert "keyShareCurves" not in c2 and "trustAnchorsPayload" not in c2 and "alpnProtocols" not in c2
    assert c2["supportedVersions"] == P.CHROME_SUPPORTED_VERSIONS

    # opt out entirely
    c3 = Session(ja3_string=ja3, fill_custom_with_chrome_defaults=False)._custom_tls_client()
    assert set(c3) == {"ja3String"}

    # explicit values always win
    c4 = Session(ja3_string=ja3, alpn_protocols=["http/1.1"])._custom_tls_client()
    assert c4["alpnProtocols"] == ["http/1.1"]


def test_payload_uses_v1_16_keys():
    s = Session(cert_compression_algo="brotli", ja3_string="771,4865,27,29,0")
    payload = s._build_payload("GET", "https://x/", CaseInsensitiveDict(), [], None, [], 2.5, "", True)
    assert payload["customTlsClient"]["certCompressionAlgos"] == ["brotli"]
    assert payload["timeoutMilliseconds"] == 2500 and "timeoutSeconds" not in payload
    assert payload["withoutCookieJar"] is True and "withDefaultCookieJar" not in payload
    assert "additionalDecode" not in payload
    assert payload["followRedirects"] is False


def test_header_order_defaults_to_insertion_order():
    s = Session()
    headers = CaseInsensitiveDict({"User-Agent": "x", "Accept": "*/*", "sec-ch-ua": "y"})
    assert s._effective_header_order(headers, None) == ["user-agent", "accept", "sec-ch-ua"]
    # explicit order first, the rest appended in insertion order
    assert s._effective_header_order(headers, ["accept"]) == ["accept", "user-agent", "sec-ch-ua"]
    s.header_order = ["sec-ch-ua", "cookie"]
    assert s._effective_header_order(headers, None) == ["sec-ch-ua", "cookie", "user-agent", "accept"]


def test_cookies_are_filtered_by_request_host():
    s = Session()
    s.cookies.set("a", "1", domain="tls.peet.ws")
    s.cookies.set("b", "2", domain="example.com")
    s.cookies.set("c", "3")  # no domain: sent everywhere (requests semantics)
    names = sorted(c["name"] for c in s._cookies_for_url("https://tls.peet.ws/api/all", None))
    assert names == ["a", "c"]
    names = sorted(c["name"] for c in s._cookies_for_url("https://example.com/", {"d": "4"}))
    assert names == ["b", "c", "d"]


def test_transport_change_is_detected():
    s = Session()
    a = s._transport_config(30, True)
    s.force_http1 = True
    b = s._transport_config(30, True)
    assert a != b
    assert json.loads(b)["force_http1"] is True


def test_proxy_resolution():
    s = Session(proxy="socks5://u:p@h:1")
    assert s._resolve_proxy(None) == "socks5://u:p@h:1"
    assert s._resolve_proxy({"https": "http://h:2"}) == "http://h:2"
    assert s._resolve_proxy({"http": "http://h:3"}) == "http://h:3"
    assert Session()._resolve_proxy(None) == ""
