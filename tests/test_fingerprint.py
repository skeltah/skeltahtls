"""Network tests: what we put on the wire, against what a real Chrome puts there.

Run with:  pytest -m network
The reference capture lives in conftest.py; update it (and CHROME_LATEST) when a new
profile actually changes the ClientHello.
"""
import asyncio

import pytest

from conftest import BROWSERLEAKS, CHROME, CHROME_HEADERS, PEET, fetch, headers_frame
from skeltahtls import AsyncSession, Session

pytestmark = pytest.mark.network


def test_default_profile_matches_real_chrome():
    with Session() as s:
        d = fetch(BROWSERLEAKS, s, headers=CHROME_HEADERS)
    for field in ("ja4", "ja4_r", "ja3n_text", "akamai_hash", "akamai_text"):
        assert d[field] == CHROME[field], field


def test_header_order_follows_the_request_and_pseudo_headers_are_chromes():
    with Session() as s:
        sent = headers_frame(fetch(PEET, s, headers=CHROME_HEADERS))
    assert [h.split(":")[1] for h in sent[:4]] == ["method", "authority", "scheme", "path"]
    assert [h.split(":")[0] for h in sent[4:]] == list(CHROME_HEADERS)


def test_random_extension_order_changes_ja3_but_not_ja4():
    with Session() as s:
        a = fetch(BROWSERLEAKS, s)
        s.reset_connection()
        b = fetch(BROWSERLEAKS, s)
    assert a["ja4"] == b["ja4"] == CHROME["ja4"]
    assert a["ja3n_text"] == b["ja3n_text"]  # normalised: order-independent
    assert a["ja3_hash"] != b["ja3_hash"]    # raw: Chrome shuffles its extensions too


def test_custom_ja3_reaches_the_same_fingerprint():
    """A bare Chrome ja3 string, with the rest filled in from the Chrome defaults."""
    ja3 = CHROME["ja3n_text"]
    with Session(ja3_string=ja3) as s:
        d = fetch(BROWSERLEAKS, s)
    assert d["ja4"] == CHROME["ja4"]
    assert d["akamai_hash"] == CHROME["akamai_hash"]


def test_cookies_only_go_to_matching_hosts():
    with Session() as s:
        s.cookies.set("mine", "1", domain="tls.peet.ws")
        s.cookies.set("foreign", "2", domain="example.com")
        sent = headers_frame(fetch(PEET, s))
    assert [h for h in sent if h.startswith("cookie:")] == ["cookie: mine=1"]


def test_async_session_concurrent():
    async def main():
        async with AsyncSession() as a:
            responses = await asyncio.gather(*(a.get(BROWSERLEAKS, timeout=30) for _ in range(4)))
            return [r.json()["ja4"] for r in responses]

    try:
        assert asyncio.run(main()) == [CHROME["ja4"]] * 4
    except Exception as error:  # the service, not us
        if "unreachable" in str(error) or "dial tcp" in str(error):
            pytest.skip(str(error))
        raise


def test_redirects_are_followed_with_history():
    # httpbin.org is not usable for this: it serves a certificate for an unrelated domain
    with Session() as s:
        r = s.get("https://httpbingo.org/redirect/2", headers={"user-agent": CHROME["user_agent"]})
    assert r.status_code == 200 and len(r.history) == 2
    assert r.url.endswith("/get")
