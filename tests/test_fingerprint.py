"""Network tests: compare what the library sends with real Chrome (via https://tls.peet.ws).

Run with:  pytest -m network
Reference values come from Google Chrome 152 stable (Windows). Update them together with
CHROME_LATEST when a new profile becomes the default.
"""
import asyncio

import pytest

from skeltahtls import AsyncSession, Session
from skeltahtls import profiles as P

pytestmark = pytest.mark.network

PEET = "https://tls.peet.ws/api/all"
CHROME_152_JA4 = "t13d1517h2_8daaf6152771_cb7bf5808d99"
CHROME_AKAMAI = "52d84b11737d980aef856699f885ca86"  # 1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p
CHROME_152_JA3 = (
    "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
    "51764-27-65037-65281-11-23-16-18-0-35-17613-5-45-51-10-13-43,4588-29-23-24,0"
)
HEADERS = {
    "sec-ch-ua": '"Chromium";v="152", "Not?A_Brand";v="24", "Google Chrome";v="152"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
    "priority": "u=0, i",
}


def _headers_frame(data):
    return next(f for f in data["http2"]["sent_frames"] if f["frame_type"] == "HEADERS")["headers"]


def test_default_profile_matches_chrome_152():
    with Session() as s:
        d = s.get(PEET, headers=HEADERS).json()
    assert d["tls"]["ja4"] == CHROME_152_JA4
    assert d["http2"]["akamai_fingerprint_hash"] == CHROME_AKAMAI
    sent = _headers_frame(d)
    assert [h.split(":")[1] for h in sent[:4]] == ["method", "authority", "scheme", "path"]
    assert [h.split(":")[0] for h in sent[4:]] == list(HEADERS)


def test_random_extension_order_changes_ja3_but_not_ja4():
    with Session() as s:
        a = s.get(PEET).json()["tls"]
        s.reset_connection()
        b = s.get(PEET).json()["tls"]
    assert a["ja4"] == b["ja4"] == CHROME_152_JA4
    assert a["ja3_hash"] != b["ja3_hash"]


def test_custom_ja3_with_defaults_matches_chrome_152():
    with Session(ja3_string=CHROME_152_JA3) as s:
        d = s.get(PEET).json()
    assert d["tls"]["ja4"] == CHROME_152_JA4
    assert d["http2"]["akamai_fingerprint_hash"] == CHROME_AKAMAI


def test_force_http1_can_be_toggled_mid_session():
    with Session() as s:
        assert s.get(PEET).json()["http_version"] == "h2"
        s.force_http1 = True
        assert s.get(PEET).json()["http_version"] == "HTTP/1.1"
        s.force_http1 = False
        assert s.get(PEET).json()["http_version"] == "h2"


def test_cookies_only_go_to_matching_hosts():
    with Session() as s:
        s.cookies.set("mine", "1", domain="tls.peet.ws")
        s.cookies.set("foreign", "2", domain="example.com")
        sent = _headers_frame(s.get(PEET).json())
    cookies = [h for h in sent if h.startswith("cookie:")]
    assert cookies == ["cookie: mine=1"]


def test_async_session_concurrent():
    async def main():
        async with AsyncSession() as a:
            rs = await asyncio.gather(*(a.get(PEET) for _ in range(4)))
            return [r.json()["tls"]["ja4"] for r in rs]

    assert asyncio.run(main()) == [CHROME_152_JA4] * 4


def test_redirects_are_followed_with_history():
    with Session() as s:
        r = s.get("https://httpbin.org/redirect/2", headers={"user-agent": HEADERS["user-agent"]})
    assert r.status_code == 200 and len(r.history) == 2
    assert r.url.endswith("/get")
