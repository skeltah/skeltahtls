"""Shared helpers for the network tests.

Two fingerprint services are used, because one of them going down should not look like a
broken library: browserleaks for the TLS/HTTP2 hashes, peet for the frames a request
actually sent (header order, pseudo headers, cookie fields). A test that needs one of them
is skipped when it cannot be reached.
"""
import pytest

from skeltahtls import Session, TLSClientException

BROWSERLEAKS = "https://tls.browserleaks.com/json"
PEET = "https://tls.peet.ws/api/all"
QUIC_HOST = "https://cloudflare-quic.com/"      # advertises alt-svc h3
NO_QUIC_HOST = "https://httpbingo.org/get"      # does not, so an h3 race falls back to h2

# Google Chrome 156.0.8078.48 on Windows, captured from tls.browserleaks.com/json.
# chrome_152 is still the newest profile upstream ships, and these values say it is still
# the right one: Chrome 153-156 did not change the ClientHello.
CHROME = {
    "ja4": "t13d1517h2_8daaf6152771_cb7bf5808d99",
    "ja4_r": (
        "t13d1517h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9"
        "_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,ca34,fe0d,ff01"
        "_0904,0905,0906,0403,0804,0401,0503,0805,0501,0806,0601"
    ),
    "ja3n_text": (
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "0-5-10-11-13-16-18-23-27-35-43-45-51-17613-51764-65037-65281,4588-29-23-24,0"
    ),
    "akamai_hash": "52d84b11737d980aef856699f885ca86",
    "akamai_text": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
    "user_agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/156.0.0.0 Safari/537.36"
    ),
}

CHROME_HEADERS = {
    "sec-ch-ua": '"Chromium";v="156", "Not?A_Brand";v="24", "Google Chrome";v="156"',
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "upgrade-insecure-requests": "1",
    "user-agent": CHROME["user_agent"],
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,"
              "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "sec-fetch-site": "none",
    "sec-fetch-mode": "navigate",
    "sec-fetch-user": "?1",
    "sec-fetch-dest": "document",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
    "priority": "u=0, i",
}


def fetch(url, session=None, **kwargs):
    """Fetch a fingerprint service, skipping the test when it is unreachable."""
    kwargs.setdefault("timeout", 30)
    kwargs.setdefault("headers", {"user-agent": CHROME["user_agent"]})
    own = session is None
    session = session or Session()
    try:
        return session.get(url, **kwargs).json()
    except TLSClientException as error:
        pytest.skip(f"{url} is unreachable: {error}")
    finally:
        if own:
            session.close()


def headers_frame(peet_data):
    """The HEADERS frame of the request, as tls.peet.ws saw it."""
    return next(f for f in peet_data["http2"]["sent_frames"] if f["frame_type"] == "HEADERS")["headers"]
