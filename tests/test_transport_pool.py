"""One Go client per transport configuration, and http_version= per request.

Before this, a Session had a single Go client and changing a transport option rebuilt it,
so concurrent AsyncSession requests that wanted different settings ran on each other's
client - 3 of 6 went over the wrong protocol when measured.
"""
import asyncio
import warnings

import pytest

from conftest import NO_QUIC_HOST, QUIC_HOST
from skeltahtls import AsyncSession, Session, SessionConfigurationError
from skeltahtls import session as session_module
from skeltahtls.structures import CaseInsensitiveDict


@pytest.fixture
def destroyed(monkeypatch):
    """Record destroySession calls instead of reaching the shared library."""
    calls = []
    real = session_module._cffi.call

    def fake(name, payload):
        if name == "destroySession":
            calls.append(payload["sessionId"])
            return {"id": "", "success": True}
        return real(name, payload)

    monkeypatch.setattr(session_module._cffi, "call", fake)
    return calls


def go_id(session, http_version=session_module._UNSET, timeout=30, verify=True):
    flags = session._transport_flags(http_version)
    return session._go_session_for(session._transport_config(timeout, verify, flags))


# ------------------------------------------------------------------ the pool

def test_same_transport_reuses_its_client_and_a_different_one_gets_its_own(destroyed):
    s = Session()
    auto = go_id(s)
    assert go_id(s) == auto
    h1 = go_id(s, "1.1")
    assert h1 != auto
    assert go_id(s, "auto") == auto  # back to the warm one, nothing rebuilt
    assert destroyed == []
    s.close()


def test_switching_the_session_attribute_keeps_the_old_client_warm(destroyed):
    s = Session()
    before = s.session_id
    s.http_version = 1
    assert s.session_id != before
    s.http_version = "auto"
    assert s.session_id == before
    assert destroyed == []  # toggling no longer tears the connection down
    s.close()


def test_pool_is_bounded_and_evicts_the_least_recently_used(destroyed):
    s = Session()
    first = go_id(s, timeout=1)
    ids = [go_id(s, timeout=t) for t in range(2, s.MAX_TRANSPORTS + 2)]
    assert len(s._go_clients) == s.MAX_TRANSPORTS
    assert destroyed == [first]
    assert go_id(s, timeout=1) not in [first, *ids]  # a fresh client after eviction
    s.close()


def test_close_destroys_every_client_but_never_a_broken_one(destroyed):
    s = Session()
    a, b = go_id(s), go_id(s, "1.1")
    s._forget_go_session(s._transport_config(30, True, s._transport_flags("1.1")), b, broken=True)
    s.close()
    assert destroyed == [a]  # destroying a nil client would panic inside Go
    assert s._go_clients == {}


# ------------------------------------------------------------------ http_version per request

def test_per_request_http_version_reaches_the_payload_and_leaves_the_session_alone():
    s = Session()
    for version, expected in (("1.1", (True, False, False)), ("2", (False, True, False)),
                              ("auto", (False, False, False))):
        flags = s._transport_flags(version)
        payload = s._build_payload("GET", "https://x/", CaseInsensitiveDict(), [], None, [], 30, "", True,
                                   flags=flags)
        assert (payload["forceHttp1"], payload["disableHttp3"], payload["withProtocolRacing"]) == expected
    assert s.http_version == "auto"
    s.close()


def test_per_request_http_version_overrides_the_session_setting():
    s = Session(http_version=1)
    assert s._transport_flags("auto") == (False, False, False)
    assert s._transport_flags() == (True, False, False)  # session default still 1.1
    s.close()


def test_per_request_validation_uses_the_request_flags():
    s = Session()
    with pytest.raises(SessionConfigurationError, match="SOCKS5"):
        s.get("https://example.com/", http_version=3, proxy="http://h:1")
    with pytest.raises(SessionConfigurationError, match="unknown http_version"):
        s.get("https://example.com/", http_version="4")
    # nothing was sent, so nothing was poisoned
    assert s._broken_go_ids == set()
    s.close()


def test_per_request_warning_is_shown_once_per_session():
    s = Session()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        for _ in range(3):
            try:
                s.get("https://example.invalid/", http_version=3, timeout=0.001)
            except Exception:
                pass
    assert sum("no HTTP/3 settings" in str(w.message) for w in caught) == 1
    s.close()


# ------------------------------------------------------------------ network

@pytest.mark.network
def test_per_request_http_version_on_the_wire():
    with Session() as s:
        assert s.get(NO_QUIC_HOST, timeout=30, http_version=1).http_version == "1.1"
        assert s.get(NO_QUIC_HOST, timeout=30).http_version == "2"
        assert s.http_version == "auto"


@pytest.mark.network
def test_concurrent_requests_with_different_versions_do_not_cross():
    """The regression: one shared Go client sent half of these over the wrong protocol."""
    async def main():
        async with AsyncSession() as s:
            async def one(i):
                want = "1.1" if i % 2 else "2"
                r = await s.get(NO_QUIC_HOST, timeout=30, http_version=want)
                return want, r.http_version
            return await asyncio.gather(*(one(i) for i in range(12)))

    results = asyncio.run(main())
    assert [got for _, got in results] == [want for want, _ in results]


@pytest.mark.network
def test_h3_per_request():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with Session(client_identifier="chrome_144") as s:
            assert s.get(QUIC_HOST, timeout=30, http_version=3).http_version == "3"
            assert s.get(QUIC_HOST, timeout=30).http_version in ("1.1", "2")
