"""CookieJar: one cookie per (name, domain, path), friendly loaders, no duplicates on the wire."""
from skeltahtls import CookieJar, Session
from skeltahtls.cookies import extract_cookies_to_jar
from skeltahtls.structures import CaseInsensitiveDict

EXPORT = [
    {"domain": ".etsy.com", "hostOnly": False, "httpOnly": True, "name": "datadome", "path": "/",
     "sameSite": "lax", "secure": True, "session": False, "expirationDate": 1800000000.5, "value": "abc"},
    {"domain": "www.etsy.com", "hostOnly": True, "httpOnly": False, "name": "uaid", "path": "/",
     "sameSite": None, "secure": False, "session": True, "value": "u1"},
]


def test_same_identity_replaces():
    j = CookieJar()
    j.set("a", "1", domain=".example.com")
    j.set("a", "2", domain="example.com")     # dot-insensitive identity
    j.set("a", "3", domain=".EXAMPLE.com")
    assert [(c.name, c.value) for c in j] == [("a", "3")]


def test_domainless_update_rewrites_existing_variants():
    j = CookieJar().load(EXPORT)
    j.update({"datadome": "new"})
    assert len(j) == 2
    c = j.get_cookie("datadome")
    assert c.value == "new" and c.domain == ".etsy.com" and c.expires == 1800000000


def test_domain_cookie_replaces_placeholder():
    j = CookieJar().load({"datadome": "placeholder"})
    extract_cookies_to_jar("https://www.etsy.com/x", CaseInsensitiveDict(), j,
                           {"set-cookie": ["datadome=srv; Domain=.etsy.com; Path=/; Max-Age=3600; Secure"]})
    assert [(c.value, c.domain) for c in j] == [("srv", ".etsy.com")]


def test_browser_export_round_trip():
    j = CookieJar().load(EXPORT)
    out = {c["name"]: c for c in j.export()}
    assert out["datadome"]["httpOnly"] is True and out["datadome"]["secure"] is True
    assert out["datadome"]["expirationDate"] == 1800000000 and out["datadome"]["session"] is False
    assert out["uaid"]["hostOnly"] is True and out["uaid"]["session"] is True
    assert CookieJar().load(j.export()).to_dict() == {"datadome": "abc", "uaid": "u1"}


def test_header_string_and_kwargs():
    j = CookieJar().load("a=1; b=2", domain=".example.com")
    j.update(c="3", domain="example.com")
    assert j.to_dict() == {"a": "1", "b": "2", "c": "3"}
    assert all(c.domain in (".example.com", "example.com") for c in j)


def test_only_most_specific_cookie_is_sent():
    s = Session()
    s.cookies.set("x", "domain", domain=".etsy.com")
    s.cookies.set("x", "host", domain="www.etsy.com")
    s.cookies.set("other", "1", domain="example.com")
    sent = s._cookies_for_url("https://www.etsy.com/", None)
    assert [(c["name"], c["value"]) for c in sent] == [("x", "host")]
    sent = s._cookies_for_url("https://api.etsy.com/", None)
    assert [(c["name"], c["value"]) for c in sent] == [("x", "domain")]


def test_remove_and_dict_api():
    j = CookieJar().load(EXPORT)
    assert "datadome" in j and j["datadome"] == "abc"
    del j["datadome"]
    assert "datadome" not in j
    j.set("uaid", None)
    assert len(j) == 0


def test_session_accepts_cookies_input():
    s = Session(cookies=EXPORT)
    assert s.cookies["uaid"] == "u1"


def test_set_cookie_accepts_a_browser_export_dict():
    """The stdlib method only takes Cookie objects; a dict used to die on cookie.value."""
    j = CookieJar().load(EXPORT)
    j.set_cookie({"name": "datadome", "value": "fresh"})
    c = j.get_cookie("datadome")
    assert (c.value, c.domain, c.expires) == ("fresh", ".etsy.com", 1800000000)  # replaced in place
    assert len(j) == 2

    j.set_cookie({"name": "new_one", "value": "1", "domain": ".etsy.com", "secure": True})
    assert j.get_cookie("new_one").secure is True


def test_set_cookie_explains_what_it_takes():
    import pytest
    j = CookieJar()
    with pytest.raises(TypeError, match="'name' and 'value'"):
        j.set_cookie({"name": "datadome"})
    with pytest.raises(TypeError, match=r"cookies\.set\(name, value"):
        j.set_cookie("datadome=abc")


def test_stdlib_set_cookie_path_still_works():
    from skeltahtls.cookies import create_cookie
    j = CookieJar()
    j.set_cookie(create_cookie("a", "1", domain=".example.com"))
    assert j["a"] == "1"
