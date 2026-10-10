"""The verb methods spell out their parameters, so editors can hint them.

If this file fails after you add a parameter to ``execute_request``, add it to the verb
methods too (both in session.py and async_session.py) - that is the whole point of them
not being ``**kwargs``.
"""
import inspect

import pytest

from skeltahtls import AsyncSession, Session

VERBS = ("request", "get", "options", "head", "post", "put", "patch", "delete")
BODY_VERBS = ("post", "put", "patch")


def params(func):
    return inspect.signature(func).parameters


def test_execute_request_documents_every_parameter():
    doc = Session.execute_request.__doc__ or ""
    for name in params(Session.execute_request):
        if name in ("self", "method", "url"):
            continue
        assert name in doc, f"{name} is not described in execute_request's docstring"


@pytest.mark.parametrize("verb", VERBS)
@pytest.mark.parametrize("cls", [Session, AsyncSession])
def test_verbs_expose_the_same_parameters_as_execute_request(cls, verb):
    expected = set(params(Session.execute_request)) - {"self", "method"}
    actual = set(params(getattr(cls, verb))) - {"self", "method"}
    assert actual == expected
    assert not any(p.kind is p.VAR_KEYWORD for p in params(getattr(cls, verb)).values()), \
        "**kwargs hides the parameters from editors"


@pytest.mark.parametrize("cls", [Session, AsyncSession])
def test_body_is_positional_on_post_put_patch_only(cls):
    for verb in BODY_VERBS:
        p = params(getattr(cls, verb))
        assert p["data"].kind is p["data"].POSITIONAL_OR_KEYWORD  # post(url, data, json) still works
        assert p["json"].kind is p["json"].POSITIONAL_OR_KEYWORD
    for verb in ("get", "options", "head", "delete"):
        p = params(getattr(cls, verb))
        assert p["data"].kind is p["data"].KEYWORD_ONLY
        assert p["headers"].kind is p["headers"].KEYWORD_ONLY


@pytest.mark.parametrize("cls", [Session, AsyncSession])
def test_head_does_not_follow_redirects_by_default(cls):
    assert params(getattr(cls, "head"))["allow_redirects"].default is False
    for verb in ("get", "post", "request"):
        assert params(getattr(cls, verb))["allow_redirects"].default is True


@pytest.mark.parametrize("verb", VERBS)
def test_async_verbs_are_coroutines(verb):
    assert inspect.iscoroutinefunction(getattr(AsyncSession, verb))


@pytest.mark.parametrize("verb", VERBS)
def test_every_verb_has_a_docstring(verb):
    assert (getattr(Session, verb).__doc__ or "").strip()
    assert (getattr(AsyncSession, verb).__doc__ or "").strip()


def test_unknown_keyword_is_a_typeerror():
    s = Session()
    with pytest.raises(TypeError):
        s.get("https://example.com/", order=["accept"])  # it is header_order
    s.close()
