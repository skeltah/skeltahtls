"""Discoverability of client_identifier: Literal annotation, Profiles namespace, find/suggest."""
import typing
from pathlib import Path

import pytest

import skeltahtls
from skeltahtls import ALL_IDENTIFIERS, Profiles, Session, SessionConfigurationError, find, suggest
from skeltahtls import profiles as P


def test_annotation_carries_every_identifier():
    """This is what makes editors complete the values."""
    hints = typing.get_type_hints(Session.__init__)
    optional_literal = typing.get_args(hints["client_identifier"])  # (Literal[...], NoneType)
    literal_values = typing.get_args(optional_literal[0])
    assert set(literal_values) == set(ALL_IDENTIFIERS)
    assert len(literal_values) == len(ALL_IDENTIFIERS) == 83


def test_http_version_annotation_carries_every_accepted_value():
    from skeltahtls.session import _HTTP_VERSION_ALIASES

    hints = typing.get_type_hints(Session.__init__)
    accepted = set(typing.get_args(hints["http_version"]))
    accepted.discard(type(None))
    # 1.1 is a float alias that Literal cannot express; everything else must be listed
    assert set(_HTTP_VERSION_ALIASES) - accepted - {None, 1.1} == set()


def test_py_typed_marker_ships():
    """Without it a type checker ignores our annotations in an installed package (PEP 561)."""
    assert (Path(skeltahtls.__file__).parent / "py.typed").is_file()


def test_profiles_namespace_matches_the_identifier_list():
    attrs = {v for k, v in vars(Profiles).items() if not k.startswith("_") and isinstance(v, str)}
    assert attrs == set(ALL_IDENTIFIERS)
    assert Profiles.CHROME_152 == "chrome_152"
    assert Profiles.LATEST_CHROME == P.CHROME_LATEST == "chrome_152"
    assert Profiles.LATEST_FIREFOX == P.FIREFOX_LATEST
    # every attribute is usable as-is
    Session(client_identifier=Profiles.LATEST_CHROME).close()


def test_find_filters_by_prefix():
    assert find("chrome_15") == ["chrome_150", "chrome_150_PSK", "chrome_152", "chrome_152_PSK"]
    assert find("CHROME_152") == ["chrome_152", "chrome_152_PSK"]
    assert find("safari_ios")[-1] == "safari_ios_26_0"
    assert find("nope") == []
    assert set(find("")) == set(ALL_IDENTIFIERS)


@pytest.mark.parametrize("typo,expected", [
    ("chrome152", "chrome_152"),
    ("chrome_153", "chrome_152"),
    ("Chrome_152", "chrome_152"),
    ("firefox", "firefox_148"),
    ("safari_ios_27", "safari_ios_26_0"),
])
def test_suggest_finds_the_intended_profile(typo, expected):
    assert expected in suggest(typo)


def test_unknown_identifier_error_lists_the_options():
    with pytest.raises(SessionConfigurationError) as exc:
        Session(client_identifier="chrome152")
    message = str(exc.value)
    assert "did you mean" in message and "'chrome_152'" in message
    assert "ALL_IDENTIFIERS" in message and "Profiles" in message

    # nothing close: still points at the full list instead of guessing
    with pytest.raises(SessionConfigurationError) as exc:
        Session(client_identifier="nonsense")
    assert "did you mean" not in str(exc.value)
    assert "ALL_IDENTIFIERS" in str(exc.value)


def test_a_runtime_string_is_still_accepted():
    """The Literal is for editors; a name from a config file works at runtime."""
    name = "".join(["chrome", "_", "146"])
    Session(client_identifier=name).close()  # type: ignore[arg-type]
