"""Cookie jar keyed by (name, domain, path) - one cookie per identity, no duplicates.

The stdlib / requests jar treats ``datadome`` for ``""``, ``etsy.com``, ``.etsy.com`` and
``www.etsy.com`` as four different cookies and happily sends all of them. Here:

* a cookie's identity is ``(name, domain-without-leading-dot, path)``; setting it again
  replaces the previous one (value, expiry, flags);
* setting a cookie *with* a domain removes a domain-less placeholder of the same name
  (the ``jar.update({"name": "value"})`` style) and vice versa: a domain-less update
  of a name that already exists rewrites the value of every existing variant instead
  of adding a new cookie;
* when several cookies still match one request URL (e.g. ``a.example.com`` host cookie
  and ``.example.com`` domain cookie with the same name), only the most specific one
  is sent.

Accepted input everywhere (``load`` / ``update`` / ``Session(cookies=...)``):

* ``{"name": "value", ...}`` (+ optional ``domain=`` / ``path=`` keyword)
* browser export: ``[{"name", "value", "domain", "path", "expirationDate"|"expires",
  "secure", "httpOnly", "hostOnly", "sameSite", "session"}, ...]``
* ``"a=1; b=2"`` Cookie-header string (+ ``domain=``)
* another jar / iterable of ``http.cookiejar.Cookie``
"""
from __future__ import annotations

import copy
import time
from http.cookiejar import Cookie
from http.cookiejar import CookieJar as _StdCookieJar
from typing import Any, Dict, Iterable, List, Mapping, Optional, Union

from .cookies import RequestsCookieJar, create_cookie

CookieInput = Union[
    None, str, Mapping[str, Any], Iterable[Mapping[str, Any]], Iterable[Cookie], _StdCookieJar
]


def _norm_domain(domain: Optional[str]) -> str:
    return (domain or "").lower().lstrip(".")


def _identity(cookie: Cookie):
    return cookie.name, _norm_domain(cookie.domain), cookie.path or "/"


def _to_expires(value: Any) -> Optional[int]:
    if value in (None, "", False):
        return None
    try:
        expires = int(float(value))
    except (TypeError, ValueError):
        return None
    return expires if expires > 0 else None


class CookieJar(RequestsCookieJar):
    """Deduplicating cookie jar (see module docstring)."""

    # ------------------------------------------------------------------ core: one cookie per identity

    def set_cookie(self, cookie: Cookie, *args: Any, **kwargs: Any) -> None:
        if isinstance(cookie.value, str) and cookie.value.startswith('"') and cookie.value.endswith('"'):
            cookie.value = cookie.value.replace('\\"', "")

        name, domain, path = _identity(cookie)
        existing = [c for c in list(self) if c.name == name]

        if not domain:
            # domain-less set of an existing name -> update every variant in place
            targets = [c for c in existing if (c.path or "/") == path]
            if targets:
                for c in targets:
                    c.value = cookie.value
                    if cookie.expires is not None:
                        c.expires = cookie.expires
                return
        else:
            # a real cookie replaces its own identity and any domain-less placeholder
            for c in existing:
                c_domain = _norm_domain(c.domain)
                if (c.path or "/") == path and (c_domain == domain or c_domain == ""):
                    self._remove(c)

        return _StdCookieJar.set_cookie(self, cookie)

    def _remove(self, cookie: Cookie) -> None:
        try:
            self.clear(cookie.domain, cookie.path, cookie.name)
        except KeyError:
            pass

    # ------------------------------------------------------------------ friendly API

    def set(  # type: ignore[override]
        self,
        name: str,
        value: Optional[str],
        domain: Optional[str] = None,
        path: str = "/",
        expires: Any = None,
        secure: bool = False,
        http_only: bool = False,
        same_site: Optional[str] = None,
        **kwargs: Any,
    ) -> Optional[Cookie]:
        """Set (or replace) one cookie. ``value=None`` deletes it."""
        if value is None:
            self.remove(name, domain=domain, path=path)
            return None
        rest: Dict[str, Any] = {}
        if http_only:
            rest["HttpOnly"] = None
        if same_site:
            rest["SameSite"] = same_site
        cookie = create_cookie(
            name, str(value), domain=domain or "", path=path or "/",
            expires=_to_expires(expires), secure=bool(secure), rest=rest,
            discard=_to_expires(expires) is None, **kwargs,
        )
        self.set_cookie(cookie)
        return cookie

    def load(self, cookies: CookieInput, domain: Optional[str] = None, path: str = "/") -> "CookieJar":
        """Add cookies from any supported input (see module docstring). Returns self."""
        if cookies is None:
            return self
        if isinstance(cookies, _StdCookieJar):
            for c in cookies:
                self.set_cookie(copy.copy(c))
            return self
        if isinstance(cookies, str):
            for part in cookies.split(";"):
                if "=" in part:
                    name, _, value = part.strip().partition("=")
                    self.set(name.strip(), value.strip(), domain=domain, path=path)
            return self
        if isinstance(cookies, Mapping):
            if "name" in cookies and "value" in cookies:  # a single browser-export dict
                self._load_export_dict(cookies, domain, path)
            else:
                for name, value in cookies.items():
                    self.set(name, value, domain=domain, path=path)
            return self
        for item in cookies:
            if isinstance(item, Cookie):
                self.set_cookie(copy.copy(item))
            elif isinstance(item, Mapping):
                self._load_export_dict(item, domain, path)
            else:
                raise TypeError(f"unsupported cookie item: {item!r}")
        return self

    def _load_export_dict(self, d: Mapping[str, Any], domain: Optional[str], path: str) -> None:
        c_domain = d.get("domain") or domain or ""
        if d.get("hostOnly") and c_domain.startswith("."):
            c_domain = c_domain[1:]
        expires = None if d.get("session") else (d.get("expirationDate") or d.get("expires"))
        self.set(
            d["name"], d.get("value", ""),
            domain=c_domain, path=d.get("path") or path,
            expires=expires, secure=bool(d.get("secure")),
            http_only=bool(d.get("httpOnly") or d.get("http_only")),
            same_site=d.get("sameSite") or d.get("same_site"),
        )

    def update(self, other: CookieInput = None, domain: Optional[str] = None, path: str = "/", **named: str) -> None:  # type: ignore[override]
        """``jar.update({"datadome": "..."}, domain=".etsy.com")`` - same inputs as ``load``."""
        self.load(other, domain=domain, path=path)
        if named:
            self.load(named, domain=domain, path=path)

    def remove(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> int:
        """Remove every cookie matching name (and optionally domain/path). Returns count."""
        n_domain = _norm_domain(domain) if domain else None
        removed = 0
        for c in list(self):
            if c.name != name:
                continue
            if n_domain is not None and _norm_domain(c.domain) != n_domain:
                continue
            if path is not None and (c.path or "/") != path:
                continue
            self._remove(c)
            removed += 1
        return removed

    def clear_domain(self, domain: str) -> int:
        """Remove every cookie whose domain equals or is a subdomain of ``domain``."""
        n_domain = _norm_domain(domain)
        removed = 0
        for c in list(self):
            cd = _norm_domain(c.domain)
            if cd == n_domain or cd.endswith("." + n_domain):
                self._remove(c)
                removed += 1
        return removed

    def get_cookie(self, name: str, domain: Optional[str] = None, path: Optional[str] = None) -> Optional[Cookie]:
        """Return the Cookie object (most specific match), or None."""
        matches = [c for c in self if c.name == name
                   and (domain is None or _norm_domain(c.domain) == _norm_domain(domain))
                   and (path is None or (c.path or "/") == path)]
        if not matches:
            return None
        return max(matches, key=_specificity)

    def get(self, name: str, default: Any = None, domain: Optional[str] = None, path: Optional[str] = None) -> Any:  # type: ignore[override]
        """Value of the most specific cookie with this name (never raises on duplicates)."""
        c = self.get_cookie(name, domain, path)
        return default if c is None else c.value

    def __getitem__(self, name: str) -> str:
        c = self.get_cookie(name)
        if c is None:
            raise KeyError(name)
        return c.value

    def __setitem__(self, name: str, value: str) -> None:
        self.set(name, value)

    def __delitem__(self, name: str) -> None:
        if not self.remove(name):
            raise KeyError(name)

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self.get_cookie(name) is not None

    # ------------------------------------------------------------------ export

    def export(self, domain: Optional[str] = None) -> List[Dict[str, Any]]:
        """Browser-export style list of dicts (round-trips through ``load``)."""
        out = []
        for c in self:
            if domain and not _norm_domain(c.domain).endswith(_norm_domain(domain)):
                continue
            out.append({
                "name": c.name,
                "value": c.value,
                "domain": c.domain,
                "path": c.path or "/",
                "hostOnly": not c.domain.startswith("."),
                "secure": bool(c.secure),
                "httpOnly": c.has_nonstandard_attr("HttpOnly"),
                "sameSite": c.get_nonstandard_attr("SameSite"),
                "session": c.expires is None,
                "expirationDate": c.expires,
            })
        return out

    def to_dict(self, domain: Optional[str] = None) -> Dict[str, str]:
        """``{name: value}`` (most specific value wins on collisions)."""
        result: Dict[str, str] = {}
        for c in sorted(self, key=_specificity):
            if domain and not _norm_domain(c.domain).endswith(_norm_domain(domain)):
                continue
            result[c.name] = c.value
        return result

    def copy(self) -> "CookieJar":
        new = CookieJar()
        new.set_policy(self.get_policy())
        for c in self:
            _StdCookieJar.set_cookie(new, copy.copy(c))
        return new

    def __repr__(self) -> str:
        items = ", ".join(f"{c.name}@{c.domain or '*'}" for c in self)
        return f"<CookieJar[{items}]>"

    # ------------------------------------------------------------------ request-time selection

    def cookies_for_request(self, request: Any) -> List[Cookie]:
        """Cookies that apply to a (Mock)Request, deduplicated by name (most specific wins)."""
        self._policy._now = self._now = int(time.time())  # type: ignore[attr-defined]
        try:
            matching: Iterable[Cookie] = self._cookies_for_request(request)  # type: ignore[attr-defined]
        except Exception:  # private stdlib API changed - fall back to everything
            matching = list(self)
        best: Dict[str, Cookie] = {}
        for c in matching:
            prev = best.get(c.name)
            if prev is None or _specificity(c) > _specificity(prev):
                best[c.name] = c
        return list(best.values())


def _specificity(cookie: Cookie):
    # host-only (no leading dot) beats domain cookie; longer domain/path beats shorter; newer wins ties
    domain = cookie.domain or ""
    return (len(_norm_domain(domain)), not domain.startswith("."), len(cookie.path or "/"), cookie.expires or 0)
