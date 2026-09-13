"""HTTP response object, requests-compatible where it matters."""
from __future__ import annotations

import base64
import json as _json
from datetime import timedelta
from http import HTTPStatus
from typing import Any, Dict, Iterator, List, Optional

from .cookies import RequestsCookieJar, cookiejar_from_dict
from .exceptions import HTTPError
from .structures import CaseInsensitiveDict

try:  # optional, only used when no charset is announced by the server
    import charset_normalizer as _chardet
except ImportError:  # pragma: no cover
    try:
        import chardet as _chardet  # type: ignore
    except ImportError:
        _chardet = None


class Response:
    """The response to an HTTP request."""

    def __init__(self) -> None:
        self.url: Optional[str] = None
        self._status_code: int = 0
        self.reason: str = ""
        self.encoding: Optional[str] = None
        self._headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.cookies: RequestsCookieJar = cookiejar_from_dict({})
        self.history: List["Response"] = []
        self.elapsed: timedelta = timedelta(0)
        self._content: bytes = b""
        # "h2", "http/1.1" or "h3" as reported by the Go client
        self.used_protocol: Optional[str] = None
        # request that produced this response (method, url, headers) - handy for debugging
        self.request: Optional[Dict[str, Any]] = None

    def __enter__(self) -> "Response":
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def __repr__(self) -> str:
        return f"<Response [{self.status_code}]>"

    def __bool__(self) -> bool:
        return self.ok

    def __iter__(self) -> Iterator[bytes]:
        return self.iter_content(128)

    @property
    def headers(self) -> CaseInsensitiveDict:
        return self._headers

    @headers.setter
    def headers(self, value: Any) -> None:
        self._headers = CaseInsensitiveDict(value)

    @property
    def status_code(self) -> int:
        return self._status_code

    @status_code.setter
    def status_code(self, status_code: int) -> None:
        self._status_code = status_code
        try:
            self.reason = HTTPStatus(status_code).phrase
        except ValueError:
            self.reason = "UNKNOWN"

    @property
    def ok(self) -> bool:
        return self.status_code < 400

    @property
    def is_redirect(self) -> bool:
        return "location" in self.headers and self.status_code in (301, 302, 303, 307, 308)

    @property
    def is_permanent_redirect(self) -> bool:
        return "location" in self.headers and self.status_code in (301, 308)

    @property
    def apparent_encoding(self) -> str:
        if _chardet is None or not self._content:
            return "utf-8"
        guess = _chardet.detect(self._content).get("encoding")
        return guess or "utf-8"

    @property
    def content(self) -> bytes:
        return self._content

    @property
    def text(self) -> str:
        if not self._content:
            return ""
        encoding = self.encoding or self.apparent_encoding
        try:
            return str(self._content, encoding, errors="replace")
        except (LookupError, TypeError):
            return str(self._content, errors="replace")

    def json(self, **kwargs: Any) -> Any:
        return _json.loads(self.text, **kwargs)

    def raise_for_status(self) -> None:
        if 400 <= self.status_code < 500:
            raise HTTPError(f"{self.status_code} Client Error: {self.reason} for url: {self.url}", response=self)
        if 500 <= self.status_code < 600:
            raise HTTPError(f"{self.status_code} Server Error: {self.reason} for url: {self.url}", response=self)

    def iter_content(self, chunk_size: int = 1024) -> Iterator[bytes]:
        data = self._content
        for i in range(0, len(data), chunk_size):
            yield data[i:i + chunk_size]

    def iter_lines(self, chunk_size: int = 128, delimiter: Optional[str] = None) -> Iterator[str]:
        text = self.text
        if delimiter:
            yield from text.split(delimiter)
        else:
            yield from text.splitlines()


def _parse_content_type_header(header: str):
    tokens = header.split(";")
    content_type, params = tokens[0].strip(), tokens[1:]
    params_dict = {}
    for param in params:
        param = param.strip()
        if param:
            key, value = param, True
            index_of_equals = param.find("=")
            if index_of_equals != -1:
                key = param[:index_of_equals].strip()
                value = param[index_of_equals + 1:].strip().strip("'\"")
            params_dict[key.lower()] = value
    return content_type, params_dict


def get_encoding_from_headers(headers: CaseInsensitiveDict) -> Optional[str]:
    content_type = headers.get("content-type")
    if not content_type:
        return None
    content_type, params = _parse_content_type_header(content_type)
    if "charset" in params:
        return params["charset"]
    if "text" in content_type:
        return "ISO-8859-1"
    if "application/json" in content_type:
        return "utf-8"
    return None


def build_response(res: dict, res_cookies: RequestsCookieJar, request_info: Optional[Dict[str, Any]] = None) -> Response:
    """Build a Response from the JSON the Go shared library returned."""
    response = Response()
    response.url = res.get("target")
    response.status_code = res["status"]
    response.used_protocol = res.get("usedProtocol")
    response.request = request_info

    response_headers = CaseInsensitiveDict()
    for header_key, header_value in (res.get("headers") or {}).items():
        response_headers[header_key] = header_value[0] if len(header_value) == 1 else header_value
    response.encoding = get_encoding_from_headers(response_headers)
    response.headers = response_headers
    response.cookies = res_cookies

    body = res.get("body") or ""
    # the Go side returns "data:<content-type>;base64,<payload>"
    response._content = base64.b64decode(body.split(",", 1)[1]) if "," in body else b""
    return response
