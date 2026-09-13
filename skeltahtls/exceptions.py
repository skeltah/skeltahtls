"""Exceptions raised by skeltahtls."""
from __future__ import annotations

from typing import Any, Optional


class TLSClientException(IOError):
    """Error reported by the Go tls-client shared library (connect failure, timeout, proxy error, ...)."""


# backwards-compatible alias (the original wrapper misspelt it)
TLSClientExeption = TLSClientException


class HTTPError(IOError):
    """Raised by Response.raise_for_status()."""

    def __init__(self, message: str, response: Optional[Any] = None) -> None:
        super().__init__(message)
        self.response = response


class SessionConfigurationError(ValueError):
    """Invalid / conflicting Session options (e.g. profile and ja3_string given together)."""
