"""skeltahtls - requests-like HTTP client with browser-accurate TLS/HTTP2 fingerprints.

    from skeltahtls import Session, AsyncSession
    s = Session()                       # newest Chrome profile bundled (skeltahtls.CHROME_LATEST)
    r = s.get("https://tls.peet.ws/api/all")

Built on the bogdanfinn/tls-client Go library (shipped as a shared library in ./dependencies).
"""
from .__version__ import __version__
from ._cffi import destroy_all, library_features, library_version
from .async_session import AsyncSession
from .cookiejar import CookieJar
from .exceptions import HTTPError, SessionConfigurationError, TLSClientException, TLSClientExeption
from .profiles import (
    ALL_IDENTIFIERS,
    CHROME_LATEST,
    CHROME_LATEST_PSK,
    DEFAULT_PROFILE,
    FIREFOX_LATEST,
    ClientIdentifiers,
)
from .response import Response
from .session import Session

__all__ = [
    "Session", "AsyncSession", "Response", "CookieJar",
    "TLSClientException", "TLSClientExeption", "HTTPError", "SessionConfigurationError",
    "ClientIdentifiers", "ALL_IDENTIFIERS", "CHROME_LATEST", "CHROME_LATEST_PSK", "FIREFOX_LATEST", "DEFAULT_PROFILE",
    "destroy_all", "library_version", "library_features", "__version__",
]
