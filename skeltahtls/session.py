"""Synchronous session on top of the bogdanfinn/tls-client shared library."""
from __future__ import annotations

import base64
import json as _json
import time
import urllib.parse
import uuid
import warnings
from datetime import timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple, Union
from urllib.parse import urljoin

from . import _cffi
from .cookiejar import CookieInput, CookieJar
from .cookies import MockRequest, extract_cookies_to_jar
from .exceptions import SessionConfigurationError, TLSClientException
from . import profiles as _profiles
from .profiles import DEFAULT_PROFILE, builtin_pseudo_header_order, is_known_identifier
from .response import Response, build_response
from .structures import CaseInsensitiveDict

_UNSET: Any = object()

# http_version -> (force_http1, disable_http3, with_protocol_racing)
HTTP_VERSIONS: Dict[str, Tuple[bool, bool, bool]] = {
    # ALPN as the profile defines it: h2, falling back to http/1.1. Never QUIC.
    "auto": (False, False, False),
    # ALPN forced to ["http/1.1"]. This changes the ClientHello: JA4 becomes ...h1_...
    "1.1": (True, False, False),
    # Like auto, plus h3 stripped from ALPN/ALPS for the profiles that advertise it
    # (profiles.PROFILES_WITH_H3_ALPN); identical to auto for every other profile.
    "2": (False, True, False),
    # Chrome-style protocol racing: QUIC immediately, HTTP/2 after 300 ms, winner cached per
    # host. Needs a SOCKS5 proxy if a proxy is used at all - only SOCKS5 can tunnel UDP.
    "3": (False, False, True),
}
_HTTP_VERSION_ALIASES: Dict[Any, str] = {
    None: "auto", "auto": "auto", "negotiate": "auto",
    1: "1.1", 1.1: "1.1", "1": "1.1", "1.1": "1.1", "h1": "1.1", "http1": "1.1", "http/1.1": "1.1",
    2: "2", "2": "2", "h2": "2", "http2": "2", "http/2": "2",
    3: "3", "3": "3", "h3": "3", "http3": "3", "http/3": "3", "quic": "3",
}


def normalize_http_version(value: Any) -> str:
    """Map 1 / "1.1" / "h2" / 3 / "quic" / None onto a key of HTTP_VERSIONS."""
    try:
        return _HTTP_VERSION_ALIASES[value]
    except (KeyError, TypeError):
        raise SessionConfigurationError(
            "unknown http_version {!r}; use one of {} (aliases: 1, 2, 3, 'h2', 'h3', 'quic', None)".format(
                value, ", ".join(repr(v) for v in HTTP_VERSIONS)
            )
        ) from None

CUSTOM_TLS_FIELDS = (
    "ja3_string", "h2_settings", "h2_settings_order", "supported_signature_algorithms",
    "supported_delegated_credentials_algorithms", "supported_versions", "key_share_curves",
    "cert_compression_algos", "alpn_protocols", "alps_protocols", "ech_candidate_payloads",
    "ech_candidate_cipher_suites", "record_size_limit", "trust_anchors_payload", "pseudo_header_order",
    "connection_flow", "priority_frames", "header_priority", "stream_id", "fill_custom_with_chrome_defaults",
)

# options that are baked into the Go client at creation time; changing any of them
# after the first request means the Go session must be rebuilt
_TRANSPORT_FIELDS = (
    "client_identifier", "random_tls_extension_order", "force_http1", "disable_http3",
    "disable_session_tickets", "with_protocol_racing", "disable_ipv4", "disable_ipv6",
    "certificate_pinning", "server_name_overwrite", "local_address", "transport_options",
    "default_headers", "connect_headers", "catch_panics", "debug",
) + CUSTOM_TLS_FIELDS


class Session:
    """requests-like session with a browser TLS/HTTP2 fingerprint.

    Default profile is the newest Chrome bundled with the library (see skeltahtls.CHROME_LATEST).
    Pass ``client_identifier=None`` together with ``ja3_string`` / ``h2_settings`` / ... to
    build a fully custom fingerprint instead.
    """

    MAX_REDIRECTS = 30

    def __init__(
        self,
        client_identifier: Optional[str] = _UNSET,
        *,
        # --- custom fingerprint (only when client_identifier is None) -------------------------------
        ja3_string: Optional[str] = None,
        h2_settings: Optional[Dict[str, int]] = None,
        h2_settings_order: Optional[List[str]] = None,
        supported_signature_algorithms: Optional[List[str]] = None,
        supported_delegated_credentials_algorithms: Optional[List[str]] = None,
        supported_versions: Optional[List[str]] = None,
        key_share_curves: Optional[List[str]] = None,
        cert_compression_algos: Optional[Union[str, List[str]]] = None,
        cert_compression_algo: Optional[str] = None,  # legacy alias
        alpn_protocols: Optional[List[str]] = None,
        alps_protocols: Optional[List[str]] = None,
        ech_candidate_payloads: Optional[List[int]] = None,
        ech_candidate_cipher_suites: Optional[List[Dict[str, str]]] = None,
        record_size_limit: Optional[int] = None,
        trust_anchors_payload: Optional[str] = None,
        fill_custom_with_chrome_defaults: bool = True,
        pseudo_header_order: Optional[Sequence[str]] = None,
        connection_flow: Optional[int] = None,
        priority_frames: Optional[List[dict]] = None,
        header_priority: Optional[Dict[str, Any]] = None,
        stream_id: Optional[int] = None,
        # --- request shaping -------------------------------------------------------------------------
        header_order: Optional[Sequence[str]] = None,
        random_tls_extension_order: bool = True,
        http_version: Any = _UNSET,
        force_http1: bool = False,
        disable_http3: bool = False,
        disable_session_tickets: bool = False,
        with_protocol_racing: bool = False,
        # --- transport ------------------------------------------------------------------------------
        proxy: Optional[Union[str, Mapping[str, str]]] = None,
        cookies: CookieInput = None,
        timeout: Optional[float] = 30,
        verify: bool = True,
        certificate_pinning: Optional[Dict[str, List[str]]] = None,
        disable_ipv4: bool = False,
        disable_ipv6: bool = False,
        local_address: Optional[str] = None,
        server_name_overwrite: Optional[str] = None,
        transport_options: Optional[Dict[str, Any]] = None,
        default_headers: Optional[Dict[str, List[str]]] = None,
        connect_headers: Optional[Dict[str, List[str]]] = None,
        catch_panics: bool = True,
        debug: bool = False,
    ) -> None:
        if cert_compression_algos is None and cert_compression_algo is not None:
            cert_compression_algos = cert_compression_algo
        if isinstance(cert_compression_algos, str):
            cert_compression_algos = [cert_compression_algos]

        custom_given = {
            "ja3_string": ja3_string, "h2_settings": h2_settings, "h2_settings_order": h2_settings_order,
            "supported_signature_algorithms": supported_signature_algorithms,
            "supported_delegated_credentials_algorithms": supported_delegated_credentials_algorithms,
            "supported_versions": supported_versions, "key_share_curves": key_share_curves,
            "cert_compression_algos": cert_compression_algos, "alpn_protocols": alpn_protocols,
            "alps_protocols": alps_protocols, "ech_candidate_payloads": ech_candidate_payloads,
            "ech_candidate_cipher_suites": ech_candidate_cipher_suites, "record_size_limit": record_size_limit,
            "trust_anchors_payload": trust_anchors_payload, "connection_flow": connection_flow, "priority_frames": priority_frames,
            "header_priority": header_priority, "stream_id": stream_id,
        }
        uses_custom = any(v is not None for v in custom_given.values())

        if client_identifier is _UNSET:
            # Not specified: a ja3_string (or any other custom field) means "custom client",
            # otherwise the default profile. The old wrapper silently kept chrome_124 here
            # and ignored the ja3_string.
            client_identifier = None if uses_custom else DEFAULT_PROFILE
        elif client_identifier is not None and uses_custom:
            given = ", ".join(k for k, v in custom_given.items() if v is not None)
            raise SessionConfigurationError(
                f"client_identifier={client_identifier!r} cannot be combined with custom TLS options ({given}). "
                "Pass client_identifier=None to use a custom fingerprint."
            )
        if client_identifier is None and ja3_string is None:
            raise SessionConfigurationError("client_identifier=None requires at least a ja3_string")
        if client_identifier is not None and not is_known_identifier(client_identifier):
            raise SessionConfigurationError(
                f"unknown client_identifier {client_identifier!r}; see skeltahtls.profiles.ALL_IDENTIFIERS"
            )

        if pseudo_header_order is not None and client_identifier is not None:
            builtin = builtin_pseudo_header_order(client_identifier)
            if tuple(pseudo_header_order) != builtin:
                raise SessionConfigurationError(
                    f"pseudo_header_order {list(pseudo_header_order)} conflicts with the order built into "
                    f"{client_identifier} ({list(builtin)}). Built-in profiles cannot change it; "
                    "use client_identifier=None with a ja3_string to control pseudo headers."
                )

        self._session_id = str(uuid.uuid4())
        self._go_client_config: Optional[str] = None  # config the live Go client was created with
        self._go_client_broken = False  # the library stored a nil client under this id

        # requests-compatible public state
        self.headers: CaseInsensitiveDict = CaseInsensitiveDict()
        self.cookies: CookieJar = CookieJar().load(cookies)
        self.params: Dict[str, Any] = {}
        self.proxies: Union[str, Mapping[str, str], None] = proxy

        self.client_identifier = client_identifier
        self.ja3_string = ja3_string
        self.h2_settings = h2_settings
        self.h2_settings_order = h2_settings_order
        self.supported_signature_algorithms = supported_signature_algorithms
        self.supported_delegated_credentials_algorithms = supported_delegated_credentials_algorithms
        self.supported_versions = supported_versions
        self.key_share_curves = key_share_curves
        self.cert_compression_algos = cert_compression_algos
        self.alpn_protocols = alpn_protocols
        self.alps_protocols = alps_protocols
        self.ech_candidate_payloads = ech_candidate_payloads
        self.ech_candidate_cipher_suites = ech_candidate_cipher_suites
        self.record_size_limit = record_size_limit
        self.trust_anchors_payload = trust_anchors_payload
        self.fill_custom_with_chrome_defaults = fill_custom_with_chrome_defaults
        self.pseudo_header_order = list(pseudo_header_order) if pseudo_header_order else None
        self.connection_flow = connection_flow
        self.priority_frames = priority_frames
        self.header_priority = header_priority
        self.stream_id = stream_id

        self.header_order = list(header_order) if header_order else None
        self.random_tls_extension_order = random_tls_extension_order
        self.force_http1 = force_http1
        self.disable_http3 = disable_http3
        self.disable_session_tickets = disable_session_tickets
        self.with_protocol_racing = with_protocol_racing

        self.timeout = timeout
        self.verify = verify
        self.certificate_pinning = certificate_pinning
        self.disable_ipv4 = disable_ipv4
        self.disable_ipv6 = disable_ipv6
        self.local_address = local_address
        self.server_name_overwrite = server_name_overwrite
        self.transport_options = transport_options
        self.default_headers = default_headers
        self.connect_headers = connect_headers
        self.catch_panics = catch_panics
        self.debug = debug

        if http_version is not _UNSET:
            if force_http1 or disable_http3 or with_protocol_racing:
                raise SessionConfigurationError(
                    "http_version cannot be combined with force_http1 / disable_http3 / "
                    "with_protocol_racing - they are the same setting at a lower level"
                )
            self.http_version = http_version
        self._validate_transport()

    # ------------------------------------------------------------------ lifecycle

    def __enter__(self) -> "Session":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def close(self) -> None:
        """Destroy the Go-side session (connections, TLS session cache)."""
        if self._go_client_config is None:
            return
        self._go_client_config = None
        if self._go_client_broken:
            # destroying a session whose client failed to build panics inside Go and takes the
            # process down; abandon the id instead (one unused map entry inside the library)
            return
        _cffi.call("destroySession", {"sessionId": self._session_id})

    def reset_connection(self) -> None:
        """Drop the underlying connection pool; the next request performs a fresh TLS handshake."""
        self.close()

    @property
    def session_id(self) -> str:
        return self._session_id

    # ------------------------------------------------------------------ transport protocol

    @property
    def http_version(self) -> str:
        """Transport protocol: "auto" (default), "1.1", "2" or "3" - see HTTP_VERSIONS.

        Assignable between requests (``s.http_version = 3``); the next request opens a new
        connection with the new setting. Accepts 1 / 2 / 3, "h2", "h3", "quic", None.
        """
        if self.with_protocol_racing:
            return "3"
        if self.force_http1:
            return "1.1"
        if self.disable_http3:
            return "2"
        return "auto"

    @http_version.setter
    def http_version(self, value: Any) -> None:
        version = normalize_http_version(value)
        self.force_http1, self.disable_http3, self.with_protocol_racing = HTTP_VERSIONS[version]
        self._warn_about_http_version(version)
        self._validate_transport()

    def _warn_about_http_version(self, version: str) -> None:
        identifier = self.client_identifier
        if identifier is None:
            return
        if version == "2" and identifier in _profiles.PROFILES_WITH_H3_ALPN:
            warnings.warn(
                "http_version=2 removes h3 from the ALPN/ALPS of {}, which changes its ClientHello "
                "(JA3/JA4). Use http_version='auto' to keep the profile byte-exact.".format(identifier),
                stacklevel=3,
            )
        if version == "3" and identifier not in _profiles.PROFILES_WITH_HTTP3_SETTINGS:
            warnings.warn(
                "{} carries no HTTP/3 settings, so an h3 connection uses the library's default QUIC/h3 "
                "parameters instead of browser-accurate ones. Profiles with h3 settings: {}.".format(
                    identifier, ", ".join(sorted(_profiles.PROFILES_WITH_HTTP3_SETTINGS))
                ),
                stacklevel=3,
            )

    def _validate_transport(self, proxy: str = "") -> None:
        """Reject option combinations the Go library refuses.

        Not a nicety: a rejected config makes the shared library store a nil client under this
        session id, and destroying that session afterwards panics inside Go, which takes the
        whole process down. Catching it here keeps that from happening.
        """
        if self.with_protocol_racing and self.force_http1:
            raise SessionConfigurationError(
                "http_version=3 (protocol racing) cannot be combined with force_http1"
            )
        if self.with_protocol_racing and self.disable_http3:
            raise SessionConfigurationError(
                "http_version=3 (protocol racing) cannot be combined with disable_http3"
            )
        if self.disable_ipv4 and self.disable_ipv6:
            raise SessionConfigurationError("cannot disable both IPv4 and IPv6")
        if self.certificate_pinning and not self.verify:
            raise SessionConfigurationError("certificate_pinning cannot be used with verify=False")
        proxy = proxy or self._resolve_proxy(None)
        if self.with_protocol_racing and proxy:
            scheme = proxy.split("://", 1)[0].lower() if "://" in proxy else ""
            if scheme not in ("socks5", "socks5h"):
                raise SessionConfigurationError(
                    "http_version=3 (protocol racing) needs a SOCKS5 proxy: {} cannot tunnel "
                    "QUIC/UDP, so HTTP/3 would bypass the proxy and leak the real IP. Use socks5:// "
                    "or http_version='auto'.".format(scheme or "this proxy")
                )

    # ------------------------------------------------------------------ cookie helpers

    def get_cookies_from_session(self, url: str) -> List[Dict[str, Any]]:
        """Cookies that would be sent for ``url`` (kept for API compatibility)."""
        return self._cookies_for_url(url, None)

    def add_cookies_to_session(self, url: str, cookies: Iterable[Dict[str, Any]]) -> None:
        host = urllib.parse.urlsplit(url).hostname or ""
        for c in cookies:
            self.cookies.set(c["name"], c["value"], domain=c.get("domain") or host, path=c.get("path") or "/")

    # ------------------------------------------------------------------ request preparation

    @staticmethod
    def _prepare_url(url: str, params: Optional[Mapping[str, Any]]) -> str:
        if not params:
            return url
        query = urllib.parse.urlencode(params, doseq=True)
        return f"{url}&{query}" if "?" in url else f"{url}?{query}"

    @staticmethod
    def _prepare_body(data: Any, json: Any) -> Tuple[Optional[Union[str, bytes]], Optional[str]]:
        if data is None and json is not None:
            return _json.dumps(json, separators=(",", ":"), ensure_ascii=False), "application/json"
        if data is not None and not isinstance(data, (str, bytes, bytearray)):
            return urllib.parse.urlencode(data, doseq=True), "application/x-www-form-urlencoded"
        return data, None

    def _merge_headers(self, headers: Optional[Mapping[str, str]]) -> CaseInsensitiveDict:
        merged = CaseInsensitiveDict(self.headers)
        if headers:
            for k, v in headers.items():
                if v is None:
                    merged.pop(k, None)
                else:
                    merged[k] = v
        return merged

    def _effective_header_order(self, headers: CaseInsensitiveDict, header_order: Optional[Sequence[str]]) -> List[str]:
        # Explicit order wins. Otherwise use insertion order of the header dict - the Go side
        # sorts every header *not* in headerOrder alphabetically, which no browser does.
        order = [h.lower() for h in (header_order or self.header_order or [])]
        seen = set(order)
        for key in headers.keys():
            k = key.lower()
            if k not in seen:
                order.append(k)
                seen.add(k)
        return order

    def _cookies_for_url(self, url: str, extra: CookieInput) -> List[Dict[str, Any]]:
        jar = self.cookies
        if extra:
            jar = jar.copy()
            jar.load(extra)
        return [
            {
                "name": c.name,
                "value": c.value.replace('"', "") if c.value else "",
                "domain": c.domain,
                "path": c.path or "/",
                "expires": c.expires or 0,
            }
            for c in jar.cookies_for_request(MockRequest(url, {}))
        ]

    def _resolve_proxy(self, proxy: Any) -> str:
        proxy = proxy if proxy is not None else self.proxies
        if isinstance(proxy, str):
            return proxy
        if isinstance(proxy, Mapping):
            return proxy.get("https") or proxy.get("http") or ""
        return ""

    def _custom_tls_client(self) -> Dict[str, Any]:
        """customTlsClient payload. Fields you leave None are filled with Chrome values
        (only where the ja3 actually lists the matching extension), so a bare ja3_string works."""
        ja3 = self.ja3_string or ""
        parts = ja3.split(",")
        ext_ids = {int(e) for e in parts[2].split("-") if e} if len(parts) > 2 else set()
        curve_ids = {int(c) for c in parts[3].split("-") if c} if len(parts) > 3 else set()
        fill = self.fill_custom_with_chrome_defaults
        P = _profiles

        def default(value, condition, chrome_value):
            return value if value is not None or not fill or not condition else chrome_value

        key_shares = self.key_share_curves
        if key_shares is None and fill and P.KEY_SHARE_EXTENSION_ID in ext_ids:
            key_shares = P.CHROME_KEY_SHARE_CURVES if P.X25519MLKEM768_GROUP_ID in curve_ids else ["GREASE", "X25519"]

        sigalgs = P.CHROME_SIGNATURE_ALGORITHMS
        if not _cffi.library_features().get("custom_client_grease_mldsa_sigalgs", True):
            # upstream release binaries predate the GREASE/MLDSA names in the ja3 mapper
            sigalgs = [a for a in sigalgs if a != "GREASE" and not a.startswith("MLDSA")]

        payload: Dict[str, Any] = {"ja3String": ja3}
        optional = {
            "h2Settings": default(self.h2_settings, True, P.CHROME_H2_SETTINGS),
            "h2SettingsOrder": default(self.h2_settings_order, True, P.CHROME_H2_SETTINGS_ORDER),
            "connectionFlow": default(self.connection_flow, True, P.CHROME_CONNECTION_FLOW),
            "pseudoHeaderOrder": default(self.pseudo_header_order, True, list(P.CHROME_PSEUDO_HEADER_ORDER)),
            "supportedVersions": default(self.supported_versions, P.SUPPORTED_VERSIONS_EXTENSION_ID in ext_ids, P.CHROME_SUPPORTED_VERSIONS),
            "keyShareCurves": key_shares,
            "supportedSignatureAlgorithms": default(self.supported_signature_algorithms, P.SIGNATURE_ALGORITHMS_EXTENSION_ID in ext_ids, sigalgs),
            "alpnProtocols": default(self.alpn_protocols, P.ALPN_EXTENSION_ID in ext_ids, P.CHROME_ALPN),
            "alpsProtocols": default(self.alps_protocols, any(i in ext_ids for i in P.ALPS_EXTENSION_IDS), P.CHROME_ALPS),
            "certCompressionAlgos": default(self.cert_compression_algos, P.COMPRESS_CERTIFICATE_EXTENSION_ID in ext_ids, P.CHROME_CERT_COMPRESSION),
            "trustAnchorsPayload": default(self.trust_anchors_payload, P.TRUST_ANCHORS_EXTENSION_ID in ext_ids, P.CHROME_TRUST_ANCHORS_PAYLOAD),
            "supportedDelegatedCredentialsAlgorithms": self.supported_delegated_credentials_algorithms,
            "ECHCandidatePayloads": self.ech_candidate_payloads,
            "ECHCandidateCipherSuites": self.ech_candidate_cipher_suites,
            "recordSizeLimit": self.record_size_limit,
            "priorityFrames": self.priority_frames,
            "headerPriority": self.header_priority,
            "streamId": self.stream_id,
        }
        payload.update({k: v for k, v in optional.items() if v is not None})
        return payload

    def _transport_config(self, timeout: Optional[float], verify: bool) -> str:
        values = {name: getattr(self, name) for name in _TRANSPORT_FIELDS}
        values["timeout"] = timeout
        values["verify"] = verify
        return _json.dumps(values, sort_keys=True, default=str)

    def _build_payload(
        self,
        method: str,
        url: str,
        headers: CaseInsensitiveDict,
        header_order: List[str],
        body: Optional[Union[str, bytes, bytearray]],
        cookies: List[Dict[str, Any]],
        timeout: Optional[float],
        proxy: str,
        verify: bool,
    ) -> Dict[str, Any]:
        is_bytes = isinstance(body, (bytes, bytearray))
        payload: Dict[str, Any] = {
            "sessionId": self._session_id,
            "requestUrl": url,
            "requestMethod": method,
            "requestBody": base64.b64encode(body).decode() if is_bytes else body,
            "isByteRequest": is_bytes,
            "isByteResponse": True,
            "headers": dict(headers),
            "headerOrder": header_order,
            "requestCookies": cookies,
            "proxyUrl": proxy,
            "isRotatingProxy": False,
            "followRedirects": False,  # redirects are handled here so history/cookies stay in Python
            "forceHttp1": self.force_http1,
            "disableHttp3": self.disable_http3,
            "disableSessionTickets": self.disable_session_tickets,
            "withProtocolRacing": self.with_protocol_racing,
            "insecureSkipVerify": not verify,
            "disableIPV4": self.disable_ipv4,
            "disableIPV6": self.disable_ipv6,
            "catchPanics": self.catch_panics,
            "withDebug": self.debug,
            # the Python jar is the single source of truth for cookies
            "withoutCookieJar": True,
            "withCustomCookieJar": False,
            "withRandomTLSExtensionOrder": self.random_tls_extension_order,
        }

        if timeout is not None:
            if float(timeout).is_integer():
                payload["timeoutSeconds"] = int(timeout)
            else:
                payload["timeoutMilliseconds"] = int(timeout * 1000)

        if self.client_identifier is not None:
            payload["tlsClientIdentifier"] = self.client_identifier
        else:
            payload["customTlsClient"] = self._custom_tls_client()

        for key, value in (
            ("certificatePinningHosts", self.certificate_pinning),
            ("localAddress", self.local_address),
            ("serverNameOverwrite", self.server_name_overwrite),
            ("transportOptions", self.transport_options),
            ("defaultHeaders", self.default_headers),
            ("connectHeaders", self.connect_headers),
        ):
            if value is not None:
                payload[key] = value
        return payload

    # ------------------------------------------------------------------ execution

    def execute_request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        data: Any = None,
        headers: Optional[Mapping[str, str]] = None,
        cookies: CookieInput = None,
        json: Any = None,
        allow_redirects: bool = True,
        verify: Optional[bool] = None,
        timeout: Optional[float] = _UNSET,
        proxy: Any = None,
        proxies: Any = None,
        header_order: Optional[Sequence[str]] = None,
        host_override: Optional[str] = None,
    ) -> Response:
        method = method.upper()
        merged_params = {**self.params, **(params or {})} if (self.params or params) else None
        url = self._prepare_url(url, merged_params)
        body, content_type = self._prepare_body(data, json)
        request_headers = self._merge_headers(headers)
        if content_type is not None and "content-type" not in request_headers:
            request_headers["content-type"] = content_type

        verify = self.verify if verify is None else verify
        timeout = self.timeout if timeout is _UNSET else timeout
        proxy_url = self._resolve_proxy(proxy if proxy is not None else proxies)
        self._validate_transport(proxy_url)

        history: List[Response] = []
        start = time.perf_counter()

        while True:
            self._ensure_go_client(timeout, verify)
            order = self._effective_header_order(request_headers, header_order)
            request_cookies = [] if "cookie" in request_headers else self._cookies_for_url(url, cookies)

            payload = self._build_payload(
                method, url, request_headers, order, body, request_cookies, timeout, proxy_url, verify
            )
            if host_override:
                payload["requestHostOverride"] = host_override

            result = _cffi.call("request", payload)
            if result.get("status") == 0:
                message = result.get("body", "unknown tls-client error")
                if "failed to build client" in message or "invalid config" in message:
                    self._go_client_broken = True
                    self._renew_session_id()
                raise TLSClientException(message)

            jar = extract_cookies_to_jar(
                request_url=url,
                request_headers=request_headers,
                cookie_jar=self.cookies,
                response_headers=result.get("headers") or {},
            )
            response = build_response(
                result, jar,
                {"method": method, "url": url, "headers": dict(request_headers), "header_order": order},
            )
            response.elapsed = timedelta(seconds=time.perf_counter() - start)

            if not allow_redirects or not response.is_redirect:
                response.history = history
                return response

            history.append(response)
            if len(history) > self.MAX_REDIRECTS:
                raise TLSClientException(f"Max redirects ({self.MAX_REDIRECTS}) exceeded")

            url = urljoin(url, response.headers["location"])
            if response.status_code in (301, 302, 303) and method != "HEAD":
                method = "GET"
                body = None
                for h in ("content-length", "content-type", "transfer-encoding"):
                    request_headers.pop(h, None)

    def _renew_session_id(self) -> None:
        """Leave a broken Go-side session behind and continue under a fresh id."""
        self._session_id = str(uuid.uuid4())
        self._go_client_config = None
        self._go_client_broken = False

    def _ensure_go_client(self, timeout: Optional[float], verify: bool) -> None:
        """Rebuild the Go client when a transport-level option changed since it was created.

        The Go library caches one client per sessionId and only proxy/redirect settings can
        be changed in place; force_http1, profile, timeout etc. would otherwise be ignored.
        """
        config = self._transport_config(timeout, verify)
        if self._go_client_config is None:
            self._go_client_config = config
        elif config != self._go_client_config:
            if self._go_client_broken:
                self._renew_session_id()
            else:
                _cffi.call("destroySession", {"sessionId": self._session_id})
            self._go_client_config = config

    # ------------------------------------------------------------------ verbs

    def request(self, method: str, url: str, **kwargs: Any) -> Response:
        return self.execute_request(method, url, **kwargs)

    def get(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("GET", url, **kwargs)

    def options(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("OPTIONS", url, **kwargs)

    def head(self, url: str, **kwargs: Any) -> Response:
        kwargs.setdefault("allow_redirects", False)
        return self.execute_request("HEAD", url, **kwargs)

    def post(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("POST", url, data=data, json=json, **kwargs)

    def put(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("PUT", url, data=data, json=json, **kwargs)

    def patch(self, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> Response:
        return self.execute_request("PATCH", url, data=data, json=json, **kwargs)

    def delete(self, url: str, **kwargs: Any) -> Response:
        return self.execute_request("DELETE", url, **kwargs)

