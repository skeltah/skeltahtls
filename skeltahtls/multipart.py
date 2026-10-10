"""multipart/form-data exactly as Chrome writes it.

Chrome's body is not interchangeable with the one most HTTP libraries produce: the boundary
has a recognisable shape, simple fields carry no Content-Type, nothing is percent-encoded or
RFC 2231-escaped, and the field order is the order the page submitted them in. Servers that
fingerprint uploads look at all of that, and signed uploads (S3 presigned POST) reject a body
whose fields arrive in a different order than the policy was signed for.

    body, content_type = encode_multipart({"file": ("doc.pdf", pdf_bytes, "application/pdf")})

``Session.post(..., files=...)`` calls this; use it directly when you want to send the body
yourself or need to see the exact bytes.
"""
from __future__ import annotations

import os
import random
import string
from typing import Any, Iterable, List, Mapping, Optional, Sequence, Tuple, Union

CRLF = b"\r\n"
# Chrome 154: "----WebKitFormBoundary" + 16 characters out of [A-Za-z0-9]
BOUNDARY_PREFIX = "----WebKitFormBoundary"
BOUNDARY_RANDOM_LENGTH = 16
BOUNDARY_ALPHABET = string.ascii_letters + string.digits
DEFAULT_FILE_CONTENT_TYPE = "application/octet-stream"

# {"field": value} or [("field", value), ...] - the list form fixes the order of the parts.
# value: bytes | str | file object | (filename, content) | (filename, content, content_type)
FilesInput = Union[
    Mapping[str, Any],
    Sequence[Tuple[str, Any]],
    None,
]

# one part, already normalised: (name, filename or None, content_type or None, content)
Part = Tuple[str, Optional[str], Optional[str], bytes]


def generate_boundary() -> str:
    """A fresh boundary shaped like Chrome's."""
    tail = "".join(random.choices(BOUNDARY_ALPHABET, k=BOUNDARY_RANDOM_LENGTH))
    return BOUNDARY_PREFIX + tail


def boundary_from_content_type(content_type: Optional[str]) -> Optional[str]:
    """The boundary inside a Content-Type header, or None.

    Lets a caller who already set ``content-type`` keep their own boundary instead of
    getting a body that disagrees with the header they sent.
    """
    if not content_type or "boundary=" not in content_type.lower():
        return None
    for parameter in content_type.split(";"):
        name, _, value = parameter.strip().partition("=")
        if name.strip().lower() == "boundary":
            value = value.strip()
            if value.startswith('"') and value.endswith('"') and len(value) > 1:
                value = value[1:-1]
            return value or None
    return None


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if hasattr(value, "read"):  # an open file / BytesIO / StringIO
        return _as_bytes(value.read())
    return str(value).encode("utf-8")


def _filename_of(value: Any) -> Optional[str]:
    name = getattr(value, "name", None)
    if isinstance(name, str) and name:
        return os.path.basename(name)
    return None


def normalize_files(files: FilesInput) -> List[Part]:
    """Turn the accepted ``files`` shapes into ordered parts.

    A bare ``bytes``/``str``/file object becomes a file part; its filename comes from the
    file object when it has one, otherwise from the field name (pass a tuple for an exact
    filename). ``(None, content)`` is a plain field rather than a file.
    """
    if not files:
        return []
    items: Iterable[Tuple[str, Any]] = files.items() if isinstance(files, Mapping) else files

    parts: List[Part] = []
    for entry in items:
        try:
            name, value = entry
        except (TypeError, ValueError):
            raise TypeError(
                f"files entries must be (name, value) pairs, got {entry!r}"
            ) from None

        filename: Optional[str]
        content_type: Optional[str] = None
        if isinstance(value, (tuple, list)):
            if len(value) == 2:
                filename, content = value
            elif len(value) == 3:
                filename, content, content_type = value
            else:
                raise TypeError(
                    f"files[{name!r}] must be (filename, content) or (filename, content, content_type), "
                    f"got a {len(value)}-tuple"
                )
            if filename is not None and not isinstance(filename, str):
                raise TypeError(f"files[{name!r}] filename must be a string or None, got {filename!r}")
            content_bytes = _as_bytes(content)
            if filename is not None and content_type is None:
                content_type = DEFAULT_FILE_CONTENT_TYPE
        else:
            filename = _filename_of(value) or name
            content_bytes = _as_bytes(value)
            content_type = DEFAULT_FILE_CONTENT_TYPE

        parts.append((name, filename, content_type, content_bytes))
    return parts


def normalize_fields(data: Any) -> List[Part]:
    """Plain form fields (a mapping or (name, value) pairs) as parts without a filename."""
    if not data:
        return []
    items: Iterable[Tuple[str, Any]] = data.items() if isinstance(data, Mapping) else data

    parts: List[Part] = []
    for name, value in items:
        if isinstance(value, (list, tuple)) and not isinstance(value, (bytes, bytearray)):
            for item in value:  # one part per value, like urlencode(doseq=True)
                parts.append((name, None, None, _as_bytes(item)))
        else:
            parts.append((name, None, None, _as_bytes(value)))
    return parts


def render_multipart(parts: Sequence[Part], boundary: str) -> bytes:
    """Serialise already-ordered parts with the given boundary.

    Names and filenames are written as they were given: Chrome does not percent-encode or
    RFC 2231-escape them, so neither do we.
    """
    delimiter = b"--" + boundary.encode("utf-8")
    chunks: List[bytes] = []
    for name, filename, content_type, content in parts:
        disposition = f'Content-Disposition: form-data; name="{name}"'
        if filename is not None:
            disposition += f'; filename="{filename}"'
        chunks.append(delimiter + CRLF)
        chunks.append(disposition.encode("utf-8") + CRLF)
        if filename is not None:
            chunks.append(f"Content-Type: {content_type or DEFAULT_FILE_CONTENT_TYPE}".encode("utf-8") + CRLF)
        chunks.append(CRLF)
        chunks.append(content)
        chunks.append(CRLF)
    chunks.append(delimiter + b"--" + CRLF)
    return b"".join(chunks)


def encode_multipart(
    files: FilesInput = None,
    data: Any = None,
    boundary: Optional[str] = None,
) -> Tuple[bytes, str]:
    """Build a Chrome-shaped multipart body.

    Returns ``(body, content_type)``; the content type carries the boundary that was used,
    so the two can never disagree. Fields from ``data`` come first, in their own order,
    then the files - a presigned S3 POST rejects the upload when its fields move.
    """
    boundary = boundary or generate_boundary()
    parts = normalize_fields(data) + normalize_files(files)
    return render_multipart(parts, boundary), f"multipart/form-data; boundary={boundary}"
