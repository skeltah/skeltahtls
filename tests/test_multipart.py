"""multipart/form-data: exact bytes, part order, and how files= reaches the request."""
import io
import json
import re

import pytest

from skeltahtls import Session, encode_multipart, generate_boundary
from skeltahtls import multipart as M
from skeltahtls.structures import CaseInsensitiveDict

B = "----WebKitFormBoundaryFIXEDFIXEDFIXE"  # 16 chars after the prefix, like Chrome


def body_of(payload):
    """The request body the Go side would send, decoded back from the payload."""
    import base64
    if payload["isByteRequest"]:
        return base64.b64decode(payload["requestBody"])
    return payload["requestBody"].encode() if payload["requestBody"] else b""


def build(session, **kwargs):
    headers = session._merge_headers(kwargs.pop("headers", None))
    body, content_type = session._prepare_body(
        kwargs.pop("data", None), kwargs.pop("json", None), kwargs.pop("files", None),
        headers.get("content-type"),
    )
    if content_type is not None and "content-type" not in headers:
        headers["content-type"] = content_type
    payload = session._build_payload("POST", "https://x/", headers, [], body, [], 30, "", True)
    return payload, headers


# ------------------------------------------------------------------ the bytes

def test_exact_bytes_of_a_presigned_s3_post():
    """The case this was written for: field order is signed, so it must not move."""
    fields = {
        "signature": "c2ln",
        "AWSAccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "acl": "private",
        "x-amz-meta-fileid": "42",
        "key": "uploads/42/blob",
        "policy": "eyJleHBpcmF0aW9uIjoi",
    }
    body, content_type = encode_multipart(
        {"file": ("blob", b"%PDF-1.7\n%\xe2\xe3\xcf\xd3", "application/pdf")}, fields, boundary=B
    )

    expected = b"".join(
        b"--" + B.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="' + name.encode() + b'"\r\n'
        b"\r\n" + value.encode() + b"\r\n"
        for name, value in fields.items()
    ) + (
        b"--" + B.encode() + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="blob"\r\n'
        b"Content-Type: application/pdf\r\n"
        b"\r\n"
        b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\r\n"
        b"--" + B.encode() + b"--\r\n"
    )
    assert body == expected
    assert content_type == f"multipart/form-data; boundary={B}"


def test_matches_a_real_chrome_152_body():
    """Captured from Chrome 152.0.7977.130 with FormData + fetch to httpbingo.org/post."""
    boundary = "----WebKitFormBoundaryWFDP9bfNcqfXAOqA"
    chrome = (
        "------WebKitFormBoundaryWFDP9bfNcqfXAOqA\r\n"
        'Content-Disposition: form-data; name="key"\r\n\r\nuploads/42\r\n'
        "------WebKitFormBoundaryWFDP9bfNcqfXAOqA\r\n"
        'Content-Disposition: form-data; name="acl"\r\n\r\nprivate\r\n'
        "------WebKitFormBoundaryWFDP9bfNcqfXAOqA\r\n"
        'Content-Disposition: form-data; name="file"; filename="blob"\r\n'
        "Content-Type: application/pdf\r\n\r\n%PDF\r\n"
        "------WebKitFormBoundaryWFDP9bfNcqfXAOqA--\r\n"
    ).encode()
    body, content_type = encode_multipart(
        {"file": ("blob", b"%PDF", "application/pdf")},
        {"key": "uploads/42", "acl": "private"},
        boundary=boundary,
    )
    assert body == chrome
    assert content_type == f"multipart/form-data; boundary={boundary}"


def test_line_endings_are_crlf_everywhere():
    body, _ = encode_multipart({"f": ("a.txt", b"line1\nline2")}, {"x": "1"}, boundary=B)
    # every structural newline is a CRLF; the only bare LF is inside the file content
    # field part: delimiter, disposition, blank, trailing = 4; file part adds a
    # Content-Type line = 5; the closing delimiter = 1
    assert body.count(b"\r\n") == 10
    assert body.replace(b"\r\n", b"").count(b"\n") == 1


def test_simple_fields_carry_no_content_type_and_files_always_do():
    body, _ = encode_multipart({"f": ("a.bin", b"x")}, {"plain": "1"}, boundary=B)
    field, file_part = body.split(b"--" + B.encode() + b"\r\n")[1:3]
    assert b"Content-Type" not in field
    assert b"Content-Type: application/octet-stream\r\n" in file_part


def test_names_are_written_literally():
    # Chrome does not percent-encode or RFC 2231-escape these
    body, _ = encode_multipart({"f": ("имя файла.pdf", b"x", "application/pdf")}, boundary=B)
    assert 'filename="имя файла.pdf"'.encode("utf-8") in body


def test_boundary_shape():
    boundary = generate_boundary()
    assert re.fullmatch(r"----WebKitFormBoundary[A-Za-z0-9]{16}", boundary)
    assert len({generate_boundary() for _ in range(50)}) == 50
    body, content_type = encode_multipart({"f": (None, "v")})
    used = M.boundary_from_content_type(content_type)
    assert body.startswith(b"--" + used.encode() + b"\r\n")
    assert body.endswith(b"--" + used.encode() + b"--\r\n")


# ------------------------------------------------------------------ accepted shapes

def test_value_shapes():
    parts = M.normalize_files({
        "raw_bytes": b"a",
        "raw_str": "b",
        "fileobj": io.BytesIO(b"c"),
        "pair": ("n.txt", b"d"),
        "triple": ("n.pdf", b"e", "application/pdf"),
        "plain_field": (None, "f"),
    })
    assert [(name, filename, ctype) for name, filename, ctype, _ in parts] == [
        ("raw_bytes", "raw_bytes", "application/octet-stream"),
        ("raw_str", "raw_str", "application/octet-stream"),
        ("fileobj", "fileobj", "application/octet-stream"),
        ("pair", "n.txt", "application/octet-stream"),
        ("triple", "n.pdf", "application/pdf"),
        ("plain_field", None, None),
    ]
    assert [content for *_, content in parts] == [b"a", b"b", b"c", b"d", b"e", b"f"]


def test_file_object_with_a_name_keeps_its_basename(tmp_path):
    path = tmp_path / "report.pdf"
    path.write_bytes(b"%PDF")
    with path.open("rb") as handle:
        parts = M.normalize_files({"file": handle})
    assert parts[0][1] == "report.pdf"


def test_list_of_pairs_fixes_the_order_and_allows_repeats():
    body, _ = encode_multipart(
        [("policy", (None, "p")), ("file", ("a.txt", b"1")), ("file", ("b.txt", b"2"))], boundary=B
    )
    names = re.findall(rb'name="([^"]+)"(?:; filename="([^"]+)")?', body)
    assert names == [(b"policy", b""), (b"file", b"a.txt"), (b"file", b"b.txt")]


def test_bad_shapes_are_rejected():
    with pytest.raises(TypeError, match="filename, content"):
        M.normalize_files({"f": ("a", b"b", "c", "d")})
    with pytest.raises(TypeError, match="filename must be a string"):
        M.normalize_files({"f": (123, b"b")})


# ------------------------------------------------------------------ through the session

def test_files_produce_a_byte_request_with_a_matching_content_type():
    s = Session()
    payload, headers = build(s, files={"file": ("blob", b"%PDF", "application/pdf")},
                             data={"key": "uploads/1"})
    assert payload["isByteRequest"] is True
    boundary = M.boundary_from_content_type(headers["content-type"])
    assert re.fullmatch(r"----WebKitFormBoundary[A-Za-z0-9]{16}", boundary)
    body = body_of(payload)
    assert body.startswith(b"--" + boundary.encode())
    assert body.endswith(b"--" + boundary.encode() + b"--\r\n")
    assert body.index(b'name="key"') < body.index(b'name="file"')
    s.close()


def test_a_content_type_set_by_the_caller_wins_and_lends_its_boundary():
    s = Session()
    mine = "----WebKitFormBoundaryMINEMINEMINE12"
    payload, headers = build(
        s,
        files={"file": ("blob", b"x")},
        headers={"content-type": f"multipart/form-data; boundary={mine}"},
    )
    assert headers["content-type"] == f"multipart/form-data; boundary={mine}"
    assert body_of(payload).startswith(b"--" + mine.encode() + b"\r\n")
    s.close()


def test_quoted_boundary_in_a_caller_supplied_header():
    s = Session()
    payload, _ = build(s, files={"f": (None, "v")},
                       headers={"content-type": 'multipart/form-data; boundary="xyz"; charset=utf-8'})
    assert body_of(payload).startswith(b"--xyz\r\n")
    s.close()


def test_files_with_json_is_refused():
    s = Session()
    with pytest.raises(TypeError, match="files= and json="):
        build(s, files={"f": (None, "v")}, json={"a": 1})
    s.close()


def test_files_with_a_raw_body_is_refused():
    s = Session()
    with pytest.raises(TypeError, match="data= must be a mapping"):
        build(s, files={"f": (None, "v")}, data=b"raw")
    s.close()


def test_other_bodies_are_untouched():
    s = Session()
    assert s._prepare_body({"a": "1"}, None) == ("a=1", "application/x-www-form-urlencoded")
    assert s._prepare_body(None, {"a": 1}) == ('{"a":1}', "application/json")
    assert s._prepare_body(b"raw", None) == (b"raw", None)
    assert s._prepare_body(None, None) == (None, None)
    s.close()


def test_files_is_keyword_only_on_every_verb():
    import inspect
    from skeltahtls import AsyncSession
    for cls in (Session, AsyncSession):
        for verb in ("request", "get", "options", "head", "post", "put", "patch", "delete"):
            parameter = inspect.signature(getattr(cls, verb)).parameters["files"]
            assert parameter.kind is parameter.KEYWORD_ONLY, f"{cls.__name__}.{verb}"


# ------------------------------------------------------------------ network

@pytest.mark.network
def test_upload_round_trip():
    with Session() as s:
        r = s.post("https://httpbingo.org/post",
                   data={"key": "uploads/42", "acl": "private"},
                   files={"file": ("blob", b"%PDF-1.7 payload", "application/pdf")},
                   timeout=30)
    assert r.status_code == 200
    echoed = r.json()
    assert echoed["form"]["key"] == ["uploads/42"]
    assert "%PDF-1.7 payload" in json.dumps(echoed["files"])
    assert echoed["headers"]["Content-Type"][0].startswith("multipart/form-data; boundary=----WebKitFormBoundary")
