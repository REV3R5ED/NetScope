"""Edge-case coverage for the minimal DER/X.509 certificate parser."""

from __future__ import annotations

import pytest

from netscope.tls import (
    _der_name,
    _der_oid,
    _der_read,
    _der_subject_alt_names,
    _der_time,
    _DERError,
    _parse_certificate,
)


def enc(tag: int, content: bytes) -> bytes:
    """Encode one DER TLV (short or long form length)."""
    if len(content) < 128:
        return bytes([tag, len(content)]) + content
    length_bytes = len(content).to_bytes((len(content).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length_bytes)]) + length_bytes + content


def seq(*parts: bytes) -> bytes:
    return enc(0x30, b"".join(parts))


def oid(*arcs: int) -> bytes:
    first = bytes([arcs[0] * 40 + arcs[1]])
    rest = b""
    for arc in arcs[2:]:
        encoded = bytes([arc & 0x7F])
        arc >>= 7
        while arc:
            encoded = bytes([0x80 | (arc & 0x7F)]) + encoded
            arc >>= 7
        rest += encoded
    return enc(0x06, first + rest)


def name(common_name: str) -> bytes:
    atv = seq(oid(2, 5, 4, 3), enc(0x0C, common_name.encode()))
    return seq(enc(0x31, atv))


def validity(not_before: tuple[int, bytes], not_after: tuple[int, bytes]) -> bytes:
    return seq(enc(not_before[0], not_before[1]), enc(not_after[0], not_after[1]))


def build_cert(
    *,
    with_version: bool = True,
    with_extensions: bool = True,
    not_after: tuple[int, bytes] = (0x17, b"360929215903Z"),
    issuer_extra: bytes = b"",
    extensions_override: bytes | None = None,
    trailing_tbs: bytes = b"",
) -> bytes:
    parts = []
    if with_version:
        parts.append(enc(0xA0, enc(0x02, b"\x02")))
    parts.append(enc(0x02, b"\x01"))  # serial
    parts.append(seq(oid(1, 2, 840, 113549, 1, 1, 11), enc(0x05, b"")))  # signature
    parts.append(name("issuer.test") + issuer_extra)
    parts.append(validity((0x17, b"260929215903Z"), not_after))
    parts.append(name("subject.test"))
    parts.append(
        seq(
            seq(oid(1, 2, 840, 113549, 1, 1, 1), enc(0x05, b"")),
            enc(0x03, b"\x00\x01\x02"),
        )
    )  # spki
    if with_extensions:
        if extensions_override is not None:
            parts.append(enc(0xA3, extensions_override))
        else:
            san_value = seq(enc(0x82, b"subject.test"), enc(0x87, b"\xc0\x00\x02\x01"))
            san_ext = seq(oid(2, 5, 29, 17), enc(0x04, san_value))
            other_ext = seq(oid(2, 5, 29, 19), enc(0x01, b"\xff"), enc(0x04, b"\x00"))
            parts.append(enc(0xA3, seq(san_ext, other_ext)))
    if trailing_tbs:
        parts.append(trailing_tbs)
    return seq(seq(*parts), seq(), enc(0x03, b"\x00"))


def test_parse_hand_built_certificate():
    parsed = _parse_certificate(build_cert())
    assert parsed.subject["commonName"] == ("subject.test",)
    assert parsed.issuer["commonName"] == ("issuer.test",)
    assert parsed.sans == ("DNS:subject.test", "IP:192.0.2.1")
    assert parsed.not_after is not None
    assert (parsed.not_after.year, parsed.not_after.month) == (2036, 9)


def test_parse_certificate_without_version_or_extensions():
    parsed = _parse_certificate(build_cert(with_version=False, with_extensions=False))
    assert parsed.subject["commonName"] == ("subject.test",)
    assert parsed.sans == ()


def test_parse_certificate_with_generalized_time():
    parsed = _parse_certificate(build_cert(not_after=(0x18, b"20360929215903Z")))
    assert parsed.not_after is not None
    assert parsed.not_after.year == 2036


def test_parse_certificate_rejects_non_sequence_tbs():
    with pytest.raises(_DERError, match="tbsCertificate"):
        _parse_certificate(seq(enc(0x02, b"\x01")))


def test_parse_certificate_rejects_truncated_tbs():
    with pytest.raises(_DERError, match="missing fields"):
        _parse_certificate(seq(seq(enc(0x02, b"\x01"))))


def test_der_read_rejects_truncated_header():
    with pytest.raises(_DERError, match="truncated DER header"):
        _der_read(b"\x30", 0)


def test_der_read_rejects_overlong_length():
    with pytest.raises(_DERError, match="exceeds available"):
        _der_read(b"\x30\x05\x01\x02", 0)


def test_der_read_supports_long_form_length():
    payload = b"x" * 200
    tag, value, next_offset = _der_read(enc(0x04, payload), 0)
    assert tag == 0x04
    assert value == payload
    assert next_offset == len(enc(0x04, payload))


def test_der_read_rejects_indefinite_length():
    with pytest.raises(_DERError):
        _der_read(b"\x30\x80\x00\x00", 0)


def test_der_oid_rejects_empty_and_truncated():
    with pytest.raises(_DERError, match="empty OID"):
        _der_oid(b"")
    with pytest.raises(_DERError, match="truncated OID"):
        _der_oid(b"\x55\x81")


def test_der_oid_decodes_common_name():
    assert _der_oid(bytes([0x55, 0x04, 0x03])) == (2, 5, 4, 3)


def test_der_time_rejects_unknown_tag_and_garbage():
    assert _der_time(0x19, b"whatever") is None
    assert _der_time(0x17, b"not-a-time") is None
    assert _der_time(0x18, b"not-a-time") is None
    parsed = _der_time(0x17, b"360929215903Z")
    assert parsed is not None and parsed.tzinfo is not None


def test_der_name_skips_malformed_attributes():
    good = enc(0x31, seq(oid(2, 5, 4, 3), enc(0x0C, b"good.test")))
    malformed = enc(0x31, seq(enc(0x02, b"\x01")))  # not an OID pair
    not_a_set = enc(0x30, b"\x01\x01\x00")  # wrong tag entirely
    unknown_oid = enc(0x31, seq(oid(1, 2, 3, 4), enc(0x0C, b"mystery")))
    names = _der_name(b"".join([good, malformed, not_a_set, unknown_oid]))
    assert names["commonName"] == ("good.test",)
    assert names["1.2.3.4"] == ("mystery",)


def test_der_subject_alt_names_rejects_non_sequence():
    assert _der_subject_alt_names(b"\x02\x01\x01") == ()


def test_der_subject_alt_names_skips_bad_ip():
    wrapped = seq(enc(0x82, b"a.test"), enc(0x87, b"\x01\x02"))
    assert _der_subject_alt_names(wrapped) == ("DNS:a.test",)


def test_parse_certificate_ignores_non_extension_trailing_fields():
    parsed = _parse_certificate(build_cert(trailing_tbs=enc(0xA1, b"\x00")))
    assert parsed.subject["commonName"] == ("subject.test",)
    assert parsed.sans == ("DNS:subject.test", "IP:192.0.2.1")


def test_parse_certificate_ignores_malformed_extensions_block():
    parsed = _parse_certificate(build_cert(extensions_override=enc(0x02, b"\x01")))
    assert parsed.sans == ()


def test_parse_certificate_ignores_malformed_extension_entries():
    malformed = seq(enc(0x02, b"\x01"))  # not an OID-led extension
    parsed = _parse_certificate(build_cert(extensions_override=seq(malformed)))
    assert parsed.sans == ()
