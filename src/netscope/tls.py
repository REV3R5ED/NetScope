"""Bounded TLS handshake diagnostics using only the standard library."""

from __future__ import annotations

import ipaddress
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .diagnostics import (
    MAX_TCP_TIMEOUT,
    _normalized_host,
    _result_dict,
    _valid_port,
    _valid_timeout,
)
from .validation import has_control_characters

logger = logging.getLogger(__name__)


class _DERError(ValueError):
    """Raised when certificate bytes do not follow the expected DER layout."""


def _der_read(data: bytes, offset: int) -> tuple[int, bytes, int]:
    """Read one DER TLV; return (tag, value bytes, offset of next TLV)."""
    if offset + 2 > len(data):
        raise _DERError("truncated DER header")
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or offset + count > len(data):
            raise _DERError("unsupported DER length encoding")
        length = int.from_bytes(data[offset : offset + count], "big")
        offset += count
    if offset + length > len(data):
        raise _DERError("DER length exceeds available bytes")
    return tag, data[offset : offset + length], offset + length


def _der_children(value: bytes) -> list[tuple[int, bytes]]:
    """Split the value of a constructed DER element into (tag, value) pairs."""
    children: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(value):
        tag, child, offset = _der_read(value, offset)
        children.append((tag, child))
    return children


def _der_oid(value: bytes) -> tuple[int, ...]:
    """Decode a DER OBJECT IDENTIFIER value into its arc tuple."""
    if not value:
        raise _DERError("empty OID")
    arcs = [value[0] // 40, value[0] % 40]
    number = 0
    started = False
    for byte in value[1:]:
        number = (number << 7) | (byte & 0x7F)
        started = True
        if not byte & 0x80:
            arcs.append(number)
            number = 0
            started = False
    if started:
        raise _DERError("truncated OID")
    return tuple(arcs)


_OID_LABELS = {
    (2, 5, 4, 3): "commonName",
    (2, 5, 4, 4): "surname",
    (2, 5, 4, 5): "serialNumber",
    (2, 5, 4, 6): "countryName",
    (2, 5, 4, 7): "localityName",
    (2, 5, 4, 8): "stateOrProvinceName",
    (2, 5, 4, 10): "organizationName",
    (2, 5, 4, 11): "organizationalUnitName",
    (2, 5, 4, 12): "title",
    (2, 5, 4, 42): "givenName",
    (2, 5, 4, 43): "initials",
    (2, 5, 4, 44): "generationQualifier",
    (2, 5, 4, 65): "pseudonym",
    (1, 2, 840, 113549, 1, 9, 1): "emailAddress",
}

_SAN_OID = (2, 5, 29, 17)


def _der_name(value: bytes) -> dict[str, tuple[str, ...]]:
    """Decode a DER Name (RDNSequence) into attribute label -> values."""
    names: dict[str, list[str]] = {}
    for rdn_tag, rdn in _der_children(value):
        if rdn_tag != 0x31:  # SET OF AttributeTypeAndValue
            continue
        for _, attribute in _der_children(rdn):
            parts = _der_children(attribute)
            if len(parts) != 2 or parts[0][0] != 0x06:
                continue
            oid = _der_oid(parts[0][1])
            label = _OID_LABELS.get(oid, ".".join(str(arc) for arc in oid))
            names.setdefault(label, []).append(parts[1][1].decode("utf-8", "replace"))
    return {label: tuple(values) for label, values in names.items()}


def _der_time(tag: int, value: bytes) -> datetime | None:
    """Decode a DER UTCTime/GeneralizedTime validity bound as UTC."""
    text = value.decode("ascii", "replace").strip()
    if tag == 0x17:  # UTCTime: YYMMDDHHMMSSZ
        moment = text[:12]
        parsed = _parse_time_fields(moment, "%y%m%d%H%M%S")
    elif tag == 0x18:  # GeneralizedTime: YYYYMMDDHHMMSSZ
        moment = text[:14]
        parsed = _parse_time_fields(moment, "%Y%m%d%H%M%S")
    else:
        return None
    return parsed


def _parse_time_fields(moment: str, pattern: str) -> datetime | None:
    try:
        parsed = datetime.strptime(moment, pattern)
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _der_subject_alt_names(value: bytes) -> tuple[str, ...]:
    """Decode a DER SubjectAltName extension value into 'TYPE:value' strings."""
    entries: list[str] = []
    wrapped = _der_children(value)
    if not wrapped or wrapped[0][0] != 0x30:  # GeneralNames SEQUENCE
        return ()
    for tag, entry in _der_children(wrapped[0][1]):
        if tag == 0x82:  # dNSName IA5String
            entries.append(f"DNS:{entry.decode('ascii', 'replace')}")
        elif tag == 0x87:  # iPAddress OCTET STRING
            try:
                address = ipaddress.ip_address(entry)
            except ValueError:
                continue
            entries.append(f"IP:{address}")
    return tuple(entries)


@dataclass(frozen=True)
class _ParsedCertificate:
    subject: dict[str, tuple[str, ...]] = field(default_factory=dict)
    issuer: dict[str, tuple[str, ...]] = field(default_factory=dict)
    sans: tuple[str, ...] = ()
    not_after: datetime | None = None


def _parse_certificate(der: bytes) -> _ParsedCertificate:
    """Extract subject, issuer, SANs, and expiry from DER certificate bytes.

    Raises _DERError when the bytes do not follow the expected layout.
    """
    _, certificate, _ = _der_read(der, 0)
    tbs_children = _der_children(certificate)
    # tbsCertificate ::= SEQUENCE { ... } is the first child of Certificate
    if not tbs_children or tbs_children[0][0] != 0x30:
        raise _DERError("expected tbsCertificate SEQUENCE")
    fields = _der_children(tbs_children[0][1])
    index = 0
    if fields and fields[0][0] == 0xA0:  # [0] EXPLICIT version
        index += 1
    # serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo
    if len(fields) < index + 6:
        raise _DERError("tbsCertificate is missing fields")
    issuer = _der_name(fields[index + 2][1])
    validity = _der_children(fields[index + 3][1])
    subject = _der_name(fields[index + 4][1])
    not_after: datetime | None = None
    if len(validity) >= 2:
        not_after = _der_time(validity[1][0], validity[1][1])
    sans: tuple[str, ...] = ()
    for tag, value in fields[index + 6 :]:
        if tag != 0xA3:  # [3] EXPLICIT extensions
            continue
        extensions = _der_children(value)
        if not extensions or extensions[0][0] != 0x30:
            continue
        for _, extension in _der_children(extensions[0][1]):
            parts = _der_children(extension)
            if len(parts) < 2 or parts[0][0] != 0x06:
                continue
            if _der_oid(parts[0][1]) == _SAN_OID:
                # extnValue is the last child (critical is optional)
                sans = _der_subject_alt_names(parts[-1][1])
    return _ParsedCertificate(
        subject=subject, issuer=issuer, sans=sans, not_after=not_after
    )


@dataclass(frozen=True)
class TLSResult:
    host: str
    port: int
    ok: bool
    latency_ms: float | None = None
    protocol: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    subject: dict[str, tuple[str, ...]] | None = None
    sans: tuple[str, ...] = ()
    issuer: dict[str, tuple[str, ...]] | None = None
    cert_expires_at: str | None = None
    days_until_expiry: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


def check_tls(host: str, port: int, timeout: float = 3.0) -> TLSResult:
    """Perform one bounded TLS handshake against an explicit host and port.

    The handshake uses an unverified client context on purpose: expiry and
    inventory monitoring must still report certificate details when a
    certificate is expired or self-signed. Only the handshake is completed;
    no application data is exchanged.
    """
    target = _normalized_host(host)
    if target is None:
        logger.debug("TLS check rejected: host must be a string")
        return TLSResult(host="", port=port, ok=False, error="host must be a string")
    if not target:
        logger.debug("TLS check rejected: host is required")
        return TLSResult(host=host, port=port, ok=False, error="host is required")
    if has_control_characters(target):
        logger.debug("TLS check rejected for %r: control characters", target)
        return TLSResult(
            host=target,
            port=port,
            ok=False,
            error="host must not contain control characters",
        )
    if not _valid_port(port):
        logger.debug("TLS check rejected for %s: invalid port %r", target, port)
        return TLSResult(
            host=target, port=port, ok=False, error="port must be between 1 and 65535"
        )
    if not _valid_timeout(timeout, MAX_TCP_TIMEOUT):
        logger.debug("TLS check rejected for %s: invalid timeout %r", target, timeout)
        return TLSResult(
            host=target,
            port=port,
            ok=False,
            error="timeout must be finite, greater than 0, and at most 30 seconds",
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=target) as tls_sock:
                protocol = tls_sock.version()
                cipher_info = tls_sock.cipher()
                der_cert = tls_sock.getpeercert(binary_form=True)
                latency_ms = round((time.monotonic() - started) * 1000, 2)
    except (TimeoutError, OSError, ssl.SSLError) as exc:
        logger.warning("TLS handshake with %s:%s failed: %s", target, port, exc)
        return TLSResult(host=target, port=port, ok=False, error=str(exc))
    cipher_name: str | None = None
    cipher_bits: int | None = None
    if cipher_info:
        cipher_name = str(cipher_info[0])
        cipher_bits = int(cipher_info[2]) if len(cipher_info) > 2 else None
    # With verification disabled the parsed getpeercert() mapping is empty, so
    # certificate details come from a minimal DER parse of the peer bytes.
    parsed: _ParsedCertificate | None = None
    if der_cert:
        try:
            parsed = _parse_certificate(der_cert)
        except _DERError as exc:
            logger.debug(
                "TLS certificate from %s:%s could not be parsed: %s", target, port, exc
            )
    cert_expires_at: str | None = None
    days_until_expiry: float | None = None
    if parsed is not None and parsed.not_after is not None:
        cert_expires_at = parsed.not_after.isoformat()
        days_until_expiry = round(
            (parsed.not_after - datetime.now(tz=timezone.utc)).total_seconds() / 86400,
            2,
        )
    return TLSResult(
        host=target,
        port=port,
        ok=True,
        latency_ms=latency_ms,
        protocol=protocol,
        cipher=cipher_name,
        cipher_bits=cipher_bits,
        subject=(parsed.subject or None) if parsed else None,
        sans=parsed.sans if parsed else (),
        issuer=(parsed.issuer or None) if parsed else None,
        cert_expires_at=cert_expires_at,
        days_until_expiry=days_until_expiry,
    )


def evaluate_tls_gates(
    result: TLSResult, *, min_days_cert_valid: float | None = None
) -> tuple[str, ...]:
    """Return human-readable descriptions of violated TLS health gates."""
    if min_days_cert_valid is None:
        return ()
    if result.days_until_expiry is None:
        violation = "certificate expiry could not be determined"
    elif result.days_until_expiry < min_days_cert_valid:
        violation = (
            f"certificate expires in {result.days_until_expiry:.2f} days, "
            f"below minimum {min_days_cert_valid:g} days"
        )
    else:
        return ()
    logger.warning(
        "TLS health gate violated for %s:%s: %s", result.host, result.port, violation
    )
    return (violation,)
