"""Tests for bounded TLS handshake diagnostics and the DER certificate parser."""

from __future__ import annotations

import base64
import json
import ssl
from datetime import datetime, timezone
from pathlib import Path

import pytest

from netscope import cli, tls
from netscope.tls import (
    TLSResult,
    _DERError,
    _parse_certificate,
    check_tls,
    evaluate_tls_gates,
)

FIXTURE = Path(__file__).parent / "fixtures" / "tls-test-cert.pem"


def _fixture_der() -> bytes:
    text = FIXTURE.read_text(encoding="utf-8")
    payload = "".join(
        line for line in text.splitlines() if not line.startswith("-----")
    )
    return base64.b64decode(payload)


def test_parse_certificate_reads_subject_issuer_sans_and_expiry():
    parsed = _parse_certificate(_fixture_der())
    assert parsed.subject["commonName"] == ("tls.test.example",)
    assert parsed.subject["organizationName"] == ("NetScope Tests",)
    assert parsed.subject["countryName"] == ("US",)
    assert parsed.issuer["commonName"] == ("tls.test.example",)
    assert parsed.sans == (
        "DNS:tls.test.example",
        "DNS:www.tls.test.example",
        "IP:192.0.2.1",
    )
    assert parsed.not_after == datetime(2036, 9, 29, 21, 59, 3, tzinfo=timezone.utc)


def test_parse_certificate_rejects_truncated_bytes():
    with pytest.raises(_DERError):
        _parse_certificate(b"\x30\x82")


def test_parse_certificate_rejects_garbage():
    with pytest.raises(_DERError):
        _parse_certificate(b"\xff" * 64)


class _FakeRawSocket:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeTLSSocket:
    def __init__(self, der: bytes | None):
        self._der = der

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def version(self):
        return "TLSv1.3"

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def getpeercert(self, binary_form=False):
        return self._der if binary_form else {}


class _FakeContext:
    def __init__(self, der: bytes | None):
        self._der = der
        self.check_hostname = True
        self.verify_mode = ssl.CERT_REQUIRED

    def wrap_socket(self, raw, server_hostname=None):
        assert self.check_hostname is False
        assert self.verify_mode == ssl.CERT_NONE
        assert server_hostname == "tls.test.example"
        return _FakeTLSSocket(self._der)


def _patch_tls_stack(monkeypatch, der: bytes | None):
    def fake_create_connection(address, timeout=None):
        assert address == ("tls.test.example", 443)
        return _FakeRawSocket()

    monkeypatch.setattr(tls.socket, "create_connection", fake_create_connection)
    monkeypatch.setattr(tls.ssl, "SSLContext", lambda *args: _FakeContext(der))


def test_check_tls_reports_handshake_and_certificate(monkeypatch):
    _patch_tls_stack(monkeypatch, _fixture_der())
    result = check_tls("tls.test.example", 443)
    assert result.ok is True
    assert result.protocol == "TLSv1.3"
    assert result.cipher == "TLS_AES_256_GCM_SHA384"
    assert result.cipher_bits == 256
    assert result.latency_ms is not None and result.latency_ms >= 0
    assert result.subject is not None
    assert result.subject["commonName"] == ("tls.test.example",)
    assert result.sans == (
        "DNS:tls.test.example",
        "DNS:www.tls.test.example",
        "IP:192.0.2.1",
    )
    assert result.issuer is not None
    assert result.cert_expires_at == "2036-09-29T21:59:03+00:00"
    assert result.days_until_expiry is not None
    assert 3640 < result.days_until_expiry <= 3650
    assert result.error is None


def test_check_tls_without_peer_certificate_still_succeeds(monkeypatch):
    _patch_tls_stack(monkeypatch, None)
    result = check_tls("tls.test.example", 443)
    assert result.ok is True
    assert result.subject is None
    assert result.sans == ()
    assert result.cert_expires_at is None
    assert result.days_until_expiry is None


def test_check_tls_with_unparsable_certificate_keeps_handshake_result(monkeypatch):
    _patch_tls_stack(monkeypatch, b"\xff" * 64)
    result = check_tls("tls.test.example", 443)
    assert result.ok is True
    assert result.protocol == "TLSv1.3"
    assert result.subject is None
    assert result.days_until_expiry is None


def test_check_tls_handshake_failure_is_structured_and_logged(monkeypatch, caplog):
    def failing_connection(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(tls.socket, "create_connection", failing_connection)
    with caplog.at_level("WARNING", logger="netscope.tls"):
        result = check_tls("tls.test.example", 443)
    assert result.ok is False
    assert result.error == "connection refused"
    assert result.protocol is None
    assert any("failed" in record.message for record in caplog.records)


@pytest.mark.parametrize("port", [0, 65536, -1, "443", True])
def test_check_tls_invalid_port_never_connects(monkeypatch, port):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(tls.socket, "create_connection", unexpected)
    result = check_tls("tls.test.example", port)
    assert result.ok is False
    assert result.error == "port must be between 1 and 65535"


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), 30.1])
def test_check_tls_invalid_timeout_never_connects(monkeypatch, timeout):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(tls.socket, "create_connection", unexpected)
    result = check_tls("tls.test.example", 443, timeout)
    assert result.ok is False
    assert "timeout" in result.error


def test_check_tls_rejects_bad_host_without_network(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(tls.socket, "create_connection", unexpected)
    assert check_tls(None, 443).error == "host must be a string"
    assert check_tls("   ", 443).error == "host is required"
    assert (
        check_tls("ho\x00st", 443).error == "host must not contain control characters"
    )


def test_evaluate_tls_gates():
    healthy = TLSResult("h", 443, True, days_until_expiry=45.0)
    assert evaluate_tls_gates(healthy) == ()
    assert evaluate_tls_gates(healthy, min_days_cert_valid=30.0) == ()
    violations = evaluate_tls_gates(healthy, min_days_cert_valid=90.0)
    assert len(violations) == 1
    assert "45.00" in violations[0]
    unknown = TLSResult("h", 443, True, days_until_expiry=None)
    assert evaluate_tls_gates(unknown, min_days_cert_valid=30.0) != ()


def test_tls_result_is_json_native():
    result = TLSResult(
        "tls.test.example",
        443,
        True,
        latency_ms=12.5,
        protocol="TLSv1.3",
        cipher="TLS_AES_256_GCM_SHA384",
        cipher_bits=256,
        subject={"commonName": ("tls.test.example",)},
        sans=("DNS:tls.test.example",),
        issuer={"commonName": ("tls.test.example",)},
        cert_expires_at="2036-09-29T21:59:03+00:00",
        days_until_expiry=3649.5,
    )
    payload = result.to_dict()
    assert json.loads(json.dumps(payload)) == payload
    assert payload["subject"] == {"commonName": ["tls.test.example"]}
    assert payload["sans"] == ["DNS:tls.test.example"]


def _tls_result(**overrides):
    base = {
        "host": "tls.test.example",
        "port": 443,
        "ok": True,
        "latency_ms": 10.0,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "subject": {"commonName": ("tls.test.example",)},
        "sans": ("DNS:tls.test.example",),
        "issuer": {"commonName": ("tls.test.example",)},
        "cert_expires_at": "2036-09-29T21:59:03+00:00",
        "days_until_expiry": 45.0,
    }
    base.update(overrides)
    return TLSResult(**base)


def test_tls_cli_human_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: _tls_result())
    assert cli.main(["tls", "tls.test.example", "443"]) == 0
    output = capsys.readouterr().out
    assert "TLSv1.3" in output
    assert "TLS_AES_256_GCM_SHA384" in output
    assert "SANs: DNS:tls.test.example" in output
    assert "45.00 days remaining" in output


def test_tls_cli_json_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: _tls_result())
    assert cli.main(["tls", "tls.test.example", "443", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["protocol"] == "TLSv1.3"
    assert payload["days_until_expiry"] == 45.0


def test_tls_cli_failure_returns_nonzero(monkeypatch, capsys):
    result = _tls_result(ok=False, error="handshake timeout")
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: result)
    assert cli.main(["tls", "tls.test.example", "443"]) == 1
    assert "handshake failed: handshake timeout" in capsys.readouterr().out


def test_tls_cli_cert_gate_violation_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: _tls_result())
    assert (
        cli.main(["tls", "tls.test.example", "443", "--min-days-cert-valid", "90"]) == 1
    )


def test_tls_cli_cert_gate_satisfied_returns_zero(monkeypatch):
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: _tls_result())
    assert (
        cli.main(["tls", "tls.test.example", "443", "--min-days-cert-valid", "30"]) == 0
    )


@pytest.mark.parametrize("port", ["0", "65536", "-1", "notaport"])
def test_tls_cli_rejects_invalid_port_as_usage_error(port):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tls", "tls.test.example", port])
    assert exc_info.value.code == 2
