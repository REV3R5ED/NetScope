"""CI contract test: every command's JSON output validates against its schema."""

from __future__ import annotations

import json

import pytest

from netscope import cli
from netscope.address import AddressResult
from netscope.diagnostics import (
    DNSResult,
    InterfaceResult,
    PathResult,
    PingResult,
    TCPResult,
    TCPSummaryResult,
)
from netscope.dns import DNSFamilyResult
from netscope.network import NetworkResult
from netscope.schemas import (
    SCHEMA_VERSION,
    load_schema,
    schema_names,
    validate_against_schema,
)
from netscope.tls import TLSResult


def _representative_results():
    return {
        "interfaces": InterfaceResult(
            "workstation", ("eth0", "lo"), ("192.0.2.10", "2001:db8::1"), True
        ),
        "address": AddressResult(
            "10.20.30.40", 4, "private", "40.30.20.10.in-addr.arpa", True
        ),
        "network": NetworkResult(
            "10.20.30.0/24",
            4,
            24,
            "10.20.30.0",
            "10.20.30.255",
            256,
            "private",
            True,
        ),
        "dns": DNSResult("example.test", ("192.0.2.1",), True),
        "tcp": TCPResult("example.test", 443, True, latency_ms=12.5),
        "tcp-summary": TCPSummaryResult(
            "example.test",
            443,
            3,
            3,
            0,
            100.0,
            10.0,
            12.0,
            15.0,
            2.0,
            True,
            (),
            baseline_avg_latency_ms=11.0,
            latency_drift_percent=9.09,
        ),
        "path": PathResult(
            "example.test", 5, ("1 192.0.2.1", "2 192.0.2.2"), True, True
        ),
        "ping": PingResult("example.test", 4, 4, 0, 100.0, 1.0, 1.5, 2.0, True, ()),
        "tls": TLSResult(
            "example.test",
            443,
            True,
            latency_ms=20.0,
            protocol="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            subject={"commonName": ("example.test",)},
            sans=("DNS:example.test",),
            issuer={"commonName": ("Example CA",)},
            cert_expires_at="2030-01-01T00:00:00+00:00",
            days_until_expiry=1200.0,
        ),
    }


def test_every_command_has_a_schema():
    assert set(schema_names()) == set(_representative_results())


@pytest.mark.parametrize("command", schema_names())
def test_command_json_output_validates_against_schema(command):
    payload = _representative_results()[command].to_dict()
    # The payload must survive a JSON round trip, exactly as --json emits it.
    round_tripped = json.loads(json.dumps(payload))
    violations = validate_against_schema(command, round_tripped)
    assert violations == []


@pytest.mark.parametrize("command", schema_names())
def test_failed_results_validate_against_schema(command):
    results = _representative_results()
    failed = {
        "interfaces": InterfaceResult("", (), (), False, "boom"),
        "address": AddressResult("nope", None, None, None, False, "boom"),
        "network": NetworkResult(
            "nope", None, None, None, None, None, None, False, "boom"
        ),
        "dns": DNSResult("example.test", (), False, "boom"),
        "tcp": TCPResult("example.test", 443, False, error="boom"),
        "tcp-summary": TCPSummaryResult(
            "example.test", 443, 3, 0, 3, 0.0, None, None, None, None, False, ("boom",)
        ),
        "path": PathResult("example.test", 5, (), False, False, "boom"),
        "ping": PingResult(
            "example.test", 4, 0, 4, 0.0, None, None, None, False, ("boom",)
        ),
        "tls": TLSResult("example.test", 443, False, error="boom"),
    }
    payload = json.loads(json.dumps(failed[command].to_dict()))
    assert validate_against_schema(command, payload) == []
    assert results[command].to_dict()["ok"] is True


def test_dns_family_result_validates_against_dns_schema():
    result = DNSFamilyResult("example.test", "ipv6", ("2001:db8::1",), True)
    payload = json.loads(json.dumps(result.to_dict()))
    assert validate_against_schema("dns", payload) == []


@pytest.mark.parametrize("command", schema_names())
def test_schema_rejects_wrong_types(command):
    violations = validate_against_schema(command, {"ok": "yes"})
    assert violations != []


def test_schema_rejects_unknown_properties():
    violations = validate_against_schema(
        "tcp", {"host": "h", "port": 1, "ok": True, "bogus": 1}
    )
    assert any("unexpected property" in violation for violation in violations)


def test_schemas_carry_version_and_stable_id():
    for command in schema_names():
        document = load_schema(command)
        assert document["version"] == SCHEMA_VERSION == 1
        assert document["$id"].endswith(f"/v1/{command}.schema.json")
        assert document["type"] == "object"


def test_schema_command_prints_document(capsys):
    assert cli.main(["schema", "tls"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == load_schema("tls")


def test_schema_command_rejects_unknown_command():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["schema", "nope"])
    assert exc_info.value.code == 2
