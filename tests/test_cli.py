"""CLI integration tests for NetScope's public command surface."""

from __future__ import annotations

import json

import pytest

from netscope import cli
from netscope.diagnostics import DNSResult, InterfaceResult, PathResult, TCPResult, TCPSummaryResult


def test_interfaces_json_output(monkeypatch, capsys):
    result = InterfaceResult("workstation", ("eth0",), ("192.0.2.10",), True)
    monkeypatch.setattr(cli, "inspect_interfaces", lambda: result)

    assert cli.main(["interfaces", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    # JSON arrays deserialize as lists even when the internal immutable model
    # intentionally stores these collections as tuples.
    expected = json.loads(json.dumps(result.to_dict()))
    assert payload == expected


def test_dns_csv_output(monkeypatch, capsys):
    result = DNSResult("example.com", ("192.0.2.1",), True)
    monkeypatch.setattr(cli, "resolve_hostname", lambda hostname: result)

    assert cli.main(["dns", "example.com", "--csv"]) == 0
    output = capsys.readouterr().out
    assert "hostname,addresses,ok,error" in output
    assert "example.com" in output


def test_tcp_failure_returns_nonzero(monkeypatch, capsys):
    result = TCPResult("example.com", 443, False, error="connection refused")
    monkeypatch.setattr(cli, "check_tcp", lambda host, port, timeout: result)

    assert cli.main(["tcp", "example.com", "443"]) == 1
    assert "connection failed: connection refused" in capsys.readouterr().out


def test_tcp_summary_human_output(monkeypatch, capsys):
    result = TCPSummaryResult("example.com", 443, 3, 2, 1, 10.0, 15.0, 20.0, True, ("timeout",))
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: result)

    assert cli.main(["tcp-summary", "example.com", "443", "--count", "3"]) == 0
    output = capsys.readouterr().out
    assert "2/3 successful" in output
    assert "min 10.00, avg 15.00, max 20.00" in output
    assert "Failures: 1" in output


def test_path_json_output(monkeypatch, capsys):
    result = PathResult("example.com", 12, ("1 192.0.2.1 1.0 ms",), False, True, "destination not reached")
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)

    assert cli.main(["path", "example.com", "--max-hops", "12", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["host"] == "example.com"
    assert payload["max_hops"] == 12
    assert payload["reached"] is False


def test_output_formats_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.main(["dns", "example.com", "--json", "--csv"])
    assert exc.value.code == 2
