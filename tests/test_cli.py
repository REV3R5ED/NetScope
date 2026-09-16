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
    assert payload == json.loads(json.dumps(result.to_dict()))


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


def _summary(successes=2, failures=1):
    return TCPSummaryResult("example.com", 443, 3, successes, failures, round(successes / 3 * 100, 2), 10.0, 15.0, 20.0, 4.08, True, ("timeout",) if failures else ())


def test_tcp_summary_human_output(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--count", "3"]) == 0
    output = capsys.readouterr().out
    assert "2/3 successful (66.67%)" in output
    assert "min 10.00, avg 15.00, max 20.00, jitter 4.08" in output
    assert "Failures: 1" in output


def test_tcp_summary_require_all_returns_nonzero_on_partial_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--require-all", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["successes"] == 2
    assert payload["failures"] == 1
    assert payload["success_rate_percent"] == 66.67
    assert payload["jitter_ms"] == 4.08


def test_tcp_summary_require_all_succeeds_when_every_attempt_succeeds(monkeypatch):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary(3, 0))
    assert cli.main(["tcp-summary", "example.com", "443", "--require-all", "--json"]) == 0


def test_tcp_summary_min_success_rate_fails_below_threshold(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--min-success-rate", "80", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["success_rate_percent"] == 66.67


def test_tcp_summary_min_success_rate_succeeds_at_threshold(monkeypatch):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--min-success-rate", "66.67", "--json"]) == 0


@pytest.mark.parametrize("value", ["-1", "100.1"])
def test_tcp_summary_min_success_rate_rejects_out_of_range(value):
    with pytest.raises(SystemExit) as exc:
        cli.main(["tcp-summary", "example.com", "443", "--min-success-rate", value])
    assert exc.value.code == 2


def test_tcp_summary_health_gates_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.main(["tcp-summary", "example.com", "443", "--require-all", "--min-success-rate", "90"])
    assert exc.value.code == 2


def test_path_json_output(monkeypatch, capsys):
    result = PathResult("example.com", 12, ("1 192.0.2.1 1.0 ms",), False, True, "destination not reached")
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.com", "--max-hops", "12", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["host"] == "example.com"
    assert payload["max_hops"] == 12
    assert payload["reached"] is False


def test_path_require_reached_returns_nonzero_when_destination_not_reached(monkeypatch, capsys):
    result = PathResult("example.com", 12, ("1 192.0.2.1 1.0 ms",), False, True, "destination not reached")
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.com", "--require-reached", "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["reached"] is False
    assert payload["ok"] is True


def test_path_require_reached_succeeds_when_destination_reached(monkeypatch):
    result = PathResult("example.com", 12, ("1 192.0.2.1 1.0 ms", "2 192.0.2.2 2.0 ms"), True, True)
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.com", "--require-reached", "--json"]) == 0


def test_output_formats_are_mutually_exclusive():
    with pytest.raises(SystemExit) as exc:
        cli.main(["dns", "example.com", "--json", "--csv"])
    assert exc.value.code == 2
