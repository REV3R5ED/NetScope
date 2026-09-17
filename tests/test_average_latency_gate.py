"""CLI coverage for the bounded average-latency health gate."""

from __future__ import annotations

import json

from netscope import cli
from netscope.diagnostics import TCPSummaryResult


def _summary(avg_latency_ms: float = 15.0) -> TCPSummaryResult:
    return TCPSummaryResult(
        "example.com", 443, 3, 3, 0, 100.0,
        10.0, avg_latency_ms, 20.0, 4.08, True, (),
    )


def test_max_average_latency_fails_above_threshold(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--max-avg-latency-ms", "14", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["avg_latency_ms"] == 15.0


def test_max_average_latency_succeeds_at_threshold(monkeypatch):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main(["tcp-summary", "example.com", "443", "--max-avg-latency-ms", "15"]) == 0


def test_average_latency_gate_combines_with_other_health_gates(monkeypatch):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _summary())
    assert cli.main([
        "tcp-summary", "example.com", "443",
        "--min-success-rate", "100",
        "--max-jitter-ms", "5",
        "--max-avg-latency-ms", "14",
    ]) == 1
