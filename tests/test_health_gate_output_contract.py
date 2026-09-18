"""Regression tests for automation-facing health-gate output semantics.

These tests use synthetic diagnostic results only: they never resolve names, open
sockets, or invoke traceroute subprocesses.
"""

from __future__ import annotations

import csv
import io
import json

from netscope import cli
from netscope.diagnostics import PathResult, TCPSummaryResult


def _partial_summary() -> TCPSummaryResult:
    return TCPSummaryResult(
        "example.invalid",
        443,
        3,
        2,
        1,
        66.67,
        10.0,
        15.0,
        20.0,
        4.08,
        True,
        ("synthetic timeout",),
    )


def test_failing_tcp_health_gate_keeps_json_stdout_parseable(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _partial_summary())

    assert cli.main([
        "tcp-summary",
        "example.invalid",
        "443",
        "--min-success-rate",
        "90",
        "--json",
    ]) == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["success_rate_percent"] == 66.67
    assert payload["errors"] == ["synthetic timeout"]


def test_failing_tcp_health_gate_keeps_csv_stdout_parseable(monkeypatch, capsys):
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: _partial_summary())

    assert cli.main([
        "tcp-summary",
        "example.invalid",
        "443",
        "--max-jitter-ms",
        "4",
        "--csv",
    ]) == 1

    captured = capsys.readouterr()
    rows = list(csv.DictReader(io.StringIO(captured.out)))
    assert len(rows) == 1
    assert rows[0]["host"] == "example.invalid"
    assert rows[0]["success_rate_percent"] == "66.67"
    assert rows[0]["jitter_ms"] == "4.08"


def test_failing_path_reachability_gate_keeps_json_context(monkeypatch, capsys):
    result = PathResult(
        "example.invalid",
        8,
        ("1 192.0.2.1 1.0 ms", "2 *"),
        False,
        True,
        "destination not reached",
    )
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)

    assert cli.main([
        "path",
        "example.invalid",
        "--max-hops",
        "8",
        "--require-reached",
        "--json",
    ]) == 1

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["ok"] is True
    assert payload["reached"] is False
    assert payload["hops"] == ["1 192.0.2.1 1.0 ms", "2 *"]
    assert payload["error"] == "destination not reached"
