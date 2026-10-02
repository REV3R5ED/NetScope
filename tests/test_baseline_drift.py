"""Tests for tcp-summary baseline/regression drift detection."""

from __future__ import annotations

import json

import pytest

from netscope import cli, diagnostics
from netscope.diagnostics import (
    TCPSummaryResult,
    latency_drift_percent,
    load_latency_baseline,
)


def _summary(**overrides):
    base = {
        "host": "example.test",
        "port": 443,
        "attempts": 3,
        "successes": 3,
        "failures": 0,
        "success_rate_percent": 100.0,
        "min_latency_ms": 10.0,
        "avg_latency_ms": 12.0,
        "max_latency_ms": 15.0,
        "jitter_ms": 2.0,
        "ok": True,
        "errors": (),
    }
    base.update(overrides)
    return TCPSummaryResult(**base)


def _write_baseline(tmp_path, payload):
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def test_latency_drift_percent_math():
    assert latency_drift_percent(12.0, 10.0) == 20.0
    assert latency_drift_percent(8.0, 10.0) == -20.0
    assert latency_drift_percent(10.0, 10.0) == 0.0


def test_load_latency_baseline_reads_saved_json_report(tmp_path):
    path = _write_baseline(tmp_path, _summary().to_dict())
    assert load_latency_baseline(path) == 12.0


def test_load_latency_baseline_rejects_problems(tmp_path):
    with pytest.raises(ValueError, match="not found"):
        load_latency_baseline(str(tmp_path / "missing.json"))
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        load_latency_baseline(str(bad_json))
    not_object = _write_baseline(tmp_path, [1, 2, 3])
    with pytest.raises(ValueError, match="JSON object"):
        load_latency_baseline(not_object)
    no_avg = _write_baseline(tmp_path, {"host": "example.test"})
    with pytest.raises(ValueError, match="no usable avg_latency_ms"):
        load_latency_baseline(no_avg)
    zero_avg = _write_baseline(tmp_path, {"avg_latency_ms": 0})
    with pytest.raises(ValueError, match="no usable avg_latency_ms"):
        load_latency_baseline(zero_avg)


def test_cli_baseline_reports_drift_in_human_output(tmp_path, monkeypatch, capsys):
    baseline = _write_baseline(tmp_path, {"avg_latency_ms": 10.0})
    monkeypatch.setattr(
        cli, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    assert cli.main(["tcp-summary", "example.test", "443", "--baseline", baseline]) == 0
    output = capsys.readouterr().out
    assert "Baseline avg: 10.00 ms, drift: +20.00%" in output


def test_cli_baseline_drift_within_threshold_returns_zero(tmp_path, monkeypatch):
    baseline = _write_baseline(tmp_path, {"avg_latency_ms": 10.0})
    monkeypatch.setattr(
        cli, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    assert (
        cli.main(
            [
                "tcp-summary",
                "example.test",
                "443",
                "--baseline",
                baseline,
                "--max-latency-drift-pct",
                "25",
            ]
        )
        == 0
    )


def test_cli_baseline_drift_exceeded_returns_nonzero(tmp_path, monkeypatch, capsys):
    baseline = _write_baseline(tmp_path, {"avg_latency_ms": 10.0})
    monkeypatch.setattr(
        cli, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    assert (
        cli.main(
            [
                "tcp-summary",
                "example.test",
                "443",
                "--baseline",
                baseline,
                "--max-latency-drift-pct",
                "10",
            ]
        )
        == 1
    )


def test_cli_baseline_drift_appears_in_json(tmp_path, monkeypatch, capsys):
    baseline = _write_baseline(tmp_path, {"avg_latency_ms": 10.0})
    monkeypatch.setattr(
        cli, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    assert (
        cli.main(
            ["tcp-summary", "example.test", "443", "--baseline", baseline, "--json"]
        )
        == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["baseline_avg_latency_ms"] == 10.0
    assert payload["latency_drift_percent"] == 20.0


def test_cli_drift_threshold_without_baseline_is_usage_error():
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            ["tcp-summary", "example.test", "443", "--max-latency-drift-pct", "10"]
        )
    assert exc_info.value.code == 2


def test_cli_invalid_baseline_file_is_usage_error(tmp_path, monkeypatch):
    monkeypatch.setattr(
        cli, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "tcp-summary",
                "example.test",
                "443",
                "--baseline",
                str(tmp_path / "missing.json"),
            ]
        )
    assert exc_info.value.code == 2


def test_cli_baseline_loads_before_network_activity(tmp_path, monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("baseline error must fail before network activity")

    monkeypatch.setattr(diagnostics, "check_tcp", unexpected)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "tcp-summary",
                "example.test",
                "443",
                "--baseline",
                str(tmp_path / "missing.json"),
            ]
        )
    assert exc_info.value.code == 2
