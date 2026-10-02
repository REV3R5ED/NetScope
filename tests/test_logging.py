"""Operational failures are logged in addition to structured result errors."""

from __future__ import annotations

import socket
import subprocess

from netscope import diagnostics, tls


def _warning_messages(caplog):
    return [
        record.message for record in caplog.records if record.levelname == "WARNING"
    ]


def test_dns_resolution_failure_is_logged(monkeypatch, caplog):
    def failing_resolver(*args, **kwargs):
        raise OSError("resolution boom")

    monkeypatch.setattr(socket, "getaddrinfo", failing_resolver)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.resolve_hostname("example.test")
    assert result.ok is False
    assert any("example.test" in message for message in _warning_messages(caplog))


def test_tcp_connection_failure_is_logged(monkeypatch, caplog):
    def failing_connection(*args, **kwargs):
        raise OSError("connection refused")

    monkeypatch.setattr(diagnostics.socket, "create_connection", failing_connection)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.check_tcp("example.test", 443)
    assert result.ok is False
    assert any("example.test:443" in message for message in _warning_messages(caplog))


def test_tcp_summary_total_failure_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(
        diagnostics,
        "check_tcp",
        lambda host, port, timeout: diagnostics.TCPResult(
            host, port, False, error="refused"
        ),
    )
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.summarize_tcp("example.test", 443, count=2)
    assert result.ok is False
    assert _warning_messages(caplog)


def test_path_subprocess_failure_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/traceroute")

    def failing_run(*args, **kwargs):
        raise OSError("cannot fork")

    monkeypatch.setattr(diagnostics.subprocess, "run", failing_run)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.trace_path("example.test")
    assert result.ok is False
    assert any("example.test" in message for message in _warning_messages(caplog))


def test_path_missing_utility_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.trace_path("example.test")
    assert result.ok is False
    assert any("traceroute" in message for message in _warning_messages(caplog))


def test_tls_handshake_failure_is_logged(monkeypatch, caplog):
    def failing_connection(*args, **kwargs):
        raise OSError("tls boom")

    monkeypatch.setattr(tls.socket, "create_connection", failing_connection)
    with caplog.at_level("WARNING", logger="netscope.tls"):
        result = tls.check_tls("example.test", 443)
    assert result.ok is False
    assert any("example.test:443" in message for message in _warning_messages(caplog))


def test_health_gate_violations_are_logged(monkeypatch, caplog):
    result = diagnostics.TCPSummaryResult(
        "example.test", 443, 3, 2, 1, 66.67, 10.0, 15.0, 20.0, 4.08, True, ()
    )
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        violations = diagnostics.evaluate_tcp_summary_gates(
            result, min_success_rate=80.0
        )
    assert violations
    assert _warning_messages(caplog)


def test_tls_gate_violation_is_logged(caplog):
    result = tls.TLSResult("example.test", 443, True, days_until_expiry=5.0)
    with caplog.at_level("WARNING", logger="netscope.tls"):
        violations = tls.evaluate_tls_gates(result, min_days_cert_valid=30.0)
    assert violations
    assert _warning_messages(caplog)


def test_ping_total_failure_is_logged(monkeypatch, caplog):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/ping")

    def failing_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1.0)

    monkeypatch.setattr(diagnostics.subprocess, "run", failing_run)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = diagnostics.ping_host("example.test", count=1, timeout=1.0)
    assert result.ok is False
    assert any("example.test" in message for message in _warning_messages(caplog))
