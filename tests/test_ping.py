"""Tests for bounded ICMP ping diagnostics."""

from __future__ import annotations

import json
import subprocess

import pytest

from netscope import cli, diagnostics
from netscope.diagnostics import PingResult, ping_host


class _Completed:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _patch_ping(monkeypatch, results, executable="ping"):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: f"/usr/bin/{name}")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        return results.pop(0)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    return calls


def test_ping_success_reports_latency_statistics(monkeypatch):
    calls = _patch_ping(
        monkeypatch,
        [_Completed(0), _Completed(0), _Completed(0)],
    )
    result = ping_host("example.test", count=3, timeout=1.0)
    assert result.ok is True
    assert result.host == "example.test"
    assert result.count == 3
    assert result.successes == 3
    assert result.failures == 0
    assert result.success_rate_percent == 100.0
    assert result.min_latency_ms is not None
    assert result.avg_latency_ms is not None
    assert result.max_latency_ms is not None
    assert result.min_latency_ms <= result.avg_latency_ms <= result.max_latency_ms
    assert len(calls) == 3
    assert calls[0][:4] == ("ping", "-n", "-c", "1")
    assert calls[0][-1] == "example.test"


def test_ping_partial_failures_keep_working_latencies(monkeypatch):
    _patch_ping(
        monkeypatch,
        [_Completed(0), _Completed(1, stderr="no reply"), _Completed(0)],
    )
    result = ping_host("example.test", count=3)
    assert result.ok is True
    assert result.successes == 2
    assert result.failures == 1
    assert result.success_rate_percent == round(2 / 3 * 100, 2)
    assert result.errors == ("no reply",)


def test_ping_total_failure_is_structured(monkeypatch):
    _patch_ping(
        monkeypatch,
        [_Completed(1, stderr="network unreachable"), _Completed(1, stderr="x")],
    )
    result = ping_host("example.test", count=2)
    assert result.ok is False
    assert result.successes == 0
    assert result.min_latency_ms is None
    assert "network unreachable" in result.errors


def test_ping_subprocess_timeout_counts_as_failure(monkeypatch, caplog):
    def raising_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=args[0], timeout=1.0)

    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/ping")
    monkeypatch.setattr(diagnostics.subprocess, "run", raising_run)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = ping_host("example.test", count=1, timeout=1.0)
    assert result.ok is False
    assert result.errors != ()
    assert caplog.records


def test_ping_missing_utility_is_a_structured_failure(monkeypatch):
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: None)
    result = ping_host("example.test")
    assert result.ok is False
    assert result.errors == ("no ping utility is available on this system",)


def test_ping_uses_ping6_for_ipv6_when_available(monkeypatch):
    def which(name):
        return f"/usr/bin/{name}" if name in ("ping", "ping6") else None

    monkeypatch.setattr(diagnostics.shutil, "which", which)
    monkeypatch.setattr(diagnostics.subprocess, "run", lambda *a, **k: _Completed(0))
    result = ping_host("example.test", count=1, family="ipv6")
    assert result.ok is True


def test_ping_falls_back_to_ping_dash_6(monkeypatch):
    calls = []

    def which(name):
        return "/usr/bin/ping" if name == "ping" else None

    monkeypatch.setattr(diagnostics.shutil, "which", which)

    def fake_run(command, **kwargs):
        calls.append(command)
        return _Completed(0)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    result = ping_host("example.test", count=1, family="ipv6")
    assert result.ok is True
    assert "-6" in calls[0]


def test_ping_windows_command_shape(monkeypatch):
    calls = []
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Windows")
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "C:\\ping.exe")

    def fake_run(command, **kwargs):
        calls.append(command)
        return _Completed(0)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    result = ping_host("example.test", count=1, timeout=2.0, family="ipv4")
    assert result.ok is True
    assert calls[0][:5] == ("ping", "-n", "1", "-w", "2000")
    assert "-4" in calls[0]


def test_ping_windows_ipv6_command_shape(monkeypatch):
    calls = []
    monkeypatch.setattr(diagnostics.platform, "system", lambda: "Windows")
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "C:\\ping.exe")

    def fake_run(command, **kwargs):
        calls.append(command)
        return _Completed(0)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    result = ping_host("example.test", count=1, timeout=2.0, family="ipv6")
    assert result.ok is True
    assert "-6" in calls[0]


def test_ping_posix_ipv4_command_shape(monkeypatch):
    calls = []
    monkeypatch.setattr(diagnostics.shutil, "which", lambda name: "/usr/bin/ping")

    def fake_run(command, **kwargs):
        calls.append(command)
        return _Completed(0)

    monkeypatch.setattr(diagnostics.subprocess, "run", fake_run)
    result = ping_host("example.test", count=1, family="ipv4")
    assert result.ok is True
    assert "-4" in calls[0]


def test_check_tcp_rejects_blank_host_without_network(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")

    monkeypatch.setattr(diagnostics.socket, "create_connection", unexpected)
    result = diagnostics.check_tcp("   ", 443)
    assert result.ok is False
    assert result.error == "host is required"


def test_ping_host_starting_with_dash_is_rejected_before_subprocess(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected)
    result = ping_host("-n 1 evil.test")
    assert result.ok is False
    assert result.errors == ("host must not begin with '-'",)


@pytest.mark.parametrize("count", [0, 11, "3", True])
def test_ping_invalid_count_is_rejected(monkeypatch, count):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected)
    result = ping_host("example.test", count=count)
    assert result.ok is False
    assert result.count == 0
    assert result.errors == ("count must be between 1 and 10",)


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), 10.1])
def test_ping_invalid_timeout_is_rejected(monkeypatch, timeout):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected)
    result = ping_host("example.test", timeout=timeout)
    assert result.ok is False
    assert "timeout" in result.errors[0]


def test_ping_rejects_bad_host_and_family_without_subprocess(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected)
    assert ping_host(None).errors == ("host must be a string",)
    assert ping_host("   ").errors == ("host is required",)
    assert ping_host("ho\x00st").errors == ("host must not contain control characters",)
    assert ping_host("example.test", family="bogus").errors == (
        "family must be one of: any, ipv4, ipv6",
    )


def test_ping_result_is_json_native():
    result = PingResult("example.test", 2, 2, 0, 100.0, 1.0, 1.5, 2.0, True, ())
    payload = result.to_dict()
    assert json.loads(json.dumps(payload)) == payload


def _ping_result(**overrides):
    base = {
        "host": "example.test",
        "count": 4,
        "successes": 4,
        "failures": 0,
        "success_rate_percent": 100.0,
        "min_latency_ms": 1.0,
        "avg_latency_ms": 1.5,
        "max_latency_ms": 2.0,
        "ok": True,
        "errors": (),
    }
    base.update(overrides)
    return PingResult(**base)


def test_ping_cli_human_output(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "ping_host", lambda host, count, timeout, family: _ping_result()
    )
    assert cli.main(["ping", "example.test"]) == 0
    output = capsys.readouterr().out
    assert "4/4 replies (100.00%)" in output
    assert "min 1.00" in output


def test_ping_cli_json_output(monkeypatch, capsys):
    monkeypatch.setattr(
        cli, "ping_host", lambda host, count, timeout, family: _ping_result()
    )
    assert cli.main(["ping", "example.test", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["success_rate_percent"] == 100.0


def test_ping_cli_failure_returns_nonzero(monkeypatch, capsys):
    result = _ping_result(
        ok=False,
        successes=0,
        failures=4,
        success_rate_percent=0.0,
        min_latency_ms=None,
        avg_latency_ms=None,
        max_latency_ms=None,
        errors=("no reply",),
    )
    monkeypatch.setattr(cli, "ping_host", lambda host, count, timeout, family: result)
    assert cli.main(["ping", "example.test"]) == 1
    assert "ping failed: no reply" in capsys.readouterr().out


def test_ping_cli_passes_family_and_count(monkeypatch):
    seen = {}

    def fake_ping(host, count, timeout, family):
        seen.update(host=host, count=count, timeout=timeout, family=family)
        return _ping_result()

    monkeypatch.setattr(cli, "ping_host", fake_ping)
    assert cli.main(["ping", "example.test", "--count", "2", "--family", "ipv6"]) == 0
    assert seen == {
        "host": "example.test",
        "count": 2,
        "timeout": 2.0,
        "family": "ipv6",
    }
