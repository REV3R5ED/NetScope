"""Regression tests for NetScope's defensive execution bounds."""

from __future__ import annotations

import pytest

from netscope import diagnostics


@pytest.mark.parametrize("port", [0, 65536])
def test_tcp_invalid_port_never_opens_socket(monkeypatch, port):
    def unexpected_connection(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(diagnostics.socket, "create_connection", unexpected_connection)
    result = diagnostics.check_tcp("example.com", port)
    assert result.ok is False
    assert result.error == "port must be between 1 and 65535"


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), 30.1])
def test_tcp_invalid_timeout_never_opens_socket(monkeypatch, timeout):
    def unexpected_connection(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(diagnostics.socket, "create_connection", unexpected_connection)
    result = diagnostics.check_tcp("example.com", 443, timeout)
    assert result.ok is False
    assert result.error == "timeout must be finite, greater than 0, and at most 30 seconds"


@pytest.mark.parametrize("count", [0, 11])
def test_tcp_summary_invalid_count_never_attempts_connection(monkeypatch, count):
    def unexpected_check(*args, **kwargs):
        raise AssertionError("invalid input must fail before network activity")

    monkeypatch.setattr(diagnostics, "check_tcp", unexpected_check)
    result = diagnostics.summarize_tcp("example.com", 443, count=count)
    assert result.ok is False
    assert result.attempts == 0
    assert result.errors == ("count must be between 1 and 10",)


@pytest.mark.parametrize("max_hops", [0, 31])
def test_path_invalid_hop_bound_never_spawns_process(monkeypatch, max_hops):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("invalid input must fail before subprocess activity")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected_run)
    result = diagnostics.trace_path("example.com", max_hops=max_hops)
    assert result.ok is False
    assert result.error == "max hops must be between 1 and 30"


@pytest.mark.parametrize("timeout", [0, -1, float("inf"), float("nan"), 10.1])
def test_path_invalid_timeout_never_spawns_process(monkeypatch, timeout):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("invalid input must fail before subprocess activity")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected_run)
    result = diagnostics.trace_path("example.com", timeout=timeout)
    assert result.ok is False
    assert result.error == "timeout must be finite, greater than 0, and at most 10 seconds"


def test_path_option_like_host_never_spawns_process(monkeypatch):
    def unexpected_run(*args, **kwargs):
        raise AssertionError("option-like host must fail before subprocess activity")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected_run)
    result = diagnostics.trace_path("--help")
    assert result.ok is False
    assert result.error == "host must not begin with '-'"
