"""Remaining defensive-path coverage for diagnostics edge cases."""

from __future__ import annotations

import socket

import pytest

from netscope import diagnostics
from netscope.diagnostics import (
    inspect_interfaces,
    load_latency_baseline,
    trace_path,
)


def test_inspect_interfaces_gethostname_failure_is_logged(monkeypatch, caplog):
    def failing_gethostname():
        raise OSError("no hostname")

    monkeypatch.setattr(diagnostics.socket, "gethostname", failing_gethostname)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = inspect_interfaces()
    assert result.ok is False
    assert result.error == "no hostname"
    assert caplog.records


def test_inspect_interfaces_blank_hostname_is_rejected(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "   ")
    result = inspect_interfaces()
    assert result.ok is False
    assert result.error == "local hostname is unavailable"


def test_inspect_interfaces_if_nameindex_failure(monkeypatch, caplog):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "workstation")

    def failing_if_nameindex():
        raise OSError("no interfaces")

    monkeypatch.setattr(diagnostics.socket, "if_nameindex", failing_if_nameindex)
    with caplog.at_level("WARNING", logger="netscope.diagnostics"):
        result = inspect_interfaces()
    assert result.ok is False
    assert result.error == "no interfaces"


def test_inspect_interfaces_local_resolution_failure(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "workstation")
    monkeypatch.setattr(diagnostics.socket, "if_nameindex", lambda: [(1, "eth0")])

    def failing_getaddrinfo(*args, **kwargs):
        raise OSError("resolver down")

    monkeypatch.setattr(diagnostics.socket, "getaddrinfo", failing_getaddrinfo)
    result = inspect_interfaces()
    assert result.ok is False
    assert result.error == "resolver down"


def test_inspect_interfaces_empty_resolution_is_a_failure(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "workstation")
    monkeypatch.setattr(diagnostics.socket, "if_nameindex", lambda: [(1, "eth0")])
    monkeypatch.setattr(diagnostics.socket, "getaddrinfo", lambda *a, **k: [])
    result = inspect_interfaces()
    assert result.ok is False
    assert result.error == "local hostname resolved to no addresses"


def test_load_latency_baseline_unreadable_file(tmp_path):
    with pytest.raises(ValueError, match="cannot read baseline file"):
        load_latency_baseline(str(tmp_path))


def test_trace_path_rejects_non_string_and_blank_host(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("subprocess should not run")

    monkeypatch.setattr(diagnostics.subprocess, "run", unexpected)
    assert trace_path(None).error == "host must be a string"
    assert trace_path("   ").error == "host is required"


def test_interfaces_attribute_error_degrades_gracefully(monkeypatch):
    monkeypatch.setattr(diagnostics.socket, "gethostname", lambda: "workstation")

    def no_if_nameindex():
        raise AttributeError("no if_nameindex")

    monkeypatch.setattr(diagnostics.socket, "if_nameindex", no_if_nameindex)
    monkeypatch.setattr(
        diagnostics.socket,
        "getaddrinfo",
        lambda *a, **k: [(socket.AF_INET, None, None, None, ("192.0.2.1", 0))],
    )
    result = inspect_interfaces()
    assert result.ok is True
    assert result.interfaces == ()
    assert result.error == "interface enumeration unavailable on this platform"
