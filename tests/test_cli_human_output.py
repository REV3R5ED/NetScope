"""Human-readable output paths for every command."""

from __future__ import annotations

from netscope import cli
from netscope.address import AddressResult
from netscope.diagnostics import (
    InterfaceResult,
    PathResult,
    PingResult,
    TCPResult,
    TCPSummaryResult,
)
from netscope.tls import TLSResult


def test_interfaces_human_success(monkeypatch, capsys):
    result = InterfaceResult("workstation", ("eth0",), ("192.0.2.10",), True)
    monkeypatch.setattr(cli, "inspect_interfaces", lambda: result)
    assert cli.main(["interfaces"]) == 0
    output = capsys.readouterr().out
    assert "Hostname: workstation" in output
    assert "Interfaces: eth0" in output
    assert "Addresses: 192.0.2.10" in output


def test_interfaces_human_failure(monkeypatch, capsys):
    result = InterfaceResult("", (), (), False, "boom")
    monkeypatch.setattr(cli, "inspect_interfaces", lambda: result)
    assert cli.main(["interfaces"]) == 1
    assert "Interface inspection failed: boom" in capsys.readouterr().out


def test_address_cli_human_output(monkeypatch, capsys):
    result = AddressResult(
        "10.20.30.40", 4, "private", "40.30.20.10.in-addr.arpa", True
    )
    monkeypatch.setattr(cli, "classify_address", lambda value: result)
    assert cli.main(["address", "10.20.30.40"]) == 0
    output = capsys.readouterr().out
    assert "10.20.30.40: IPv4 private" in output
    assert "Reverse pointer: 40.30.20.10.in-addr.arpa" in output


def test_interfaces_human_empty_lists(monkeypatch, capsys):
    result = InterfaceResult("workstation", (), (), True)
    monkeypatch.setattr(cli, "inspect_interfaces", lambda: result)
    assert cli.main(["interfaces"]) == 0
    assert "none reported" in capsys.readouterr().out


def test_tcp_summary_human_failure(monkeypatch, capsys):
    result = TCPSummaryResult(
        "example.test", 443, 3, 0, 3, 0.0, None, None, None, None, False, ("refused",)
    )
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: result)
    assert cli.main(["tcp-summary", "example.test", "443"]) == 1
    assert "summary failed: refused" in capsys.readouterr().out


def test_tcp_summary_human_failure_without_errors(monkeypatch, capsys):
    result = TCPSummaryResult(
        "example.test", 443, 3, 0, 3, 0.0, None, None, None, None, False, ()
    )
    monkeypatch.setattr(cli, "summarize_tcp", lambda host, port, count, timeout: result)
    assert cli.main(["tcp-summary", "example.test", "443"]) == 1
    assert "no successful connections" in capsys.readouterr().out


def test_tls_human_without_certificate_details(monkeypatch, capsys):
    result = TLSResult(
        "example.test",
        443,
        True,
        latency_ms=5.0,
        protocol="TLSv1.2",
        cipher="ECDHE-RSA-AES128-GCM-SHA256",
        cipher_bits=128,
    )
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: result)
    assert cli.main(["tls", "example.test", "443"]) == 0
    output = capsys.readouterr().out
    assert "TLSv1.2" in output
    assert "Certificate expiry: not reported by peer" in output


def test_ping_human_with_failures(monkeypatch, capsys):
    result = PingResult(
        "example.test", 4, 3, 1, 75.0, 1.0, 1.5, 2.0, True, ("timeout",)
    )
    monkeypatch.setattr(cli, "ping_host", lambda host, count, timeout, family: result)
    assert cli.main(["ping", "example.test"]) == 0
    output = capsys.readouterr().out
    assert "3/4 replies" in output
    assert "Failures: 1" in output


def test_ping_human_failure_without_errors(monkeypatch, capsys):
    result = PingResult("example.test", 4, 0, 4, 0.0, None, None, None, False, ())
    monkeypatch.setattr(cli, "ping_host", lambda host, count, timeout, family: result)
    assert cli.main(["ping", "example.test"]) == 1
    assert "no replies received" in capsys.readouterr().out


def test_path_human_output_with_note(monkeypatch, capsys):
    result = PathResult("example.test", 5, ("1 192.0.2.1",), False, True, "not reached")
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.test"]) == 0
    output = capsys.readouterr().out
    assert "Path to example.test (max 5 hops):" in output
    assert "1 192.0.2.1" in output
    assert "Note: not reached" in output


def test_path_require_reached_failure(monkeypatch):
    result = PathResult("example.test", 5, ("1 192.0.2.1",), False, True, None)
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.test", "--require-reached"]) == 1


def test_path_failed_trace_returns_nonzero(monkeypatch):
    result = PathResult("example.test", 5, (), False, False, "boom")
    monkeypatch.setattr(cli, "trace_path", lambda host, max_hops, timeout: result)
    assert cli.main(["path", "example.test"]) == 1


def test_check_human_dispatches_tls_and_tcp(tmp_path, monkeypatch, capsys):
    path = tmp_path / "netscope-profiles.toml"
    path.write_text(
        '[t]\ntype = "tls"\nhost = "example.test"\nport = 443\n'
        '[c]\ntype = "tcp"\nhost = "example.test"\nport = 80\n',
        encoding="utf-8",
    )
    tls_result = TLSResult("example.test", 443, True, protocol="TLSv1.3")
    tcp_result = TCPResult("example.test", 80, True, latency_ms=2.0)
    monkeypatch.setattr(cli, "check_tls", lambda host, port, timeout: tls_result)
    monkeypatch.setattr(
        cli,
        "execute_check",
        lambda profile: (
            (tls_result, 0) if profile.check_type == "tls" else (tcp_result, 0)
        ),
    )
    assert cli.main(["check", "--profile", "t", "--profiles", str(path)]) == 0
    assert "TLSv1.3" in capsys.readouterr().out
    assert cli.main(["check", "--profile", "c", "--profiles", str(path)]) == 0
    assert "reachable" in capsys.readouterr().out


def test_check_human_failure_result(tmp_path, monkeypatch, capsys):
    path = tmp_path / "netscope-profiles.toml"
    path.write_text(
        '[c]\ntype = "tcp"\nhost = "example.test"\nport = 80\n', encoding="utf-8"
    )
    tcp_result = TCPResult("example.test", 80, False, error="refused")
    monkeypatch.setattr(cli, "execute_check", lambda profile: (tcp_result, 1))
    assert cli.main(["check", "--profile", "c", "--profiles", str(path)]) == 1
    assert "connection failed: refused" in capsys.readouterr().out
