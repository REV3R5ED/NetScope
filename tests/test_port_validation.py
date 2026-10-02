"""TCP port is validated at the argparse layer as a usage error (exit 2)."""

from __future__ import annotations

import pytest

from netscope import cli


@pytest.mark.parametrize("port", ["0", "-1", "65536", "99999", "notaport", "443.5"])
def test_tcp_rejects_invalid_port_as_usage_error(monkeypatch, port):
    def unexpected(*args, **kwargs):
        raise AssertionError("usage errors must fail before diagnostics run")

    monkeypatch.setattr(cli, "check_tcp", unexpected)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tcp", "example.test", port])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("port", ["0", "65536", "notaport"])
def test_tcp_summary_rejects_invalid_port_as_usage_error(monkeypatch, port):
    def unexpected(*args, **kwargs):
        raise AssertionError("usage errors must fail before diagnostics run")

    monkeypatch.setattr(cli, "summarize_tcp", unexpected)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["tcp-summary", "example.test", port])
    assert exc_info.value.code == 2


@pytest.mark.parametrize("port", ["1", "443", "65535"])
def test_tcp_accepts_boundary_ports(monkeypatch, port):
    seen = {}

    def fake_check(host, port_number, timeout):
        seen["port"] = port_number
        from netscope.diagnostics import TCPResult

        return TCPResult(host, port_number, True, latency_ms=1.0)

    monkeypatch.setattr(cli, "check_tcp", fake_check)
    assert cli.main(["tcp", "example.test", port]) == 0
    assert seen["port"] == int(port)
