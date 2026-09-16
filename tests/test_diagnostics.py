import socket

from netscope.diagnostics import check_tcp, inspect_interfaces, resolve_hostname, summarize_tcp


def test_resolve_hostname_deduplicates_and_sorts(monkeypatch):
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.2", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    result = resolve_hostname("example.test")
    assert result.ok is True
    assert result.addresses == ("192.0.2.1", "192.0.2.2")
    assert result.error is None


def test_resolve_hostname_rejects_blank_input():
    result = resolve_hostname("   ")
    assert result.ok is False
    assert result.addresses == ()
    assert result.error == "hostname is required"


def test_resolve_hostname_normalizes_resolver_error(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("not found")
    monkeypatch.setattr(socket, "getaddrinfo", fail)
    result = resolve_hostname("missing.test")
    assert result.ok is False
    assert result.error == "not found"


def test_inspect_interfaces_normalizes_and_sorts(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "workstation")
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(2, "eth0"), (1, "lo"), (3, "eth0")])
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::20", 0, 0, 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)
    result = inspect_interfaces()
    assert result.ok is True
    assert result.hostname == "workstation"
    assert result.interfaces == ("eth0", "lo")
    assert result.addresses == ("192.0.2.20", "2001:db8::20")
    assert result.error is None


def test_inspect_interfaces_normalizes_os_error(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "workstation")
    def fail():
        raise OSError("interface lookup unavailable")
    monkeypatch.setattr(socket, "if_nameindex", fail)
    result = inspect_interfaces()
    assert result.ok is False
    assert result.hostname == "workstation"
    assert result.interfaces == ()
    assert result.addresses == ()
    assert result.error == "interface lookup unavailable"


class FakeSocket:
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return None


def test_check_tcp_reports_success_and_latency(monkeypatch):
    monkeypatch.setattr(socket, "create_connection", lambda address, timeout: FakeSocket())
    ticks = iter((10.0, 10.01234))
    monkeypatch.setattr("netscope.diagnostics.time.monotonic", lambda: next(ticks))
    result = check_tcp("example.test", 443, timeout=2.0)
    assert result.ok is True
    assert result.host == "example.test"
    assert result.port == 443
    assert result.latency_ms == 12.34
    assert result.error is None


def test_check_tcp_normalizes_connection_failure(monkeypatch):
    def fail(*args, **kwargs):
        raise ConnectionRefusedError("refused")
    monkeypatch.setattr(socket, "create_connection", fail)
    result = check_tcp("example.test", 443)
    assert result.ok is False
    assert result.error == "refused"
    assert result.latency_ms is None


def test_check_tcp_validates_port_without_connecting(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")
    monkeypatch.setattr(socket, "create_connection", unexpected)
    result = check_tcp("example.test", 70000)
    assert result.ok is False
    assert result.error == "port must be between 1 and 65535"


def test_check_tcp_caps_timeout():
    result = check_tcp("example.test", 443, timeout=31)
    assert result.ok is False
    assert result.error == "timeout must be greater than 0 and at most 30 seconds"


def test_summarize_tcp_calculates_latency_and_failures(monkeypatch):
    results = iter([
        type("R", (), {"ok": True, "latency_ms": 10.0, "error": None})(),
        type("R", (), {"ok": False, "latency_ms": None, "error": "refused"})(),
        type("R", (), {"ok": True, "latency_ms": 20.0, "error": None})(),
    ])
    monkeypatch.setattr("netscope.diagnostics.check_tcp", lambda *args, **kwargs: next(results))
    result = summarize_tcp("example.test", 443, count=3)
    assert result.ok is True
    assert result.attempts == 3
    assert result.successes == 2
    assert result.failures == 1
    assert result.success_rate_percent == 66.67
    assert result.min_latency_ms == 10.0
    assert result.avg_latency_ms == 15.0
    assert result.max_latency_ms == 20.0
    assert result.jitter_ms == 5.0
    assert result.errors == ("refused",)


def test_summarize_tcp_single_success_has_zero_jitter(monkeypatch):
    success = type("R", (), {"ok": True, "latency_ms": 12.5, "error": None})()
    monkeypatch.setattr("netscope.diagnostics.check_tcp", lambda *args, **kwargs: success)
    result = summarize_tcp("example.test", 443, count=1)
    assert result.success_rate_percent == 100.0
    assert result.jitter_ms == 0.0


def test_summarize_tcp_rejects_unbounded_count(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("network should not be touched")
    monkeypatch.setattr("netscope.diagnostics.check_tcp", unexpected)
    result = summarize_tcp("example.test", 443, count=11)
    assert result.ok is False
    assert result.attempts == 0
    assert result.success_rate_percent == 0.0
    assert result.jitter_ms is None
    assert result.errors == ("count must be between 1 and 10",)


def test_summarize_tcp_reports_all_failures(monkeypatch):
    failure = type("R", (), {"ok": False, "latency_ms": None, "error": "timed out"})()
    monkeypatch.setattr("netscope.diagnostics.check_tcp", lambda *args, **kwargs: failure)
    result = summarize_tcp("example.test", 443, count=2)
    assert result.ok is False
    assert result.successes == 0
    assert result.failures == 2
    assert result.success_rate_percent == 0.0
    assert result.min_latency_ms is None
    assert result.jitter_ms is None
    assert result.errors == ("timed out", "timed out")
