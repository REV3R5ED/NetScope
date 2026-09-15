import socket

from netscope.diagnostics import check_tcp, inspect_interfaces, resolve_hostname


def test_inspect_interfaces_sorts_names(monkeypatch):
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(2, "eth0"), (1, "lo")])

    result = inspect_interfaces()

    assert result.ok is True
    assert result.interfaces == ("eth0", "lo")
    assert result.error is None


def test_inspect_interfaces_normalizes_os_error(monkeypatch):
    def fail():
        raise OSError("not supported")

    monkeypatch.setattr(socket, "if_nameindex", fail)
    result = inspect_interfaces()

    assert result.ok is False
    assert result.interfaces == ()
    assert result.error == "not supported"


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
