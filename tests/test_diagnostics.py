import socket

from netscope.diagnostics import resolve_hostname


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
