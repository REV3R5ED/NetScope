import socket

from netscope.diagnostics import inspect_interfaces


def test_inspect_interfaces_normalizes_hostname_failure(monkeypatch):
    def fail():
        raise OSError("hostname unavailable")

    monkeypatch.setattr(socket, "gethostname", fail)
    result = inspect_interfaces()

    assert result.ok is False
    assert result.hostname == ""
    assert result.interfaces == ()
    assert result.addresses == ()
    assert result.error == "hostname unavailable"


def test_inspect_interfaces_rejects_empty_local_resolution(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "workstation")
    monkeypatch.setattr(socket, "if_nameindex", lambda: [(1, "lo")])
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])

    result = inspect_interfaces()

    assert result.ok is False
    assert result.hostname == "workstation"
    assert result.interfaces == ("lo",)
    assert result.addresses == ()
    assert result.error == "local hostname resolved to no addresses"
