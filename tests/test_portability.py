import socket

from netscope.diagnostics import inspect_interfaces


def test_interface_inspection_falls_back_when_name_index_is_unavailable(monkeypatch):
    monkeypatch.setattr(socket, "gethostname", lambda: "portable-host")
    monkeypatch.delattr(socket, "if_nameindex")
    records = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.50", 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::50", 0, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: records)

    result = inspect_interfaces()

    assert result.ok is True
    assert result.hostname == "portable-host"
    assert result.interfaces == ()
    assert result.addresses == ("192.0.2.50", "2001:db8::50")
    assert result.error == "interface enumeration unavailable on this platform"
