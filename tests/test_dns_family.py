import socket

import pytest

from netscope.dns import resolve_hostname_family


def _record(family: int, address: str):
    if family == socket.AF_INET6:
        endpoint = (address, 0, 0, 0)
    else:
        endpoint = (address, 0)
    return (family, socket.SOCK_STREAM, 6, "", endpoint)


@pytest.mark.parametrize(
    ("requested", "expected_family", "address"),
    [
        ("ipv4", socket.AF_INET, "192.0.2.10"),
        ("ipv6", socket.AF_INET6, "2001:db8::10"),
    ],
)
def test_family_filter_is_passed_to_system_resolver(monkeypatch, requested, expected_family, address):
    seen = {}

    def fake_getaddrinfo(host, port, *, family, type):
        seen.update(host=host, port=port, family=family, type=type)
        return [_record(expected_family, address), _record(expected_family, address)]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = resolve_hostname_family(" example.com ", requested)

    assert result.ok is True
    assert result.hostname == "example.com"
    assert result.family == requested
    assert result.addresses == (address,)
    assert seen == {"host": "example.com", "port": None, "family": expected_family, "type": socket.SOCK_STREAM}


def test_any_family_uses_unspecified_family(monkeypatch):
    def fake_getaddrinfo(host, port, *, family, type):
        assert family == socket.AF_UNSPEC
        return [_record(socket.AF_INET6, "2001:db8::2"), _record(socket.AF_INET, "192.0.2.2")]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    result = resolve_hostname_family("example.com")

    assert result.ok is True
    assert result.addresses == ("192.0.2.2", "2001:db8::2")


def test_invalid_family_fails_without_resolver_call(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be called")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)

    result = resolve_hostname_family("example.com", "ipx")

    assert result.ok is False
    assert result.error == "family must be one of: any, ipv4, ipv6"


def test_family_result_has_json_native_addresses(monkeypatch):
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda *args, **kwargs: [_record(socket.AF_INET, "192.0.2.20")],
    )

    payload = resolve_hostname_family("example.com", "ipv4").to_dict()

    assert payload["family"] == "ipv4"
    assert payload["addresses"] == ["192.0.2.20"]
