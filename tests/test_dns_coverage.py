"""Error-path and edge coverage for family-specific DNS diagnostics."""

from __future__ import annotations

import socket

from netscope.dns import DNSFamilyResult, resolve_hostname_family


def test_rejects_non_string_hostname_without_resolver(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be touched")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    for hostname in (None, 123, True, object()):
        result = resolve_hostname_family(hostname, "ipv4")
        assert result.ok is False
        assert result.hostname == ""
        assert result.family == "ipv4"
        assert result.error == "hostname must be a string"


def test_rejects_non_string_family_without_resolver(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be touched")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    result = resolve_hostname_family("example.test", None)
    assert result.ok is False
    assert result.hostname == "example.test"
    assert result.family == ""
    assert result.error == "family must be one of: any, ipv4, ipv6"


def test_rejects_blank_hostname():
    result = resolve_hostname_family("   ")
    assert result.ok is False
    assert result.error == "hostname is required"


def test_rejects_control_characters_in_hostname(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be touched")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    result = resolve_hostname_family("example\x00.test", "ipv6")
    assert result.ok is False
    assert result.error == "hostname must not contain control characters"


def test_rejects_unknown_family_without_resolver(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError("resolver should not be touched")

    monkeypatch.setattr(socket, "getaddrinfo", unexpected)
    result = resolve_hostname_family("example.test", "IPv7")
    assert result.ok is False
    assert result.family == "ipv7"
    assert result.error == "family must be one of: any, ipv4, ipv6"


def test_normalizes_family_case_and_whitespace(monkeypatch):
    def fake_getaddrinfo(host, port, family=0, type=0):
        assert family == socket.AF_INET6
        return [(socket.AF_INET6, None, None, None, ("2001:db8::1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    result = resolve_hostname_family("example.test", " IPv6 ")
    assert result.ok is True
    assert result.family == "ipv6"
    assert result.addresses == ("2001:db8::1",)


def test_resolver_os_error_becomes_structured_failure(monkeypatch):
    def failing_resolver(*args, **kwargs):
        raise OSError("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", failing_resolver)
    result = resolve_hostname_family("example.test", "ipv4")
    assert result.ok is False
    assert result.addresses == ()
    assert result.error == "name resolution failed"


def test_empty_resolver_response_is_a_failure(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [])
    result = resolve_hostname_family("example.test", "any")
    assert result.ok is False
    assert result.error == "resolver returned no any addresses"


def test_successful_lookup_returns_sorted_unique_addresses(monkeypatch):
    records = [
        (socket.AF_INET, None, None, None, ("192.0.2.2", 0)),
        (socket.AF_INET, None, None, None, ("192.0.2.1", 0)),
        (socket.AF_INET, None, None, None, ("192.0.2.1", 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: records)
    result = resolve_hostname_family("example.test")
    assert result.ok is True
    assert result.family == "any"
    assert result.addresses == ("192.0.2.1", "192.0.2.2")
    assert isinstance(result, DNSFamilyResult)
