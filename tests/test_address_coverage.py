"""Scope-branch and error-path coverage for offline address classification."""

from __future__ import annotations

import pytest

from netscope.address import AddressResult, classify_address


@pytest.mark.parametrize(
    ("value", "version", "scope"),
    [
        ("0.0.0.0", 4, "unspecified"),
        ("::", 6, "unspecified"),
        ("127.0.0.1", 4, "loopback"),
        ("::1", 6, "loopback"),
        ("169.254.10.20", 4, "link-local"),
        ("fe80::1", 6, "link-local"),
        ("224.0.0.1", 4, "multicast"),
        ("ff02::1", 6, "multicast"),
        ("10.0.0.1", 4, "private"),
        ("192.168.1.1", 4, "private"),
        ("fd00::1", 6, "private"),
        ("240.0.0.1", 4, "reserved"),
        ("8.8.8.8", 4, "global"),
        ("2001:4860:4860::8888", 6, "global"),
        ("100.64.0.1", 4, "special"),
    ],
)
def test_classify_address_covers_every_scope_branch(value, version, scope):
    result = classify_address(value)
    assert result.ok is True
    assert result.version == version
    assert result.scope == scope
    assert result.error is None


def test_classify_address_rejects_non_string_without_parsing():
    result = classify_address(None)
    assert result.ok is False
    assert result.address == ""
    assert result.error == "address must be a string"


def test_classify_address_rejects_blank_input():
    result = classify_address("   ")
    assert result.ok is False
    assert result.error == "address is required"


def test_classify_address_rejects_control_characters():
    result = classify_address("10.0.0.\x001")
    assert result.ok is False
    assert result.error == "address must not contain control characters"


def test_classify_address_rejects_non_literal():
    result = classify_address("not-an-address")
    assert result.ok is False
    assert result.error == "address must be a literal IPv4 or IPv6 address"


def test_classify_address_reports_reverse_pointer():
    result = classify_address("10.20.30.40")
    assert result.ok is True
    assert result.reverse_pointer == "40.30.20.10.in-addr.arpa"
    assert isinstance(result, AddressResult)
    assert result.to_dict()["reverse_pointer"] == "40.30.20.10.in-addr.arpa"
