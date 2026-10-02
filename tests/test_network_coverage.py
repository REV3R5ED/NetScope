"""Scope-branch and error-path coverage for offline network classification."""

from __future__ import annotations

import pytest

from netscope.network import NetworkResult, classify_network


@pytest.mark.parametrize(
    ("value", "version", "scope", "num_addresses"),
    [
        ("0.0.0.0/0", 4, "unspecified", 2**32),
        ("127.0.0.0/8", 4, "loopback", 2**24),
        ("169.254.0.0/16", 4, "link-local", 2**16),
        ("224.0.0.0/4", 4, "multicast", 2**28),
        ("10.0.0.0/8", 4, "private", 2**24),
        ("fd00::/8", 6, "private", 2**120),
        ("240.0.0.0/4", 4, "reserved", 2**28),
        ("8.8.8.0/24", 4, "global", 256),
        ("2001:4860::/32", 6, "global", 2**96),
        ("100.64.0.0/10", 4, "special", 2**22),
    ],
)
def test_classify_network_covers_every_scope_branch(
    value, version, scope, num_addresses
):
    result = classify_network(value)
    assert result.ok is True
    assert result.version == version
    assert result.scope == scope
    assert result.num_addresses == num_addresses
    assert result.error is None


def test_classify_network_reports_boundaries():
    result = classify_network("10.20.30.0/24")
    assert result.ok is True
    assert result.network == "10.20.30.0/24"
    assert result.prefix_length == 24
    assert result.network_address == "10.20.30.0"
    assert result.last_address == "10.20.30.255"
    assert isinstance(result, NetworkResult)


def test_classify_network_rejects_non_string():
    result = classify_network(None)
    assert result.ok is False
    assert result.network == ""
    assert result.error == "network must be a string"


def test_classify_network_rejects_blank_input():
    result = classify_network("  ")
    assert result.ok is False
    assert result.error == "network is required"


def test_classify_network_rejects_control_characters():
    result = classify_network("10.0.0.0/8\x7f")
    assert result.ok is False
    assert result.error == "network must not contain control characters"


def test_classify_network_rejects_non_canonical_prefix():
    result = classify_network("10.0.0.1/24")
    assert result.ok is False
    assert result.error == "network must be a canonical IPv4 or IPv6 prefix"


def test_classify_network_rejects_hostname():
    result = classify_network("example.com")
    assert result.ok is False
    assert result.error == "network must be a canonical IPv4 or IPv6 prefix"
