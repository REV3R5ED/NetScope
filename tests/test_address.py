import json

from netscope.address import classify_address
from netscope.cli import main


def test_classifies_ipv4_private_address():
    result = classify_address("10.20.30.40")
    assert result.ok is True
    assert result.address == "10.20.30.40"
    assert result.version == 4
    assert result.scope == "private"
    assert result.reverse_pointer == "40.30.20.10.in-addr.arpa"


def test_classifies_ipv6_loopback():
    result = classify_address("::1")
    assert result.ok is True
    assert result.version == 6
    assert result.scope == "loopback"
    assert result.reverse_pointer.endswith("ip6.arpa")


def test_rejects_hostname_without_resolving():
    result = classify_address("example.com")
    assert result.ok is False
    assert result.error == "address must be a literal IPv4 or IPv6 address"


def test_address_cli_json(capsys):
    assert main(["address", "192.0.2.1", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["address"] == "192.0.2.1"
    assert payload["version"] == 4
    assert payload["scope"] in {"private", "reserved"}
    assert payload["ok"] is True


def test_address_cli_invalid_returns_nonzero(capsys):
    assert main(["address", "not-an-address"]) == 1
    assert "classification failed" in capsys.readouterr().out
