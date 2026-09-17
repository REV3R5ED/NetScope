"""CLI coverage for address-family-specific DNS diagnostics."""

from __future__ import annotations

import json

from netscope import cli
from netscope.dns import DNSFamilyResult


def test_dns_family_json_uses_requested_family(monkeypatch, capsys):
    seen = []

    def fake_resolve(hostname, family):
        seen.append((hostname, family))
        return DNSFamilyResult(hostname, family, ("2001:db8::1",), True)

    monkeypatch.setattr(cli, "resolve_hostname_family", fake_resolve)
    assert cli.main(["dns", "example.com", "--family", "ipv6", "--json"]) == 0
    assert seen == [("example.com", "ipv6")]
    payload = json.loads(capsys.readouterr().out)
    assert payload["family"] == "ipv6"
    assert payload["addresses"] == ["2001:db8::1"]


def test_dns_family_failure_returns_nonzero(monkeypatch, capsys):
    monkeypatch.setattr(
        cli,
        "resolve_hostname_family",
        lambda hostname, family: DNSFamilyResult(hostname, family, (), False, "no IPv6 address"),
    )
    assert cli.main(["dns", "example.com", "--family", "ipv6"]) == 1
    assert "resolution failed: no IPv6 address" in capsys.readouterr().out


def test_dns_without_family_preserves_legacy_resolver(monkeypatch, capsys):
    from netscope.diagnostics import DNSResult

    monkeypatch.setattr(cli, "resolve_hostname", lambda hostname: DNSResult(hostname, ("192.0.2.1",), True))
    monkeypatch.setattr(cli, "resolve_hostname_family", lambda *args: (_ for _ in ()).throw(AssertionError("unexpected family resolver")))
    assert cli.main(["dns", "example.com", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {"hostname": "example.com", "addresses": ["192.0.2.1"], "ok": True, "error": None}
