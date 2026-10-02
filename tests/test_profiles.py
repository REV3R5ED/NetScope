"""Tests for saved endpoint profiles and the check command."""

from __future__ import annotations

import json

import pytest

from netscope import cli, profiles
from netscope.diagnostics import TCPResult, TCPSummaryResult
from netscope.profiles import (
    CheckProfile,
    ProfileError,
    _loads_toml_fallback,
    discover_profiles_file,
    execute_check,
    load_profile,
    load_profiles,
)
from netscope.tls import TLSResult

VALID_TOML = """
# Production checks
[prod-web]
description = "Production web endpoint"
type = "tcp-summary"
host = "example.com"
port = 443
count = 5
timeout = 3.0
min_success_rate = 95.0
max_jitter_ms = 25.0
max_avg_latency_ms = 200.0

[prod-tls]
type = "tls"
host = "example.com"
port = 443
min_days_cert_valid = 30.0

[simple]
type = "tcp"
host = "example.com"
port = 80
"""


def _write_profiles(tmp_path, text=VALID_TOML):
    path = tmp_path / "netscope-profiles.toml"
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_load_profiles_parses_all_check_types(tmp_path):
    path = _write_profiles(tmp_path)
    loaded = load_profiles(path)
    assert set(loaded) == {"prod-web", "prod-tls", "simple"}
    web = loaded["prod-web"]
    assert web.check_type == "tcp-summary"
    assert web.host == "example.com"
    assert web.port == 443
    assert web.count == 5
    assert web.timeout == 3.0
    assert web.description == "Production web endpoint"
    assert web.min_success_rate == 95.0
    assert web.max_jitter_ms == 25.0
    assert web.max_avg_latency_ms == 200.0
    assert loaded["prod-tls"].min_days_cert_valid == 30.0
    assert loaded["simple"].check_type == "tcp"


def test_load_profiles_applies_defaults(tmp_path):
    path = _write_profiles(tmp_path, '[minimal]\ntype = "tcp"\nhost = "h"\nport = 1\n')
    profile = load_profiles(path)["minimal"]
    assert profile.timeout == 3.0
    assert profile.count == 3
    assert profile.description == ""
    assert profile.min_success_rate is None


def test_load_profile_missing_name_lists_available(tmp_path):
    path = _write_profiles(tmp_path)
    with pytest.raises(ProfileError, match="available"):
        load_profile(path, "nope")


def test_load_profiles_missing_file(tmp_path):
    with pytest.raises(ProfileError, match="not found"):
        load_profiles(str(tmp_path / "missing.toml"))


def test_load_profiles_rejects_invalid_toml(tmp_path):
    path = _write_profiles(tmp_path, "[broken\ntype = ")
    with pytest.raises(ProfileError):
        load_profiles(path)


def test_load_profiles_rejects_empty_file(tmp_path):
    path = _write_profiles(tmp_path, "# nothing here\n")
    with pytest.raises(ProfileError, match="no profiles"):
        load_profiles(path)


@pytest.mark.parametrize(
    "body",
    [
        '[bad]\nhost = "h"\nport = 1\n',  # missing type
        '[bad]\ntype = "scan"\nhost = "h"\nport = 1\n',  # unknown type
        '[bad]\ntype = "tcp"\nport = 1\n',  # missing host
        '[bad]\ntype = "tcp"\nhost = "h"\nport = 0\n',  # bad port
        '[bad]\ntype = "tcp"\nhost = "h"\nport = 1\ntimeout = 31\n',  # bad timeout
        '[bad]\ntype = "tcp-summary"\nhost = "h"\nport = 1\ncount = 11\n',  # bad count
        '[bad]\ntype = "tcp-summary"\nhost = "h"\nport = 1\nmin_success_rate = 101\n',
        '[bad]\ntype = "tls"\nhost = "h"\nport = 1\ncount = 2\n',  # count not for tls
        '[bad]\ntype = "tcp"\nhost = "h"\nport = 1\nmin_days_cert_valid = 3\n',
        '[bad]\ntype = "tcp"\nhost = "h\x00"\nport = 1\n',  # control chars
        '[bad]\ntype = "tcp"\nhost = "h"\nport = 1\nbogus = 1\n',  # unknown key
    ],
)
def test_load_profiles_rejects_invalid_profiles(tmp_path, body):
    path = _write_profiles(tmp_path, body)
    with pytest.raises(ProfileError):
        load_profiles(path)


def test_fallback_toml_parser_supports_profile_subset():
    parsed = _loads_toml_fallback(VALID_TOML)
    assert parsed["prod-web"]["type"] == "tcp-summary"
    assert parsed["prod-web"]["port"] == 443
    assert parsed["prod-web"]["timeout"] == 3.0
    assert parsed["prod-web"]["description"] == "Production web endpoint"
    assert parsed["prod-tls"]["min_days_cert_valid"] == 30.0


def test_fallback_toml_parser_handles_comments_and_literals():
    text = (
        "# comment\n"
        "[p] # trailing comment\n"
        "type = 'tcp' # literal string\n"
        'host = "exa#mple.com"\n'
        "port = 80\n"
        "flag = true\n"
    )
    parsed = _loads_toml_fallback(text)
    assert parsed["p"]["type"] == "tcp"
    assert parsed["p"]["host"] == "exa#mple.com"
    assert parsed["p"]["flag"] is True


def test_fallback_toml_parser_rejects_bad_input():
    with pytest.raises(ProfileError):
        _loads_toml_fallback("key = 1\n")  # no section
    with pytest.raises(ProfileError):
        _loads_toml_fallback("[a]\n[a]\n")  # duplicate section
    with pytest.raises(ProfileError):
        _loads_toml_fallback("[a]\ntype = \n")  # empty value


def test_discover_profiles_file_prefers_explicit(tmp_path):
    explicit = tmp_path / "custom.toml"
    explicit.write_text('[a]\ntype = "tcp"\nhost = "h"\nport = 1\n')
    assert discover_profiles_file(str(explicit)) == str(explicit)


def test_discover_profiles_file_finds_cwd_file(tmp_path, monkeypatch):
    target = _write_profiles(tmp_path)
    monkeypatch.chdir(tmp_path)
    assert discover_profiles_file(None) == target


def test_discover_profiles_file_returns_none_when_absent(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty-config"))
    assert discover_profiles_file(None) is None


def _summary(**overrides):
    base = {
        "host": "example.com",
        "port": 443,
        "attempts": 3,
        "successes": 3,
        "failures": 0,
        "success_rate_percent": 100.0,
        "min_latency_ms": 10.0,
        "avg_latency_ms": 12.0,
        "max_latency_ms": 15.0,
        "jitter_ms": 2.0,
        "ok": True,
        "errors": (),
    }
    base.update(overrides)
    return TCPSummaryResult(**base)


def test_execute_check_tcp_summary_success_and_gate_failure(monkeypatch):
    monkeypatch.setattr(
        profiles, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    profile = CheckProfile(
        name="web", check_type="tcp-summary", host="example.com", port=443
    )
    result, exit_code = execute_check(profile)
    assert exit_code == 0
    assert result.ok is True
    gated = CheckProfile(
        name="web",
        check_type="tcp-summary",
        host="example.com",
        port=443,
        max_avg_latency_ms=5.0,
    )
    _, exit_code = execute_check(gated)
    assert exit_code == 1


def test_execute_check_tcp(monkeypatch):
    def failing_check(host, port, timeout):
        return TCPResult(host, port, False, error="refused")

    monkeypatch.setattr(profiles, "check_tcp", failing_check)
    profile = CheckProfile(name="t", check_type="tcp", host="example.com", port=80)
    result, exit_code = execute_check(profile)
    assert exit_code == 1
    assert isinstance(result, TCPResult)


def test_execute_check_tls_gate(monkeypatch):
    monkeypatch.setattr(
        profiles,
        "check_tls",
        lambda host, port, timeout: TLSResult(host, port, True, days_until_expiry=10.0),
    )
    profile = CheckProfile(
        name="t",
        check_type="tls",
        host="example.com",
        port=443,
        min_days_cert_valid=30.0,
    )
    _, exit_code = execute_check(profile)
    assert exit_code == 1
    ok_profile = CheckProfile(name="t", check_type="tls", host="example.com", port=443)
    _, exit_code = execute_check(ok_profile)
    assert exit_code == 0


def test_check_cli_runs_named_profile(tmp_path, monkeypatch, capsys):
    path = _write_profiles(tmp_path)
    monkeypatch.setattr(
        profiles, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    monkeypatch.setattr(cli, "summarize_tcp", profiles.summarize_tcp)
    assert cli.main(["check", "--profile", "prod-web", "--profiles", path]) == 0
    assert "[prod-web] tcp-summary" in capsys.readouterr().out


def test_check_cli_json_emits_underlying_result(tmp_path, monkeypatch, capsys):
    path = _write_profiles(tmp_path)
    monkeypatch.setattr(
        profiles, "summarize_tcp", lambda host, port, count, timeout: _summary()
    )
    monkeypatch.setattr(cli, "summarize_tcp", profiles.summarize_tcp)
    assert (
        cli.main(["check", "--profile", "prod-web", "--profiles", path, "--json"]) == 0
    )
    payload = json.loads(capsys.readouterr().out)
    assert payload["success_rate_percent"] == 100.0


def test_check_cli_gate_violation_returns_nonzero(tmp_path, monkeypatch):
    path = _write_profiles(tmp_path)
    monkeypatch.setattr(
        profiles,
        "summarize_tcp",
        lambda host, port, count, timeout: _summary(avg_latency_ms=500.0),
    )
    monkeypatch.setattr(cli, "summarize_tcp", profiles.summarize_tcp)
    assert cli.main(["check", "--profile", "prod-web", "--profiles", path]) == 1


def test_check_cli_missing_profile_is_usage_error(tmp_path, capsys):
    path = _write_profiles(tmp_path)
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["check", "--profile", "nope", "--profiles", path])
    assert exc_info.value.code == 2


def test_check_cli_missing_file_is_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["check", "--profile", "x", "--profiles", str(tmp_path / "no.toml")])
    assert exc_info.value.code == 2
    assert "not found" in capsys.readouterr().err


def test_check_cli_no_profiles_file_found_is_usage_error(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "empty-config"))
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["check", "--profile", "x"])
    assert exc_info.value.code == 2
