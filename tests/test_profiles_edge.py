"""Edge-case coverage for profiles parsing, validation, and discovery."""

from __future__ import annotations

import pytest

from netscope import profiles
from netscope.diagnostics import TCPSummaryResult
from netscope.profiles import (
    CheckProfile,
    ProfileError,
    _build_profile,
    _coerce_float,
    _coerce_int,
    _loads_toml_fallback,
    _parse_value,
    _split_array,
    discover_profiles_file,
    execute_check,
    load_profiles,
)
from netscope.tls import TLSResult


def test_parse_value_string_escapes():
    assert _parse_value(r'"a\\b\"c"') == 'a\\b"c'
    assert _parse_value(r'"line1\nline2"') == "line1\nline2"
    assert _parse_value(r'"tab\there"') == "tab\there"
    assert _parse_value("'literal\\n'") == "literal\\n"


def test_parse_value_numbers_and_booleans():
    assert _parse_value("42") == 42
    assert _parse_value("3.5") == 3.5
    assert _parse_value("true") is True
    assert _parse_value("false") is False
    with pytest.raises(ProfileError):
        _parse_value("not-a-value!!")


def test_parse_value_arrays():
    assert _parse_value("[]") == []
    assert _parse_value('["a", "b"]') == ["a", "b"]
    assert _parse_value("[1, 2]") == [1, 2]
    assert _parse_value("[1.5, true]") == [1.5, True]


def test_split_array_ignores_commas_inside_strings():
    assert _split_array("\"a,b\", 'c,d', 3") == ['"a,b"', " 'c,d'", " 3"]


def test_fallback_parser_rejects_dotted_keys(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text("[a]\nfoo.bar = 1\n", encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profiles(str(path))


def test_fallback_parser_rejects_line_without_section(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('type = "tcp"\n', encoding="utf-8")
    with pytest.raises(ProfileError):
        load_profiles(str(path))


def test_coerce_float_rejects_bad_values():
    with pytest.raises(ProfileError, match="must be a number"):
        _coerce_float("p", "timeout", "fast", 0.0, 30.0)
    with pytest.raises(ProfileError, match="must be a number"):
        _coerce_float("p", "timeout", True, 0.0, 30.0)
    with pytest.raises(ProfileError, match="between"):
        _coerce_float("p", "timeout", 31.0, 0.0, 30.0)


def test_coerce_int_rejects_bad_values():
    with pytest.raises(ProfileError, match="must be an integer"):
        _coerce_int("p", "port", 80.5, 1, 65535)
    with pytest.raises(ProfileError, match="must be an integer"):
        _coerce_int("p", "port", False, 1, 65535)
    with pytest.raises(ProfileError, match="between"):
        _coerce_int("p", "port", 70000, 1, 65535)


def test_load_profiles_rejects_non_table_profile(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text('[a]\ntype = "tcp"\n', encoding="utf-8")
    # tomllib path with a top-level non-table value instead of a section
    path.write_text("a = 1\n", encoding="utf-8")
    with pytest.raises(ProfileError, match="TOML table"):
        load_profiles(str(path))


def test_load_profiles_rejects_non_string_description(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        '[a]\ntype = "tcp"\nhost = "h"\nport = 1\ndescription = 42\n',
        encoding="utf-8",
    )
    with pytest.raises(ProfileError, match="description must be a string"):
        load_profiles(str(path))


def test_load_profiles_rejects_zero_timeout(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        '[a]\ntype = "tcp"\nhost = "h"\nport = 1\ntimeout = 0\n', encoding="utf-8"
    )
    with pytest.raises(ProfileError, match="greater than 0"):
        load_profiles(str(path))


def test_load_profiles_rejects_unreadable_file(tmp_path, monkeypatch):
    path = tmp_path / "p.toml"
    path.write_text('[a]\ntype = "tcp"\nhost = "h"\nport = 1\n', encoding="utf-8")

    def failing_read(*args, **kwargs):
        raise PermissionError("denied")

    monkeypatch.setattr(profiles.Path, "read_text", failing_read)
    with pytest.raises(ProfileError, match="cannot read"):
        load_profiles(str(path))


def test_discover_profiles_file_uses_xdg_config(tmp_path, monkeypatch):
    config = tmp_path / "config" / "netscope" / "profiles.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[a]\ntype = "tcp"\nhost = "h"\nport = 1\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert discover_profiles_file(None) == str(config)


def test_discover_profiles_file_prefers_cwd_over_xdg(tmp_path, monkeypatch):
    config = tmp_path / "config" / "netscope" / "profiles.toml"
    config.parent.mkdir(parents=True)
    config.write_text('[a]\ntype = "tcp"\nhost = "h"\nport = 1\n', encoding="utf-8")
    cwd_file = tmp_path / "netscope-profiles.toml"
    cwd_file.write_text('[b]\ntype = "tcp"\nhost = "h"\nport = 1\n', encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    assert discover_profiles_file(None) == str(cwd_file)


def test_fallback_parser_rejects_empty_key():
    with pytest.raises(ProfileError, match="invalid key"):
        _loads_toml_fallback("[a]\n= 1\n")


def test_loads_toml_uses_fallback_on_python_310(monkeypatch):
    import sys

    monkeypatch.setattr(sys, "version_info", (3, 10, 0))
    parsed = profiles._loads_toml('[a]\ntype = "tcp"\n')
    assert parsed == {"a": {"type": "tcp"}}


def test_build_profile_rejects_control_characters_in_host():
    with pytest.raises(ProfileError, match="control characters"):
        _build_profile("x", {"type": "tcp", "host": "h\x00", "port": 1})


def test_execute_check_tls_failure_returns_nonzero(monkeypatch):
    monkeypatch.setattr(
        profiles,
        "check_tls",
        lambda host, port, timeout: TLSResult(host, port, False, error="boom"),
    )
    profile = CheckProfile(name="t", check_type="tls", host="h", port=443)
    result, exit_code = execute_check(profile)
    assert exit_code == 1
    assert result.ok is False


def test_execute_check_summary_failure_returns_nonzero(monkeypatch):
    def failing_summary(host, port, count, timeout):
        return TCPSummaryResult(
            host, port, 0, 0, 0, 0.0, None, None, None, None, False, ("boom",)
        )

    monkeypatch.setattr(profiles, "summarize_tcp", failing_summary)
    profile = CheckProfile(name="s", check_type="tcp-summary", host="h", port=443)
    result, exit_code = execute_check(profile)
    assert exit_code == 1
    assert result.ok is False


def test_load_profiles_supports_toml_float_and_int_thresholds(tmp_path):
    path = tmp_path / "p.toml"
    path.write_text(
        '[a]\ntype = "tcp-summary"\nhost = "h"\nport = 1\n'
        "min_success_rate = 95\nmax_jitter_ms = 10\n",
        encoding="utf-8",
    )
    profile = load_profiles(str(path))["a"]
    assert profile.min_success_rate == 95.0
    assert profile.max_jitter_ms == 10.0
