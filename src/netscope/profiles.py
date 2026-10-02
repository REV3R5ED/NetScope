"""Named endpoint profiles for repeatable checks from cron or CI.

Profiles are TOML documents mapping a profile name to one bounded check:

```toml
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
timeout = 5.0
min_days_cert_valid = 30.0
```

``netscope check --profile prod-web`` executes the stored check with the same
structured exit codes as the equivalent direct command (0 success, 1 failure
or violated health gate, 2 usage error).
"""

from __future__ import annotations

import logging
import math
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib

from .diagnostics import (
    TCPResult,
    TCPSummaryResult,
    check_tcp,
    evaluate_tcp_summary_gates,
    summarize_tcp,
)
from .tls import TLSResult, check_tls, evaluate_tls_gates
from .validation import has_control_characters

logger = logging.getLogger(__name__)

CHECK_TYPES = ("tcp", "tcp-summary", "tls")
TCP_SUMMARY_KEYS = {
    "count",
    "min_success_rate",
    "max_jitter_ms",
    "max_avg_latency_ms",
}
TLS_KEYS = {"min_days_cert_valid"}
COMMON_KEYS = {"description", "type", "host", "port", "timeout"}
KNOWN_KEYS = COMMON_KEYS | TCP_SUMMARY_KEYS | TLS_KEYS

DEFAULT_FILENAME = "netscope-profiles.toml"


class ProfileError(ValueError):
    """Raised when a profiles file or a single profile is invalid."""


def _parse_value(text: str) -> Any:
    """Parse one TOML value from the supported profile subset."""
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return (
            text[1:-1]
            .replace("\\\\", "\\")
            .replace('\\"', '"')
            .replace("\\n", "\n")
            .replace("\\t", "\t")
        )
    if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
        return text[1:-1]
    if text in ("true", "false"):
        return text == "true"
    if text.startswith("[") and text.endswith("]"):
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_parse_value(item) for item in _split_array(inner)]
    try:
        return int(text)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        pass
    raise ProfileError(f"unsupported TOML value: {text!r}")


def _split_array(inner: str) -> list[str]:
    """Split a single-line TOML array body on top-level commas."""
    items: list[str] = []
    current: list[str] = []
    in_string: str | None = None
    for character in inner:
        if in_string:
            current.append(character)
            if character == in_string:
                in_string = None
        elif character in "\"'":
            in_string = character
            current.append(character)
        elif character == ",":
            items.append("".join(current))
            current = []
        else:
            current.append(character)
    items.append("".join(current))
    return items


def _strip_comment(line: str) -> str:
    """Remove a trailing # comment, ignoring # inside quoted strings."""
    in_string: str | None = None
    for index, character in enumerate(line):
        if in_string:
            if character == in_string:
                in_string = None
        elif character in "\"'":
            in_string = character
        elif character == "#":
            return line[:index]
    return line


def _loads_toml_fallback(text: str) -> dict[str, dict[str, Any]]:
    """Minimal TOML parser for profile files on Python 3.10 (no tomllib).

    Supports the profile schema only: ``[section]`` tables, string/integer/
    float/boolean values, and single-line arrays. Anything else is rejected
    with ProfileError so misconfigurations fail loudly instead of silently.
    """
    profiles: dict[str, dict[str, Any]] = {}
    current: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        header = _strip_comment(line).strip()
        if header.startswith("[") and header.endswith("]"):
            current = header[1:-1].strip()
            if not current or current in profiles:
                raise ProfileError(
                    f"invalid or duplicate profile section on line {line_number}"
                )
            profiles[current] = {}
            continue
        if current is None or "=" not in line:
            raise ProfileError(f"invalid TOML on line {line_number}: {raw_line!r}")
        key, _, raw_value = line.partition("=")
        key = key.strip()
        if not key or "." in key:
            raise ProfileError(f"invalid key on line {line_number}: {raw_line!r}")
        try:
            profiles[current][key] = _parse_value(_strip_comment(raw_value))
        except ProfileError as exc:
            raise ProfileError(f"line {line_number}: {exc}") from None
    return profiles


def _loads_toml(text: str) -> dict[str, Any]:
    if sys.version_info >= (3, 11):
        try:
            return dict(tomllib.loads(text))
        except tomllib.TOMLDecodeError as exc:
            raise ProfileError(f"invalid TOML: {exc}") from None
    return _loads_toml_fallback(text)


def discover_profiles_file(explicit: str | None) -> str | None:
    """Resolve the profiles file: explicit path, local file, or XDG config."""
    if explicit:
        return explicit
    cwd_candidate = Path.cwd() / DEFAULT_FILENAME
    if cwd_candidate.is_file():
        return str(cwd_candidate)
    config_home = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    config_candidate = Path(config_home) / "netscope" / "profiles.toml"
    if config_candidate.is_file():
        return str(config_candidate)
    return None


@dataclass(frozen=True)
class CheckProfile:
    """One validated named endpoint check."""

    name: str
    check_type: str
    host: str
    port: int
    timeout: float = 3.0
    count: int = 3
    description: str = ""
    min_success_rate: float | None = None
    max_jitter_ms: float | None = None
    max_avg_latency_ms: float | None = None
    min_days_cert_valid: float | None = None


def _require_keys(name: str, table: dict[str, Any], check_type: str) -> None:
    allowed = set(COMMON_KEYS)
    if check_type == "tcp-summary":
        allowed |= TCP_SUMMARY_KEYS
    elif check_type == "tls":
        allowed |= TLS_KEYS
    unknown = sorted(set(table) - allowed)
    if unknown:
        raise ProfileError(
            f"profile {name!r}: unsupported option(s) for {check_type}: "
            + ", ".join(unknown)
        )


def _coerce_float(
    name: str, key: str, value: Any, minimum: float, maximum: float
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ProfileError(f"profile {name!r}: {key} must be a number")
    number = float(value)
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ProfileError(
            f"profile {name!r}: {key} must be between {minimum:g} and {maximum:g}"
        )
    return number


def _coerce_int(name: str, key: str, value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ProfileError(f"profile {name!r}: {key} must be an integer")
    if not minimum <= value <= maximum:
        raise ProfileError(
            f"profile {name!r}: {key} must be between {minimum} and {maximum}"
        )
    return value


def _build_profile(name: str, table: dict[str, Any]) -> CheckProfile:
    if not isinstance(table, dict):
        raise ProfileError(f"profile {name!r} must be a TOML table")
    check_type = table.get("type")
    if check_type not in CHECK_TYPES:
        raise ProfileError(
            f"profile {name!r}: type must be one of: {', '.join(CHECK_TYPES)}"
        )
    _require_keys(name, table, check_type)
    host = table.get("host")
    if not isinstance(host, str) or not host.strip():
        raise ProfileError(f"profile {name!r}: host is required")
    target = host.strip()
    if has_control_characters(target):
        raise ProfileError(
            f"profile {name!r}: host must not contain control characters"
        )
    port = _coerce_int(name, "port", table.get("port"), 1, 65535)
    timeout = _coerce_float(name, "timeout", table.get("timeout", 3.0), 0.0, 30.0)
    if timeout <= 0:
        raise ProfileError(f"profile {name!r}: timeout must be greater than 0")
    description = table.get("description", "")
    if not isinstance(description, str):
        raise ProfileError(f"profile {name!r}: description must be a string")
    extra: dict[str, Any] = {}
    if check_type == "tcp-summary":
        extra["count"] = _coerce_int(name, "count", table.get("count", 3), 1, 10)
        if "min_success_rate" in table:
            extra["min_success_rate"] = _coerce_float(
                name, "min_success_rate", table["min_success_rate"], 0.0, 100.0
            )
        if "max_jitter_ms" in table:
            extra["max_jitter_ms"] = _coerce_float(
                name, "max_jitter_ms", table["max_jitter_ms"], 0.0, float("inf")
            )
        if "max_avg_latency_ms" in table:
            extra["max_avg_latency_ms"] = _coerce_float(
                name,
                "max_avg_latency_ms",
                table["max_avg_latency_ms"],
                0.0,
                float("inf"),
            )
    elif check_type == "tls":
        if "min_days_cert_valid" in table:
            extra["min_days_cert_valid"] = _coerce_float(
                name,
                "min_days_cert_valid",
                table["min_days_cert_valid"],
                0.0,
                float("inf"),
            )
    return CheckProfile(
        name=name,
        check_type=check_type,
        host=target,
        port=port,
        timeout=timeout,
        description=description,
        **extra,
    )


def load_profiles(path: str) -> dict[str, CheckProfile]:
    """Load and validate all profiles from a TOML file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise ProfileError(f"profiles file not found: {path}") from None
    except OSError as exc:
        raise ProfileError(f"cannot read profiles file {path}: {exc}") from None
    tables = _loads_toml(text)
    profiles: dict[str, CheckProfile] = {}
    for name, table in tables.items():
        profiles[name] = _build_profile(name, table)
    if not profiles:
        raise ProfileError(f"profiles file {path} defines no profiles")
    logger.debug("Loaded %d profile(s) from %s", len(profiles), path)
    return profiles


def load_profile(path: str, name: str) -> CheckProfile:
    """Load one named profile, raising ProfileError when it is missing."""
    profiles = load_profiles(path)
    try:
        return profiles[name]
    except KeyError:
        raise ProfileError(
            f"profile {name!r} not found; available: {', '.join(sorted(profiles))}"
        ) from None


CheckOutcome = tuple[TCPResult | TCPSummaryResult | TLSResult, int]


def execute_check(profile: CheckProfile) -> CheckOutcome:
    """Run a profile's bounded check, returning (result, structured exit code)."""
    if profile.check_type == "tcp":
        result: TCPResult | TCPSummaryResult | TLSResult = check_tcp(
            profile.host, profile.port, profile.timeout
        )
        return result, 0 if result.ok else 1
    if profile.check_type == "tls":
        tls_result = check_tls(profile.host, profile.port, profile.timeout)
        if not tls_result.ok:
            return tls_result, 1
        violations = evaluate_tls_gates(
            tls_result, min_days_cert_valid=profile.min_days_cert_valid
        )
        return tls_result, 1 if violations else 0
    summary_result = summarize_tcp(
        profile.host, profile.port, profile.count, profile.timeout
    )
    if not summary_result.ok:
        return summary_result, 1
    violations = evaluate_tcp_summary_gates(
        summary_result,
        min_success_rate=profile.min_success_rate,
        max_jitter_ms=profile.max_jitter_ms,
        max_avg_latency_ms=profile.max_avg_latency_ms,
    )
    return summary_result, 1 if violations else 0
