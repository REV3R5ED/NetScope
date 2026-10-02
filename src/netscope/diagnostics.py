"""Small, bounded defensive network diagnostics."""

from __future__ import annotations

import logging
import math
import platform
import shutil
import socket
import statistics
import subprocess
import time
from dataclasses import asdict, dataclass
from typing import Any

from .validation import has_control_characters

logger = logging.getLogger(__name__)

MAX_TCP_TIMEOUT = 30.0
MAX_PING_TIMEOUT = 10.0
MAX_PING_COUNT = 10


def _json_native(value: object) -> object:
    """Recursively normalize dataclass values for stable JSON-facing APIs."""
    if isinstance(value, dict):
        return {key: _json_native(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_native(item) for item in value]
    return value


def _result_dict(result: Any) -> dict[str, object]:
    normalized = _json_native(asdict(result))
    assert isinstance(normalized, dict)
    return normalized


def _normalized_host(host: object) -> str | None:
    """Return a trimmed host string, rejecting non-string API input."""
    return host.strip() if isinstance(host, str) else None


def _valid_port(port: object) -> bool:
    return isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535


def _valid_timeout(timeout: object, maximum: float) -> bool:
    return (
        isinstance(timeout, (int, float))
        and not isinstance(timeout, bool)
        and math.isfinite(timeout)
        and 0 < timeout <= maximum
    )


def _resolver_addresses(records: Any) -> tuple[str, ...]:
    """Extract sorted unique address strings from getaddrinfo records."""
    return tuple(sorted({str(record[4][0]) for record in records}))


@dataclass(frozen=True)
class DNSResult:
    hostname: str
    addresses: tuple[str, ...]
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


@dataclass(frozen=True)
class TCPResult:
    host: str
    port: int
    ok: bool
    latency_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


@dataclass(frozen=True)
class TCPSummaryResult:
    host: str
    port: int
    attempts: int
    successes: int
    failures: int
    success_rate_percent: float
    min_latency_ms: float | None
    avg_latency_ms: float | None
    max_latency_ms: float | None
    jitter_ms: float | None
    ok: bool
    errors: tuple[str, ...] = ()
    baseline_avg_latency_ms: float | None = None
    latency_drift_percent: float | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


@dataclass(frozen=True)
class InterfaceResult:
    hostname: str
    interfaces: tuple[str, ...]
    addresses: tuple[str, ...]
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


@dataclass(frozen=True)
class PathResult:
    host: str
    max_hops: int
    hops: tuple[str, ...]
    reached: bool
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


@dataclass(frozen=True)
class PingResult:
    host: str
    count: int
    successes: int
    failures: int
    success_rate_percent: float
    min_latency_ms: float | None
    avg_latency_ms: float | None
    max_latency_ms: float | None
    ok: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return _result_dict(self)


def resolve_hostname(hostname: str) -> DNSResult:
    """Resolve a hostname using the OS resolver without scanning or probing hosts."""
    target = _normalized_host(hostname)
    if target is None:
        logger.debug("DNS resolution rejected: hostname must be a string")
        return DNSResult(
            hostname="", addresses=(), ok=False, error="hostname must be a string"
        )
    if not target:
        logger.debug("DNS resolution rejected: hostname is required")
        return DNSResult(
            hostname=hostname, addresses=(), ok=False, error="hostname is required"
        )
    if has_control_characters(target):
        logger.debug("DNS resolution rejected for %r: control characters", target)
        return DNSResult(
            hostname=target,
            addresses=(),
            ok=False,
            error="hostname must not contain control characters",
        )
    try:
        records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        logger.warning("DNS resolution failed for %s: %s", target, exc)
        return DNSResult(hostname=target, addresses=(), ok=False, error=str(exc))
    addresses = _resolver_addresses(records)
    if not addresses:
        logger.warning("DNS resolver returned no addresses for %s", target)
        return DNSResult(
            hostname=target,
            addresses=(),
            ok=False,
            error="resolver returned no addresses",
        )
    return DNSResult(hostname=target, addresses=addresses, ok=True)


def inspect_interfaces() -> InterfaceResult:
    """Inspect local network identity without sending network traffic."""
    try:
        hostname = socket.gethostname().strip()
    except OSError as exc:
        logger.warning("Interface inspection failed reading local hostname: %s", exc)
        return InterfaceResult("", (), (), False, str(exc))
    if not hostname:
        logger.warning("Interface inspection failed: local hostname is unavailable")
        return InterfaceResult("", (), (), False, "local hostname is unavailable")
    interface_warning: str | None = None
    try:
        interfaces = tuple(sorted({name for _, name in socket.if_nameindex()}))
    except AttributeError:
        interfaces = ()
        interface_warning = "interface enumeration unavailable on this platform"
        logger.warning("Interface enumeration unavailable on this platform")
    except OSError as exc:
        logger.warning("Interface enumeration failed: %s", exc)
        return InterfaceResult(hostname, (), (), False, str(exc))
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = _resolver_addresses(records)
    except OSError as exc:
        logger.warning("Local hostname resolution failed for %s: %s", hostname, exc)
        return InterfaceResult(hostname, interfaces, (), False, str(exc))
    if not addresses:
        logger.warning("Local hostname %s resolved to no addresses", hostname)
        return InterfaceResult(
            hostname, interfaces, (), False, "local hostname resolved to no addresses"
        )
    return InterfaceResult(hostname, interfaces, addresses, True, interface_warning)


def check_tcp(host: str, port: int, timeout: float = 3.0) -> TCPResult:
    """Attempt one bounded TCP connection to an explicit host and port."""
    target = _normalized_host(host)
    if target is None:
        logger.debug("TCP check rejected: host must be a string")
        return TCPResult(host="", port=port, ok=False, error="host must be a string")
    if not target:
        logger.debug("TCP check rejected: host is required")
        return TCPResult(host=host, port=port, ok=False, error="host is required")
    if has_control_characters(target):
        logger.debug("TCP check rejected for %r: control characters", target)
        return TCPResult(
            host=target,
            port=port,
            ok=False,
            error="host must not contain control characters",
        )
    if not _valid_port(port):
        logger.debug("TCP check rejected for %s: invalid port %r", target, port)
        return TCPResult(
            host=target, port=port, ok=False, error="port must be between 1 and 65535"
        )
    if not _valid_timeout(timeout, MAX_TCP_TIMEOUT):
        logger.debug("TCP check rejected for %s: invalid timeout %r", target, timeout)
        return TCPResult(
            host=target,
            port=port,
            ok=False,
            error="timeout must be finite, greater than 0, and at most 30 seconds",
        )
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            latency_ms = round((time.monotonic() - started) * 1000, 2)
    except (TimeoutError, OSError) as exc:
        logger.warning("TCP connection to %s:%s failed: %s", target, port, exc)
        return TCPResult(host=target, port=port, ok=False, error=str(exc))
    return TCPResult(host=target, port=port, ok=True, latency_ms=latency_ms)


def summarize_tcp(
    host: str, port: int, count: int = 3, timeout: float = 3.0
) -> TCPSummaryResult:
    """Summarize up to ten connection attempts to one explicit endpoint."""
    target = _normalized_host(host)
    validation_error: str | None = None
    if target is None:
        target = ""
        validation_error = "host must be a string"
    elif not target:
        validation_error = "host is required"
    elif has_control_characters(target):
        validation_error = "host must not contain control characters"
    elif not _valid_port(port):
        validation_error = "port must be between 1 and 65535"
    elif not _valid_timeout(timeout, MAX_TCP_TIMEOUT):
        validation_error = (
            "timeout must be finite, greater than 0, and at most 30 seconds"
        )
    elif not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10:
        validation_error = "count must be between 1 and 10"
    if validation_error:
        logger.debug("TCP summary rejected for %r: %s", target, validation_error)
        return TCPSummaryResult(
            target,
            port,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            None,
            False,
            (validation_error,),
        )
    results = tuple(check_tcp(target, port, timeout) for _ in range(count))
    latencies = tuple(
        result.latency_ms
        for result in results
        if result.ok and result.latency_ms is not None
    )
    errors = tuple(
        result.error or "unknown connection error"
        for result in results
        if not result.ok
    )
    successes = len(latencies)
    success_rate = round(successes / count * 100, 2)
    if not latencies:
        logger.warning(
            "TCP summary for %s:%s failed: no successful connections", target, port
        )
        return TCPSummaryResult(
            target, port, count, 0, count, 0.0, None, None, None, None, False, errors
        )
    jitter = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0
    return TCPSummaryResult(
        target,
        port,
        count,
        successes,
        count - successes,
        success_rate,
        round(min(latencies), 2),
        round(sum(latencies) / successes, 2),
        round(max(latencies), 2),
        jitter,
        True,
        errors,
    )


def evaluate_tcp_summary_gates(
    result: TCPSummaryResult,
    *,
    require_all: bool = False,
    min_success_rate: float | None = None,
    max_jitter_ms: float | None = None,
    max_avg_latency_ms: float | None = None,
) -> tuple[str, ...]:
    """Return human-readable descriptions of violated tcp-summary health gates.

    The caller decides the exit code; the complete diagnostic report is always
    preserved regardless of gate violations.
    """
    violations: list[str] = []
    if require_all and result.failures:
        violations.append(
            f"{result.failures} of {result.attempts} bounded attempts failed"
        )
    if min_success_rate is not None and result.success_rate_percent < min_success_rate:
        violations.append(
            f"success rate {result.success_rate_percent:.2f}% "
            f"is below minimum {min_success_rate:g}%"
        )
    if (
        max_jitter_ms is not None
        and result.jitter_ms is not None
        and result.jitter_ms > max_jitter_ms
    ):
        violations.append(
            f"jitter {result.jitter_ms:.2f} ms exceeds maximum {max_jitter_ms:g} ms"
        )
    if (
        max_avg_latency_ms is not None
        and result.avg_latency_ms is not None
        and result.avg_latency_ms > max_avg_latency_ms
    ):
        violations.append(
            f"average latency {result.avg_latency_ms:.2f} ms "
            f"exceeds maximum {max_avg_latency_ms:g} ms"
        )
    if violations:
        logger.warning(
            "TCP summary health gates violated for %s:%s: %s",
            result.host,
            result.port,
            "; ".join(violations),
        )
    return tuple(violations)


def latency_drift_percent(current_avg_ms: float, baseline_avg_ms: float) -> float:
    """Return the signed percentage drift of current average latency vs baseline."""
    return round((current_avg_ms - baseline_avg_ms) / baseline_avg_ms * 100, 2)


def load_latency_baseline(path: str) -> float:
    """Load a saved tcp-summary JSON report and return its average latency.

    Raises ValueError with a human-readable message when the file is missing,
    unreadable, or does not contain a usable baseline average latency.
    """
    import json

    try:
        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
    except FileNotFoundError:
        raise ValueError(f"baseline file not found: {path}") from None
    except OSError as exc:
        raise ValueError(f"cannot read baseline file {path}: {exc}") from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"baseline file {path} is not valid JSON: {exc}") from None
    if not isinstance(payload, dict):
        raise ValueError(f"baseline file {path} must contain a JSON object")
    baseline = payload.get("avg_latency_ms")
    if not isinstance(baseline, (int, float)) or isinstance(baseline, bool):
        raise ValueError(
            f"baseline file {path} has no usable avg_latency_ms for drift comparison"
        )
    baseline_value = float(baseline)
    if not math.isfinite(baseline_value) or baseline_value <= 0:
        raise ValueError(
            f"baseline file {path} has no usable avg_latency_ms for drift comparison"
        )
    return baseline_value


def trace_path(host: str, max_hops: int = 15, timeout: float = 2.0) -> PathResult:
    """Run one bounded OS route trace to an explicit destination."""
    target = _normalized_host(host)
    if target is None:
        logger.debug("Path trace rejected: host must be a string")
        return PathResult("", max_hops, (), False, False, "host must be a string")
    if not target:
        logger.debug("Path trace rejected: host is required")
        return PathResult(host, max_hops, (), False, False, "host is required")
    if has_control_characters(target):
        logger.debug("Path trace rejected for %r: control characters", target)
        return PathResult(
            target,
            max_hops,
            (),
            False,
            False,
            "host must not contain control characters",
        )
    if target.startswith("-"):
        logger.debug("Path trace rejected for %r: leading dash", target)
        return PathResult(
            target, max_hops, (), False, False, "host must not begin with '-'"
        )
    if (
        not isinstance(max_hops, int)
        or isinstance(max_hops, bool)
        or not 1 <= max_hops <= 30
    ):
        logger.debug(
            "Path trace rejected for %s: invalid max hops %r", target, max_hops
        )
        return PathResult(
            target, max_hops, (), False, False, "max hops must be between 1 and 30"
        )
    if not _valid_timeout(timeout, MAX_PING_TIMEOUT):
        logger.debug("Path trace rejected for %s: invalid timeout %r", target, timeout)
        return PathResult(
            target,
            max_hops,
            (),
            False,
            False,
            "timeout must be finite, greater than 0, and at most 10 seconds",
        )
    is_windows = platform.system().lower() == "windows"
    executable = "tracert" if is_windows else "traceroute"
    command = (
        [executable, "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target]
        if is_windows
        else [executable, "-n", "-m", str(max_hops), "-w", str(timeout), target]
    )
    if shutil.which(executable) is None:
        logger.warning(
            "Path trace failed: %s is not available on this system", executable
        )
        return PathResult(
            target,
            max_hops,
            (),
            False,
            False,
            f"{executable} is not available on this system",
        )
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=min(max_hops * timeout + 5, 305),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logger.warning("Path trace to %s failed: %s", target, exc)
        return PathResult(target, max_hops, (), False, False, str(exc))
    hops = tuple(
        line.strip()
        for line in completed.stdout.splitlines()
        if line.strip() and line.lstrip()[:1].isdigit()
    )
    reached = completed.returncode == 0
    error = (
        None
        if reached
        else (
            completed.stderr.strip()
            or "destination was not reached within the bounded trace"
        )
    )
    if not reached:
        logger.warning(
            "Path trace to %s did not reach the destination: %s", target, error
        )
    return PathResult(target, max_hops, hops, reached, bool(hops) or reached, error)


def _ping_command(target: str, timeout: float, family: str) -> tuple[str, ...] | None:
    """Build the OS ping invocation for one bounded ICMP echo request.

    Returns None when no suitable ping utility is available.
    """
    is_windows = platform.system().lower() == "windows"
    if is_windows:
        executable = "ping"
        command = [executable, "-n", "1", "-w", str(int(timeout * 1000))]
        if family == "ipv4":
            command.append("-4")
        elif family == "ipv6":
            command.append("-6")
        command.append(target)
        return tuple(command) if shutil.which(executable) else None
    if family == "ipv6" and shutil.which("ping6"):
        return ("ping6", "-n", "-c", "1", target)
    if shutil.which("ping") is None:
        return None
    command = ["ping", "-n", "-c", "1"]
    if family == "ipv4":
        command.append("-4")
    elif family == "ipv6":
        command.append("-6")
    command.append(target)
    return tuple(command)


def ping_host(
    host: str, count: int = 4, timeout: float = 2.0, family: str = "any"
) -> PingResult:
    """Send a bounded number of ICMP echo requests to one explicit host.

    Each echo request runs as one OS ``ping`` subprocess invocation with a hard
    per-request timeout, mirroring how ``trace_path`` delegates to the OS
    utility without a shell. Round-trip latency is measured around each
    subprocess call.
    """
    target = _normalized_host(host)
    if target is None:
        logger.debug("Ping rejected: host must be a string")
        return PingResult(
            "", 0, 0, 0, 0.0, None, None, None, False, ("host must be a string",)
        )
    if not target:
        logger.debug("Ping rejected: host is required")
        return PingResult(
            host, 0, 0, 0, 0.0, None, None, None, False, ("host is required",)
        )
    if has_control_characters(target):
        logger.debug("Ping rejected for %r: control characters", target)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            ("host must not contain control characters",),
        )
    if target.startswith("-"):
        logger.debug("Ping rejected for %r: leading dash", target)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            ("host must not begin with '-'",),
        )
    if (
        not isinstance(count, int)
        or isinstance(count, bool)
        or not 1 <= count <= MAX_PING_COUNT
    ):
        logger.debug("Ping rejected for %s: invalid count %r", target, count)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            (f"count must be between 1 and {MAX_PING_COUNT}",),
        )
    if not _valid_timeout(timeout, MAX_PING_TIMEOUT):
        logger.debug("Ping rejected for %s: invalid timeout %r", target, timeout)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            ("timeout must be finite, greater than 0, and at most 10 seconds",),
        )
    normalized_family = family.strip().lower() if isinstance(family, str) else ""
    if normalized_family not in ("any", "ipv4", "ipv6"):
        logger.debug("Ping rejected for %s: invalid family %r", target, family)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            ("family must be one of: any, ipv4, ipv6",),
        )
    command = _ping_command(target, timeout, normalized_family)
    if command is None:
        logger.warning("Ping failed for %s: no ping utility available", target)
        return PingResult(
            target,
            0,
            0,
            0,
            0.0,
            None,
            None,
            None,
            False,
            ("no ping utility is available on this system",),
        )
    latencies: list[float] = []
    errors: list[str] = []
    for attempt in range(1, count + 1):
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=timeout, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(str(exc) or f"request {attempt} timed out")
            logger.warning("Ping request %d to %s failed: %s", attempt, target, exc)
            continue
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        if completed.returncode == 0:
            latencies.append(elapsed_ms)
        else:
            detail = completed.stderr.strip() or completed.stdout.strip() or "no reply"
            errors.append(detail)
            logger.warning("Ping request %d to %s failed: %s", attempt, target, detail)
    successes = len(latencies)
    success_rate = round(successes / count * 100, 2)
    if not latencies:
        logger.warning("Ping to %s failed: no replies received", target)
        return PingResult(
            target, count, 0, count, 0.0, None, None, None, False, tuple(errors)
        )
    return PingResult(
        target,
        count,
        successes,
        count - successes,
        success_rate,
        round(min(latencies), 2),
        round(sum(latencies) / successes, 2),
        round(max(latencies), 2),
        True,
        tuple(errors),
    )
