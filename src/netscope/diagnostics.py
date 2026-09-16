"""Small, bounded defensive network diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import platform
import shutil
import socket
import statistics
import subprocess
import time


def _json_native(value: object) -> object:
    """Recursively normalize dataclass values for stable JSON-facing APIs."""
    if isinstance(value, dict):
        return {key: _json_native(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_native(item) for item in value]
    return value


def _result_dict(result: object) -> dict[str, object]:
    normalized = _json_native(asdict(result))
    assert isinstance(normalized, dict)
    return normalized


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


def resolve_hostname(hostname: str) -> DNSResult:
    """Resolve a hostname using the OS resolver without scanning or probing hosts."""
    target = hostname.strip()
    if not target:
        return DNSResult(hostname=hostname, addresses=(), ok=False, error="hostname is required")
    try:
        records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except OSError as exc:
        return DNSResult(hostname=target, addresses=(), ok=False, error=str(exc))
    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses:
        return DNSResult(hostname=target, addresses=(), ok=False, error="resolver returned no addresses")
    return DNSResult(hostname=target, addresses=addresses, ok=True)


def inspect_interfaces() -> InterfaceResult:
    """Inspect local network identity without sending network traffic."""
    try:
        hostname = socket.gethostname()
    except OSError as exc:
        return InterfaceResult("", (), (), False, str(exc))

    interface_warning: str | None = None
    try:
        interfaces = tuple(sorted({name for _, name in socket.if_nameindex()}))
    except AttributeError:
        interfaces = ()
        interface_warning = "interface enumeration unavailable on this platform"
    except OSError as exc:
        return InterfaceResult(hostname, (), (), False, str(exc))
    try:
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = tuple(sorted({record[4][0] for record in records}))
    except OSError as exc:
        return InterfaceResult(hostname, interfaces, (), False, str(exc))
    if not addresses:
        return InterfaceResult(hostname, interfaces, (), False, "local hostname resolved to no addresses")
    return InterfaceResult(hostname, interfaces, addresses, True, interface_warning)


def check_tcp(host: str, port: int, timeout: float = 3.0) -> TCPResult:
    """Attempt one bounded TCP connection to an explicit host and port."""
    target = host.strip()
    if not target:
        return TCPResult(host=host, port=port, ok=False, error="host is required")
    if not 1 <= port <= 65535:
        return TCPResult(host=target, port=port, ok=False, error="port must be between 1 and 65535")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
        return TCPResult(host=target, port=port, ok=False, error="timeout must be finite, greater than 0, and at most 30 seconds")
    started = time.monotonic()
    try:
        with socket.create_connection((target, port), timeout=timeout):
            latency_ms = round((time.monotonic() - started) * 1000, 2)
    except (OSError, socket.timeout) as exc:
        return TCPResult(host=target, port=port, ok=False, error=str(exc))
    return TCPResult(host=target, port=port, ok=True, latency_ms=latency_ms)


def summarize_tcp(host: str, port: int, count: int = 3, timeout: float = 3.0) -> TCPSummaryResult:
    """Summarize up to ten connection attempts to one explicit endpoint."""
    target = host.strip()
    validation_error: str | None = None
    if not target:
        validation_error = "host is required"
    elif not 1 <= port <= 65535:
        validation_error = "port must be between 1 and 65535"
    elif not math.isfinite(timeout) or timeout <= 0 or timeout > 30:
        validation_error = "timeout must be finite, greater than 0, and at most 30 seconds"
    elif not 1 <= count <= 10:
        validation_error = "count must be between 1 and 10"
    if validation_error:
        return TCPSummaryResult(target, port, 0, 0, 0, 0.0, None, None, None, None, False, (validation_error,))

    results = tuple(check_tcp(target, port, timeout) for _ in range(count))
    latencies = tuple(result.latency_ms for result in results if result.ok and result.latency_ms is not None)
    errors = tuple(result.error or "unknown connection error" for result in results if not result.ok)
    successes = len(latencies)
    success_rate = round(successes / count * 100, 2)
    if not latencies:
        return TCPSummaryResult(target, port, count, 0, count, 0.0, None, None, None, None, False, errors)
    jitter = round(statistics.pstdev(latencies), 2) if len(latencies) > 1 else 0.0
    return TCPSummaryResult(target, port, count, successes, count - successes, success_rate, round(min(latencies), 2), round(sum(latencies) / successes, 2), round(max(latencies), 2), jitter, True, errors)


def trace_path(host: str, max_hops: int = 15, timeout: float = 2.0) -> PathResult:
    """Run one bounded OS route trace to an explicit destination."""
    target = host.strip()
    if not target:
        return PathResult(host, max_hops, (), False, False, "host is required")
    if target.startswith("-"):
        return PathResult(target, max_hops, (), False, False, "host must not begin with '-'")
    if not 1 <= max_hops <= 30:
        return PathResult(target, max_hops, (), False, False, "max hops must be between 1 and 30")
    if not math.isfinite(timeout) or timeout <= 0 or timeout > 10:
        return PathResult(target, max_hops, (), False, False, "timeout must be finite, greater than 0, and at most 10 seconds")

    is_windows = platform.system().lower() == "windows"
    executable = "tracert" if is_windows else "traceroute"
    command = [executable, "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), target] if is_windows else [executable, "-n", "-m", str(max_hops), "-w", str(timeout), target]
    if shutil.which(executable) is None:
        return PathResult(target, max_hops, (), False, False, f"{executable} is not available on this system")

    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=min(max_hops * timeout + 5, 305), check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return PathResult(target, max_hops, (), False, False, str(exc))

    hops = tuple(line.strip() for line in completed.stdout.splitlines() if line.strip() and line.lstrip()[:1].isdigit())
    reached = completed.returncode == 0
    error = None if reached else (completed.stderr.strip() or "destination was not reached within the bounded trace")
    return PathResult(target, max_hops, hops, reached, bool(hops) or reached, error)