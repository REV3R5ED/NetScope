"""Small, bounded defensive network diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import platform
import shutil
import socket
import subprocess
import time


@dataclass(frozen=True)
class DNSResult:
    """Normalized DNS lookup result suitable for CLI or JSON output."""
    hostname: str
    addresses: tuple[str, ...]
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TCPResult:
    """Result of one explicitly requested TCP connection attempt."""
    host: str
    port: int
    ok: bool
    latency_ms: float | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class TCPSummaryResult:
    """Bounded latency summary for repeated checks of one explicit endpoint."""
    host: str
    port: int
    attempts: int
    successes: int
    failures: int
    min_latency_ms: float | None
    avg_latency_ms: float | None
    max_latency_ms: float | None
    ok: bool
    errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class InterfaceResult:
    """Read-only summary of interfaces and addresses visible to the OS."""
    hostname: str
    interfaces: tuple[str, ...]
    addresses: tuple[str, ...]
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class PathResult:
    """Bounded route/path diagnostic produced by the OS traceroute utility."""
    host: str
    max_hops: int
    hops: tuple[str, ...]
    reached: bool
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def resolve_hostname(hostname: str) -> DNSResult:
    """Resolve a hostname using the OS resolver without scanning or probing hosts."""
    target = hostname.strip()
    if not target:
        return DNSResult(hostname=hostname, addresses=(), ok=False, error="hostname is required")
    try:
        records = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return DNSResult(hostname=target, addresses=(), ok=False, error=str(exc))
    addresses = tuple(sorted({record[4][0] for record in records}))
    return DNSResult(hostname=target, addresses=addresses, ok=True)


def inspect_interfaces() -> InterfaceResult:
    """Inspect local network identity without sending network traffic."""
    hostname = socket.gethostname()
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
    return InterfaceResult(hostname, interfaces, addresses, True, interface_warning)


def check_tcp(host: str, port: int, timeout: float = 3.0) -> TCPResult:
    """Attempt one bounded TCP connection to an explicit host and port."""
    target = host.strip()
    if not target:
        return TCPResult(host=host, port=port, ok=False, error="host is required")
    if not 1 <= port <= 65535:
        return TCPResult(host=target, port=port, ok=False, error="port must be between 1 and 65535")
    if timeout <= 0 or timeout > 30:
        return TCPResult(host=target, port=port, ok=False, error="timeout must be greater than 0 and at most 30 seconds")
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
    if not 1 <= count <= 10:
        return TCPSummaryResult(target, port, 0, 0, 0, None, None, None, False, ("count must be between 1 and 10",))
    results = tuple(check_tcp(host, port, timeout) for _ in range(count))
    latencies = tuple(result.latency_ms for result in results if result.ok and result.latency_ms is not None)
    errors = tuple(result.error or "unknown connection error" for result in results if not result.ok)
    successes = len(latencies)
    if not latencies:
        return TCPSummaryResult(target, port, count, 0, count, None, None, None, False, errors)
    return TCPSummaryResult(target, port, count, successes, count - successes, round(min(latencies), 2), round(sum(latencies) / successes, 2), round(max(latencies), 2), True, errors)


def trace_path(host: str, max_hops: int = 15, timeout: float = 2.0) -> PathResult:
    """Run one bounded OS route trace to an explicit destination.

    NetScope never expands targets. Numeric output is requested to avoid extra
    reverse-DNS traffic, arguments are passed without a shell, and hop/time limits
    are capped. The raw per-hop lines are preserved because traceroute formatting
    differs across operating systems.
    """
    target = host.strip()
    if not target:
        return PathResult(host, max_hops, (), False, False, "host is required")
    if target.startswith("-"):
        return PathResult(target, max_hops, (), False, False, "host must not begin with '-'")
    if not 1 <= max_hops <= 30:
        return PathResult(target, max_hops, (), False, False, "max hops must be between 1 and 30")
    if timeout <= 0 or timeout > 10:
        return PathResult(target, max_hops, (), False, False, "timeout must be greater than 0 and at most 10 seconds")

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
