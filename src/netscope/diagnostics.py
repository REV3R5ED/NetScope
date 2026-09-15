"""Small, bounded defensive network diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import socket
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
    """Inspect local network identity without sending network traffic.

    Some Python/platform combinations do not expose ``socket.if_nameindex``.
    In that case NetScope still reports local-host addresses instead of failing
    the entire read-only diagnostic. OS errors from an available interface API
    remain explicit failures rather than being silently hidden.
    """
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

    return InterfaceResult(
        hostname=hostname,
        interfaces=interfaces,
        addresses=addresses,
        ok=True,
        error=interface_warning,
    )


def check_tcp(host: str, port: int, timeout: float = 3.0) -> TCPResult:
    """Attempt one bounded TCP connection to an explicit host and port.

    This intentionally performs a single connection attempt rather than accepting
    ranges, CIDRs, or port lists, keeping the diagnostic useful without becoming
    a scanning primitive.
    """
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
    """Summarize up to ten connection attempts to one explicit endpoint.

    The small hard cap keeps this diagnostic bounded. It never expands a host,
    network, or port range and delegates all endpoint validation to ``check_tcp``.
    """
    target = host.strip()
    if not 1 <= count <= 10:
        return TCPSummaryResult(target, port, 0, 0, 0, None, None, None, False, ("count must be between 1 and 10",))

    results = tuple(check_tcp(host, port, timeout) for _ in range(count))
    latencies = tuple(result.latency_ms for result in results if result.ok and result.latency_ms is not None)
    errors = tuple(result.error or "unknown connection error" for result in results if not result.ok)
    successes = len(latencies)

    if not latencies:
        return TCPSummaryResult(target, port, count, 0, count, None, None, None, False, errors)

    return TCPSummaryResult(
        host=target,
        port=port,
        attempts=count,
        successes=successes,
        failures=count - successes,
        min_latency_ms=round(min(latencies), 2),
        avg_latency_ms=round(sum(latencies) / successes, 2),
        max_latency_ms=round(max(latencies), 2),
        ok=True,
        errors=errors,
    )
