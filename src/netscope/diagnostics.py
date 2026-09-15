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

    Interface names come from the operating system and addresses come from the
    system resolver for the local hostname. The standard library does not offer
    a portable interface-to-address mapping, so NetScope intentionally reports
    these as separate normalized collections rather than guessing associations.
    """
    hostname = socket.gethostname()
    try:
        interfaces = tuple(sorted({name for _, name in socket.if_nameindex()}))
        records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        addresses = tuple(sorted({record[4][0] for record in records}))
    except OSError as exc:
        return InterfaceResult(
            hostname=hostname,
            interfaces=(),
            addresses=(),
            ok=False,
            error=str(exc),
        )

    return InterfaceResult(
        hostname=hostname,
        interfaces=interfaces,
        addresses=addresses,
        ok=True,
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
