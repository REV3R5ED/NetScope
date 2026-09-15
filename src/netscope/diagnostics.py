"""Small, bounded defensive network diagnostics."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import socket


@dataclass(frozen=True)
class DNSResult:
    """Normalized DNS lookup result suitable for CLI or JSON output."""

    hostname: str
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
