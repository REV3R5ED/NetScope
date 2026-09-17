"""Focused DNS diagnostics for defensive network troubleshooting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import socket


_FAMILIES = {
    "any": socket.AF_UNSPEC,
    "ipv4": socket.AF_INET,
    "ipv6": socket.AF_INET6,
}


@dataclass(frozen=True)
class DNSFamilyResult:
    """Normalized result for an address-family-specific DNS lookup."""

    hostname: str
    family: str
    addresses: tuple[str, ...]
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["addresses"] = list(self.addresses)
        return data


def resolve_hostname_family(hostname: str, family: str = "any") -> DNSFamilyResult:
    """Resolve one hostname while optionally restricting results to IPv4 or IPv6.

    This uses the operating system resolver only. It does not connect to returned
    addresses or perform scanning/probing traffic.
    """
    if not isinstance(hostname, str):
        return DNSFamilyResult("", family if isinstance(family, str) else "", (), False, "hostname must be a string")
    target = hostname.strip()
    if not target:
        return DNSFamilyResult(hostname, family if isinstance(family, str) else "", (), False, "hostname is required")
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        return DNSFamilyResult(target, family if isinstance(family, str) else "", (), False, "hostname must not contain control characters")
    if not isinstance(family, str):
        return DNSFamilyResult(target, "", (), False, "family must be one of: any, ipv4, ipv6")
    normalized_family = family.strip().lower()
    address_family = _FAMILIES.get(normalized_family)
    if address_family is None:
        return DNSFamilyResult(target, normalized_family, (), False, "family must be one of: any, ipv4, ipv6")

    try:
        records = socket.getaddrinfo(target, None, family=address_family, type=socket.SOCK_STREAM)
    except OSError as exc:
        return DNSFamilyResult(target, normalized_family, (), False, str(exc))

    addresses = tuple(sorted({record[4][0] for record in records}))
    if not addresses:
        return DNSFamilyResult(target, normalized_family, (), False, f"resolver returned no {normalized_family} addresses")
    return DNSFamilyResult(target, normalized_family, addresses, True)
