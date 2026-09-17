"""Offline IP network-prefix classification for defensive troubleshooting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress


@dataclass(frozen=True)
class NetworkResult:
    """Normalized, JSON-friendly classification of one IP network prefix."""

    network: str
    version: int | None
    prefix_length: int | None
    network_address: str | None
    last_address: str | None
    num_addresses: int | None
    scope: str | None
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_network(value: str) -> NetworkResult:
    """Classify one IPv4/IPv6 prefix locally without enumerating or probing hosts."""
    if not isinstance(value, str):
        return NetworkResult("", None, None, None, None, None, None, False, "network must be a string")
    target = value.strip()
    if not target:
        return NetworkResult(value, None, None, None, None, None, None, False, "network is required")
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        return NetworkResult(target, None, None, None, None, None, None, False, "network must not contain control characters")
    try:
        network = ipaddress.ip_network(target, strict=True)
    except ValueError:
        return NetworkResult(target, None, None, None, None, None, None, False, "network must be a canonical IPv4 or IPv6 prefix")

    address = network.network_address
    if address.is_unspecified:
        scope = "unspecified"
    elif address.is_loopback:
        scope = "loopback"
    elif address.is_link_local:
        scope = "link-local"
    elif address.is_multicast:
        scope = "multicast"
    elif address.is_private:
        scope = "private"
    elif address.is_reserved:
        scope = "reserved"
    elif address.is_global:
        scope = "global"
    else:
        scope = "special"

    return NetworkResult(
        str(network),
        network.version,
        network.prefixlen,
        str(network.network_address),
        str(network[-1]),
        network.num_addresses,
        scope,
        True,
    )
