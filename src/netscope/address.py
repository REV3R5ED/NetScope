"""Local IP address classification for defensive network troubleshooting."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import ipaddress


@dataclass(frozen=True)
class AddressResult:
    """Normalized, JSON-friendly classification of one literal IP address."""

    address: str
    version: int | None
    scope: str | None
    reverse_pointer: str | None
    ok: bool
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def classify_address(value: str) -> AddressResult:
    """Classify one literal IPv4/IPv6 address without sending network traffic."""
    if not isinstance(value, str):
        return AddressResult("", None, None, None, False, "address must be a string")
    target = value.strip()
    if not target:
        return AddressResult(value, None, None, None, False, "address is required")
    if any(ord(character) < 32 or ord(character) == 127 for character in target):
        return AddressResult(target, None, None, None, False, "address must not contain control characters")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        return AddressResult(target, None, None, None, False, "address must be a literal IPv4 or IPv6 address")

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

    return AddressResult(str(address), address.version, scope, address.reverse_pointer, True)
