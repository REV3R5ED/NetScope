# Address-family DNS diagnostics

NetScope now provides a small library-level diagnostic for troubleshooting IPv4/IPv6 resolution differences without connecting to any returned address.

```python
from netscope.dns import resolve_hostname_family

ipv4 = resolve_hostname_family("example.com", "ipv4")
ipv6 = resolve_hostname_family("example.com", "ipv6")
```

`family` accepts `any` (the default), `ipv4`, or `ipv6`. The selected family is passed directly to the operating system resolver through `socket.getaddrinfo`, and results are normalized, deduplicated, and sorted for deterministic reporting. `to_dict()` returns JSON-native address lists for downstream automation.

This is useful when an operator needs to distinguish a general DNS failure from an address-family-specific problem, such as an IPv6 record being unavailable while IPv4 resolution remains healthy.

## Safety scope

This diagnostic performs name resolution only. It does not connect to resolved addresses, enumerate neighboring hosts, sweep networks, scan ports, or execute external commands. Input validation rejects empty hostnames and control characters before the resolver is called.

The existing `netscope dns` CLI behavior remains unchanged; this incremental API is intentionally additive so the v0.2 report schema and command contract stay stable while the capability receives test coverage before any future CLI exposure.
