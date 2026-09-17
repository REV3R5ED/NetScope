# Address-family DNS diagnostics

NetScope provides focused DNS diagnostics for troubleshooting IPv4/IPv6 resolution differences without connecting to any returned address.

## CLI

Use the normal `dns` command for the existing resolver behavior, or add `--family ipv4` / `--family ipv6` when troubleshooting one address family explicitly:

```bash
netscope dns example.com --family ipv4
netscope dns example.com --family ipv6 --json
netscope dns example.com --family ipv4 --csv
```

The family-specific JSON/CSV result includes the selected `family`, making automated reports self-describing. Omitting `--family` deliberately preserves the existing CLI result schema and resolver path for backward compatibility.

## Python API

```python
from netscope.dns import resolve_hostname_family

ipv4 = resolve_hostname_family("example.com", "ipv4")
ipv6 = resolve_hostname_family("example.com", "ipv6")
```

`family` accepts `any` (the library default), `ipv4`, or `ipv6`. The selected family is passed directly to the operating system resolver through `socket.getaddrinfo`, and results are normalized, deduplicated, and sorted for deterministic reporting. `to_dict()` returns JSON-native address lists for downstream automation.

This is useful when an operator needs to distinguish a general DNS failure from an address-family-specific problem, such as an IPv6 record being unavailable while IPv4 resolution remains healthy.

## Safety scope

This diagnostic performs name resolution only. It does not connect to resolved addresses, enumerate neighboring hosts, sweep networks, scan ports, or execute external commands. Input validation rejects empty hostnames and control characters before the resolver is called.
