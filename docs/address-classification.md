# Local address classification

`netscope address ADDRESS` classifies one literal IPv4 or IPv6 address entirely locally. It is useful when reviewing interface output, firewall records, routing notes, or incident evidence and you need a quick normalized description of an address without generating network traffic.

```bash
netscope address 10.20.30.40
netscope address 2001:db8::1 --json
netscope address ::1 --csv
```

The result includes the normalized address, IP version, scope, and syntactic reverse-DNS pointer. Scope values distinguish `unspecified`, `loopback`, `link-local`, `multicast`, `private`, `reserved`, `global`, and other special addresses.

The command accepts literal addresses only. Hostnames are rejected rather than resolved, and the reverse pointer is calculated locally with Python's standard `ipaddress` module; no PTR query is sent. JSON and CSV use the same normalized result model as other NetScope diagnostics.

## Safety

This diagnostic is read-only and offline. It opens no sockets, sends no packets, performs no DNS lookups, scans no ports or address ranges, and modifies no system state.
