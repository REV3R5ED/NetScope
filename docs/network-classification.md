# Offline network-prefix classification

`netscope.network.classify_network()` parses and summarizes one canonical IPv4 or IPv6 network prefix entirely offline.

The result reports the normalized prefix, IP version, prefix length, network address, last address, address count, and a high-level scope classification. This is useful when validating subnet documentation, inventory data, firewall change plans, or incident notes without generating traffic.

```python
from netscope.network import classify_network

result = classify_network("10.20.30.0/24")
print(result.to_dict())
```

## Safety boundary

This helper performs parsing and arithmetic only. It does **not** enumerate hosts, resolve DNS, open sockets, send packets, probe ports, or invoke operating-system networking commands. Non-canonical inputs with host bits set (for example `10.20.30.40/24`) are rejected instead of silently rewritten, which helps surface configuration mistakes.

The address count is calculated mathematically by Python's standard-library `ipaddress` module, so even very large IPv6 prefixes are handled without allocating or iterating over their address space.
