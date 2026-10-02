# Bounded ICMP ping diagnostics

`netscope ping HOST` sends a bounded number of ICMP echo requests to one
explicit host using the operating system's `ping` (POSIX) or `ping`
(Windows) utility, and `ping6` for IPv6 when the platform provides it. It
follows the same subprocess discipline as `netscope path`: no shell, explicit
arguments, numeric output, and a hard timeout.

## Bounds

- `--count N`: 1–10 echo requests (default 4). Each request is one subprocess
  invocation so round-trip latency can be measured portably.
- `--timeout S`: hard per-request timeout in seconds (maximum 10). The total
  wall time is bounded by `count × timeout` plus small overhead.
- `--family any|ipv4|ipv6`: address family selection (default `any`).

Round-trip latency is measured around each subprocess call and reported as
minimum, average, and maximum, alongside the reply success rate. Hosts
starting with `-` and control characters are rejected before any subprocess
runs.

## Exit codes

`0` when at least one reply is received, `1` when all requests fail or the
check is invalid, `2` for usage errors. JSON and CSV output follow the same
one-record schema as the other diagnostics (`schemas/ping.schema.json`).
