# NetScope

Defensive network visibility and diagnostics toolkit for operators, IT professionals, and security engineers.

> Status: v0.3.0 release candidate; awaiting the first tagged GitHub release

## Goals

NetScope makes common network diagnostics easy to run, understand, automate, and export without turning into an offensive scanning framework.

## Capability matrix

| Command | Purpose | Network activity | Automation output |
| --- | --- | --- | --- |
| `netscope interfaces` | Inspect local interfaces and addresses | Local inspection only | JSON / CSV |
| `netscope address ADDRESS` | Classify one IPv4/IPv6 literal | None | JSON / CSV |
| `netscope network PREFIX` | Classify one canonical IPv4/IPv6 prefix | None | JSON / CSV |
| `netscope dns HOST` | Diagnose name resolution | DNS resolution only | JSON / CSV |
| `netscope tcp HOST PORT` | Test one explicit TCP endpoint | One bounded connection attempt | JSON / CSV |
| `netscope tcp-summary HOST PORT` | Measure bounded endpoint reliability and latency | 1–10 bounded attempts | JSON / CSV + health gates |
| `netscope path HOST` | Inspect the route to one explicit destination | Bounded OS traceroute/tracert | JSON / CSV + reachability gate |

This separation is intentional: offline classification stays fully local, while active diagnostics require an explicit destination and enforce hard bounds. The result is a small toolkit that demonstrates network troubleshooting, cross-platform subprocess handling, typed/structured reporting, defensive guardrails, and CI-oriented exit semantics without broad scanning behavior.

Current capabilities include:

- local interface and address visibility
- offline IPv4/IPv6 literal address and canonical network-prefix classification
- DNS resolution diagnostics with optional IPv4/IPv6 family selection
- bounded single-target TCP connectivity checks
- bounded latency and reachability summaries with CI-friendly health gates
- bounded route/path diagnostics using the operating system traceroute utility
- structured JSON and CSV output for automation and reporting
- clear, human-readable CLI reports

## Quick start

Requires Python 3.10+.

### Install the release candidate

Until the first tagged release is published, install the reviewed `main` branch directly from GitHub:

```bash
python -m pip install "git+https://github.com/REV3R5ED/NetScope.git@main"
netscope --help
netscope interfaces
netscope address 10.20.30.40
netscope dns example.com --json
```

Pin a commit SHA instead of `main` when reproducibility matters. Once `v0.3.0` is tagged, prefer that immutable tag for portfolio demos and operational evaluation.

### Contributor setup

Clone the repository and use an editable install only when developing or running the test suite:

```bash
git clone https://github.com/REV3R5ED/NetScope.git
cd NetScope
python -m pip install -e '.[dev]'
pytest -q
```

A few representative diagnostics:

```bash
netscope address 2001:db8::1 --json
netscope network 10.20.30.0/24
netscope network 2001:db8::/126 --json
netscope dns example.com --family ipv6 --json
netscope tcp example.com 443 --timeout 2 --json
netscope tcp-summary example.com 443 --count 5 --min-success-rate 80 --max-jitter-ms 25 --max-avg-latency-ms 150 --json
netscope path example.com --max-hops 12 --require-reached --json
```

`netscope interfaces` performs read-only local inspection. On Python/platform combinations without `socket.if_nameindex`, it degrades gracefully and still reports resolved local-host addresses with a structured warning.

`netscope address ADDRESS` classifies one literal IPv4 or IPv6 address locally. It performs no DNS lookup or network traffic and reports normalized address, version, scope, and a syntactically calculated reverse pointer.

`netscope network PREFIX` classifies one canonical IPv4 or IPv6 network prefix locally. It reports normalized boundaries, prefix length, address count, and scope using arithmetic only. Host bits are rejected rather than silently normalized, and the command never enumerates addresses or generates network traffic.

DNS diagnostics use the operating system resolver and provide deterministic normalized results. `--family ipv4` or `--family ipv6` narrows troubleshooting to one address family without connecting to any returned address. TCP diagnostics make exactly one connection attempt to the explicitly supplied host and port, measure connection latency, enforce a maximum 30-second timeout, and support the same structured reporting workflow.

`netscope tcp-summary` repeats that same single-endpoint diagnostic a small, explicitly bounded number of times (default 3, maximum 10). It reports successful and failed attempts plus minimum, average, maximum, and jitter latency metrics. Opt-in health gates can require all attempts, enforce minimum success rate, cap jitter, or cap average latency while preserving the complete report before a non-zero threshold exit.

### Route/path diagnostics

`netscope path HOST` invokes the platform's standard `traceroute` (POSIX) or `tracert` (Windows) utility for one explicit destination. It requests numeric output to avoid reverse-DNS lookups, never uses a shell, caps the route at 30 hops and per-hop waiting at 10 seconds, and preserves partial hop output when a destination is not reached. `--require-reached` can make incomplete reachability a non-zero automation result without discarding diagnostic context.

### Exportable reports

Every diagnostic command supports either `--json` or `--csv`. The options are mutually exclusive. CSV exports use a deterministic one-record schema based on the normalized result model; compound fields are compact JSON inside the CSV cell so their structure is preserved.

## Safety Scope

NetScope is designed for defensive diagnostics and authorized environments. Development intentionally avoids exploit delivery, stealth, credential attacks, persistence, unrestricted offensive scanning, CIDR sweeps, and port-range scanning. TCP and path commands accept one explicit host per invocation; TCP commands accept one explicit port. Summary checks are hard-capped at 10 attempts. Path diagnostics are hard-capped at 30 hops and invoke the OS utility without a shell. Interface, literal-address, and network-prefix inspection are read-only; address and network-prefix classification are fully offline and never enumerate hosts.

## Roadmap

### v0.1 — Foundation
- [x] Python package and CLI skeleton
- [x] shared normalized result models
- [x] interface inspection
- [x] DNS diagnostics
- [x] bounded TCP connectivity checks
- [x] JSON output
- [x] unit tests and CI

### v0.2 — Visibility
- [x] richer latency summaries
- [x] route/path diagnostics
- [x] exportable reports
- [x] improved cross-platform behavior

### v0.3 — Operational diagnostics
- [x] CI-friendly TCP health gates
- [x] address-family-specific DNS diagnostics
- [x] offline IPv4/IPv6 address classification
- [x] offline canonical IPv4/IPv6 network-prefix classification and CLI reporting
- [x] hardened input and CSV reporting behavior
- [x] validate built release artifacts in CI
- [ ] publish tagged portfolio release

## Development

The v0.3.0 release candidate aligns package/runtime version metadata with the code currently on `main` and documents the operational diagnostics as a distinct release boundary. CI covers Python 3.10–3.13 and validates the built source distribution and wheel before release. The remaining release step is to publish the first `v0.3.0` tag/GitHub Release only after the exact candidate commit passes those checks.

See [CHANGELOG.md](CHANGELOG.md) for release notes and safety-relevant changes.

## License

NetScope is released under the [MIT License](LICENSE).
