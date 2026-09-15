# NetScope

Defensive network visibility and diagnostics toolkit for operators, IT professionals, and security engineers.

> Status: v0.2 visibility milestone feature-complete; release hardening in progress

## Goals

NetScope makes common network diagnostics easy to run, understand, automate, and export without turning into an offensive scanning framework.

Current capabilities include:

- local interface and address visibility
- DNS resolution diagnostics
- bounded single-target TCP connectivity checks
- bounded latency and reachability summaries
- bounded route/path diagnostics using the operating system traceroute utility
- structured JSON and CSV output for automation and reporting
- clear, human-readable CLI reports

## Quick start

Requires Python 3.10+.

```bash
python -m pip install -e '.[dev]'
netscope interfaces
netscope interfaces --json
netscope dns example.com
netscope dns example.com --csv
netscope tcp example.com 443 --timeout 2 --json
netscope tcp-summary example.com 443 --count 5
netscope tcp-summary example.com 443 --count 5 --csv
netscope path example.com --max-hops 12
netscope path example.com --max-hops 12 --json
pytest -q
```

`netscope interfaces` performs read-only local inspection. On Python/platform combinations without `socket.if_nameindex`, it degrades gracefully and still reports resolved local-host addresses with a structured warning.

DNS diagnostics use the operating system resolver and provide deterministic normalized results. TCP diagnostics make exactly one connection attempt to the explicitly supplied host and port, measure connection latency, enforce a maximum 30-second timeout, and support the same structured reporting workflow.

`netscope tcp-summary` repeats that same single-endpoint diagnostic a small, explicitly bounded number of times (default 3, maximum 10). It reports successful and failed attempts plus minimum, average, and maximum connection latency.

### Route/path diagnostics

`netscope path HOST` invokes the platform's standard `traceroute` (POSIX) or `tracert` (Windows) utility for one explicit destination. It requests numeric output to avoid reverse-DNS lookups, never uses a shell, caps the route at 30 hops and per-hop waiting at 10 seconds, and preserves partial hop output when a destination is not reached. The command fails clearly when the platform utility is unavailable. Raw hop lines are retained in structured output because traceroute formatting varies across operating systems.

### Exportable reports

Every diagnostic command supports either `--json` or `--csv`. The options are mutually exclusive. CSV exports use a deterministic one-record schema based on the normalized result model; compound fields are compact JSON inside the CSV cell so their structure is preserved.

## Safety Scope

NetScope is designed for defensive diagnostics and authorized environments. Development intentionally avoids exploit delivery, stealth, credential attacks, persistence, unrestricted offensive scanning, CIDR sweeps, and port-range scanning. TCP and path commands accept one explicit host per invocation; TCP commands accept one explicit port. Summary checks are hard-capped at 10 attempts. Path diagnostics are hard-capped at 30 hops and invoke the OS utility without a shell. Interface inspection is local and sends no probing traffic.

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

### Next — Release hardening
- [x] expand CLI integration tests
- [ ] add changelog and release notes
- [ ] finalize project license
- [ ] prepare tagged portfolio release

## Development

The v0.2 visibility milestone is feature-complete. Release hardening now includes integration coverage across the public CLI surface, including human-readable, JSON, CSV, failure-exit, and argument-validation behavior. CI runs the full test suite across Python 3.10–3.13. Remaining work is documentation/release polish, license selection, and tagged-release preparation.

## License

A project license will be finalized before the first stable release.
