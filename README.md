# NetScope

Defensive network visibility and diagnostics toolkit for operators, IT professionals, and security engineers.

> Status: v0.1 foundation feature-complete; v0.2 visibility work in progress

## Goals

NetScope aims to make common network diagnostics easy to run, understand, automate, and export without turning into an offensive scanning framework.

Current/planned capabilities include:

- local interface and address visibility
- DNS resolution diagnostics
- bounded single-target TCP connectivity checks
- bounded latency and reachability summaries
- structured JSON output for automation
- clear, human-readable CLI reports

## Quick start

Requires Python 3.10+.

```bash
python -m pip install -e '.[dev]'
netscope interfaces
netscope interfaces --json
netscope dns example.com
netscope dns example.com --json
netscope tcp example.com 443
netscope tcp example.com 443 --timeout 2 --json
netscope tcp-summary example.com 443 --count 5
netscope tcp-summary example.com 443 --count 5 --json
pytest -q
```

`netscope interfaces` performs read-only local inspection: it reports the OS-visible interface names, local hostname, and addresses returned for that hostname by the system resolver. Because Python's standard library does not provide a portable interface-to-address mapping, NetScope deliberately reports interface names and host addresses as separate collections rather than guessing an association.

DNS diagnostics use the operating system resolver and provide deterministic normalized results. TCP diagnostics make exactly one connection attempt to the explicitly supplied host and port, measure connection latency, enforce a maximum 30-second timeout, and support the same structured JSON workflow.

`netscope tcp-summary` repeats that same single-endpoint diagnostic a small, explicitly bounded number of times (default 3, maximum 10). It reports successful and failed attempts plus minimum, average, and maximum connection latency. Partial failures remain visible in both terminal and JSON output rather than being discarded.

## Safety Scope

NetScope is designed for defensive diagnostics and authorized environments. Development intentionally avoids exploit delivery, stealth, credential attacks, persistence, unrestricted offensive scanning, CIDR sweeps, and port-range scanning. TCP commands accept one explicit host and one explicit port per invocation. Summary checks are hard-capped at 10 attempts and never expand targets or ports. Interface inspection is local and sends no probing traffic.

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
- [ ] route/path diagnostics
- [ ] exportable reports
- [ ] improved cross-platform behavior

## Development

The v0.1 feature foundation is complete and v0.2 visibility work has started. Current work focuses on bounded diagnostic depth, portability, CLI ergonomics, and release readiness. CI runs the test suite across Python 3.10–3.13.

## License

A project license will be finalized before the first stable release.
