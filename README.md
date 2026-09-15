# NetScope

Defensive network visibility and diagnostics toolkit for operators, IT professionals, and security engineers.

> Status: early development / v0.1 roadmap

## Goals

NetScope aims to make common network diagnostics easy to run, understand, automate, and export without turning into an offensive scanning framework.

Current/planned capabilities include:

- local interface and address visibility
- DNS resolution diagnostics
- bounded single-target TCP connectivity checks
- latency and reachability summaries
- structured JSON output for automation
- clear, human-readable CLI reports

## Quick start

Requires Python 3.10+.

```bash
python -m pip install -e '.[dev]'
netscope dns example.com
netscope dns example.com --json
netscope tcp example.com 443
netscope tcp example.com 443 --timeout 2 --json
pytest -q
```

DNS diagnostics use the operating system resolver and provide deterministic normalized results. TCP diagnostics make exactly one connection attempt to the explicitly supplied host and port, measure connection latency, enforce a maximum 30-second timeout, and support the same structured JSON workflow.

## Safety Scope

NetScope is designed for defensive diagnostics and authorized environments. Development intentionally avoids exploit delivery, stealth, credential attacks, persistence, unrestricted offensive scanning, CIDR sweeps, and port-range scanning. The TCP command accepts one explicit host and one explicit port per invocation.

## Roadmap

### v0.1 — Foundation
- [x] Python package and CLI skeleton
- [x] shared normalized result models
- [ ] interface inspection
- [x] DNS diagnostics
- [x] bounded TCP connectivity checks
- [x] JSON output
- [x] unit tests and CI

### v0.2 — Visibility
- [ ] richer latency summaries
- [ ] route/path diagnostics
- [ ] exportable reports
- [ ] improved cross-platform behavior

## Development

The project is being built incrementally with tests, documentation, and CI as first-class requirements. CI runs the test suite across Python 3.10–3.13.

## License

A project license will be finalized before the first stable release.
