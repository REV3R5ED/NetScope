# NetScope

Defensive network visibility and diagnostics toolkit for operators, IT professionals, and security engineers.

> Status: early development / v0.1 roadmap

## Goals

NetScope aims to make common network diagnostics easy to run, understand, automate, and export without turning into an offensive scanning framework.

Current/planned capabilities include:

- local interface and address visibility
- DNS resolution diagnostics
- bounded TCP connectivity checks
- latency and reachability summaries
- structured JSON output for automation
- clear, human-readable CLI reports

## Quick start

Requires Python 3.10+.

```bash
python -m pip install -e '.[dev]'
netscope dns example.com
netscope dns example.com --json
pytest -q
```

The first implemented diagnostic uses the operating system resolver, deduplicates returned IPv4/IPv6 addresses, and provides deterministic structured results for scripts and tests.

## Safety Scope

NetScope is designed for defensive diagnostics and authorized environments. Development intentionally avoids exploit delivery, stealth, credential attacks, persistence, or unrestricted offensive scanning.

## Roadmap

### v0.1 — Foundation
- [x] Python package and CLI skeleton
- [x] shared result model (initial DNS result model)
- [ ] interface inspection
- [x] DNS diagnostics
- [ ] bounded TCP connectivity checks
- [x] JSON output (DNS command)
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
