# Changelog

All notable changes to NetScope are documented here. The project follows semantic versioning for portfolio releases.

## [Unreleased]

### Added
- `tcp-summary --require-all` for CI and monitoring health gates that should fail when any bounded connection attempt fails while still emitting the complete human, JSON, or CSV report.
- `path --require-reached` for automation workflows that need a non-zero exit status when a bounded route trace completes but does not reach its explicit destination; partial diagnostic output is still preserved.
- TCP summaries now report success rate and latency jitter (population standard deviation) in human, JSON, and CSV output for clearer intermittent-connectivity diagnostics.

## [0.2.0] - 2026-09-15

### Added
- Bounded TCP latency summaries with success/failure counts and min/average/max latency.
- Cross-platform route/path diagnostics using the operating system traceroute utility with explicit hop and timeout limits.
- Deterministic CSV exports alongside JSON and human-readable output.
- CLI integration coverage for human-readable, JSON, CSV, failure-exit, and argument-validation behavior.

### Improved
- Local interface inspection now degrades gracefully when `socket.if_nameindex` is unavailable while retaining local address visibility.
- Structured diagnostic results are consistent across commands for automation and reporting workflows.
- Safety boundaries are documented for single-target TCP and path diagnostics.

### Safety
- No CIDR sweeps, port-range scanning, exploit delivery, credential attacks, persistence, or stealth functionality.
- TCP diagnostics remain limited to one explicit host and port per invocation; summaries are capped at 10 attempts.
- Path diagnostics remain limited to one explicit destination, at most 30 hops, bounded per-hop waits, and shell-free subprocess execution.

## [0.1.0] - 2026-09-15

### Added
- Initial Python package and `netscope` CLI.
- Local interface/address inspection.
- DNS resolution diagnostics.
- Bounded single-target TCP connectivity checks.
- Normalized result models and JSON output.
- Unit tests and CI across supported Python versions.
