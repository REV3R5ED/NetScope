# Changelog

All notable changes to NetScope are documented here. The project follows semantic versioning for portfolio releases.

## [Unreleased]

## [0.3.0] - 2026-09-17

### Added
- `tcp-summary --require-all` for CI and monitoring health gates that should fail when any bounded connection attempt fails while still emitting the complete human, JSON, or CSV report.
- `tcp-summary --min-success-rate PERCENT` for bounded availability gates that tolerate a controlled amount of intermittent failure while returning non-zero when the measured success rate falls below an explicit 0–100 threshold.
- `tcp-summary --max-jitter-ms MS` and `--max-avg-latency-ms MS` for explicit latency-stability and average-latency health gates that can be combined with availability thresholds.
- `path --require-reached` for automation workflows that need a non-zero exit status when a bounded route trace completes but does not reach its explicit destination; partial diagnostic output is still preserved.
- TCP summaries now report success rate and latency jitter (population standard deviation) in human, JSON, and CSV output for clearer intermittent-connectivity diagnostics.
- Human-readable TCP summaries now include stable, de-duplicated failure reasons when some bounded attempts fail.
- Address-family-aware DNS diagnostics with `netscope dns HOST --family ipv4|ipv6`, preserving legacy behavior when no family is selected.
- Offline `netscope address ADDRESS` classification for literal IPv4/IPv6 addresses, including normalized address, version, scope, and locally calculated reverse pointer.
- `netscope network PREFIX` exposes offline IPv4/IPv6 network-prefix classification through the primary CLI, with human, JSON, and CSV output. It calculates boundaries and address counts arithmetically without enumerating hosts or generating network traffic.

### Fixed
- Local interface diagnostics now reject a blank OS hostname before interface enumeration or resolver lookup, returning a structured failure instead of attempting ambiguous local-name resolution.
- Local interface diagnostics now normalize hostname lookup failures and treat an empty local-host address resolution as a structured failure instead of reporting misleading success with no addresses.
- DNS diagnostics now treat an empty resolver response as a failed lookup instead of reporting a misleading success with no addresses, and normalize broader OS-level resolver failures into structured diagnostic results.
- TCP summaries now validate the host, port, timeout, and bounded attempt count before any connection attempt, so invalid requests report zero attempts instead of repeating the same configuration error as failed network probes.
- TCP and path diagnostics now reject non-finite timeout values such as `NaN` and infinity before any socket connection or traceroute subprocess can run.

### Security
- Diagnostic host inputs reject ASCII control characters before resolver, socket, or traceroute activity.
- CSV exports neutralize text fields that could be interpreted as spreadsheet formulas, including formula prefixes hidden behind leading ASCII or Unicode whitespace, while leaving numeric diagnostic values unchanged.
- Address classification is fully offline: it accepts literal addresses only and performs no DNS lookup, socket connection, probing, scanning, or system mutation.
- Network-prefix classification requires a canonical prefix and remains fully offline: no DNS resolution, sockets, packets, host enumeration, subprocesses, or system mutation.
- Family-specific DNS diagnostics perform resolution only and never connect to returned addresses.

### Release hardening
- CI validates built source and wheel distribution metadata with `twine check` before installing and smoke-testing the wheel.
- Runtime and package metadata are aligned on version `0.3.0` for the first tagged portfolio release.

## [0.2.0] - 2026-09-17

### Added
- Bounded TCP latency summaries with success/failure counts and min/average/max latency.
- Cross-platform route/path diagnostics using the operating system traceroute utility with explicit hop and timeout limits.
- Deterministic CSV exports alongside JSON and human-readable output.
- CLI integration coverage for human-readable, JSON, CSV, failure-exit, and argument-validation behavior.

### Changed
- Local interface inspection now degrades gracefully when interface enumeration is unavailable, while preserving structured local-address visibility.
- Package metadata now explicitly requires Python 3.10+ and exposes the `netscope` console entry point.

### Security
- TCP diagnostics remain restricted to one explicit host and one explicit port per invocation; summary mode is capped at 10 attempts.
- Path diagnostics remain restricted to one explicit host, cap traces at 30 hops and 10 seconds per hop, request numeric output to avoid reverse-DNS lookups, and invoke the platform utility without a shell.

## [0.1.0] - 2026-09-15

### Added
- Initial Python package and command-line interface.
- Read-only local interface/address inspection.
- DNS resolution diagnostics with deterministic normalized output.
- Single-target, single-port TCP connectivity diagnostics with bounded timeouts.
- Human-readable and JSON reporting.
- Unit tests and CI coverage.

### Security
- Project scope explicitly excludes exploit delivery, stealth, credential attacks, persistence, unrestricted offensive scanning, CIDR sweeps, and port-range scanning.
