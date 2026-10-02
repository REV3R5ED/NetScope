# Changelog

All notable changes to NetScope are documented here. The project follows semantic versioning for portfolio releases.

## [Unreleased]

### Added
- `netscope tls HOST PORT` performs one bounded TLS handshake against an explicit host and port, reporting negotiated protocol/cipher, certificate subject/SANs, issuer, and days until expiry parsed from the peer certificate bytes with a stdlib-only DER reader. The handshake uses an unverified context on purpose so expired or self-signed certificates remain inspectable for monitoring; no application data is exchanged.
- `tls --min-days-cert-valid DAYS` health gate for CI/CD certificate-expiry monitoring, returning exit code 1 when the certificate expires sooner while preserving the full diagnostic report.
- `netscope ping HOST` sends a bounded number of ICMP echo requests (1–10, default 4) to one explicit host via the OS `ping`/`ping6` utility with a hard per-request timeout (max 10s) and per-request round-trip latency measurement, following the same subprocess discipline as `path`.
- Saved TOML endpoint profiles with `netscope check --profile NAME` for cron/CI: named `tcp`, `tcp-summary`, and `tls` checks with thresholds, resolved from `--profiles FILE`, `./netscope-profiles.toml`, or `~/.config/netscope/profiles.toml`, exiting with the same structured codes (0/1/2) as the direct commands. A small built-in TOML parser covers the profile schema on Python 3.10.
- Versioned JSON Schema documents for every command's JSON output, bundled at `src/netscope/schemas/`, printable via `netscope schema COMMAND`, with a CI contract test validating live `--json` output against each schema.
- `tcp-summary --baseline FILE --max-latency-drift-pct PCT` for latency regression detection: compares current average latency against a saved `--json` report and returns exit code 1 when drift exceeds PCT percent, reporting `baseline_avg_latency_ms` and `latency_drift_percent` in human, JSON, and CSV output.
- Structured `logging` for operational failures across diagnostics (DNS, TCP, TLS, ping, path, interfaces, profiles) in addition to the existing structured result error strings.
- Ruff lint/format configuration and strict mypy type checking, enforced in CI alongside pytest.

### Fixed
- TCP ports are now validated at the argparse layer: `netscope tcp` and `netscope tcp-summary` reject out-of-range or non-integer ports as usage errors (exit code 2) before any diagnostic runs.
- `__version__` is now single-sourced from installed package metadata instead of duplicating the pyproject version in `__init__.py`.
- The control-character validation helper is now shared (`netscope.validation`) instead of being inlined in `address.py`, `network.py`, and `dns.py`.
- Address and network-prefix classification now report `240.0.0.0/4` as `reserved` (checked before `private`), matching its RFC 1112 designation.
- Unused imports and import ordering issues across the test suite.

### Security
- TLS diagnostics complete only the handshake and never transmit application data; the unverified context exists solely so monitoring can inspect expired or self-signed certificates.
- Ping diagnostics reject hosts beginning with `-` and control characters before spawning the OS utility, which is invoked without a shell.
- Saved profiles cannot widen any diagnostic bound; they only parameterize the same single-target checks with the same hard caps.

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
