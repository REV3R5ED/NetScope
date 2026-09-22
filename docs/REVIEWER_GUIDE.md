# NetScope reviewer guide

This guide gives recruiters, maintainers, and security/networking reviewers a short, reproducible path for evaluating NetScope without requiring access to a lab network.

## Five-minute evaluation

### 1. Install and run the quality gate

NetScope requires Python 3.10+.

```bash
python -m pip install -e '.[dev]'
pytest -q
```

The test suite exercises the normalized result models, CLI behavior, defensive bounds, reporting, and cross-platform route handling. CI additionally tests supported Python versions and validates built distribution artifacts.

### 2. Exercise the offline diagnostics

These commands do not generate network traffic:

```bash
netscope address 10.20.30.40
netscope address 2001:db8::1 --json
netscope network 10.20.30.0/24
netscope network 2001:db8::/126 --csv
```

They demonstrate IPv4/IPv6 parsing, normalization, scope classification, deterministic structured output, and rejection of ambiguous network prefixes with host bits set.

### 3. Exercise one bounded active diagnostic

On a network where you are authorized to test the destination:

```bash
netscope dns example.com --json
netscope tcp example.com 443 --timeout 2 --json
netscope tcp-summary example.com 443 --count 3 --min-success-rate 80 --json
```

The TCP commands operate on one explicit endpoint. Summary checks are intentionally capped at 10 attempts and can return a non-zero exit status when a health gate fails while preserving the diagnostic report.

### 4. Inspect the defensive route implementation

```bash
netscope path example.com --max-hops 12 --require-reached --json
```

The path command uses the operating system's `traceroute`/`tracert` utility for one explicit destination, requests numeric output, enforces hop/wait bounds, and invokes the process without a shell. Partial diagnostic output is retained when the destination is not reached.

### 5. Review the engineering signals

Useful areas to inspect include:

- the CLI boundary and validation for explicit single-target operations;
- normalized result models shared across human, JSON, and CSV reporting;
- deterministic exit semantics for CI-oriented health gates;
- subprocess handling for POSIX and Windows route diagnostics;
- tests covering malformed input, hard limits, structured output, and platform differences;
- GitHub Actions coverage across supported Python versions and built artifacts; and
- `SECURITY.md` for vulnerability-reporting and authorization expectations.

## What NetScope demonstrates

NetScope is intentionally a diagnostics toolkit rather than a scanner. It demonstrates practical Python packaging, network troubleshooting, IPv4/IPv6 handling, defensive input validation, bounded socket operations, cross-platform subprocess control, structured reporting, automated tests, and CI/release engineering.

It deliberately excludes unrestricted scanning, CIDR sweeps, port-range enumeration, credential attacks, exploit delivery, stealth, persistence, and destructive behavior.

## Release status

The repository currently describes `v0.3.0` as a release candidate. Do not treat that version as a published release until the corresponding Git tag and GitHub Release exist and the tag-triggered release workflow has validated its artifacts.
