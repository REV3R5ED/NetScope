# Saved profiles and scheduled checks

`netscope check --profile NAME` executes a named endpoint check stored in a
TOML profiles file. It is designed for cron jobs and CI pipelines: the same
bounded single-target checks as the direct commands, with the same structured
exit codes and the same hard bounds. Profiles cannot widen any bound; they
only parameterize the check.

## Profiles file

`netscope check` looks for profiles in this order:

1. `--profiles FILE` when given explicitly,
2. `./netscope-profiles.toml` in the working directory,
3. `~/.config/netscope/profiles.toml` (or `$XDG_CONFIG_HOME/netscope/profiles.toml`).

Example:

```toml
[prod-web]
description = "Production web endpoint"
type = "tcp-summary"
host = "example.com"
port = 443
count = 5
timeout = 3.0
min_success_rate = 95.0
max_jitter_ms = 25.0
max_avg_latency_ms = 200.0

[prod-tls]
type = "tls"
host = "example.com"
port = 443
timeout = 5.0
min_days_cert_valid = 30.0
```

Supported check types are `tcp`, `tcp-summary`, and `tls`. Threshold keys are
type-specific: `count`, `min_success_rate`, `max_jitter_ms`, and
`max_avg_latency_ms` apply to `tcp-summary`; `min_days_cert_valid` applies to
`tls`. Unknown or misplaced keys are rejected with a usage error (exit code
2) so misconfigurations fail loudly instead of silently.

TOML is parsed with the standard library `tomllib` on Python 3.11+; on
Python 3.10 NetScope falls back to a small built-in parser covering the
profile schema (sections, strings, numbers, booleans, single-line arrays).

## Running checks

```bash
netscope check --profile prod-web
netscope check --profile prod-tls --json
netscope check --profile prod-web --profiles /etc/netscope/profiles.toml --csv
```

Exit codes mirror the underlying command: `0` on success, `1` when the check
fails or a health gate is violated, `2` for profile or usage errors. The
`--json`/`--csv` output is the underlying check's normal report, so existing
`--json` consumers and the schema contract tests apply unchanged.

## Cron example

```cron
*/5 * * * * /usr/local/bin/netscope check --profile prod-web --json >> /var/log/netscope-checks.jsonl
```

Operational failures are also emitted through the `netscope` logger, so a
cron wrapper can enable `logging` to capture diagnostics alongside the
structured report.
