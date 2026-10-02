# TCP summary health gates

NetScope's bounded `tcp-summary` diagnostic can act as a small CI or operational health check for one explicitly supplied endpoint. It never expands the target into a range or sweep, and the attempt count remains capped at 10.

## Available gates

- `--require-all` requires every bounded attempt to succeed.
- `--min-success-rate PERCENT` enforces an explicit availability threshold.
- `--max-jitter-ms MS` enforces a latency-stability threshold.
- `--max-avg-latency-ms MS` enforces a performance threshold based on the average latency of successful connection attempts.

The availability, jitter, and average-latency thresholds can be combined. NetScope emits the complete human-readable, JSON, or CSV report before returning exit code 1 for a violated threshold, preserving diagnostic context in CI logs.

## Baseline latency-drift detection

`--baseline FILE --max-latency-drift-pct PCT` extends the gates from static
thresholds to trend detection. `FILE` is a JSON report saved from an earlier
`tcp-summary --json` run:

```bash
netscope tcp-summary example.com 443 --count 5 --json > baseline.json
# ... later, or in CI ...
netscope tcp-summary example.com 443 --count 5 \
  --baseline baseline.json --max-latency-drift-pct 25 --json
```

NetScope compares the current average latency against the baseline average and
returns exit code 1 when the drift exceeds `PCT` percent. The report carries
`baseline_avg_latency_ms` and `latency_drift_percent` in all three output
formats. A missing or unusable baseline file is a usage error (exit code 2),
raised before any connection attempt runs.

## TLS certificate-expiry gate

`netscope tls HOST PORT --min-days-cert-valid DAYS` returns exit code 1 when
the peer certificate expires in fewer than `DAYS` (see [tls.md](tls.md)).
Like the other gates, the full diagnostic report is preserved.

## Examples

```bash
netscope tcp-summary example.com 443 --count 5 --require-all
netscope tcp-summary example.com 443 --count 5 --min-success-rate 80 --json
netscope tcp-summary example.com 443 --count 5 --max-jitter-ms 25 --json
netscope tcp-summary example.com 443 --count 5 --max-avg-latency-ms 150 --json
netscope tcp-summary example.com 443 --count 5 --min-success-rate 80 --max-jitter-ms 25 --max-avg-latency-ms 150 --json
```

Use these checks only for systems you are authorized to diagnose. The feature is intentionally single-endpoint and bounded; NetScope does not provide CIDR sweeps, port-range scanning, stealth, exploitation, or credential functionality.
