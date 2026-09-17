# TCP summary health gates

NetScope's bounded `tcp-summary` diagnostic can act as a small CI or operational health check for one explicitly supplied endpoint. It never expands the target into a range or sweep, and the attempt count remains capped at 10.

## Available gates

- `--require-all` requires every bounded attempt to succeed.
- `--min-success-rate PERCENT` enforces an explicit availability threshold.
- `--max-jitter-ms MS` enforces a latency-stability threshold.
- `--max-avg-latency-ms MS` enforces a performance threshold based on the average latency of successful connection attempts.

The availability, jitter, and average-latency thresholds can be combined. NetScope emits the complete human-readable, JSON, or CSV report before returning exit code 1 for a violated threshold, preserving diagnostic context in CI logs.

## Examples

```bash
netscope tcp-summary example.com 443 --count 5 --require-all
netscope tcp-summary example.com 443 --count 5 --min-success-rate 80 --json
netscope tcp-summary example.com 443 --count 5 --max-jitter-ms 25 --json
netscope tcp-summary example.com 443 --count 5 --max-avg-latency-ms 150 --json
netscope tcp-summary example.com 443 --count 5 --min-success-rate 80 --max-jitter-ms 25 --max-avg-latency-ms 150 --json
```

Use these checks only for systems you are authorized to diagnose. The feature is intentionally single-endpoint and bounded; NetScope does not provide CIDR sweeps, port-range scanning, stealth, exploitation, or credential functionality.
