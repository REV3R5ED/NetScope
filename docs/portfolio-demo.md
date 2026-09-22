# NetScope reproducible portfolio demo

This short scenario demonstrates the project's defensive network-diagnostics design without broad scanning or exploit behavior. It is intended for recruiters, reviewers, operators, and contributors who want to verify the public CLI quickly.

## What this demonstrates

- local IPv4/IPv6 classification with no network traffic
- explicit, single-destination DNS and TCP diagnostics
- bounded connectivity sampling and automation-friendly health gates
- structured JSON output suitable for CI evidence
- defensive scope: no CIDR sweep, port-range scan, exploitation, credential activity, or stealth

## Setup

Requires Python 3.10+.

```bash
git clone https://github.com/REV3R5ED/NetScope.git
cd NetScope
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install -e '.[dev]'
```

## Scenario: validate a service endpoint before a maintenance window

First, verify that address classification is deterministic and offline:

```bash
netscope address 192.0.2.10 --json
netscope network 192.0.2.0/24 --json
```

`192.0.2.0/24` is documentation address space. These two commands perform arithmetic/classification only and do not contact that network.

Next, use a hostname you own or are authorized to diagnose. The examples below use `example.com` only as a documentation placeholder; substitute your authorized target when validating operational behavior.

```bash
netscope dns example.com --json
netscope tcp example.com 443 --timeout 2 --json
```

For a small, bounded reliability sample:

```bash
netscope tcp-summary example.com 443 --count 3 --json
```

To turn the same check into a CI-style health gate while preserving the diagnostic report:

```bash
netscope tcp-summary example.com 443 \
  --count 3 \
  --min-success-rate 100 \
  --max-avg-latency-ms 500 \
  --json > netscope-health.json
```

The command targets one explicit host and one explicit port. Sampling is intentionally bounded by the CLI rather than becoming a scanner.

## Offline review path

A reviewer who does not want to generate any network traffic can still inspect core behavior:

```bash
netscope address 2001:db8::1 --json
netscope network 2001:db8::/126 --json
pytest -q
```

`2001:db8::/32` is IPv6 documentation space; the address and network commands remain fully local.

## What to inspect in the output

Look for normalized addresses, explicit address-family/scope information, deterministic structured fields, measured TCP outcome/latency, and complete diagnostic context even when an optional health threshold produces a non-zero exit status. These properties make the output useful both interactively and as retained CI/support evidence.

## Portfolio context

NetScope covers network visibility and bounded diagnostics in the broader portfolio:

- [LogLens](https://github.com/REV3R5ED/LogLens) — defensive log analysis and explainable anomaly detection
- [SentinelKit](https://github.com/REV3R5ED/SentinelKit) — IOC extraction, hashing, IP inspection, and authentication-log triage
- [AutoOPS](https://github.com/REV3R5ED/AutoOPS) — safe IT operations automation, health gates, and audit-friendly workflows

Together the projects demonstrate a workflow from operational readiness and network troubleshooting through log analysis and defensive triage.