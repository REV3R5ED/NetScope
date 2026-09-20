# NetScope portfolio demo

This short scenario demonstrates NetScope as a defensive network-diagnostics tool without requiring privileged access, broad scanning, or an external target. It is designed to be reproducible on a developer workstation and easy to discuss in a technical interview.

## Scenario

An operator needs to verify three things before escalating a connectivity incident:

1. whether a reported address is syntactically valid and what scope it belongs to;
2. whether the local resolver can resolve `localhost` deterministically; and
3. whether a network prefix is canonical and safe to hand to downstream automation.

The first and third checks are fully offline. The DNS check uses only the operating-system resolver for `localhost`; it does not connect to any resolved address.

## Setup

```bash
python -m venv .venv
# POSIX
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

## 1. Classify a literal address

```bash
netscope address 192.0.2.10 --json
```

Expected properties to inspect in the JSON result are the normalized address, IP version, scope classification, and reverse pointer. This command accepts a literal address only and performs no DNS lookup or network traffic.

A useful negative test is:

```bash
netscope address not-an-ip --json
```

The command should fail as structured diagnostic output rather than silently resolving the input as a hostname.

## 2. Verify local name resolution

```bash
netscope dns localhost --json
netscope dns localhost --family ipv4 --json
```

Compare the normalized resolver results. The family-specific form is useful when an incident appears to affect only IPv4 or IPv6. NetScope performs resolution only; it does not connect to returned addresses.

## 3. Validate a canonical network prefix

```bash
netscope network 192.0.2.0/24 --json
```

Inspect the normalized network boundaries, prefix length, address count, and scope. NetScope calculates these values locally and does not enumerate or probe hosts.

Now try a prefix with host bits set:

```bash
netscope network 192.0.2.10/24 --json
```

The request should be rejected rather than silently normalized. That fail-closed behavior matters when diagnostic output feeds automation because it prevents an operator typo from changing the intended network boundary.

## Optional bounded endpoint check

Only against a host and port you are authorized to test:

```bash
netscope tcp HOST PORT --timeout 2 --json
netscope tcp-summary HOST PORT --count 3 --min-success-rate 100 --json
```

NetScope restricts these commands to one explicit endpoint and caps summary attempts. Do not substitute a third-party target without authorization.

## What this demonstrates

The scenario highlights input validation, IPv4/IPv6 handling, deterministic structured output, CI-friendly failure semantics, defensive safety boundaries, and separation between offline classification and explicitly requested network activity. Those design choices are intentional: NetScope is a troubleshooting and visibility utility, not a scanning framework.

For implementation details and automated coverage, see the main README, `tests/`, and `.github/workflows/ci.yml`.