# TLS handshake diagnostics

`netscope tls HOST PORT` performs one bounded TLS handshake against an explicit
host and port. It reports the negotiated protocol version, cipher name and
strength, certificate subject and subject alternative names (SANs), issuer,
and days until certificate expiry.

## Design choices

- **Unverified context on purpose.** The handshake uses a client context with
  hostname checking and certificate verification disabled so that expired or
  self-signed certificates can still be inspected. This is what makes the
  command useful for expiry and inventory monitoring. Only the handshake is
  completed; no application data is exchanged.
- **Stdlib only.** Certificate details are extracted from the peer's DER bytes
  with a small built-in parser (subject/issuer distinguished names, SAN
  extension, validity period), because the parsed `getpeercert()` mapping is
  unavailable when verification is disabled.
- **Bounded like everything else.** One host, one port, maximum 30-second
  handshake timeout. No scanning behavior.

## Expiry health gate

`--min-days-cert-valid DAYS` turns the diagnostic into a CI/CD certificate
monitor:

```bash
netscope tls example.com 443 --min-days-cert-valid 30 --json
```

NetScope emits the complete report and returns exit code 1 when the
certificate expires in fewer than `DAYS` (or when expiry cannot be
determined). Combine with `netscope check --profile` for scheduled monitoring
(see [profiles.md](profiles.md)).

## Output fields

Human output shows the handshake summary, subject, SANs, issuer, and expiry.
JSON/CSV output carries `protocol`, `cipher`, `cipher_bits`, `subject`,
`sans`, `issuer`, `cert_expires_at` (ISO-8601), `days_until_expiry`, and
`latency_ms`. The JSON shape is pinned by `schemas/tls.schema.json`
(see [schemas.md](schemas.md)).
