# Security Policy

NetScope is a defensive network diagnostics project. Security reports are welcome, especially when they involve input validation, command execution boundaries, unsafe network behavior, report integrity, dependency risk, or a way to bypass the documented single-target and bounded-operation guardrails.

## Supported versions

Until NetScope publishes its first tagged stable release, security fixes are made on the current `main` branch. After tagged releases begin, this section will identify the supported release line explicitly.

## Reporting a vulnerability

Please do **not** open a public issue for a suspected vulnerability that could put users or systems at risk. Use GitHub's private vulnerability reporting for this repository when that option is available. If private reporting is unavailable, avoid publishing exploit details; open a minimal issue asking for a private reporting channel without including sensitive reproduction steps.

A useful report includes:

- the affected command, module, and revision or version;
- the expected and observed behavior;
- a minimal, non-destructive reproduction in an authorized environment;
- the security impact and any prerequisites;
- relevant platform and Python version information; and
- suggested remediation, if known.

Please do not include credentials, tokens, private hostnames, production packet captures, or other secrets in a report.

## Scope and safety expectations

High-priority security concerns include:

- shell or command injection, argument confusion, or subprocess-boundary failures;
- unintended scanning, fan-out, host enumeration, or bypasses of attempt/hop/timeout limits;
- malformed input that causes unsafe behavior or corrupts structured reports;
- report/CSV injection or control-character handling defects;
- dependency or packaging issues that affect installation integrity; and
- unexpected network activity from commands documented as offline or local-only.

NetScope intentionally does not provide exploit delivery, credential attacks, persistence, stealth, unrestricted scanning, CIDR sweeps, or port-range scanning. Reports or feature requests that require adding offensive behavior are outside the project's scope.

## Disclosure and remediation

Please allow reasonable time to reproduce, fix, test, and release a vulnerability before public disclosure. Valid reports will be evaluated against the project's documented safety boundaries, and fixes should include regression coverage when practical. Security changes should preserve NetScope's core design: explicit targets, bounded operations, no shell invocation for route diagnostics, and offline behavior for local classification commands.

## Research authorization

This policy does not grant permission to test systems you do not own or administer. Reproduction should use systems and networks for which you have explicit authorization.