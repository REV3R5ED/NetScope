# Contributing to NetScope

Thanks for helping improve NetScope. Contributions should keep the project focused on defensive, authorized network visibility and diagnostics.

## Development setup

NetScope supports Python 3.10 through 3.13.

```bash
python -m venv .venv
# POSIX: source .venv/bin/activate
# Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
pytest -q
```

## Contribution workflow

1. Create a focused branch from `main`.
2. Keep each change small enough to review and explain.
3. Add or update tests for behavior changes and bug fixes.
4. Run the full test suite before opening a pull request.
5. Update `README.md` or `CHANGELOG.md` when public behavior changes.

## Testing expectations

Tests should be deterministic and avoid depending on uncontrolled external services. Prefer mocks, loopback/local behavior, and explicit synthetic inputs for network-facing code. New validation or health-gate behavior should cover both accepted and rejected inputs, expected exit behavior, and structured output where applicable.

Before submitting a change, run:

```bash
pytest -q
python -m build
python -m twine check dist/*
```

The GitHub Actions pipeline is the source of truth for the supported Python matrix and release-artifact validation.

## Defensive scope

NetScope intentionally supports bounded diagnostics rather than general-purpose scanning. Contributions must preserve these boundaries:

- one explicit target per TCP or path invocation;
- one explicit TCP port per invocation;
- bounded TCP summary attempts;
- bounded traceroute hops and timeouts;
- no CIDR sweeps, port-range scanning, exploit delivery, stealth, credential attacks, persistence, or evasion features;
- no shell-based execution of user-controlled network arguments.

Features that increase diagnostic depth should remain transparent, bounded, and appropriate for systems the operator owns or is authorized to assess.

## Data and examples

Do not commit credentials, API keys, private addresses, customer data, production logs, or other sensitive material. Documentation and tests should use synthetic data, loopback addresses, or documentation-reserved examples where practical.

## Pull requests

A useful pull request explains the operational problem, the chosen behavior, tests performed, and any safety or compatibility considerations. Avoid unrelated cleanup in the same change so reviewers can reason about behavior and risk clearly.
