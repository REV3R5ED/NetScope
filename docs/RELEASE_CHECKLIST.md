# Release readiness checklist

NetScope uses this checklist before creating a public GitHub release. It keeps the repository's package metadata, documentation, tests, and release artifacts aligned and gives maintainers a repeatable review trail.

## 1. Scope and version

- [ ] Confirm the release contains only intended defensive networking and diagnostic functionality.
- [ ] Confirm `pyproject.toml` and the runtime package report the same semantic version.
- [ ] Move completed entries out of `CHANGELOG.md`'s `Unreleased` section and verify the release date.
- [ ] Review user-facing behavior for compatibility and document any breaking change explicitly.

## 2. Quality gates

- [ ] Run the complete test suite on every Python version supported by project metadata.
- [ ] Confirm the default branch CI is green for the exact commit that will be tagged.
- [ ] Build both source and wheel distributions from a clean checkout.
- [ ] Run `twine check` on the built distributions.
- [ ] Install the built wheel into a clean environment and verify `netscope --help` plus representative offline/read-only commands.

## 3. Safety review

- [ ] Reconfirm network operations remain bounded to explicit user targets and documented limits.
- [ ] Confirm no port-range scanning, CIDR sweeps, credential attacks, exploit delivery, stealth, persistence, or system mutation has been introduced.
- [ ] Check subprocess calls remain shell-free and user-controlled text is validated before network or OS activity.
- [ ] Check exported text remains safe for spreadsheet consumption and reports do not expose unexpected sensitive data.

## 4. Documentation and presentation

- [ ] Verify README installation commands work from a clean environment.
- [ ] Verify examples match the current CLI and expected exit-code behavior.
- [ ] Review `SECURITY.md`, `CONTRIBUTING.md`, and architecture/scope documentation for accuracy.
- [ ] Confirm repository metadata, license, package classifiers, and supported Python versions remain accurate.

## 5. Publish

- [ ] Tag the exact green commit as `vX.Y.Z`.
- [ ] Create a GitHub release whose notes summarize user-visible additions, fixes, security hardening, and known limitations from `CHANGELOG.md`.
- [ ] Attach or publish only artifacts produced from the tagged commit by the release workflow.
- [ ] After publication, install from the documented release source and run a final CLI smoke test.

## Current portfolio milestone

NetScope's package metadata is currently `0.3.0`, and `CHANGELOG.md` already contains a dated `0.3.0` section. Before publishing the first tagged portfolio release, apply this checklist to the exact candidate commit rather than treating the version number alone as evidence of release readiness.
