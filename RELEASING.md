# Releasing NetScope

This runbook documents the portfolio release process for NetScope. Releases are intentionally fail-closed: do not publish from an unvalidated commit, and do not bypass a failed release workflow.

## v0.3.0 release procedure

1. Confirm `main` is at the release candidate recorded in the release tracking issue and that CI passed on that exact commit.
2. Confirm `pyproject.toml` reports version `0.3.0` and `CHANGELOG.md` contains the matching `0.3.0` release notes.
3. Create the annotated or lightweight tag `v0.3.0` on that exact validated commit. Do not move an existing release tag.
4. Push the tag and allow the tag-triggered release workflow to run.
5. Require the workflow to complete successfully. It must verify tag/package version parity, rebuild distributions, validate them, install and smoke-test the wheel, extract matching changelog notes, and publish the GitHub Release with the validated distributions attached.
6. Inspect the published release and verify that both the wheel and source distribution are attached and that the release notes correspond to `CHANGELOG.md`.
7. Only after the release is verified, update the README status from release candidate to released and mark the release tracking issue complete.

## Failure handling

- If CI on the candidate commit fails, fix the failure on a new commit and revalidate that new exact commit before tagging.
- If the release workflow fails, do not manually upload unvalidated artifacts as a workaround. Diagnose the failed job, fix the release path, and rerun from a validated release state.
- If a tag was created on the wrong commit and has not been published as a release, remove it and recreate it on the validated commit. Never silently move a published release tag.
- If version metadata and the tag disagree, treat that as a release-blocking error.

## Safety boundary

Release validation must not broaden NetScope's runtime behavior. Smoke tests should remain offline where possible or target only explicitly bounded, benign diagnostics such as localhost resolution. NetScope releases must not introduce unrestricted scanning, CIDR sweeps, port-range scanning, exploit delivery, credential attacks, stealth, persistence, or host enumeration.
