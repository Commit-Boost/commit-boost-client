# Release Requests

This directory contains release-request YAML files. Adding a new file here triggers a release.

## Filing a release request

1. Pick a commit SHA to release
2. Create a file at `.releases/<tag-name>.yml` where the filename (minus `.yml`) is the exact tag to create
3. File contents:
```yaml
   commit: <40-character SHA>
   reason: "<one-line description>"
```
4. In the same PR:
   - Update `CHANGELOG.md`
   - Bump the root `Cargo.toml` workspace version to `<next>-dev`
5. Open the PR, get two approvals, squash-merge

## Filename rules

- Full release: `v1.2.3.yml`
- Pre-release: `v1.2.3-rc1.yml`, `v1.2.3-rc2.yml`, etc.
- Must start with `v`
- Must be valid semver (or `-rcN` suffix)
- Must use `.yml` extension

## Constraints (enforced by CI)

- Exactly one release YAML may be added per PR
- Existing YAMLs cannot be modified or deleted
- The referenced commit must exist in the repository (on any branch)
- The tag must not already exist

## What happens after merge

1. `release-gate.yml` creates the signed tag at the referenced commit
2. `release.yml` builds artifacts from the tagged commit and publishes the release
3. `:latest` on GHCR is updated only if the new tag is the highest non-RC semver

## Reviewer checklist

Before approving a release-request PR, confirm:

- The commit SHA points at the intended code
- The commit shows as "Verified" in GitHub's UI
- **For hotfixes:** click through every commit on the fix branch from the last release tag to the release commit and verify each shows "Verified." Unsigned commits in the ancestry will cause CI to fail, but visual confirmation during review is faster feedback than waiting for CI.
- The version number makes sense (greater than the last release on this line)
- `CHANGELOG.md` has been updated with release notes
- `Cargo.toml` workspace version is bumped to the next `-dev` value
- The `reason` field accurately describes why this release is being cut

## Emergency / hotfix releases

1. Create a fix branch from the last release tag: `git checkout -b fix/<name> vX.Y.Z`
2. Apply fixes via normal PRs into the fix branch
3. File a release-request YAML on main pointing at the fix branch's tip commit
4. After release ships, reconcile the fix branch into main via a normal PR

## Closed-without-merging PRs

If a release-request PR is closed without merging, no release occurs. The validator's failure (if any) is informational; nothing happens downstream.

## Testing on a fork

The release process requires a GitHub App to function. Install a personal GitHub App on your fork with `contents: write` permission, generate a private key, and add `APP_ID` and `APP_PRIVATE_KEY` as repository secrets. The workflows then run end-to-end on your fork without any file edits.
