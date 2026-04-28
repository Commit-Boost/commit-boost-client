# Release Requests

This directory contains immutable release-request files. Merging one on main requests a release.

## Filing a release request

1. Pick the commit SHA to release.
2. Create `.releases/<tag>.yml` where the file name is the exact tag to create.
3. Add:

```yaml
commit: <40-character SHA>
reason: "<one-line description>"
```

4. In the same PR:
   - update `CHANGELOG.md`
   - bump the root `Cargo.toml` workspace version to `<next>-dev`
5. Get approvals and merge the PR to main.

## Rules

- Full release: `v1.2.3.yml`
- Pre-release: `v1.2.3-rc1.yml`, `v1.2.3-rc2.yml`, etc.
- Must start with `v`
- Must be strict semver, optionally with `-rcN` where N >= 1
- Must use `.yml`

## Constraints enforced by CI

- Exactly one release-request file may be added per PR
- Existing release-request files cannot be modified or deleted
- The referenced commit must exist in the repository
- The tag must not already exist
- The referenced commit may be on main or on an off-main hotfix branch

## Hotfix releases

A release commit does not need to be on main.

Typical flow:
1. Branch from the last release tag: `git checkout -b fix/<name> vX.Y.Z`
2. Land fixes on that branch
3. Open a PR on main adding `.releases/vA.B.C.yml` that points at the hotfix branch tip commit
4. Merge the release-request PR on main
5. After the release ships, reconcile the hotfix branch back into main separately

## After merge

1. `release-gate.yml` re-validates the request and creates the signed tag via the GitHub App
2. `release.yml` resolves the commit from the tag, builds binaries, pushes Docker images, signs artifacts, and drafts the GitHub Release
3. GHCR `:latest` moves only if the new tag is the highest non-RC version

## Operational note

Release-request files are immutable after merge. If a release attempt is botched, use the next version number and explain the gap in the changelog if needed.

## Downloading and verifying release assets

Release assets are published per binary, not as a single generic `commit-boost-...` tarball.

Examples:
- `commit-boost-cli-vX.Y.Z-linux_x86-64.tar.gz`
- `commit-boost-pbs-vX.Y.Z-linux_x86-64.tar.gz`
- `commit-boost-signer-vX.Y.Z-linux_x86-64.tar.gz`

Each tarball has a matching Sigstore bundle:
- `...tar.gz.sigstore.json`

Example verification flow:

```bash
export REPO=Commit-Boost/commit-boost-client
export VERSION=vX.Y.Z
export ARCH=linux_x86-64
export BIN=commit-boost-pbs

curl -L \
  -o "$BIN-$VERSION-$ARCH.tar.gz" \
  "https://github.com/$REPO/releases/download/$VERSION/$BIN-$VERSION-$ARCH.tar.gz"

curl -L \
  -o "$BIN-$VERSION-$ARCH.tar.gz.sigstore.json" \
  "https://github.com/$REPO/releases/download/$VERSION/$BIN-$VERSION-$ARCH.tar.gz.sigstore.json"

cosign verify-blob \
  "$BIN-$VERSION-$ARCH.tar.gz" \
  --bundle "$BIN-$VERSION-$ARCH.tar.gz.sigstore.json" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity="https://github.com/Commit-Boost/commit-boost-client/.github/workflows/release.yml@refs/heads/main"
```

To verify assets from a fork, replace `REPO` with the fork path, for example:
- `<YourUsername>/commit-boost-client`
