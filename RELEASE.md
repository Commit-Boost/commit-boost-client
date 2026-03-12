# Releasing a new version of Commit-Boost

## Process

1. Cut a release candidate (RC)
2. Test the RC
3. Collect signoffs
4. Cut the full release

## How it works

Releases are fully automated once a release PR is merged into `main`. The branch name controls what CI does:

| Branch name | Result |
| --- | --- |
| `release/vX.Y.Z-rcQ` | Creates RC tag, fast-forwards `beta`, builds and signs artifacts |
| `release/vX.Y.Z` | Creates release tag, fast-forwards `stable`, builds and signs artifacts |

No human pushes tags or updates `stable`/`beta` directly, the CI handles everything after the PR merges.

## Cutting a release candidate

1. Create a branch named `release/vX.Y.Z-rc1`. For the first RC of a new version, bump the version in `Cargo.toml` and run `cargo check` to update `Cargo.lock`. Always update `CHANGELOG.md`.
2. Open a PR targeting `main`. Get two approvals and merge.
3. CI creates the tag, fast-forwards `beta`, builds and signs binaries, Docker images, and creates a draft release on GitHub.
4. Test the RC on testnets. For subsequent RCs (`-rc2`, etc.), open a new release PR with only a `CHANGELOG.md` update (`Cargo.toml` does not change between RCs).

## Cutting the full release

Once testing is complete and signoffs are collected:

1. Create a branch named `release/vX.Y.Z` and update `CHANGELOG.md` with final release notes.
2. Open a PR targeting `main`. Get two approvals and merge.
3. CI creates the tag, fast-forwards `stable`, builds and signs artifacts, and creates a draft release.
4. Open the draft release on GitHub:
   - Click **Generate release notes** and add a plain-language summary at the top
   - Call out any breaking config changes explicitly
   - Insert the [binary verification boilerplate text](#verifying-release-artifacts)
   - Set as **latest release** (not pre-release)
   - Publish
5. Update the community.

## If the pipeline fails

CI will automatically delete the tag if any build step fails. `stable` and `beta` are only updated after all artifacts are successfully built, they are never touched on a failed run. Fix the issue and open a new release PR.

## Verifying release artifacts

All binaries are signed using [Sigstore cosign](https://docs.sigstore.dev/about/overview/). You can verify any binary was built by the official Commit-Boost CI pipeline from this release's commit.

Install cosign: https://docs.sigstore.dev/cosign/system_config/installation/

```bash
# Set the release version and your target architecture
# Architecture options: darwin_arm64, linux_arm64, linux_x86-64
export VERSION=vX.Y.Z
export ARCH=linux_x86-64

# Download the binary tarball and its signature
curl -L \
  -o "commit-boost-$VERSION-$ARCH.tar.gz" \
  "https://github.com/Commit-Boost/commit-boost-client/releases/download/$VERSION/commit-boost-$VERSION-$ARCH.tar.gz"

curl -L \
  -o "commit-boost-$VERSION-$ARCH.tar.gz.sigstore.json" \
  "https://github.com/Commit-Boost/commit-boost-client/releases/download/$VERSION/commit-boost-$VERSION-$ARCH.tar.gz.sigstore.json"

# Verify the binary was signed by the official CI pipeline
cosign verify-blob \
  "commit-boost-$VERSION-$ARCH.tar.gz" \
  --bundle "commit-boost-$VERSION-$ARCH.tar.gz.sigstore.json" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
  --certificate-identity="https://github.com/Commit-Boost/commit-boost-client/.github/workflows/release.yml@refs/tags/$VERSION"
```

A successful verification prints `Verified OK`. If the binary was modified after being built by CI, this command will fail.

The `.sigstore.json` bundle for each binary is attached to this release alongside the binary itself.
