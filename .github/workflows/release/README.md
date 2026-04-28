# Release automation

Python CLI and workflow glue for the Commit-Boost release process.

For the maintainer-facing release procedure, see [`.releases/README.md`](../../../.releases/README.md).

## Flow

```text
1. PR on main adds .releases/vX.Y.Z.yml
   - file name is the release tag
   - referenced commit may be on main or on a hotfix branch

2. validate-release-request.yml
   - pre-merge feedback for authors and reviewers
   - validates request shape before merge

3. release-gate.yml
   - authoritative post-merge check
   - re-validates the request
   - creates the tag via the GitHub App
   - dispatches release.yml from main with only the tag

4. release.yml
   - receives only the tag
   - resolves the commit from the tag itself
   - builds binaries from that exact commit
   - pushes Docker images
   - signs artifacts with Sigstore
   - drafts the GitHub Release
```

`validate-release-request.yml` is kept for fast pre-merge feedback. `release-gate.yml` is still authoritative because it is the last step before tag creation.

The release workflow always runs from the latest workflow definition on main. The tag is the trust anchor: `release-gate.yml` creates it via the GitHub App, and `release.yml` resolves the commit from that tag before building. This prevents dispatch from injecting an arbitrary tag and commit pair.

The release commit may be off-main. The workflow definition always runs from main.

## Local usage

Requires `GH_TOKEN` and `REPO` in env. `uv` is recommended.

```bash
export REPO=commit-boost/commit-boost-client
export GH_TOKEN=$(gh auth token)

uv run --with pyyaml python .github/workflows/release/release.py lint .releases/v1.2.3.yml
uv run --with pyyaml --with pytest pytest .github/workflows/release/test_release.py -v
```

## Commands

| Command | Purpose |
| --- | --- |
| `validate-filename <name>` | Validate release tag format |
| `validate-yaml <path>` | Validate release-request YAML shape |
| `find-added --base <sha> --head <sha>` | List added release-request files |
| `check-modifications --base <sha> --head <sha>` | Reject edits and deletes to existing release requests |
| `check-commit-exists <sha>` | Verify the requested commit exists |
| `check-tag-free <tag>` | Verify the tag does not already exist |
| `create-tag <tag> <commit>` | Create the signed tag via GitHub API |
| `is-latest <tag>` | Decide whether Docker `:latest` should move |
| `validate-pr` | Full pre-merge validation |
| `gate` | Authoritative post-merge validation and tag creation |
| `lint <path>` | Local pre-flight check |

## Layout

```text
.github/workflows/release/
├── release.py
├── test_release.py
└── README.md
```

## Notes

- The release request PR is the approval point.
- Release request files are immutable after merge.
- Botched attempts may leave version gaps. We accept that rather than adding retry machinery to `.releases/`.
- Workflow permissions grant write access only where required.

## Troubleshooting

- `pip install pyyaml` fails with `externally-managed-environment`: use `uv` or install inside a venv.
- `gh: not found`: install GitHub CLI and run `gh auth login`.
- Release dispatch succeeds but the build fails immediately: confirm the tag exists and points at the intended commit.
