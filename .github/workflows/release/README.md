# Release Management Scripts

Python CLI that backs the three release workflows:

- `.github/workflows/validate-release-request.yml` → `release.py validate-pr`
- `.github/workflows/release-gate.yml` → `release.py gate`
- `.github/workflows/release.yml` (the `determine-latest` job) → `release.py is-latest <tag>`

All release-request validation, tag creation, and `:latest` gating logic lives here. The workflows are thin orchestration — they set env vars and invoke a subcommand.

## Requirements

- Python 3.10+ (tested on 3.12)
- `pyyaml`
- `gh` CLI (authenticated via `GH_TOKEN` env for API calls)
- `git` (for repo-local queries)

```
pip install pyyaml pytest
```

## Running the tests

```
pytest .github/workflows/release/test_release.py -v
```

All 61 tests use mocked `subprocess.run` boundaries and a tmp-repo fixture — they don't touch the network.

## Subcommands

Quick reference — each subcommand exits 0 on success, non-zero on failure, and prints `❌` / `✅` messages to stdout.

| Command | Purpose |
| --- | --- |
| `validate-filename <basename>` | Strict semver regex check (no leading zeros, `-rcN` suffix allowed) |
| `validate-yaml <path>` | Parse and schema-check a release-request YAML |
| `find-added --base <sha> --head <sha>` | List `.releases/*.yml` files added in a diff range |
| `check-modifications --base <sha> --head <sha>` | Reject modifications/deletions of existing YAMLs |
| `check-commit-exists <sha>` | Verify commit exists via GitHub API |
| `check-tag-free <tag>` | Verify tag doesn't already exist |
| `check-signatures <commit>` | Confirm all commits from nearest tag ancestor to the release commit are signed |
| `create-tag <tag> <commit>` | Create signed tag via GitHub API (`POST /git/tags` + `POST /git/refs`) |
| `is-latest <tag>` | Print `true`/`false` — is this the highest non-RC semver? |
| `validate-pr` | End-to-end validator used by the PR workflow |
| `gate` | End-to-end gate used post-merge to create the tag |

## Running locally

Most subcommands need env vars:

```
export REPO=commit-boost/commit-boost-client
export GH_TOKEN=$(gh auth token)

# Quick lint of a YAML
python .github/workflows/release/release.py validate-yaml .releases/v1.2.3.yml

# Is v1.2.3 the latest?
python .github/workflows/release/release.py is-latest v1.2.3

# Simulate the PR validator end-to-end
export BASE_SHA=$(git merge-base origin/main HEAD)
export HEAD_SHA=HEAD
python .github/workflows/release/release.py validate-pr
```

## Layout

```
.github/workflows/release/
├── release.py          # The CLI
├── test_release.py     # pytest suite (unit + tmp-repo integration)
└── README.md           # This file
```

Located alongside the workflow files that call it. This follows the same convention as the ethereum-package Kurtosis repo, which keeps its workflow-supporting Python under `.github/workflows/`.

YAML test cases are inlined in `test_release.py` as string constants and written to `tmp_path` at test time — no standalone fixtures directory.

## Design notes

- **Single-file script, no `__init__.py`.** Keeps invocation simple and avoids packaging ceremony for a 400-line tool.
- **`run_git()` is the git boundary**; `gh_api()` is the GitHub API boundary. Both are patchable in tests. `_run()` handles raw subprocess mechanics.
- **Error messages match the workflow conventions.** `❌` for failures, `✅` for success. The old inline shell used the same prefixes.
- **Strict semver regex lives in release.py** as `SEMVER_RE` — import it from tests so the regex is authoritative in one place.
