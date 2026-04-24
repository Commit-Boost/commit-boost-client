# Release automation

Python scripts that drive the Commit-Boost release workflow. Run by CI on every release-request PR and on every release tag — but also runnable locally for development, debugging, and dry-runs.

The user-facing release procedure lives in [`.releases/README.md`](../../../.releases/README.md). Read that first if you're cutting a release. This README is for people working on the release infrastructure itself.

## How a release happens

```
   ┌────────────────────────────────────────────┐
   │ 1. Maintainer opens a PR adding            │
   │    .releases/v1.2.3.yml                    │
   │    (40-char commit SHA + reason)           │
   └──────────────┬─────────────────────────────┘
                  │
   ┌──────────────▼─────────────────────────────┐
   │ 2. validate-release-request.yml runs       │
   │    → release.py validate-pr                │
   │    Checks: filename, schema, commit exists,│
   │    tag is free, ancestor commits signed    │
   └──────────────┬─────────────────────────────┘
                  │  (2 approvals, squash-merge)
   ┌──────────────▼─────────────────────────────┐
   │ 3. release-gate.yml runs (post-merge)      │
   │    → release.py gate                       │
   │    Creates signed tag via GitHub API       │
   │    (POST /git/tags + POST /git/refs)       │
   └──────────────┬─────────────────────────────┘
                  │  (tag push triggers next workflow)
   ┌──────────────▼─────────────────────────────┐
   │ 4. release.yml runs (on tag push)          │
   │    Builds binaries (linux x64+arm64,       │
   │    darwin arm64), pushes Docker images,    │
   │    drafts GitHub Release. determine-latest │
   │    job calls release.py is-latest to       │
   │    decide whether to update :latest        │
   └────────────────────────────────────────────┘
```

## Example release-request YAML

The filename is the tag. The contents reference the commit to tag.

`.releases/v0.9.7.yml`:
```yaml
commit: a1b2c3d4e5f6789012345678901234567890abcd
reason: "Emergency hotfix for ..."
```

`.releases/v1.0.0-rc1.yml`:
```yaml
commit: 0123456789abcdef0123456789abcdef01234567
reason: "First release candidate of the 1.0 line"
```

Naming rules: `v<MAJOR>.<MINOR>.<PATCH>` or `v<MAJOR>.<MINOR>.<PATCH>-rc<N>`. No leading zeros. Must use `.yml` (not `.yaml`).

## Filing a release (the short version)

1. Pick the commit SHA you want to ship.
2. Create `.releases/v<X.Y.Z>.yml` with `commit:` and `reason:`.
3. In the same PR: bump `Cargo.toml` workspace version to `<next>-dev`, update `CHANGELOG.md`.
4. Two approvals, squash-merge.
5. Watch `release-gate.yml` create the tag, then `release.yml` build artifacts.

Hotfix variant: cut a `fix/*` branch from the last release tag, land fixes via squash-merge, then file the YAML on `main` pointing at the fix-branch tip. The release ships from that commit even though it's not in main's history. After the release, merge the fix branch back into main via a normal PR.

Full procedure including the reviewer checklist: [`.releases/README.md`](../../../.releases/README.md).

## Setting up Python locally

Use [uv](https://docs.astral.sh/uv/) — fastest path, no virtualenv ceremony.

### Install uv

```
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# or via Homebrew
brew install uv
```

### Run the test suite

uv handles Python and dependencies in one shot. From the repo root:

```
uv run --with pyyaml --with pytest pytest .github/workflows/release/test_release.py -v
```

That command provisions a Python environment with `pyyaml` and `pytest`, then runs the suite. No `venv activate`, no `pip install`, no system Python pollution. Expected output: `61 passed`.

### Run a subcommand

```
uv run --with pyyaml python .github/workflows/release/release.py --help
uv run --with pyyaml python .github/workflows/release/release.py validate-filename v1.2.3
```

### Without uv (if you must)

```
python3 -m venv .venv
source .venv/bin/activate
pip install pyyaml pytest
pytest .github/workflows/release/test_release.py -v
```

CI uses the explicit `setup-python` + `pip install pyyaml` pattern in the workflow files (no uv on the runners; pyyaml is the only runtime dep).

## Pre-commit sanity check

Before opening a release-request PR, run the same checks CI will run. One command:

```
export REPO=commit-boost/commit-boost-client
export GH_TOKEN=$(gh auth token)

uv run --with pyyaml python .github/workflows/release/release.py \
    lint .releases/v1.2.3.yml
```

`lint` runs the full validation pipeline against a single YAML: filename regex, schema, commit-exists, tag-free, ancestor-signature check. Exit 0 means CI will be happy. Exit non-zero shows the exact error CI will print.

Add this to your shell rc for repeated dry-runs:

```bash
cb-release-check() {
    export REPO=commit-boost/commit-boost-client
    export GH_TOKEN=$(gh auth token)
    uv run --with pyyaml python .github/workflows/release/release.py lint "$1"
}
```

Then `cb-release-check .releases/v1.2.3.yml` from the repo root.

## Subcommand reference

Every subcommand exits 0 on success, non-zero on failure. Output uses ❌ for errors and ✅ for success.

| Command | Purpose | Used by |
| --- | --- | --- |
| `validate-filename <basename>` | Strict semver check. Rejects leading zeros, missing `v`, wrong extension. | `validate-pr` |
| `validate-yaml <path>` | Parse + schema-check a release-request YAML. Prints `tag=...` `commit=...` on success. | `validate-pr`, `gate` |
| `find-added --base <sha> --head <sha>` | List `.releases/*.yml` files added in a diff range. | `validate-pr`, `gate` |
| `check-modifications --base <sha> --head <sha>` | Reject modifications/deletions of existing YAMLs. | `validate-pr` |
| `check-commit-exists <sha>` | Verify a commit exists via `gh api /commits/{sha}`. | `validate-pr` |
| `check-tag-free <tag>` | Verify the tag does not already exist. | `validate-pr` |
| `check-signatures <commit>` | Confirm every commit from the nearest tag ancestor to `<commit>` has a verified signature. | `validate-pr` |
| `create-tag <tag> <commit>` | Create signed annotated tag via `POST /git/tags` + `POST /git/refs`. GitHub server-signs using the App identity. | `gate` |
| `is-latest <tag>` | Print `true` if `<tag>` is the highest non-RC semver among local `v*` tags, else `false`. | `release.yml` `determine-latest` job |
| `validate-pr` | End-to-end PR validator. Reads `BASE_SHA`, `HEAD_SHA`, `GH_TOKEN`, `REPO` from env. | `validate-release-request.yml` |
| `gate` | End-to-end gate. Reads `BASE_SHA`, `MERGE_SHA`, `GH_TOKEN`, `REPO` from env. | `release-gate.yml` |
| `lint <path>` | Pre-commit sanity check on a single YAML. Same checks as CI minus the diff step. Reads `GH_TOKEN`, `REPO` from env. | local dev only |

### Local dry-run examples

See [Pre-commit sanity check](#pre-commit-sanity-check) above for the canonical recipe — it covers most needs.

For ad-hoc one-offs:

```
# Check is-latest against your current tag set
uv run --with pyyaml python .github/workflows/release/release.py is-latest v0.9.7

# Find what would be added between two refs (without validating)
uv run --with pyyaml python .github/workflows/release/release.py \
    find-added --base origin/main --head HEAD
```

## Layout

```
.github/workflows/release/
├── release.py          # The CLI (argparse, ~370 lines)
├── test_release.py     # pytest suite (~540 lines, 61 tests)
└── README.md           # This file
```

YAML test cases are inlined in `test_release.py` as string constants and written to `tmp_path` at test time — no standalone fixtures directory.

Located alongside the workflow files that call it. This follows the convention used by the [ethereum-package Kurtosis repo](https://github.com/ethpandaops/ethereum-package), which keeps workflow-supporting Python under `.github/workflows/`.

## Design notes

- **Single-file script, no packaging.** Keeps invocation simple — `python release.py <subcmd>` works from anywhere.
- **Two patchable boundaries.** `run_git()` for git, `gh_api()` for GitHub API. Tests stub these and skip the network entirely. `_run()` handles raw subprocess mechanics.
- **Errors prefixed `❌`, success `✅`.** Matches the conventions of the inline shell the workflows used to use, so log readers see consistent markers.
- **`SEMVER_RE` lives in `release.py`** and is imported by tests. Single source of truth for what counts as a valid release tag.
- **No deps beyond PyYAML.** `gh` and `git` are CLI tools, not Python packages — they're already on every GitHub runner and on every developer's machine.

## What's NOT in here

- Tag-signing keys: GitHub server-signs via the App identity when we POST to `/git/tags`. No GPG setup required on the runner.
- Branch protection rules: configured in repo Settings, not in code. See `PLAN.md` for the ruleset spec.
- The actual binary/docker build pipeline: that's in `.github/workflows/release.yml` and remains conventional GitHub Actions YAML.

## Troubleshooting

**`pip install pyyaml` fails with "externally-managed-environment"** — you're hitting PEP 668 on Ubuntu 24.04+. Use uv (above) or `pip install --user pyyaml`. CI uses `actions/setup-python@v5` to sidestep this.

**`gh: not found`** — install the GitHub CLI: `brew install gh` then `gh auth login`. Subcommands that hit the API need `GH_TOKEN` in the environment; `$(gh auth token)` works.

**`check-signatures` says "No prior tag ancestor found"** — `git describe --tags --abbrev=0 <commit>^` couldn't find a reachable tag. Either you're at the very first release, or your local clone is shallow. `git fetch --tags --unshallow` and retry.

**Tests fail with `ImportError: cannot import name 'cmd_xxx' from 'release'`** — you've added a subcommand to release.py but forgot to wire it into `main()`'s subparser, or the test imports a stale name. The tests import every command function explicitly; keep the names in sync.
