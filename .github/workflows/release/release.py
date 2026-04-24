#!/usr/bin/env python3
"""Release management CLI for Commit-Boost.

Single-file argparse CLI.  PyYAML + stdlib only.  Shells out to ``git`` and
``gh`` via ``subprocess.run``.
"""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml


# ── helpers ──────────────────────────────────────────────────────────────────

def _env(name: str) -> str:
    """Read *name* from the environment; exit 1 with a clear message if missing."""
    val = os.environ.get(name)
    if not val:
        print(f"❌ Required environment variable ${name} is not set.")
        sys.exit(1)
    return val


class GhApiError(Exception):
    """Raised when a ``gh api`` call fails non-zero."""


def gh_api(method: str, path: str, **fields) -> dict | list:
    """Thin wrapper over ``gh api``.  Returns parsed JSON."""
    token = _env("GH_TOKEN")
    repo = _env("REPO")
    full_path = f"/repos/{repo}{path}"
    argv = ["gh", "api", "--method", method, full_path]
    for k, v in fields.items():
        argv.extend(["-f", f"{k}={v}"])
    if method.upper() == "GET":
        argv.append("--paginate")
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    result = subprocess.run(argv, capture_output=True, text=True, env=env)
    if result.returncode != 0:
        print(result.stderr, file=sys.stderr, end="")
        raise GhApiError(
            f"gh api {method} {full_path} failed (exit {result.returncode})"
        )
    if not result.stdout.strip():
        return {}
    return json.loads(result.stdout)


def _run(*args: str) -> str:
    """Wrapper over ``subprocess.run`` with check, capture_output, text."""
    result = subprocess.run(list(args), capture_output=True, text=True, check=True)
    return result.stdout


# Public alias so tests can patch `release.run_git` at the boundary.
# Also lets callers shell out to git explicitly when intent needs to be clear.
def run_git(*args: str) -> str:
    return _run("git", *args)


def _git_diff(base: str, head: str, diff_filter: str) -> list[str]:
    """Return list of .releases/*.yml files from git diff with *diff_filter*."""
    try:
        out = run_git(
            "diff", "--name-only", f"--diff-filter={diff_filter}",
            f"{base}..{head}", "--", ".releases/*.yml",
        )
    except subprocess.CalledProcessError:
        return []
    return [l for l in out.strip().split("\n") if l]


# ── core validation helpers ─────────────────────────────────────────────────

SEMVER_RE = re.compile(
    r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-rc[1-9][0-9]*)?$"
)


def _semver_key(tag: str) -> tuple:
    """Return a comparable key for a semver tag (e.g. ``v1.2.3``)."""
    m = re.match(r"^v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?$", tag)
    if not m:
        return (0, 0, 0, 0)
    return (
        int(m.group(1)), int(m.group(2)), int(m.group(3)),
        int(m.group(4)) if m.group(4) else float("inf"),
    )


def validate_yaml_file(path: str) -> tuple[str, str]:
    """Parse and validate a release-request YAML.  Returns (commit_sha, tag)."""
    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        print(f"❌ File not found: {path}")
        sys.exit(1)

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        print(f"❌ YAML parse error: {e}")
        sys.exit(1)

    if not isinstance(data, dict):
        print("❌ YAML must be a mapping (dict)")
        sys.exit(1)

    missing = {"commit", "reason"} - data.keys()
    if missing:
        print(f"❌ Missing required fields: {missing}")
        sys.exit(1)

    commit = data["commit"]
    if (
        not isinstance(commit, str) or len(commit) != 40
        or not all(c in "0123456789abcdef" for c in commit)
    ):
        print("❌ commit must be a 40-character lowercase hex SHA")
        sys.exit(1)

    reason = data["reason"]
    if not isinstance(reason, str) or not reason.strip():
        print("❌ reason must be a non-empty string")
        sys.exit(1)

    tag = Path(path).stem
    return commit, tag


# ── subcommands ──────────────────────────────────────────────────────────────

def cmd_validate_filename(args: argparse.Namespace) -> None:
    if SEMVER_RE.match(args.basename):
        print(f"✅ Valid release filename: {args.basename}")
        sys.exit(0)
    print(
        f"❌ Filename '{args.basename}' is not a valid release tag.\n"
        "Expected: v<major>.<minor>.<patch> or v<major>.<minor>.<patch>-rc<N>, "
        "no leading zeros"
    )
    sys.exit(1)


def cmd_validate_yaml(args: argparse.Namespace) -> None:
    commit, tag = validate_yaml_file(args.path)
    print(f"tag={tag}")
    print(f"commit={commit}")
    print(f"✅ YAML validation passed for {Path(args.path).name}")
    sys.exit(0)


def cmd_find_added(args: argparse.Namespace) -> None:
    files = _git_diff(args.base, args.head, "A")
    for f in files:
        print(f)
    print(f"count={len(files)}", file=sys.stderr)
    sys.exit(0)


def cmd_check_modifications(args: argparse.Namespace) -> None:
    files = _git_diff(args.base, args.head, "MD")
    if files:
        print("❌ Existing release YAMLs cannot be modified or deleted:")
        for f in files:
            print(f)
        sys.exit(1)
    print("✅ No modifications or deletions detected")
    sys.exit(0)


def cmd_check_commit_exists(args: argparse.Namespace) -> None:
    try:
        gh_api("GET", f"/commits/{args.sha}")
        print(f"✅ Commit {args.sha} exists")
        sys.exit(0)
    except GhApiError:
        print(f"❌ Commit {args.sha} does not exist in this repository")
        sys.exit(1)


def cmd_check_tag_free(args: argparse.Namespace) -> None:
    try:
        gh_api("GET", f"/git/refs/tags/{args.tag}")
        print(f"❌ Tag {args.tag} already exists. Pick a different version.")
        sys.exit(1)
    except GhApiError:
        print(f"✅ Tag {args.tag} is free")
        sys.exit(0)


def cmd_check_signatures(args: argparse.Namespace) -> None:
    commit = args.commit
    try:
        prev_tag = run_git("describe", "--tags", "--abbrev=0", f"{commit}^").strip()
    except subprocess.CalledProcessError:
        print("⚠️  No prior tag ancestor found; skipping ancestor signature check")
        sys.exit(0)

    print(f"Comparing signatures from {prev_tag} (ancestor of {commit}) to {commit}...")
    try:
        data = gh_api("GET", f"/compare/{prev_tag}...{commit}")
    except GhApiError:
        print("❌ Failed to compare revisions")
        sys.exit(1)

    commits = data if isinstance(data, list) else data.get("commits", [])
    unsigned = [
        c["sha"]
        for c in commits
        if not c.get("commit", {}).get("verification", {}).get("verified", False)
    ]
    if unsigned:
        print(f"❌ Unsigned commits between {prev_tag} and {commit}:")
        for sha in unsigned:
            print(sha)
        print("Every commit in a release must be signed.")
        sys.exit(1)

    print(f"✅ All commits between {prev_tag} and {commit} are signed.")
    sys.exit(0)


def cmd_create_tag(args: argparse.Namespace) -> None:
    tag_obj = gh_api(
        "POST", "/git/tags",
        tag=args.tag, message=args.tag,
        object=args.commit, type="commit",
    )
    tag_sha = tag_obj.get("sha") if isinstance(tag_obj, dict) else None
    if not tag_sha:
        print("❌ Failed to create tag object")
        sys.exit(1)

    gh_api(
        "POST", "/git/refs",
        ref=f"refs/tags/{args.tag}", sha=tag_sha,
    )
    print(f"✅ Tag {args.tag} created at {args.commit} (signed by GitHub via App identity)")
    sys.exit(0)


def cmd_is_latest(args: argparse.Namespace) -> None:
    tag = args.tag
    try:
        all_tags = run_git("tag", "--list", "v*").strip().split("\n")
    except subprocess.CalledProcessError:
        print("true")
        sys.exit(0)
    non_rc = [t for t in all_tags if t and not re.search(r"-rc\d+$", t)]
    if not non_rc:
        print("true")
        sys.exit(0)
    highest = sorted(non_rc, key=_semver_key)[-1]
    print("true" if highest == tag else "false")
    sys.exit(0)


def cmd_validate_pr(args: argparse.Namespace) -> None:
    base = _env("BASE_SHA")
    head = _env("HEAD_SHA")

    added = _git_diff(base, head, "A")
    mods = _git_diff(base, head, "MD")

    if mods:
        print("❌ Existing release YAMLs cannot be modified or deleted:")
        for m in mods:
            print(m)
        sys.exit(1)

    if len(added) == 0:
        print("added_count=0")
        print("No release changes in this PR; validation trivially passes.")
        sys.exit(0)

    if len(added) > 1:
        print("❌ Only one release YAML may be added per PR.")
        for a in added:
            print(a)
        sys.exit(1)

    filepath = added[0]
    basename = Path(filepath).stem

    cmd_validate_filename(argparse.Namespace(basename=basename))
    commit, _ = validate_yaml_file(filepath)
    cmd_check_commit_exists(argparse.Namespace(sha=commit))
    cmd_check_tag_free(argparse.Namespace(tag=basename))
    cmd_check_signatures(argparse.Namespace(commit=commit))

    print(f"added_count=1")
    print(f"tag={basename}")
    print(f"commit={commit}")
    print(f"✅ Release request for {basename} validated.")


def cmd_gate(args: argparse.Namespace) -> None:
    base = _env("BASE_SHA")
    merge_sha = _env("MERGE_SHA")

    added = _git_diff(base, merge_sha, "A")
    if len(added) != 1:
        print(f"Expected exactly 1 added release YAML, got {len(added)}. Skipping.")
        sys.exit(0)

    filepath = added[0]
    commit, tag = validate_yaml_file(filepath)
    cmd_create_tag(argparse.Namespace(tag=tag, commit=commit))


# ── main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Commit-Boost release management")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("validate-filename", help="Validate a release filename against strict semver")
    p.add_argument("basename")
    p.set_defaults(func=cmd_validate_filename)

    p = sub.add_parser("validate-yaml", help="Parse and validate a release-request YAML file")
    p.add_argument("path")
    p.set_defaults(func=cmd_validate_yaml)

    p = sub.add_parser("find-added", help="List release YAMLs added between two refs")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.set_defaults(func=cmd_find_added)

    p = sub.add_parser("check-modifications", help="Reject modifications/deletions of release YAMLs")
    p.add_argument("--base", required=True)
    p.add_argument("--head", required=True)
    p.set_defaults(func=cmd_check_modifications)

    p = sub.add_parser("check-commit-exists", help="Verify a commit SHA exists in the repo")
    p.add_argument("sha")
    p.set_defaults(func=cmd_check_commit_exists)

    p = sub.add_parser("check-tag-free", help="Verify a tag does not already exist")
    p.add_argument("tag")
    p.set_defaults(func=cmd_check_tag_free)

    p = sub.add_parser("check-signatures", help="Check that all commits to a ref are signed")
    p.add_argument("commit")
    p.set_defaults(func=cmd_check_signatures)

    p = sub.add_parser("create-tag", help="Create an annotated tag via GitHub API")
    p.add_argument("tag")
    p.add_argument("commit")
    p.set_defaults(func=cmd_create_tag)

    p = sub.add_parser("is-latest", help="Check if a tag is the highest non-RC semver")
    p.add_argument("tag")
    p.set_defaults(func=cmd_is_latest)

    p = sub.add_parser("validate-pr", help="End-to-end PR validator (reads env)")
    p.set_defaults(func=cmd_validate_pr)

    p = sub.add_parser("gate", help="End-to-end gate after merge (reads env)")
    p.set_defaults(func=cmd_gate)

    parsed = parser.parse_args()
    parsed.func(parsed)


if __name__ == "__main__":
    main()
