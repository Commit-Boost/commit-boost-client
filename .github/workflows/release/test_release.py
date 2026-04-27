"""Tests for release.py — pure-logic and mocked-network coverage."""

import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import release

from release import (
    SEMVER_RE,
    _semver_key,
    cmd_check_commit_exists,
    cmd_check_modifications,
    cmd_check_tag_free,
    cmd_create_tag,
    cmd_find_added,
    cmd_gate,
    cmd_is_latest,
    cmd_lint,
    cmd_validate_filename,
    cmd_validate_pr,
    cmd_validate_yaml,
    GhApiError,
)

HERE = Path(__file__).parent


@pytest.fixture(autouse=True)
def _restore_cwd():
    """Restore working directory after each test."""
    orig = os.getcwd()
    yield
    os.chdir(orig)


def _write_yaml(tmp_path: Path, name: str, content: str) -> str:
    """Write a YAML fixture into tmp_path and return the absolute path."""
    p = tmp_path / name
    p.write_text(content)
    return str(p)


# Inline YAML fixtures — kept next to the tests that use them for readability.
GOOD_YAML = """\
commit: abcdef1234567890abcdef1234567890abcdef12
reason: "Emergency pagination fix"
"""

BAD_SCHEMA_YAML = """\
commit: abcdef1234567890abcdef1234567890abcdef12
"""  # missing reason

BAD_SHA_LENGTH_YAML = """\
commit: abcdef1234567890abcdef1234567890abcdef123
reason: "Too long SHA"
"""

BAD_SHA_CHARS_YAML = """\
commit: xbcdef1234567890abcdef1234567890abcdef12
reason: "Invalid hex char x"
"""

EMPTY_REASON_YAML = """\
commit: abcdef1234567890abcdef1234567890abcdef12
reason: ""
"""

NOT_A_MAPPING_YAML = """\
- item1
- item2
"""


# ── validate-filename ────────────────────────────────────────────────────────

class TestValidateFilename:
    def test_passes_full_release(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2.3"))
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "✅" in out

    def test_passes_rc_release(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2.3-rc1"))
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "✅" in out

    def test_passes_v0_0_1(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v0.0.1"))
        assert exc.value.code == 0

    def test_passes_v10_20_30(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v10.20.30"))
        assert exc.value.code == 0

    def test_fails_no_v_prefix(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="1.2.3"))
        assert exc.value.code == 1

    def test_fails_leading_zero_major(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v01.2.3"))
        assert exc.value.code == 1

    def test_fails_leading_zero_minor(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.02.3"))
        assert exc.value.code == 1

    def test_fails_leading_zero_patch(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2.03"))
        assert exc.value.code == 1

    def test_fails_rc0(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2.3-rc0"))
        assert exc.value.code == 1

    def test_fails_missing_patch(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2"))
        assert exc.value.code == 1

    def test_fails_yaml_extension(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename="v1.2.3.yaml"))
        assert exc.value.code == 1

    def test_fails_empty(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_filename(_ns(basename=""))
        assert exc.value.code == 1

    # -- regex-level tests (belt and suspenders) --

    @pytest.mark.parametrize("good", [
        "v0.0.0",
        "v1.0.0",
        "v10.20.30",
        "v0.0.0-rc1",
        "v1.2.3-rc99",
        "v999.999.999",
    ])
    def test_regex_good(self, good):
        assert SEMVER_RE.match(good), f"expected {good} to match"

    @pytest.mark.parametrize("bad", [
        "",
        "1.2.3",
        "v01.2.3",
        "v1.02.3",
        "v1.2.03",
        "v1.2",
        "v1.2.3.4",
        "v1.2.3.yaml",
        "v1.2.3-rc0",
        "v1.2.3-rc",
        "v1.2.3-alpha",
        "v1.2.3-RC1",
    ])
    def test_regex_bad(self, bad):
        assert SEMVER_RE.match(bad) is None, f"expected {bad} to NOT match"


# ── validate-yaml ────────────────────────────────────────────────────────────

class TestValidateYaml:
    def test_good_yaml(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", GOOD_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 0
        out = capsys.readouterr().out
        assert "commit=" in out
        assert "tag=" in out
        assert "✅" in out

    def test_missing_fields(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", BAD_SCHEMA_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 1
        out = capsys.readouterr().out
        assert "❌" in out
        assert "reason" in out

    def test_bad_sha_length(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", BAD_SHA_LENGTH_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 1

    def test_bad_sha_chars(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", BAD_SHA_CHARS_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 1

    def test_empty_reason(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", EMPTY_REASON_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 1

    def test_non_mapping_root(self, tmp_path, capsys):
        path = _write_yaml(tmp_path, "v1.2.3.yml", NOT_A_MAPPING_YAML)
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path=path))
        assert exc.value.code == 1

    def test_file_not_found(self, capsys):
        with pytest.raises(SystemExit) as exc:
            cmd_validate_yaml(_ns(path="/nonexistent.yml"))
        assert exc.value.code == 1


# ── is-latest ────────────────────────────────────────────────────────────────

class TestIsLatest:
    def test_highest_tag_returns_true(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\nv1.1.0\nv2.0.0\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v2.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"

    def test_lower_tag_returns_false(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\nv1.1.0\nv2.0.0\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v1.1.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "false"

    def test_rc_tags_excluded(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\nv1.1.0-rc1\nv1.1.0-rc2\nv2.0.0-rc1\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v1.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"  # v1.0.0 is highest non-RC

    def test_empty_tag_list_returns_true(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = ""
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v1.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"

    def test_only_rc_tags_returns_true(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0-rc1\nv2.0.0-rc1\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v3.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"

    def test_rc_tags_excluded_highest_non_rc_wins(self, capsys):
        """v1.0.0 is the only non-RC, so it's the highest, not v2.0.0-rc1."""
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\nv2.0.0-rc1\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v2.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "false"  # v2.0.0 doesn't exist yet
            # Now test the highest non-RC is v1.0.0
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\nv2.0.0-rc1\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v1.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"  # v1.0.0 IS the highest non-RC

    def test_single_tag_returns_true(self, capsys):
        with patch("release._run") as mock_run:
            mock_run.return_value = "v1.0.0\n"
            with pytest.raises(SystemExit) as exc:
                cmd_is_latest(_ns(tag="v1.0.0"))
            assert exc.value.code == 0
            out = capsys.readouterr().out.strip()
            assert out == "true"


# ── find-added-releases (tmp git repo) ───────────────────────────────────────

class TestFindAddedReleases:
    def test_finds_added_file(self, tmp_path):
        os.chdir(str(tmp_path))
        _init_git_repo(tmp_path)
        _git_commit(tmp_path, "initial", files={"README.md": "hello"})
        base = _git_rev(tmp_path, "HEAD")
        _git_commit(tmp_path, "add release", files={
            ".releases/v1.2.3.yml": "commit: a\nreason: test\n"
        })
        head = _git_rev(tmp_path, "HEAD")
        with pytest.raises(SystemExit) as exc:
            cmd_find_added(_ns(base=base, head=head))
        assert exc.value.code == 0

    def test_no_added_files(self, tmp_path, capsys):
        os.chdir(str(tmp_path))
        _init_git_repo(tmp_path)
        _git_commit(tmp_path, "initial", files={"README.md": "hello"})
        base = _git_rev(tmp_path, "HEAD")
        _git_commit(tmp_path, "add another file", files={"other.txt": "stuff"})
        head = _git_rev(tmp_path, "HEAD")
        with pytest.raises(SystemExit) as exc:
            cmd_find_added(_ns(base=base, head=head))
        assert exc.value.code == 0


# ── check-modifications (tmp git repo) ───────────────────────────────────────

class TestCheckModifications:
    def test_no_modifications_passes(self, tmp_path):
        os.chdir(str(tmp_path))
        _init_git_repo(tmp_path)
        _git_commit(tmp_path, "initial", files={"README.md": "hello"})
        base = _git_rev(tmp_path, "HEAD")
        _git_commit(tmp_path, "add unrelated", files={"other.txt": "stuff"})
        head = _git_rev(tmp_path, "HEAD")
        with pytest.raises(SystemExit) as exc:
            cmd_check_modifications(_ns(base=base, head=head))
        assert exc.value.code == 0

    def test_modification_fails(self, tmp_path):
        os.chdir(str(tmp_path))
        _init_git_repo(tmp_path)
        _git_commit(tmp_path, "initial", files={
            ".releases/v1.0.0.yml": "commit: a\nreason: test\n"
        })
        base = _git_rev(tmp_path, "HEAD")
        _git_commit(tmp_path, "modify release", files={
            ".releases/v1.0.0.yml": "commit: b\nreason: modified\n"
        })
        head = _git_rev(tmp_path, "HEAD")
        with pytest.raises(SystemExit) as exc:
            cmd_check_modifications(_ns(base=base, head=head))
        assert exc.value.code == 1

    def test_deletion_fails(self, tmp_path):
        os.chdir(str(tmp_path))
        _init_git_repo(tmp_path)
        _git_commit(tmp_path, "initial", files={
            ".releases/v1.0.0.yml": "commit: a\nreason: test\n"
        })
        base = _git_rev(tmp_path, "HEAD")
        (tmp_path / ".releases" / "v1.0.0.yml").unlink()
        subprocess.run(["git", "rm", ".releases/v1.0.0.yml"], cwd=str(tmp_path), capture_output=True)
        _git_commit(tmp_path, "delete release", files={})
        head = _git_rev(tmp_path, "HEAD")
        with pytest.raises(SystemExit) as exc:
            cmd_check_modifications(_ns(base=base, head=head))
        assert exc.value.code == 1


# ── check-commit-exists, check-tag-free ──────────────────────────────────────

class TestCheckCommitExists:
    def test_commit_exists(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.return_value = {"sha": "abc123"}
            with pytest.raises(SystemExit) as exc:
                cmd_check_commit_exists(_ns(sha="abc123"))
            assert exc.value.code == 0

    def test_commit_missing(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.side_effect = GhApiError("not found")
            with pytest.raises(SystemExit) as exc:
                cmd_check_commit_exists(_ns(sha="abc123"))
            assert exc.value.code == 1


class TestCheckTagFree:
    def test_tag_free(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.side_effect = GhApiError("not found")
            with pytest.raises(SystemExit) as exc:
                cmd_check_tag_free(_ns(tag="v1.2.3"))
            assert exc.value.code == 0

    def test_tag_exists(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.return_value = {"ref": "refs/tags/v1.2.3"}
            with pytest.raises(SystemExit) as exc:
                cmd_check_tag_free(_ns(tag="v1.2.3"))
            assert exc.value.code == 1


# ── create-tag ───────────────────────────────────────────────────────────────

class TestCreateTag:
    def test_creates_tag_successfully(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.side_effect = [
                {"sha": "tag_obj_sha_123"},  # POST /git/tags
                {},                           # POST /git/refs
            ]
            with pytest.raises(SystemExit) as exc:
                cmd_create_tag(_ns(tag="v1.2.3", commit="abc123"))
            assert exc.value.code == 0
            assert "✅" in capsys.readouterr().out

    def test_fails_when_tag_object_has_no_sha(self, capsys):
        with patch("release.gh_api") as mock_gh:
            mock_gh.return_value = {}  # no sha field
            with pytest.raises(SystemExit) as exc:
                cmd_create_tag(_ns(tag="v1.2.3", commit="abc123"))
            assert exc.value.code == 1


# ── _semver_key ──────────────────────────────────────────────────────────────

class TestSemverKey:
    def test_normal(self):
        assert _semver_key("v1.2.3") == (1, 2, 3, float("inf"))
        assert _semver_key("v10.20.30") == (10, 20, 30, float("inf"))

    def test_rc(self):
        key = _semver_key("v1.2.3-rc4")
        assert key == (1, 2, 3, 4)

    def test_rc_higher_than_normal(self):
        """RC versions sort before the full release of the same semver."""
        rc = _semver_key("v1.2.3-rc4")
        full = _semver_key("v1.2.3")
        assert rc < full  # rc4's 4 < inf

    def test_sort_order(self):
        tags = ["v2.0.0", "v1.10.0", "v1.2.3-rc4", "v1.2.3", "v1.2.3-rc1"]
        sorted_tags = sorted(tags, key=_semver_key)
        assert sorted_tags == [
            "v1.2.3-rc1",
            "v1.2.3-rc4",
            "v1.2.3",
            "v1.10.0",
            "v2.0.0",
        ]

    def test_rejects_non_strict(self):
        """_semver_key fails loudly on tags that don't match SEMVER_RE."""
        for bad in ["v0.7.0-rc.1", "v0.9.2-rc-dev", "v2.0.0-rc2-1",
                    "v01.02.03", "1.2.3", "garbage"]:
            with pytest.raises(ValueError):
                _semver_key(bad)


# ── helpers ──────────────────────────────────────────────────────────────────

def _ns(**kwargs):
    """Build a simple argparse.Namespace stand-in."""
    from types import SimpleNamespace
    return SimpleNamespace(**kwargs)


# git helpers for tmp-dir based tests

def _init_git_repo(path: Path) -> None:
    subprocess.run(["git", "init"], cwd=str(path), capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"],
        cwd=str(path), capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test"],
        cwd=str(path), capture_output=True,
    )


def _git_commit(path: Path, msg: str, files: dict[str, str]) -> None:
    for relpath, content in files.items():
        full = path / relpath
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(content)
        subprocess.run(["git", "add", relpath], cwd=str(path), capture_output=True)
    subprocess.run(["git", "commit", "-m", msg], cwd=str(path), capture_output=True)


def _git_rev(path: Path, ref: str) -> str:
    r = subprocess.run(
        ["git", "rev-parse", ref],
        cwd=str(path), capture_output=True, text=True,
    )
    return r.stdout.strip()


