"""
Diff builder: constructs temp git repos from test case diffs.

Creates a base branch and a PR branch so CodeGuard can diff them.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from test_cases.ground_truth import TestCase


def _run_git(cwd: str, *args: str) -> str:
    """Run a git command in the given directory."""
    result = subprocess.run(
        ["git"] + list(args),
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed: {result.stderr.strip()}"
        )
    return result.stdout.strip()


def build_repo(case: TestCase, base_dir: Optional[str] = None) -> str:
    """
    Create a temp git repo with base and PR branches from the test case diff.

    Returns path to the temp repo directory.

    The repo has:
    - 'main' branch with empty/stub files
    - 'pr-{case.id}' branch with the diff applied
    """
    repo_dir = base_dir or tempfile.mkdtemp(prefix=f"codeguard-{case.id}-")

    # Init repo
    _run_git(repo_dir, "init", "-b", "main")
    _run_git(repo_dir, "config", "user.email", "test@codeguard.dev")
    _run_git(repo_dir, "config", "user.name", "CodeGuard Test")

    # Create stub files on main branch
    for file_path in case.files_changed:
        full_path = Path(repo_dir) / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        # Write a minimal placeholder
        full_path.write_text(
            f"# Placeholder for {file_path}\n",
            encoding="utf-8",
        )
        _run_git(repo_dir, "add", file_path)

    _run_git(repo_dir, "commit", "-m", "Initial commit")

    # Create PR branch
    branch_name = f"pr-{case.id}"
    _run_git(repo_dir, "checkout", "-b", branch_name)

    # Write the diff to a patch file and apply it
    patch_path = Path(repo_dir) / ".codeguard-patch.diff"
    patch_path.write_text(case.diff_content, encoding="utf-8")

    try:
        _run_git(repo_dir, "apply", "--allow-empty", str(patch_path))
    except RuntimeError:
        # If git apply fails (expected for synthetic diffs), write files directly
        _write_files_from_diff(repo_dir, case)

    # Stage and commit
    _run_git(repo_dir, "add", "-A")

    try:
        _run_git(repo_dir, "commit", "-m", f"PR: {case.name}")
    except RuntimeError:
        # Nothing to commit (diff didn't change anything)
        pass

    # Clean up patch file
    patch_path.unlink(missing_ok=True)

    return repo_dir


def _write_files_from_diff(repo_dir: str, case: TestCase) -> None:
    """
    Fallback: write files directly when git apply fails on synthetic diffs.
    Extracts '+' lines from the diff as the new file content.
    """
    current_file = None
    file_lines: dict[str, list[str]] = {}

    for line in case.diff_content.split("\n"):
        if line.startswith("+++ b/"):
            current_file = line[6:]
            if current_file not in file_lines:
                file_lines[current_file] = []
        elif line.startswith("--- "):
            continue
        elif line.startswith("@@"):
            continue
        elif line.startswith("+") and current_file:
            file_lines[current_file].append(line[1:])
        elif line.startswith(" ") and current_file:
            file_lines[current_file].append(line[1:])

    for file_path, lines in file_lines.items():
        if file_path == "/dev/null":
            continue
        full_path = Path(repo_dir) / file_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        full_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def get_diff(repo_dir: str, case_id: str) -> str:
    """Get the diff between main and the PR branch."""
    branch_name = f"pr-{case_id}"
    return _run_git(repo_dir, "diff", "main", branch_name)
