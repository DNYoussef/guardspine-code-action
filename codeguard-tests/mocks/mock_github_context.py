"""
Mock GitHub PR event context for local testing.

Simulates the GITHUB_EVENT_PATH and related env vars that
CodeGuard expects when running as a GitHub Action.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from test_cases.ground_truth import TestCase


@dataclass
class MockGitHubContext:
    """Simulated GitHub Actions context for a PR event."""
    owner: str = "test-org"
    repo: str = "test-repo"
    pr_number: int = 1
    base_branch: str = "main"
    head_branch: str = "feature/test"
    commit_sha: str = "abc1234567890def1234567890abcdef12345678"
    actor: str = "test-bot"

    def to_event_json(self) -> Dict[str, Any]:
        """Generate a pull_request event payload."""
        return {
            "action": "opened",
            "number": self.pr_number,
            "pull_request": {
                "number": self.pr_number,
                "head": {
                    "sha": self.commit_sha,
                    "ref": self.head_branch,
                },
                "base": {
                    "ref": self.base_branch,
                },
                "user": {
                    "login": self.actor,
                },
                "title": f"Test PR #{self.pr_number}",
                "body": "Synthetic test case for CodeGuard validation.",
            },
            "repository": {
                "full_name": f"{self.owner}/{self.repo}",
                "owner": {"login": self.owner},
                "name": self.repo,
            },
        }

    def write_event_file(self, directory: Optional[str] = None) -> str:
        """Write the event JSON to a temp file, return the path."""
        dir_path = directory or tempfile.gettempdir()
        event_path = Path(dir_path) / "github_event.json"
        with open(event_path, "w", encoding="utf-8") as f:
            json.dump(self.to_event_json(), f, indent=2)
        return str(event_path)

    def set_env_vars(self, repo_dir: str) -> Dict[str, str]:
        """
        Set GitHub Actions environment variables for local testing.

        Returns dict of env vars that were set (for cleanup).
        """
        event_path = self.write_event_file(repo_dir)
        env_vars = {
            "GITHUB_EVENT_PATH": event_path,
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_REPOSITORY": f"{self.owner}/{self.repo}",
            "GITHUB_SHA": self.commit_sha,
            "GITHUB_REF": f"refs/pull/{self.pr_number}/merge",
            "GITHUB_ACTOR": self.actor,
            "GITHUB_WORKSPACE": repo_dir,
        }
        for key, value in env_vars.items():
            os.environ[key] = value
        return env_vars

    @staticmethod
    def cleanup_env_vars(env_vars: Dict[str, str]) -> None:
        """Remove environment variables that were set."""
        for key in env_vars:
            os.environ.pop(key, None)


def create_context_for_case(case: TestCase, repo_dir: str) -> MockGitHubContext:
    """Create a MockGitHubContext tailored to a specific test case."""
    return MockGitHubContext(
        pr_number=int(case.id.split("-")[1]),
        head_branch=f"pr-{case.id}",
        base_branch="main",
    )
