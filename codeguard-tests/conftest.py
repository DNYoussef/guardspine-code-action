"""
Shared pytest fixtures for CodeGuard validation harness.

Provides the codeguard_runner fixture and session-scoped report collection.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

# Ensure test_cases and lib are importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.codeguard_runner import ParsedResult, run
from lib.council_analyzer import CouncilScore, analyze_council
from lib.report_generator import generate_reports
from test_cases.ground_truth import TestCase


class CodeGuardRunner:
    """Wrapper that runs CodeGuard and collects results for reporting."""

    def __init__(self):
        self.mode = "live" if os.environ.get("CODEGUARD_LIVE") == "1" else "replay"
        self._results: List[Dict[str, Any]] = []
        self._council_scores: List[CouncilScore] = []

    def run(self, case: TestCase) -> ParsedResult:
        """Run CodeGuard against a test case."""
        return run(case, mode=self.mode)

    def record_result(self, result: Dict[str, Any]) -> None:
        """Record a test result for the final report."""
        self._results.append(result)

    def record_council_score(self, score: CouncilScore) -> None:
        """Record a council score for the final report."""
        self._council_scores.append(score)

    def generate_report(self) -> None:
        """Generate the final summary report."""
        if self._results:
            generate_reports(self._results, self._council_scores)


# Session-scoped runner so all tests share state for reporting
_runner_instance = None


def get_runner() -> CodeGuardRunner:
    global _runner_instance
    if _runner_instance is None:
        _runner_instance = CodeGuardRunner()
    return _runner_instance


@pytest.fixture
def codeguard_runner() -> CodeGuardRunner:
    """Fixture providing the CodeGuard runner."""
    return get_runner()


def pytest_sessionfinish(session, exitstatus):
    """Generate reports after all tests complete."""
    runner = get_runner()
    try:
        runner.generate_report()
    except Exception as e:
        print(f"Warning: Report generation failed: {e}")
