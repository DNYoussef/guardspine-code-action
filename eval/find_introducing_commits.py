#!/usr/bin/env python3
"""SZZ-based introducing commit finder.

Mechanically identifies the commit(s) that introduced a vulnerability by
running git-blame on lines deleted (or surrounding additions) in a fix commit.

Usage:
    # Single CVE (JSON to stdout)
    python3 find_introducing_commits.py --repo-dir ./django --fix-commit abc123

    # Batch from manifest (JSONL to stdout)
    python3 find_introducing_commits.py --manifest real-cve-manifest.yaml

    # Batch + write results back to YAML
    python3 find_introducing_commits.py --manifest real-cve-manifest.yaml --update-manifest

    # Validate confidence that a specific commit introduced the bug
    python3 find_introducing_commits.py --repo-dir ./django --fix-commit abc123 \
        --validate-intro def456 --cve-id CVE-2024-1234
"""

from __future__ import annotations

import argparse
import json
import io
import os
import re
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class HunkRange:
    start: int  # 1-based inclusive
    end: int    # 1-based inclusive


@dataclass
class CommitMeta:
    sha: str
    date: str          # YYYY-MM-DD
    summary: str
    is_initial_commit: bool = False


@dataclass
class SZZResult:
    fix_commit: str
    candidates: list[CommitMeta]
    flags: list[str]
    files_analyzed: list[str]
    deleted_line_count: int
    diff_text: str = ""


# ---------------------------------------------------------------------------
# Layer 1 - Git primitives
# ---------------------------------------------------------------------------

def run_git(args: list[str], repo_dir: str, timeout: int = 30) -> str:
    """Run a git command and return stdout."""
    cmd = ["git", "-C", repo_dir] + args
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"git command timed out: {' '.join(cmd)}")
    if result.returncode != 0:
        raise RuntimeError(
            f"git command failed (rc={result.returncode}): {' '.join(cmd)}\n"
            f"{result.stderr.strip()}"
        )
    return result.stdout


def get_fix_diff(repo_dir: str, fix_sha: str) -> str:
    """Get the full diff for a commit (against its first parent)."""
    # Try diff-tree first (works for non-merge commits)
    result = run_git(
        ["diff-tree", "-p", "--no-commit-id", "-M", fix_sha],
        repo_dir,
    )
    if result.strip():
        return result
    # For merge commits, explicitly diff against first parent
    try:
        first_parent = run_git(
            ["rev-parse", f"{fix_sha}^1"], repo_dir
        ).strip()
        return run_git(["diff", "-M", first_parent, fix_sha], repo_dir)
    except RuntimeError:
        return result


def is_merge_commit(repo_dir: str, sha: str) -> bool:
    parents = run_git(["rev-parse", f"{sha}^@"], repo_dir).strip().splitlines()
    return len(parents) > 1


def is_root_commit(repo_dir: str, sha: str) -> bool:
    try:
        run_git(["rev-parse", f"{sha}^"], repo_dir)
        return False
    except RuntimeError:
        return True


def get_commit_meta(repo_dir: str, sha: str) -> CommitMeta:
    raw = run_git(
        ["log", "-1", "--format=%H%n%as%n%s", sha],
        repo_dir,
    ).strip()
    lines = raw.splitlines()
    full_sha = lines[0]
    date = lines[1] if len(lines) > 1 else ""
    summary = lines[2] if len(lines) > 2 else ""
    initial = is_root_commit(repo_dir, full_sha)
    return CommitMeta(sha=full_sha, date=date, summary=summary, is_initial_commit=initial)


# ---------------------------------------------------------------------------
# Layer 2 - Diff parsing
# ---------------------------------------------------------------------------

_DIFF_HEADER = re.compile(r"^diff --git a/(.+?) b/(.+)$")
_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def parse_deleted_ranges(diff_text: str) -> dict[str, list[HunkRange]]:
    """Parse diff and return ranges of deleted lines per file (old-side line numbers)."""
    result: dict[str, list[HunkRange]] = {}
    current_file: Optional[str] = None
    old_line = 0

    for line in diff_text.splitlines():
        m = _DIFF_HEADER.match(line)
        if m:
            current_file = m.group(1)
            continue

        m = _HUNK_HEADER.match(line)
        if m:
            old_line = int(m.group(1))
            continue

        if current_file is None:
            continue

        if line.startswith("-") and not line.startswith("---"):
            if current_file not in result:
                result[current_file] = []
            ranges = result[current_file]
            # Merge with previous range if contiguous
            if ranges and ranges[-1].end == old_line - 1:
                ranges[-1].end = old_line
            else:
                ranges.append(HunkRange(start=old_line, end=old_line))
            old_line += 1
        elif line.startswith("+") and not line.startswith("+++"):
            # Added line: doesn't advance old-side counter
            pass
        elif line.startswith("\\"):
            # "No newline at end of file"
            pass
        else:
            # Context line
            old_line += 1

    return result


def get_context_ranges_for_additions(
    diff_text: str, context: int = 5
) -> dict[str, list[HunkRange]]:
    """For add-only fixes, get context ranges around insertion points."""
    result: dict[str, list[HunkRange]] = {}
    current_file: Optional[str] = None
    old_line = 0
    old_total = 0
    insertion_points: dict[str, set[int]] = {}

    for line in diff_text.splitlines():
        m = _DIFF_HEADER.match(line)
        if m:
            current_file = m.group(1)
            continue

        m = _HUNK_HEADER.match(line)
        if m:
            old_line = int(m.group(1))
            old_total = int(m.group(2)) if m.group(2) else 1
            continue

        if current_file is None:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if current_file not in insertion_points:
                insertion_points[current_file] = set()
            insertion_points[current_file].add(old_line)
        elif line.startswith("-") and not line.startswith("---"):
            old_line += 1
        elif line.startswith("\\"):
            pass
        else:
            old_line += 1

    for filepath, points in insertion_points.items():
        ranges = []
        for pt in sorted(points):
            start = max(1, pt - context)
            end = pt + context
            # Merge overlapping
            if ranges and ranges[-1].end >= start - 1:
                ranges[-1].end = max(ranges[-1].end, end)
            else:
                ranges.append(HunkRange(start=start, end=end))
        result[filepath] = ranges

    return result


# ---------------------------------------------------------------------------
# Layer 3 - Blame collection
# ---------------------------------------------------------------------------

def _find_ignore_revs_file(repo_dir: str) -> Optional[str]:
    """Check if repo has a .git-blame-ignore-revs file."""
    path = Path(repo_dir).resolve() / ".git-blame-ignore-revs"
    if path.is_file():
        return str(path)
    return None


def blame_range(
    repo_dir: str,
    parent_sha: str,
    file_path: str,
    start: int,
    end: int,
    ignore_revs_file: Optional[str] = None,
) -> set[str]:
    """Run git blame on a line range and return set of SHAs."""
    blame_args = ["blame", "-w", "-C", "-C", "-l"]
    if ignore_revs_file:
        blame_args.extend(["--ignore-revs-file", ignore_revs_file])
    blame_args.extend(["-L", f"{start},{end}", parent_sha, "--", file_path])
    try:
        raw = run_git(blame_args, repo_dir)
    except RuntimeError:
        if ignore_revs_file:
            # Retry without ignore-revs (file may reference commits not in history)
            fallback = ["blame", "-w", "-C", "-C", "-l",
                        "-L", f"{start},{end}", parent_sha, "--", file_path]
            try:
                raw = run_git(fallback, repo_dir)
            except RuntimeError:
                return set()
        else:
            return set()

    shas = set()
    for bline in raw.splitlines():
        # git blame -l outputs: <full_sha> <rest>
        # Handle initial-commit prefix ^
        stripped = bline.lstrip("^")
        parts = stripped.split(None, 1)
        if parts:
            sha = parts[0]
            if len(sha) >= 40 and all(c in "0123456789abcdef" for c in sha[:40]):
                shas.add(sha[:40])
    return shas


def collect_candidates(
    repo_dir: str,
    fix_sha: str,
    ranges: dict[str, list[HunkRange]],
) -> tuple[set[str], list[str], int]:
    """Blame all ranges, return (candidate_shas, files_analyzed, deleted_line_count)."""
    # Determine parent
    parent_sha = fix_sha + "~1"
    ignore_revs = _find_ignore_revs_file(repo_dir)

    all_shas: set[str] = set()
    files_analyzed: list[str] = []
    total_lines = 0

    for filepath, hunk_ranges in ranges.items():
        files_analyzed.append(filepath)
        for hr in hunk_ranges:
            total_lines += hr.end - hr.start + 1
            shas = blame_range(
                repo_dir, parent_sha, filepath, hr.start, hr.end, ignore_revs
            )
            all_shas.update(shas)

    return all_shas, files_analyzed, total_lines


# ---------------------------------------------------------------------------
# Layer 4 - Ranking
# ---------------------------------------------------------------------------

def filter_and_rank(
    repo_dir: str,
    shas: set[str],
    n: int = 5,
) -> list[CommitMeta]:
    """Remove merges, sort by date ascending, take N oldest."""
    candidates: list[CommitMeta] = []
    for sha in shas:
        try:
            if is_merge_commit(repo_dir, sha):
                continue
            meta = get_commit_meta(repo_dir, sha)
            candidates.append(meta)
        except RuntimeError:
            continue

    candidates.sort(key=lambda c: c.date)
    return candidates[:n]


# ---------------------------------------------------------------------------
# Layer 5 - Orchestration
# ---------------------------------------------------------------------------

_NOISE_PATTERNS = re.compile(
    r"(^docs/releases/|/changelog|CHANGES\.|HISTORY\.|NEWS\b)", re.IGNORECASE
)


def _is_noise_file(path: str) -> bool:
    """Check if a file is likely a release note/changelog (noisy for blame)."""
    return bool(_NOISE_PATTERNS.search(path))


def _prioritize_source_files(
    ranges: dict[str, list[HunkRange]],
) -> dict[str, list[HunkRange]]:
    """Sort files: source first, then tests, then docs/release-notes.
    Drop release-note files entirely if there are source files."""
    source = {}
    tests = {}
    noise = {}
    for path, hrs in ranges.items():
        if _is_noise_file(path):
            noise[path] = hrs
        elif "/test" in path or path.startswith("test"):
            tests[path] = hrs
        else:
            source[path] = hrs

    # If we have source files, drop release notes entirely
    if source:
        result = dict(source)
        result.update(tests)
        return result
    # Fallback: use everything
    result = dict(tests)
    result.update(noise)
    return result


def analyze_fix(
    repo_dir: str,
    fix_sha: str,
    n: int = 5,
    max_files: int = 20,
) -> SZZResult:
    """Full SZZ pipeline for a single fix commit."""
    flags: list[str] = []

    # Get diff
    try:
        diff_text = get_fix_diff(repo_dir, fix_sha)
    except RuntimeError as e:
        print(f"WARNING: Could not get diff for {fix_sha}: {e}", file=sys.stderr)
        return SZZResult(
            fix_commit=fix_sha,
            candidates=[],
            flags=["empty_diff"],
            files_analyzed=[],
            deleted_line_count=0,
        )

    if not diff_text.strip():
        return SZZResult(
            fix_commit=fix_sha,
            candidates=[],
            flags=["empty_diff"],
            files_analyzed=[],
            deleted_line_count=0,
        )

    # Parse deleted ranges
    ranges = parse_deleted_ranges(diff_text)

    if not ranges:
        # Add-only fix: use context blame
        flags.append("add_only_fix")
        ranges = get_context_ranges_for_additions(diff_text)

    if not ranges:
        return SZZResult(
            fix_commit=fix_sha,
            candidates=[],
            flags=flags + ["empty_diff"],
            files_analyzed=[],
            deleted_line_count=0,
        )

    # Prioritize source files over docs/tests/release-notes
    ranges = _prioritize_source_files(ranges)

    # Cap files
    if len(ranges) > max_files:
        flags.append("too_many_files")
        # Keep the first max_files entries
        capped = dict(list(ranges.items())[:max_files])
        ranges = capped

    # Collect blame candidates
    all_shas, files_analyzed, deleted_line_count = collect_candidates(
        repo_dir, fix_sha, ranges
    )

    if not all_shas:
        flags.append("blame_error")

    # Rank
    candidates = filter_and_rank(repo_dir, all_shas, n=n)

    # Check for initial commit
    if candidates and candidates[0].is_initial_commit:
        flags.append("initial_commit_candidate")

    return SZZResult(
        fix_commit=fix_sha,
        candidates=candidates,
        flags=flags,
        files_analyzed=files_analyzed,
        deleted_line_count=deleted_line_count,
        diff_text=diff_text,
    )


def result_to_dict(r: SZZResult) -> dict:
    """Convert SZZResult to a JSON-serializable dict."""
    return {
        "fix_commit": r.fix_commit,
        "candidates": [
            {
                "sha": c.sha,
                "date": c.date,
                "summary": c.summary,
                "is_initial_commit": c.is_initial_commit,
            }
            for c in r.candidates
        ],
        "flags": r.flags,
        "files_analyzed": r.files_analyzed,
        "deleted_line_count": r.deleted_line_count,
    }


# ---------------------------------------------------------------------------
# Manifest helpers (requires PyYAML)
# ---------------------------------------------------------------------------

def load_manifest(path: str) -> list[dict]:
    import yaml
    with open(path, "r") as f:
        data = yaml.safe_load(f)
    return data.get("vulnerabilities", [])


def save_manifest(path: str, vulns: list[dict]) -> None:
    import yaml
    data = {"vulnerabilities": vulns}
    with open(path, "w") as f:
        # Preserve readable formatting
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def repo_dir_for_entry(entry: dict, base_dir: str) -> str:
    """Determine repo directory from manifest entry."""
    repo = entry["repo"]  # e.g. "django/django"
    repo_name = repo.split("/")[-1]
    return str(Path(base_dir) / repo_name)


def run_batch(manifest_path: str, update: bool = False, claude: bool = False) -> None:
    """Run SZZ analysis for all entries in a manifest."""
    vulns = load_manifest(manifest_path)
    base_dir = str(Path(manifest_path).parent)

    for entry in vulns:
        fix_sha = entry.get("fix_commit", "")
        cve_id = entry.get("cve_id", "unknown")
        repo_dir = repo_dir_for_entry(entry, base_dir)

        if not fix_sha:
            print(f"WARNING: No fix_commit for {cve_id}, skipping", file=sys.stderr)
            continue

        if not Path(repo_dir).is_dir():
            print(f"WARNING: Repo dir {repo_dir} not found for {cve_id}, skipping", file=sys.stderr)
            continue

        print(f"Analyzing {cve_id} ({fix_sha[:12]})...", file=sys.stderr)

        result = analyze_fix(repo_dir, fix_sha)
        output = result_to_dict(result)
        output["cve_id"] = cve_id

        # JSONL to stdout
        print(json.dumps(output))

        if claude:
            run_claude_judgment(
                repo_dir, fix_sha, result,
                cve_id=cve_id,
                description=entry.get("description", ""),
            )

        # Update manifest entry
        if update and result.candidates:
            entry["introducing_commit"] = result.candidates[0].sha
            entry["introducing_date"] = result.candidates[0].date
            entry["introducing_summary"] = result.candidates[0].summary
            entry["introducing_candidates"] = [
                {"sha": c.sha, "date": c.date, "summary": c.summary}
                for c in result.candidates
            ]

    if update:
        save_manifest(manifest_path, vulns)
        print(f"Updated manifest: {manifest_path}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Claude CLI judgment
# ---------------------------------------------------------------------------

_CLAUDE_PROMPT_TEMPLATE = """\
You identify the git commit that first introduced a vulnerability. You combine
mechanical SZZ blame analysis with LLM judgment to produce a reasoned verdict.

## Context

- **CVE**: {cve_id}
- **Description**: {description}
- **Repository**: {repo_dir}
- **Fix commit**: `{fix_sha}`
- **SZZ flags**: {flags}

## Fix Diff

```diff
{diff_text_truncated}
```

## SZZ Candidate Commits

{candidate_table}

## Instructions

For each candidate commit above:

1. Run `git show <sha>` to read its diff
2. Apply this skeptical rubric:
   - **Does it actually introduce the vulnerable code pattern?** The candidate must add the specific lines/logic that created the vulnerability.
   - **Is it just a reformatter/linter?** Check commit message and diff for bulk formatting changes. These don't introduce vulnerabilities.
   - **Is it a refactor preserving existing behavior?** Moving code between files or renaming without changing semantics doesn't introduce a bug.
   - **Is it an initial import/repo creation?** If the code existed before the repo was created, the true introducing commit is unknowable from this repo alone.
   - **Does the vulnerability span multiple commits?** Sometimes a vulnerability requires code from several commits working together.

## Output Format

Produce a structured verdict:

## Introducing Commit Analysis

**CVE**: {cve_id}
**Fix commit**: `{fix_sha}`

### Verdict

| Field | Value |
|-------|-------|
| **Introducing commit** | `<sha>` |
| **Date** | <date> |
| **Summary** | <summary> |
| **Confidence** | HIGH / MEDIUM / LOW |

### Reasoning

2-5 sentences explaining why this candidate is the introducing commit.

### Why This Commit Introduced the Bug

1. **What did the commit add or change?**
2. **What specific code pattern is vulnerable?** — Quote or paraphrase the exact lines/logic.
3. **Why was this a reasonable mistake?**
4. **How did the fix address it?**

### All Candidates

| # | SHA | Date | Summary | Verdict |
|---|-----|------|---------|---------|
(one row per candidate)

## Confidence Levels

- **HIGH**: Candidate clearly adds the vulnerable code pattern for the first time.
- **MEDIUM**: Likely correct but vulnerability may span multiple commits, candidate is very old, or the pattern is subtle.
- **LOW**: Noisy results — add-only fix, initial commit candidate, or too many files touched.

## Edge Cases

- If flags contain `add_only_fix`: Context blame was used, which is less precise. Set confidence to LOW unless clearly confirmed.
- If flags contain `initial_commit_candidate`: Check if the vulnerable code was part of an initial import.
- If no candidates: Suggest manual investigation with `git log -S '<pattern>'`.
"""

_CLAUDE_VALIDATE_PROMPT_TEMPLATE = """\
You evaluate whether a specific git commit introduced a vulnerability.

## Context

- **CVE**: {cve_id}
- **Description**: {description}
- **Repository**: {repo_dir}
- **Fix commit**: `{fix_sha}`
- **Candidate commit to validate**: `{candidate_sha}`
- **SZZ flags**: {flags}

## Fix Diff (what was removed to fix the bug)

```diff
{fix_diff_truncated}
```

## Candidate Commit Diff (what this commit added/changed)

```diff
{candidate_diff_truncated}
```

## Instructions

Determine whether the candidate commit introduced the vulnerable code pattern.

1. Review the fix diff to understand what was removed/fixed.
2. Review the candidate commit diff to see what it added or changed.
3. Apply this rubric:
   - **Does the candidate add the exact code that was later removed in the fix?** Best case: direct match.
   - **Does the candidate add code that led to the vulnerability?** Good case: introduces the pattern.
   - **Could this commit be a false positive?** Check for formatting, refactoring, or initial import.
   - **Does the fix target code introduced by this commit?** If fix targets lines from this commit, it's likely correct.

## Output Format

Provide ONLY the following fields as JSON (no markdown, no extra text):

```json
{{
  "candidate_sha": "{candidate_sha}",
  "confidence": "HIGH|MEDIUM|LOW",
  "reasoning": "2-3 sentence explanation of the confidence assessment",
  "matches_fix_pattern": true|false,
  "notes": "Any additional observations"
}}
```

## Confidence Levels

- **HIGH**: Candidate clearly adds the code pattern that was later fixed. The fix directly targets lines from this commit.
- **MEDIUM**: Candidate likely introduced the vulnerability, but the evidence is not conclusive (subtle pattern, multiple commits involved, or limited diff context).
- **LOW**: Noisy signals or unclear connection between candidate and fix (formatting changes, very old commit, add-only fix used, or limited code visibility).
"""


def _build_candidate_table(candidates: list[CommitMeta]) -> str:
    if not candidates:
        return "(no candidates returned by SZZ)"
    lines = ["| # | SHA | Date | Summary |", "|---|-----|------|---------|"]
    for i, c in enumerate(candidates, 1):
        lines.append(f"| {i} | `{c.sha}` | {c.date} | {c.summary} |")
    return "\n".join(lines)


def validate_introducing_commit(
    repo_dir: str,
    fix_sha: str,
    candidate_sha: str,
    cve_id: str = "",
    description: str = "",
) -> dict:
    """Use Claude to evaluate confidence that a candidate introduced the vulnerability.

    Returns a dict with:
      - candidate_sha: the validated commit SHA
      - confidence: HIGH/MEDIUM/LOW
      - reasoning: explanation
      - matches_fix_pattern: bool
      - notes: additional observations
    """
    # Get the fix diff
    try:
        fix_diff = get_fix_diff(repo_dir, fix_sha)
    except RuntimeError as e:
        print(f"ERROR: Could not get fix diff for {fix_sha}: {e}", file=sys.stderr)
        return {
            "candidate_sha": candidate_sha,
            "confidence": "LOW",
            "reasoning": "Could not retrieve fix diff",
            "matches_fix_pattern": False,
            "notes": str(e),
        }

    # Get the candidate commit diff
    try:
        candidate_diff = get_fix_diff(repo_dir, candidate_sha)
    except RuntimeError as e:
        print(f"ERROR: Could not get diff for candidate {candidate_sha}: {e}", file=sys.stderr)
        return {
            "candidate_sha": candidate_sha,
            "confidence": "LOW",
            "reasoning": "Could not retrieve candidate diff",
            "matches_fix_pattern": False,
            "notes": str(e),
        }

    # Truncate diffs to avoid context overflow
    def _truncate_diff(diff_text: str, max_lines: int = 4000) -> str:
        lines = diff_text.splitlines()
        if len(lines) > max_lines:
            return "\n".join(lines[:max_lines]) + \
                f"\n... (truncated, {len(lines) - max_lines} more lines)"
        return diff_text

    fix_diff_truncated = _truncate_diff(fix_diff)
    candidate_diff_truncated = _truncate_diff(candidate_diff)

    # Get candidate metadata for context
    try:
        candidate_meta = get_commit_meta(repo_dir, candidate_sha)
    except RuntimeError:
        candidate_meta = CommitMeta(sha=candidate_sha, date="", summary="")

    # Get analysis flags for context
    ranges = parse_deleted_ranges(fix_diff)
    flags = []
    if not ranges:
        flags.append("add_only_fix")
    if is_root_commit(repo_dir, candidate_sha):
        flags.append("initial_commit_candidate")

    prompt = _CLAUDE_VALIDATE_PROMPT_TEMPLATE.format(
        cve_id=cve_id or "unknown",
        description=description or "Not provided",
        repo_dir=repo_dir,
        fix_sha=fix_sha,
        candidate_sha=candidate_sha,
        flags=", ".join(flags) if flags else "none",
        fix_diff_truncated=fix_diff_truncated,
        candidate_diff_truncated=candidate_diff_truncated,
    )

    # Call Claude and parse JSON response
    cmd = ["claude", "-p", "--output-format", "text"]

    print(f"Validating candidate {candidate_sha[:12]} for fix {fix_sha[:12]}...", file=sys.stderr)

    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    prompt_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    )
    try:
        prompt_file.write(prompt)
        prompt_file.close()

        stdin_fh = open(prompt_file.name, "r")
        try:
            result = subprocess.run(
                cmd,
                stdin=stdin_fh,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=repo_dir,
                env=env,
                timeout=60,
            )
        except FileNotFoundError:
            stdin_fh.close()
            print(
                "ERROR: 'claude' CLI not found. Install it or ensure it's on PATH.",
                file=sys.stderr,
            )
            return {
                "candidate_sha": candidate_sha,
                "confidence": "LOW",
                "reasoning": "Claude CLI not available",
                "matches_fix_pattern": False,
                "notes": "Could not invoke claude CLI",
            }
        except subprocess.TimeoutExpired:
            stdin_fh.close()
            print("ERROR: Claude evaluation timed out", file=sys.stderr)
            return {
                "candidate_sha": candidate_sha,
                "confidence": "LOW",
                "reasoning": "Evaluation timed out",
                "matches_fix_pattern": False,
                "notes": "Claude call exceeded timeout",
            }
        finally:
            stdin_fh.close()

        if result.returncode != 0:
            stderr_msg = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
            print(f"WARNING: Claude exited with code {result.returncode}", file=sys.stderr)
            if stderr_msg:
                print(f"Stderr: {stderr_msg}", file=sys.stderr)
            return {
                "candidate_sha": candidate_sha,
                "confidence": "LOW",
                "reasoning": f"Claude error (exit code {result.returncode})",
                "matches_fix_pattern": False,
                "notes": stderr_msg[:200],
            }

        output_text = result.stdout.decode("utf-8", errors="replace").strip()

        # Extract JSON from response
        # Look for json code block or raw JSON
        json_match = re.search(r'```json\s*(.*?)\s*```', output_text, re.DOTALL)
        if json_match:
            json_text = json_match.group(1)
        else:
            # Try to find raw JSON object
            json_match = re.search(r'\{.*\}', output_text, re.DOTALL)
            if json_match:
                json_text = json_match.group(0)
            else:
                json_text = output_text

        parsed = json.loads(json_text)
        return parsed

    except json.JSONDecodeError as e:
        print(f"ERROR: Could not parse Claude response as JSON: {e}", file=sys.stderr)
        print(f"Raw response: {output_text[:500]}", file=sys.stderr)
        return {
            "candidate_sha": candidate_sha,
            "confidence": "LOW",
            "reasoning": "Could not parse Claude response",
            "matches_fix_pattern": False,
            "notes": f"JSON parse error: {str(e)[:100]}",
        }
    finally:
        os.unlink(prompt_file.name)


def run_claude_judgment(
    repo_dir: str,
    fix_sha: str,
    result: SZZResult,
    cve_id: str = "",
    description: str = "",
) -> None:
    """Invoke claude CLI to judge SZZ candidates, streaming output to terminal."""
    # Truncate diff to avoid context overflow
    diff_lines = result.diff_text.splitlines()
    max_diff_lines = 8000
    if len(diff_lines) > max_diff_lines:
        diff_text_truncated = "\n".join(diff_lines[:max_diff_lines]) + \
            f"\n... (truncated, {len(diff_lines) - max_diff_lines} more lines)"
    else:
        diff_text_truncated = result.diff_text

    prompt = _CLAUDE_PROMPT_TEMPLATE.format(
        cve_id=cve_id or "unknown",
        description=description or "Not provided",
        repo_dir=repo_dir,
        fix_sha=fix_sha,
        flags=", ".join(result.flags) if result.flags else "none",
        diff_text_truncated=diff_text_truncated,
        candidate_table=_build_candidate_table(result.candidates),
    )

    cmd = ["claude", "-p", "--output-format", "stream-json",
           "--verbose", "--allowedTools", "Bash,Read"]

    print(f"\n{'='*60}", file=sys.stderr)
    print(f"Running Claude judgment for {cve_id or fix_sha}...", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)

    # Strip CLAUDECODE env var so we can launch claude from inside a session
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    # Write prompt to a temp file so claude reads it as a single input
    prompt_file = tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8",
    )
    try:
        prompt_file.write(prompt)
        prompt_file.close()

        stdin_fh = open(prompt_file.name, "r")
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=stdin_fh,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=repo_dir,
                env=env,
            )
        except FileNotFoundError:
            stdin_fh.close()
            print(
                "ERROR: 'claude' CLI not found. Install it or ensure it's on PATH.",
                file=sys.stderr,
            )
            sys.exit(1)
        stdin_fh.close()

        # Forward stderr in background
        def _drain_stderr():
            for line in io.TextIOWrapper(proc.stderr, encoding="utf-8", errors="replace"):
                sys.stderr.write(line)
                sys.stderr.flush()

        t_err = threading.Thread(target=_drain_stderr, daemon=True)
        t_err.start()

        # Read stdout stream-json lines and print progress
        final_text = ""
        for raw_line in io.TextIOWrapper(proc.stdout, encoding="utf-8", errors="replace"):
            raw_line = raw_line.rstrip("\n")
            if not raw_line:
                continue
            try:
                event = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            etype = event.get("type", "")

            if etype == "assistant" and "message" in event:
                msg = event["message"]
                content = msg.get("content", [])
                # Show tool calls in this assistant turn
                for block in content:
                    if block.get("type") == "tool_use":
                        name = block.get("name", "?")
                        inp = block.get("input", {})
                        # Show the command for Bash, or a summary for others
                        if name == "Bash" and "command" in inp:
                            print(f"\n> {name}: {inp['command']}", file=sys.stderr)
                        elif name == "Read" and "file_path" in inp:
                            print(f"\n> {name}: {inp['file_path']}", file=sys.stderr)
                        else:
                            # Show first 120 chars of input as summary
                            summary = json.dumps(inp)
                            if len(summary) > 120:
                                summary = summary[:120] + "..."
                            print(f"\n> {name}: {summary}", file=sys.stderr)
                    elif block.get("type") == "text":
                        text = block.get("text", "")
                        if text.strip():
                            sys.stdout.write(text)
                            sys.stdout.flush()

            elif etype == "user" and "message" in event:
                # Tool results coming back
                content = event["message"].get("content", [])
                for block in content:
                    if block.get("type") == "tool_result":
                        is_error = block.get("is_error", False)
                        status = "ERROR" if is_error else "ok"
                        # Extract text from content (may be string or list)
                        result_content = block.get("content", "")
                        if isinstance(result_content, list):
                            texts = [c.get("text", "") for c in result_content if c.get("type") == "text"]
                            result_content = "\n".join(texts)
                        # Show truncated result
                        preview = result_content[:200].replace("\n", "\\n")
                        if len(result_content) > 200:
                            preview += "..."
                        print(f"  [{status}] {preview}", file=sys.stderr)

            elif etype == "content_block_start":
                cb = event.get("content_block", {})
                if cb.get("type") == "tool_use":
                    print(f"\n> tool: {cb.get('name', '?')}",
                          file=sys.stderr)

            elif etype == "content_block_delta":
                delta = event.get("delta", {})
                if delta.get("type") == "text_delta":
                    text = delta.get("text", "")
                    sys.stdout.write(text)
                    sys.stdout.flush()
                elif delta.get("type") == "input_json_delta":
                    sys.stderr.write(".")
                    sys.stderr.flush()

            elif etype == "content_block_stop":
                pass

            elif etype == "result":
                final_text = event.get("result", "")
                if not final_text:
                    final_text = event.get("text", "")

            elif etype == "message_stop":
                pass

        t_err.join(timeout=5)
        proc.wait()

        # Print final result if we haven't already streamed it
        if final_text:
            print(f"\n{'='*60}", file=sys.stderr)
            print(final_text)

        if proc.returncode != 0:
            print(
                f"\nWARNING: claude exited with code {proc.returncode}",
                file=sys.stderr,
            )
    finally:
        os.unlink(prompt_file.name)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SZZ-based introducing commit finder"
    )
    parser.add_argument("--repo-dir", help="Path to git repository")
    parser.add_argument("--fix-commit", help="Fix commit SHA")
    parser.add_argument("--manifest", help="Path to CVE manifest YAML")
    parser.add_argument(
        "--update-manifest",
        action="store_true",
        help="Write results back to the manifest YAML",
    )
    parser.add_argument(
        "--top-n", type=int, default=5, help="Number of candidates to return"
    )
    parser.add_argument(
        "--claude",
        action="store_true",
        help="Invoke claude CLI to judge candidates after SZZ analysis",
    )
    parser.add_argument("--cve-id", default="", help="CVE identifier (for --claude context)")
    parser.add_argument("--description", default="", help="Vulnerability description (for --claude context)")
    parser.add_argument(
        "--validate-intro",
        metavar="COMMIT",
        help="Validate confidence that a specific commit introduced the bug (requires --repo-dir and --fix-commit)",
    )

    args = parser.parse_args()

    # Validate --validate-intro usage
    if args.validate_intro:
        if not args.repo_dir or not args.fix_commit:
            parser.error("--validate-intro requires both --repo-dir and --fix-commit")
        result = validate_introducing_commit(
            args.repo_dir,
            args.fix_commit,
            args.validate_intro,
            cve_id=args.cve_id,
            description=args.description,
        )
        print(json.dumps(result, indent=2))
    elif args.manifest:
        run_batch(args.manifest, update=args.update_manifest, claude=args.claude)
    elif args.repo_dir and args.fix_commit:
        result = analyze_fix(args.repo_dir, args.fix_commit, n=args.top_n)
        print(json.dumps(result_to_dict(result), indent=2))
        if args.claude:
            run_claude_judgment(
                args.repo_dir, args.fix_commit, result,
                cve_id=args.cve_id,
                description=args.description,
            )
    else:
        parser.error("Provide either --manifest, --validate-intro, or both --repo-dir and --fix-commit")


if __name__ == "__main__":
    main()
