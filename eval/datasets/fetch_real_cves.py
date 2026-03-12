#!/usr/bin/env python
"""
Fetch real-world CVE diffs from open-source repos.

Reads real-cve-manifest.yaml, clones each repo (shallow), extracts the
vulnerability-introducing diff (reverse of the fix), and also grabs clean
commits for false-positive measurement.

Output: eval/samples/real-cve/{vulnerable,clean}/*.patch

Usage:
    python fetch_real_cves.py              # Fetch all CVEs in manifest
    python fetch_real_cves.py --cve CVE-2024-34069   # Single CVE
    python fetch_real_cves.py --skip-clone            # Re-extract without cloning
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    # Fallback: parse YAML manually for simple structure
    yaml = None

_SCRIPT_DIR = Path(__file__).resolve().parent
_EVAL_DIR = _SCRIPT_DIR.parent
_SAMPLES_DIR = _EVAL_DIR / "samples" / "real-cve"
_CLONE_DIR = _EVAL_DIR / "datasets" / "_clones"
_MANIFEST = _SCRIPT_DIR / "real-cve-manifest.yaml"


def parse_manifest(path: Path) -> list[dict]:
    """Parse the YAML manifest into a list of CVE entries."""
    text = path.read_text(encoding="utf-8")
    if yaml:
        data = yaml.safe_load(text) or {}
        return data.get("vulnerabilities", [])
    # Simple fallback parser for flat YAML lists
    entries = []
    current = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("- repo:"):
            if current:
                entries.append(current)
            current = {"repo": line.split(":", 1)[1].strip()}
        elif ":" in line and not line.startswith("#") and current:
            key, val = line.split(":", 1)
            current[key.strip().lstrip("- ")] = val.strip()
    if current:
        entries.append(current)
    return entries


def run(cmd: list[str], cwd: str | Path | None = None, check: bool = True) -> str:
    """Run a command and return stdout."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, cwd=cwd, timeout=300,
            encoding="utf-8", errors="replace",
        )
    except Exception as e:
        print(f"  CMD ERROR: {' '.join(cmd)}: {e}")
        return ""
    if check and result.returncode != 0:
        print(f"  CMD FAILED: {' '.join(cmd)}")
        print(f"  stderr: {(result.stderr or '')[:500]}")
        return ""
    return result.stdout or ""


def clone_repo(repo: str, commit: str) -> Path | None:
    """Shallow-clone a repo with enough depth to reach the fix commit."""
    org, name = repo.split("/")
    clone_path = _CLONE_DIR / name

    if clone_path.exists():
        print(f"  Using cached clone: {clone_path}")
        # Fetch the specific commit if not already present
        test = run(["git", "cat-file", "-t", commit], cwd=clone_path, check=False)
        if "commit" not in test:
            print(f"  Fetching commit {commit[:8]}...")
            run(["git", "fetch", "origin", commit, "--depth=2"], cwd=clone_path, check=False)
        return clone_path

    print(f"  Cloning {repo} (shallow)...")
    _CLONE_DIR.mkdir(parents=True, exist_ok=True)

    # Clone with enough depth, then fetch the specific commit
    result = run([
        "git", "clone", "--filter=blob:none", "--no-checkout",
        f"https://github.com/{repo}.git", str(clone_path)
    ], check=False)
    if not clone_path.exists():
        print(f"  ERROR: Clone failed for {repo}")
        return None

    # Fetch the fix commit and its parent
    run(["git", "fetch", "origin", commit, "--depth=2"], cwd=clone_path, check=False)

    return clone_path


def extract_vuln_diff(clone_path: Path, entry: dict) -> Path | None:
    """Extract the vulnerability-introducing diff (reverse of the fix)."""
    commit = entry["fix_commit"]
    cve = entry["cve_id"]

    # Reverse diff: shows what the FIX removed (= the vulnerability being added)
    diff = run(["git", "diff", commit, f"{commit}~1", "--", "*.py"], cwd=clone_path)
    if not diff.strip():
        # Try without file filter
        diff = run(["git", "diff", commit, f"{commit}~1"], cwd=clone_path)
    if not diff.strip():
        print(f"  WARNING: Empty diff for {cve}")
        return None

    # Sanitize CVE ID for filename
    safe_name = cve.lower().replace("-", "_")
    out_dir = _SAMPLES_DIR / "vulnerable"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_name}.patch"
    out_path.write_text(diff, encoding="utf-8")

    lines = len(diff.splitlines())
    print(f"  Wrote vulnerable patch: {out_path.name} ({lines} lines)")
    return out_path


def extract_introducing_diff(clone_path: Path, entry: dict) -> Path | None:
    """Extract the forward diff of the bug-introducing commit."""
    intro_commit = entry.get("introducing_commit")
    if not intro_commit:
        return None
    cve = entry["cve_id"]

    # Fetch the introducing commit if needed
    test = run(["git", "cat-file", "-t", intro_commit], cwd=clone_path, check=False)
    if "commit" not in test:
        run(["git", "fetch", "origin", intro_commit, "--depth=2"],
            cwd=clone_path, check=False)

    # Forward diff: shows the vulnerable code being added
    diff = run(["git", "diff", f"{intro_commit}~1", intro_commit, "--", "*.py"],
               cwd=clone_path)
    if not diff.strip():
        diff = run(["git", "diff", f"{intro_commit}~1", intro_commit], cwd=clone_path)
    if not diff.strip():
        print(f"  WARNING: Empty introducing diff for {cve}")
        return None

    safe_name = cve.lower().replace("-", "_")
    out_dir = _SAMPLES_DIR / "introducing"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f"{safe_name}.patch"
    out_path.write_text(diff, encoding="utf-8")

    lines = len(diff.splitlines())
    print(f"  Wrote introducing patch: {out_path.name} ({lines} lines)")
    return out_path


def extract_clean_diffs(clone_path: Path, repo: str, count: int = 2) -> list[Path]:
    """Extract clean (non-security) commits for FP measurement."""
    org, name = repo.split("/")
    out_dir = _SAMPLES_DIR / "clean"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Find recent commits that touch only docs, tests, or config
    log = run([
        "git", "log", "--oneline", "--no-merges", "-50",
        "--diff-filter=M", "--", "*.md", "*.txt", "*.rst", "*.cfg", "*.toml",
        "tests/*", "docs/*"
    ], cwd=clone_path)

    clean_paths = []
    for line in log.strip().splitlines()[:count]:
        if not line.strip():
            continue
        sha = line.split()[0]
        diff = run(["git", "diff", f"{sha}~1", sha], cwd=clone_path)
        if not diff.strip() or len(diff.splitlines()) < 3:
            continue

        safe_name = f"{name}_clean_{sha[:8]}"
        out_path = out_dir / f"{safe_name}.patch"
        out_path.write_text(diff, encoding="utf-8")

        lines = len(diff.splitlines())
        print(f"  Wrote clean patch: {out_path.name} ({lines} lines)")
        clean_paths.append(out_path)

    return clean_paths


def main():
    parser = argparse.ArgumentParser(description="Fetch real-world CVE diffs")
    parser.add_argument("--cve", help="Process only this CVE ID")
    parser.add_argument("--skip-clone", action="store_true",
                        help="Skip cloning, re-extract from existing clones")
    parser.add_argument("--clean-count", type=int, default=2,
                        help="Number of clean commits per repo (default: 2)")
    args = parser.parse_args()

    print("Real-CVE Dataset Builder")
    print("=" * 60)

    entries = parse_manifest(_MANIFEST)
    print(f"Manifest: {len(entries)} CVEs")

    if args.cve:
        entries = [e for e in entries if e["cve_id"] == args.cve]
        if not entries:
            print(f"ERROR: CVE {args.cve} not found in manifest")
            sys.exit(1)

    # Group by repo to minimize cloning
    repos = {}
    for e in entries:
        repos.setdefault(e["repo"], []).append(e)

    vuln_count = 0
    intro_count = 0
    clean_count = 0

    for repo, cves in repos.items():
        print(f"\n--- {repo} ({len(cves)} CVEs) ---")

        # Clone (or reuse)
        first_commit = cves[0]["fix_commit"]
        if args.skip_clone:
            org, name = repo.split("/")
            clone_path = _CLONE_DIR / name
            if not clone_path.exists():
                print(f"  ERROR: --skip-clone but no cached clone for {repo}")
                print(f"  Expected: {clone_path}")
                continue
            print(f"  Using cached clone (--skip-clone): {clone_path}")
        else:
            clone_path = clone_repo(repo, first_commit)
        if not clone_path:
            print(f"  SKIPPING {repo}: clone failed")
            continue

        # Fetch all commits for this repo
        for cve_entry in cves:
            commit = cve_entry["fix_commit"]
            test = run(["git", "cat-file", "-t", commit], cwd=clone_path, check=False)
            if "commit" not in test:
                run(["git", "fetch", "origin", commit, "--depth=2"],
                    cwd=clone_path, check=False)

        # Extract vulnerable diffs
        for cve_entry in cves:
            print(f"\n  {cve_entry['cve_id']} ({cve_entry['cwe']}, {cve_entry['severity']})")
            print(f"  {cve_entry['description']}")
            result = extract_vuln_diff(clone_path, cve_entry)
            if result:
                vuln_count += 1

        # Extract introducing diffs (when introducing_commit is known)
        for cve_entry in cves:
            if cve_entry.get("introducing_commit"):
                print(f"\n  Introducing commit for {cve_entry['cve_id']}...")
                result = extract_introducing_diff(clone_path, cve_entry)
                if result:
                    intro_count += 1

        # Extract clean diffs (once per repo)
        print(f"\n  Extracting clean commits...")
        clean_paths = extract_clean_diffs(clone_path, repo, args.clean_count)
        clean_count += len(clean_paths)

    print(f"\n{'=' * 60}")
    print(f"Dataset complete: {vuln_count} vulnerable + {intro_count} introducing + {clean_count} clean patches")
    print(f"Location: {_SAMPLES_DIR}")

    if vuln_count == 0:
        print("\nWARNING: No vulnerable patches generated. Check git clone access.")
        sys.exit(1)


if __name__ == "__main__":
    main()
