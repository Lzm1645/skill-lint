#!/usr/bin/env python3
"""Scan a pinned list of public agent-skill repositories with skill-lint.

The scan is reproducible: `repos.json` pins every repository to a commit SHA,
clones are shallow, and the linter is the one in this repository.

Usage:
    python3 scan/scan_public.py                 # scan the pinned revisions
    python3 scan/scan_public.py --update        # re-pin to default-branch HEADs
    python3 scan/scan_public.py --json out.json # write machine-readable results

Exit code: 0 when the scan completed, 1 when a repository could not be scanned.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
LINTER = ROOT / "skill_lint.py"
CACHE = Path(os.environ.get("SKILL_LINT_CACHE", HERE / ".cache" / "repos"))
GH_BASE = "https://github.com/{repo}.git"
SKIP_DIRS = {".git", "node_modules", "vendor", ".venv", "venv", "__pycache__",
             "site-packages", ".tox", ".mypy_cache", ".pytest_cache"}


def run(cmd: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)


def load_config(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save_config(path: Path, config: dict) -> None:
    path.write_text(json.dumps(config, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def resolve_head(repo: str) -> str:
    """Default-branch HEAD SHA without cloning the repository."""
    proc = run(["git", "ls-remote", GH_BASE.format(repo=repo), "HEAD"])
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"cannot resolve HEAD for {repo}: {proc.stderr.strip()}")
    return proc.stdout.split()[0]


def update_pins(config: dict) -> dict:
    for entry in config["repos"]:
        entry["sha"] = resolve_head(entry["repo"])
        print(f"pinned {entry['repo']} -> {entry['sha'][:12]}")
    config["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return config


def ensure_checkout(repo: str, sha: str) -> Path:
    """Shallow-checkout exactly `sha` into the cache, reusing a stale clone if possible."""
    target = CACHE / repo.replace("/", "__")
    if not (target / ".git").is_dir():
        if target.exists():
            shutil.rmtree(target)
        proc = run(["git", "clone", "--quiet", GH_BASE.format(repo=repo), str(target)])
        if proc.returncode != 0:
            raise RuntimeError(f"clone failed for {repo}: {proc.stderr.strip()}")
    head = run(["git", "rev-parse", "HEAD"], cwd=target).stdout.strip()
    if head != sha:
        proc = run(["git", "fetch", "--quiet", "--depth", "1", "origin", sha], cwd=target)
        if proc.returncode != 0:
            raise RuntimeError(f"fetch {sha[:12]} failed for {repo}: {proc.stderr.strip()}")
        proc = run(["git", "checkout", "--quiet", "--detach", sha], cwd=target)
        if proc.returncode != 0:
            raise RuntimeError(f"checkout {sha[:12]} failed for {repo}: {proc.stderr.strip()}")
    return target


def find_skills(root: Path) -> list[Path]:
    """Every directory containing a SKILL.md, skipping vendored trees."""
    found = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        if any(f.lower() == "skill.md" for f in filenames):
            found.append(Path(dirpath))
    return sorted(found)


def lint_skill(skill_dir: Path, linter: Path = LINTER) -> dict:
    proc = run([sys.executable, str(linter), str(skill_dir), "--json"])
    if proc.returncode not in (0, 1) or not proc.stdout.strip():
        return {"path": str(skill_dir), "error": proc.stderr.strip() or f"exit {proc.returncode}"}
    report = json.loads(proc.stdout)
    return report


def scan(config: dict, linter: Path = LINTER) -> dict:
    tool_rev = run(["git", "rev-parse", "HEAD"], cwd=ROOT).stdout.strip()
    tool_sha256 = hashlib.sha256(Path(LINTER).read_bytes()).hexdigest()
    repos, failures = [], []
    for entry in config["repos"]:
        repo, sha = entry["repo"], entry["sha"]
        print(f"scanning {repo} @ {sha[:12]}", flush=True)
        try:
            checkout = ensure_checkout(repo, sha)
        except RuntimeError as exc:
            failures.append({"repo": repo, "sha": sha, "error": str(exc)})
            continue
        skills = find_skills(checkout)
        results = []
        for skill in skills:
            report = lint_skill(skill, linter)
            if "error" in report:
                report = {"path": str(skill.relative_to(checkout)), "result": "error",
                          "blocks": 0, "warns": 0, "issues": [], "error": report["error"]}
            report["path"] = str(skill.relative_to(checkout))
            results.append(report)
        counts = Counter(r["result"] for r in results)
        repos.append({
            "repo": repo,
            "sha": sha,
            "skills": len(results),
            "block": counts.get("block", 0),
            "warn": counts.get("warn", 0),
            "pass": counts.get("pass", 0),
            "error": counts.get("error", 0),
            "results": results,
        })
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_commit": tool_rev,
        "tool_sha256": tool_sha256,
        "pins": config.get("generated_at"),
        "repos": repos,
        "failures": failures,
    }


def summarize(data: dict) -> dict:
    by_rule: dict[str, Counter] = defaultdict(Counter)
    messages = Counter()
    total = Counter()
    for repo in data["repos"]:
        for result in repo["results"]:
            total[result["result"]] += 1
            for issue in result["issues"]:
                by_rule[issue["rule"]][issue["severity"]] += 1
                messages[(issue["rule"], issue["severity"], issue["message"])] += 1
    return {
        "skills": dict(total),
        "by_rule": {rule: dict(counter) for rule, counter in sorted(by_rule.items())},
        "top_messages": [
            {"rule": rule, "severity": severity, "message": message, "count": count}
            for (rule, severity, message), count in messages.most_common(20)
        ],
    }


def markdown_table(data: dict) -> str:
    lines = ["| repository | skills | block | warn | pass | block rate |",
             "|---|---:|---:|---:|---:|---:|"]
    for repo in data["repos"]:
        rate = repo["block"] / repo["skills"] if repo["skills"] else 0
        name = repo["repo"]
        lines.append(f"| {name} | {repo['skills']} | {repo['block']} | {repo['warn']} | "
                     f"{repo['pass']} | {rate:.0%} |")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Scan public skill repositories with skill-lint")
    parser.add_argument("--config", type=Path, default=HERE / "repos.json")
    parser.add_argument("--update", action="store_true", help="re-pin every repo to its default-branch HEAD")
    parser.add_argument("--linter", type=Path, default=LINTER, help="linter to run (default: this repo's skill_lint.py)")
    parser.add_argument("--json", type=Path, help="write full per-skill results here")
    parser.add_argument("--summary", type=Path, help="write aggregate summary here")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.update:
        config = update_pins(config)
        save_config(args.config, config)

    data = scan(config, args.linter)
    data["summary"] = summarize(data)
    if args.json:
        args.json.write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    if args.summary:
        args.summary.write_text(json.dumps({"generated_at": data["generated_at"],
                                            "tool_commit": data["tool_commit"],
                                            "tool_sha256": data["tool_sha256"],
                                            "repos": [{k: r[k] for k in ("repo", "sha", "skills", "block", "warn", "pass", "error")}
                                                      for r in data["repos"]],
                                            **data["summary"]}, ensure_ascii=False, indent=1) + "\n",
                                encoding="utf-8")
    print(markdown_table(data))
    print()
    summary = data["summary"]
    print("skills:", summary["skills"])
    for rule, counts in summary["by_rule"].items():
        print(f"{rule}: block={counts.get('block', 0)} warn={counts.get('warn', 0)}")
    if data["failures"]:
        print("FAILURES:", file=sys.stderr)
        for failure in data["failures"]:
            print(f"  {failure['repo']}: {failure['error']}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
