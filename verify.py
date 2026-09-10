#!/usr/bin/env python3
"""Verify remediation sessions against a fresh scanner run."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

import requests

from devin_api import get_session
from scan import scan


TERMINAL_STATUSES = {"finished", "blocked", "expired", "failed", "error"}


def reconcile(
    vuln_ids: list[str], claimed_fixed: list[str], scanned_ids: set[str]
) -> dict[str, list[str]]:
    input_ids = set(vuln_ids)
    actually_absent = sorted(input_ids - scanned_ids)
    unfixed = sorted(input_ids - set(actually_absent))
    false_claims = sorted(set(claimed_fixed) - set(actually_absent))
    return {
        "claimed_fixed": sorted(set(claimed_fixed)),
        "actually_absent": actually_absent,
        "unfixed": unfixed,
        "false_claims": false_claims,
    }


def _structured_output(session: dict[str, Any]) -> dict[str, Any]:
    value = session.get("structured_output") or {}
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return value if isinstance(value, dict) else {}


def _pr_number(url: str) -> str:
    match = re.search(r"/pull/(\d+)", url)
    return match.group(1) if match else ""


def _repo_from_pr(url: str) -> str:
    match = re.search(r"github\.com/([^/]+/[^/]+)/pull/", url)
    return match.group(1) if match else ""


def _scan_pr(
    repo: str, pr_url: str, scanner: str, workdir: Path
) -> tuple[list[str], str]:
    repo_dir = workdir / repo.replace("/", "__")
    remote = f"https://github.com/{repo}.git"
    if not repo_dir.exists():
        subprocess.run(["git", "clone", remote, str(repo_dir)], check=True)
    number = _pr_number(pr_url)
    local_branch = f"verify-pr-{number}"
    subprocess.run(
        ["git", "-C", str(repo_dir), "fetch", "origin", f"pull/{number}/head:{local_branch}"],
        check=True,
    )
    subprocess.run(["git", "-C", str(repo_dir), "checkout", local_branch], check=True)
    findings = scan(repo_dir, repo, scanner)
    return [finding.vuln_id for finding in findings], local_branch


def _poll(
    session_id: str, poll_interval: int, timeout: int
) -> tuple[dict[str, Any], bool]:
    started = time.monotonic()
    previous = None
    while True:
        session = get_session(session_id)
        status = str(session.get("status_enum", "")).lower()
        if status != previous:
            print(f"{session_id}: {status}")
            previous = status
        if status in TERMINAL_STATUSES:
            return session, status == "finished"
        if time.monotonic() - started >= timeout:
            return session, False
        time.sleep(max(1, poll_interval))


def write_report(
    results: list[dict[str, Any]], report_path: str, discrepancies: list[str]
) -> None:
    lines = [
        "# Vulnerability Remediation Verification",
        "",
        "| repo | PR | findings in | fixed | not fixed | tests_passed | new findings |",
        "| --- | --- | ---: | --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            "| {repo} | {pr} | {count} | {fixed} | {not_fixed} | {tests} | {new} |".format(
                repo=result["repo"],
                pr=result["pr_url"] or "n/a",
                count=len(result["vuln_ids"]),
                fixed=", ".join(result["reconciliation"]["actually_absent"]) or "none",
                not_fixed=", ".join(result["reconciliation"]["unfixed"]) or "none",
                tests=result["structured"].get("tests_passed", "unknown"),
                new=", ".join(result["new_findings"]) or "none",
            )
        )
    fixed_total = sum(len(item["reconciliation"]["actually_absent"]) for item in results)
    finding_total = sum(len(item["vuln_ids"]) for item in results)
    lines.extend(["", f"Totals: {fixed_total}/{finding_total} input findings absent after remediation."])
    lines.extend(["", "## Discrepancies"])
    lines.extend(f"- {item}" for item in discrepancies or ["None."])
    Path(report_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def run(
    state_path: str,
    poll_interval: int = 30,
    timeout: int = 3600,
    workdir: str = ".verify",
    report: str = "report.md",
    slack_webhook_url: str | None = None,
) -> int:
    state = json.loads(Path(state_path).read_text(encoding="utf-8"))
    scanner = state.get("scanner", "trivy")
    results = []
    discrepancies = []
    unfinished_sessions = []
    false_claims = []
    for repo, details in state["repos"].items():
        session, finished = _poll(details["session_id"], poll_interval, timeout)
        structured = _structured_output(session)
        pr_url = structured.get("pr_url") or (session.get("pull_request") or {}).get("url", "")
        if not structured and pr_url:
            discrepancies.append(f"{repo}: degraded verification; structured output missing")
        if not finished:
            message = f"{repo}: session did not finish ({session.get('status_enum', 'timeout')})"
            discrepancies.append(message)
            unfinished_sessions.append(message)
        if not pr_url:
            discrepancies.append(f"{repo}: no pull request URL in session output")
            continue
        scanned_ids, _ = _scan_pr(repo, pr_url, scanner, Path(workdir))
        reconciliation = reconcile(details["vuln_ids"], structured.get("fixed", []), set(scanned_ids))
        if reconciliation["false_claims"]:
            message = f"{repo}: false claims {', '.join(reconciliation['false_claims'])}"
            discrepancies.append(message)
            false_claims.append(message)
        results.append(
            {
                "repo": repo,
                "pr_url": pr_url,
                "vuln_ids": details["vuln_ids"],
                "structured": structured,
                "reconciliation": reconciliation,
                "new_findings": sorted(set(scanned_ids) - set(details["vuln_ids"])),
            }
        )
    write_report(results, report, discrepancies)
    if slack_webhook_url:
        summary = Path(report).read_text(encoding="utf-8")
        requests.post(slack_webhook_url, json={"text": summary}, timeout=30).raise_for_status()
    return 1 if unfinished_sessions or false_claims else 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", required=True)
    parser.add_argument("--poll-interval", type=int, default=30)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--workdir", default=".verify")
    parser.add_argument("--report", default="report.md")
    parser.add_argument("--slack-webhook-url")
    return parser


if __name__ == "__main__":
    args = _parser().parse_args()
    raise SystemExit(
        run(
            args.state,
            args.poll_interval,
            args.timeout,
            args.workdir,
            args.report,
            args.slack_webhook_url,
        )
    )
