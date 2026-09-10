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

from devin_api import get_session, is_session_done, is_session_successful
from scan import scan


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


def _pull_request_url(session: dict[str, Any], repo: str) -> str:
    for pull_request in session.get("pull_requests") or []:
        url = pull_request.get("pr_url", "")
        if repo in url:
            return url
    return ""


def _not_fixed_ids(entries: list[dict[str, Any]]) -> list[str]:
    return [
        item["vuln_id"]
        for entry in entries
        for item in entry.get("not_fixed") or []
        if isinstance(item, dict) and item.get("vuln_id")
    ]


def _state_groups(details: dict[str, Any]) -> list[dict[str, Any]]:
    groups = details.get("groups") or []
    if groups:
        return groups
    return [
        {
            "fix_type": "legacy",
            "scope": "legacy",
            "vuln_ids": details.get("vuln_ids", []),
        }
    ]


def _match_state_group(
    entry: dict[str, Any], groups: list[dict[str, Any]]
) -> dict[str, Any] | None:
    fix_type = entry.get("fix_type", "")
    scope = entry.get("scope")
    if scope is not None:
        for group in groups:
            if group.get("fix_type") == fix_type and group.get("scope") == scope:
                return group
        return None
    claimed = set(entry.get("fixed") or []) | set(_not_fixed_ids([entry]))
    candidates = [
        group
        for group in groups
        if group.get("fix_type") == fix_type
        and claimed.intersection(group.get("vuln_ids") or [])
    ]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        same_type = [group for group in groups if group.get("fix_type") == fix_type]
        if len(same_type) == 1:
            return same_type[0]
    return None


def _pull_request_entries(
    structured: dict[str, Any],
    details: dict[str, Any],
    repo: str,
    discrepancies: list[str],
    session: dict[str, Any],
) -> list[dict[str, Any]]:
    entries = structured.get("pull_requests")
    if isinstance(entries, list):
        return entries
    pr_url = structured.get("pr_url")
    if pr_url:
        discrepancies.append(f"{repo}: legacy single pr_url structured-output shape")
        return [
            {
                "fix_type": "legacy",
                "pr_url": pr_url,
                "fixed": structured.get("fixed", []),
                "not_fixed": structured.get("not_fixed", []),
                "tests_passed": structured.get("tests_passed", "unknown"),
                "rescan_attempts": structured.get("rescan_attempts", "unknown"),
                "legacy": True,
            }
        ]
    fallback = _pull_request_url(session, repo)
    if fallback:
        discrepancies.append(f"{repo}: degraded verification; structured output missing")
        return [
            {
                "fix_type": "legacy",
                "pr_url": fallback,
                "fixed": [],
                "not_fixed": [],
                "tests_passed": "unknown",
                "rescan_attempts": "unknown",
                "legacy": True,
                "degraded": True,
            }
        ]
    return []


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
        status = session.get("status", "")
        status_detail = session.get("status_detail", "")
        state = (status, status_detail)
        if state != previous:
            print(f"{session_id}: status={status} status_detail={status_detail}")
            previous = state
        if is_session_done(session):
            return session, is_session_successful(session)
        if time.monotonic() - started >= timeout:
            return session, False
        time.sleep(max(1, poll_interval))


def write_report(
    results: list[dict[str, Any]],
    report_path: str,
    discrepancies: list[str],
    repo_totals: dict[str, int] | None = None,
    repo_absent: dict[str, set[str]] | None = None,
) -> None:
    lines = [
        "# Vulnerability Remediation Verification",
        "",
        "| repo | PR | fix_type | findings in | fixed | not fixed | tests_passed | rescans | new findings |",
        "| --- | --- | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(
            "| {repo} | {pr} | {fix_type} | {count} | {fixed} | {not_fixed} | {tests} | {rescans} | {new} |".format(
                repo=result["repo"],
                pr=result["pr_url"] or "n/a",
                fix_type=result.get("fix_type", "legacy"),
                count=len(result["vuln_ids"]),
                fixed=", ".join(result["reconciliation"]["actually_absent"]) or "none",
                not_fixed=", ".join(result["reconciliation"]["unfixed"]) or "none",
                tests=result["structured"].get("tests_passed", "unknown"),
                rescans=result["structured"].get("rescan_attempts", "unknown"),
                new=", ".join(result["new_findings"]) or "none",
            )
        )
    if repo_totals is None:
        fixed_total = sum(
            len(item["reconciliation"]["actually_absent"]) for item in results
        )
        finding_total = sum(len(item["vuln_ids"]) for item in results)
    else:
        fixed_total = sum(len(ids) for ids in (repo_absent or {}).values())
        finding_total = sum(repo_totals.values())
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
    coverage_errors = []
    plan_errors = []
    repo_totals = {}
    repo_absent: dict[str, set[str]] = {}
    for repo, details in state["repos"].items():
        input_ids = details["vuln_ids"]
        repo_totals[repo] = len(input_ids)
        repo_absent[repo] = set()
        session, successful = _poll(details["session_id"], poll_interval, timeout)
        structured = _structured_output(session)
        if not successful:
            message = (
                f"{repo}: session did not finish "
                f"(status={session.get('status', 'timeout')}, "
                f"status_detail={session.get('status_detail', 'n/a')})"
            )
            discrepancies.append(message)
            unfinished_sessions.append(message)
        entries = _pull_request_entries(
            structured, details, repo, discrepancies, session
        )
        if not entries:
            discrepancies.append(f"{repo}: no pull request URL in session output")
        claimed_ids: list[str] = []
        claimed_ids.extend(
            item
            for entry in entries
            for item in entry.get("fixed") or []
        )
        claimed_ids.extend(_not_fixed_ids(entries))
        claimed_ids.extend(_not_fixed_ids([structured]))
        counts = {}
        for vuln_id in claimed_ids:
            counts[vuln_id] = counts.get(vuln_id, 0) + 1
        duplicates = sorted(
            vuln_id for vuln_id, count in counts.items() if count > 1 and vuln_id in input_ids
        )
        missing = sorted(set(input_ids) - set(claimed_ids))
        if duplicates:
            message = f"{repo}: duplicated coverage vuln_ids {', '.join(duplicates)}"
            discrepancies.append(message)
            if not any(entry.get("degraded") for entry in entries):
                coverage_errors.append(message)
        if missing:
            message = f"{repo}: missing coverage vuln_ids {', '.join(missing)}"
            discrepancies.append(message)
            if not any(entry.get("degraded") for entry in entries):
                coverage_errors.append(message)

        groups = _state_groups(details)
        for entry in entries:
            pr_url = entry.get("pr_url", "")
            if not pr_url:
                discrepancies.append(f"{repo}: pull_requests entry has no PR URL")
                continue
            group = None if entry.get("legacy") else _match_state_group(entry, groups)
            if group is None:
                if entry.get("legacy"):
                    group_ids = input_ids
                    fix_type = "legacy"
                else:
                    message = (
                        f"{repo}: pull_requests entry plan group not found "
                        f"(fix_type={entry.get('fix_type', 'unknown')}, "
                        f"scope={entry.get('scope', 'unknown')})"
                    )
                    discrepancies.append(message)
                    plan_errors.append(message)
                    group_ids = []
                    fix_type = entry.get("fix_type", "unknown")
            else:
                group_ids = group.get("vuln_ids") or []
                fix_type = group.get("fix_type", entry.get("fix_type", "unknown"))
            scanned_ids, _ = _scan_pr(repo, pr_url, scanner, Path(workdir))
            reconciliation = reconcile(group_ids, entry.get("fixed", []), set(scanned_ids))
            repo_absent[repo].update(reconciliation["actually_absent"])
            if reconciliation["false_claims"]:
                message = f"{repo}: false claims {', '.join(reconciliation['false_claims'])}"
                discrepancies.append(message)
                false_claims.append(message)
            results.append(
                {
                    "repo": repo,
                    "pr_url": pr_url,
                    "fix_type": fix_type,
                    "vuln_ids": group_ids,
                    "structured": entry,
                    "reconciliation": reconciliation,
                    "new_findings": sorted(set(scanned_ids) - set(input_ids)),
                }
            )
    write_report(results, report, discrepancies, repo_totals, repo_absent)
    if slack_webhook_url:
        summary = Path(report).read_text(encoding="utf-8")
        requests.post(slack_webhook_url, json={"text": summary}, timeout=30).raise_for_status()
    return 1 if unfinished_sessions or false_claims or coverage_errors or plan_errors else 0


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
