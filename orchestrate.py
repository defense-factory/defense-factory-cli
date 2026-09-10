#!/usr/bin/env python3
"""Create one Devin remediation session per repository finding group."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devin_api import create_session
from scan import CSV_COLUMNS, classify_rows, group_key


DEFAULT_PLAYBOOK_ID = "playbook-90cdbb371d5a4807babf957b36130aff"
PROMPT_COLUMNS = [
    "fix_type",
    "vuln_id",
    "package",
    "installed_version",
    "fixed_version",
    "severity",
    "cvss",
    "status",
    "relationship",
    "path",
    "start_line",
    "title",
]
SCHEMA_PATH = Path(__file__).with_name("schema.json")
SEVERITY_RANK = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
FIX_TYPE_ORDER = {
    "patch-bump": 0,
    "parent-uplift": 1,
    "major-bump": 1,
    "package-replacement": 1,
}


def read_findings(path: str | Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def group_findings(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(row)
    return dict(groups)


def fix_type_groups(
    rows: list[dict[str, str]],
) -> list[tuple[str, str, list[dict[str, str]]]]:
    classified = classify_rows(rows)
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in classified:
        fix_type = row["fix_type"]
        if fix_type != "no-fix":
            grouped[group_key(row, fix_type)].append(row)

    def sort_key(item: tuple[tuple[str, str, str], list[dict[str, str]]]) -> tuple[int, int, str, str]:
        (repo, fix_type, scope), group = item
        max_severity = max(
            (SEVERITY_RANK.get(row["severity"], 0) for row in group),
            default=0,
        )
        return (
            FIX_TYPE_ORDER.get(fix_type, 1),
            0 if fix_type == "patch-bump" else -max_severity,
            scope,
            repo,
        )

    return [
        (fix_type, scope, group)
        for (_, fix_type, scope), group in sorted(grouped.items(), key=sort_key)
    ]


def _severity_breakdown(rows: list[dict[str, str]]) -> str:
    counts = Counter(row["severity"] for row in rows)
    return ", ".join(
        f"{counts[severity]} {severity}"
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
        if counts[severity]
    )


def render_prompt(repo: str, rows: list[dict[str, str]]) -> str:
    classified = classify_rows(rows)
    plan = fix_type_groups(classified)
    no_fix = [row for row in classified if row["fix_type"] == "no-fix"]
    ordered_rows = [row for _, _, group in plan for row in group] + no_fix
    lines = [
        (
            f"Remediate the dependency vulnerabilities in {repo}. Update dependencies "
            f"to safe compatible versions, preserve the existing behavior, and keep tests green."
        ),
        "",
        "PR plan (one PR per group, in this order):",
    ]
    for fix_type, scope, group in plan:
        packages = len({row["package"] for row in group})
        lines.append(
            f"- {fix_type}: {scope} ({packages} packages, {len(group)} findings; "
            f"{_severity_breakdown(group)})"
        )
    if no_fix:
        lines.append(
            f"- no-fix: report only ({len({row['package'] for row in no_fix})} packages, "
            f"{len(no_fix)} findings; {_severity_breakdown(no_fix)})"
        )
    lines.extend(
        [
            "",
            (
                "Create one PR per planned group, starting with patch-bump. Each subsequent "
                "branch must be based on the previous group's branch because the groups touch "
                "the same lockfiles. Gate every PR on its own baseline comparison and re-scan; "
                "do not open a PR while any vuln_id in that group is still present: diagnose, "
                "fix, and re-scan again, up to 3 attempts. Report each PR in pull_requests[], "
                "and report no-fix findings at the repository level."
            ),
            "",
        "| " + " | ".join(PROMPT_COLUMNS) + " |",
        "| " + " | ".join("---" for _ in PROMPT_COLUMNS) + " |",
        ]
    )
    for row in ordered_rows:
        lines.append(
            "| "
            + " | ".join(
                str(row.get(column, "")).replace("|", "\\|")
                for column in PROMPT_COLUMNS
            )
            + " |"
        )
    lines.extend(
        [
            "",
            (
                "After the edits, run the repository test suite, then re-scan each PR branch "
                "with the same scanner and compare against its baseline. Report fixed and "
                "not_fixed per vuln_id, tests_passed, and rescan_attempts for each entry "
                "in pull_requests[], plus scanner_findings_remaining at repository level."
            ),
        ]
    )
    return "\n".join(lines)


def _load_schema() -> dict[str, Any]:
    with open(SCHEMA_PATH, encoding="utf-8") as stream:
        return json.load(stream)


def _plan_state(rows: list[dict[str, str]]) -> tuple[list[dict[str, Any]], list[str]]:
    classified = classify_rows(rows)
    groups = [
        {
            "fix_type": fix_type,
            "scope": scope,
            "vuln_ids": [row["vuln_id"] for row in group],
        }
        for fix_type, scope, group in fix_type_groups(classified)
    ]
    no_fix = [
        row["vuln_id"] for row in classified if row["fix_type"] == "no-fix"
    ]
    return groups, no_fix


def _repo_state(rows: list[dict[str, str]], response: dict[str, Any]) -> dict[str, Any]:
    groups, no_fix = _plan_state(rows)
    return {
        "session_id": response["session_id"],
        "url": response.get("url", ""),
        "vuln_ids": [row["vuln_id"] for row in rows],
        "groups": groups,
        "no_fix": no_fix,
    }


def run_orchestration(
    findings_path: str,
    playbook_id: str,
    state_path: str | None = None,
    dry_run: bool = False,
    max_acu: int | None = None,
    resume: bool = False,
) -> dict[str, Any] | None:
    groups = group_findings(read_findings(findings_path))
    prompts = {repo: render_prompt(repo, rows) for repo, rows in groups.items()}
    if dry_run:
        for repo, prompt in prompts.items():
            print(f"===== {repo} =====\n{prompt}\n")
        return None
    if resume:
        if not state_path or not Path(state_path).exists():
            raise ValueError("--resume requires an existing --state file")
        with open(state_path, encoding="utf-8") as stream:
            state = json.load(stream)
        state_repos = state.setdefault("repos", {})
        schema = _load_schema()
        for repo, rows in groups.items():
            if repo in state_repos:
                continue
            name = repo.rsplit("/", 1)[-1]
            response = create_session(
                prompts[repo],
                state["playbook_id"],
                tags=["vuln-remediation", name],
                title=f"Remediate {len(rows)} vulns in {name}",
                structured_output_schema=schema,
                max_acu_limit=max_acu,
            )
            state_repos[repo] = _repo_state(rows, response)
        with open(state_path, "w", encoding="utf-8") as stream:
            json.dump(state, stream, indent=2)
        print(f"State written to {state_path}")
        return state
    state: dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "playbook_id": playbook_id,
        "scanner": os.environ.get("SCANNER", "trivy"),
        "repos": {},
    }
    schema = _load_schema()
    for repo, rows in groups.items():
        name = repo.rsplit("/", 1)[-1]
        response = create_session(
            prompts[repo],
            playbook_id,
            tags=["vuln-remediation", name],
            title=f"Remediate {len(rows)} vulns in {name}",
            structured_output_schema=schema,
            max_acu_limit=max_acu,
        )
        state["repos"][repo] = _repo_state(rows, response)
    if not state_path:
        state_path = str(Path("runs") / f"{datetime.now().strftime('%Y%m%d%H%M%S')}.json")
    Path(state_path).parent.mkdir(parents=True, exist_ok=True)
    with open(state_path, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)
    print(f"State written to {state_path}")
    return state


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--playbook-id", default=DEFAULT_PLAYBOOK_ID)
    parser.add_argument("--state")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-acu", type=int)
    parser.add_argument("--resume", action="store_true")
    return parser


if __name__ == "__main__":
    args = _parser().parse_args()
    run_orchestration(
        args.findings,
        args.playbook_id,
        args.state,
        args.dry_run,
        args.max_acu,
        args.resume,
    )
