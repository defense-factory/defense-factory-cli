#!/usr/bin/env python3
"""Create one Devin remediation session per repository finding group."""

from __future__ import annotations

import argparse
import csv
import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from devin_api import create_session


DEFAULT_PLAYBOOK_ID = "playbook-90cdbb371d5a4807babf957b36130aff"
CSV_COLUMNS = [
    "repo",
    "path",
    "package",
    "installed_version",
    "fixed_version",
    "vuln_id",
    "severity",
    "cvss",
    "title",
]
SCHEMA_PATH = Path(__file__).with_name("schema.json")


def read_findings(path: str | Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def group_findings(rows: list[dict[str, str]]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[row["repo"]].append(row)
    return dict(groups)


def render_prompt(repo: str, rows: list[dict[str, str]]) -> str:
    lines = [
        (
            f"Remediate the dependency vulnerabilities in {repo}. Update dependencies "
            f"to safe compatible versions, preserve the existing behavior, and keep tests green."
        ),
        "",
        "| " + " | ".join(CSV_COLUMNS) + " |",
        "| " + " | ".join("---" for _ in CSV_COLUMNS) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(column, "")).replace("|", "\\|") for column in CSV_COLUMNS) + " |")
    lines.extend(
        [
            "",
            (
                "After the edits, run the repository test suite and re-scan the same branch "
                "with the same scanner. Report fixed and not_fixed per vuln_id, tests_passed, "
                "and scanner_findings_remaining in the structured output."
            ),
        ]
    )
    return "\n".join(lines)


def _load_schema() -> dict[str, Any]:
    with open(SCHEMA_PATH, encoding="utf-8") as stream:
        return json.load(stream)


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
                idempotent=True,
                max_acu_limit=max_acu,
            )
            state_repos[repo] = {
                "session_id": response["session_id"],
                "url": response.get("url", ""),
                "vuln_ids": [row["vuln_id"] for row in rows],
            }
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
            idempotent=True,
            max_acu_limit=max_acu,
        )
        state["repos"][repo] = {
            "session_id": response["session_id"],
            "url": response.get("url", ""),
            "vuln_ids": [row["vuln_id"] for row in rows],
        }
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
