#!/usr/bin/env python3
"""Start the Devin triage session for a findings CSV."""

from __future__ import annotations

import argparse
import csv
import io

from devin_api import create_session


DEFAULT_PLAYBOOK_ID = "playbook-90cdbb371d5a4807babf957b36130aff"
TRIAGE_PROMPT = """You are the triage step of a vulnerability remediation pipeline. Do not change any application code yourself — your job is to sort findings into buckets and dispatch one child session per bucket.

Below is findings.csv: {finding_count} findings across {repo_count} repositories, produced by Trivy and already classified — every row carries a fix_type.

1. Group the rows into buckets keyed by (repo, fix_type, scope), where scope is the row's `path` for fix_type patch-bump and parent-uplift, and the row's `package` for fix_type major-bump and package-replacement. Rows with fix_type no-fix have no fixed version available: leave them out of the buckets and carry them as report-only.
2. Print the bucket table before you dispatch anything: repo, fix_type, scope, distinct packages, findings, severity breakdown. Check that every row that is not no-fix landed in exactly one bucket, and say so.
3. Create one child session per bucket, all in a single devin_session_create call:
   - playbook_id: {playbook_id}
   - repos: the bucket's repo, as a single-element list
   - tags: ["vuln-remediation", the repo, the fix_type]
   - title: "<repo>: <fix_type> — <scope>"
   - prompt: the repo, the bucket's fix_type and scope, and that bucket's findings as a markdown table with the columns vuln_id, package, installed_version, fixed_version, severity, cvss, status, relationship, path, start_line, title. Include that bucket's rows and no others.
   Buckets in the same repo run in parallel off the default branch, so tell each child it owns only its own packages and may hit a lockfile conflict at merge time.
4. Wait for the children to finish, then post a final markdown summary: one row per bucket with repo, fix_type, scope, child session URL, PR URL, findings fixed, findings not fixed, tests_passed and rescan attempts; then the report-only no-fix findings; then totals. If a child opened no PR, say why rather than dropping it from the table.

findings.csv:

{csv}
"""


def render_prompt(csv_text: str, playbook_id: str) -> str:
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    repo_count = len({row["repo"] for row in rows})
    return TRIAGE_PROMPT.format(
        finding_count=len(rows),
        repo_count=repo_count,
        playbook_id=playbook_id,
        csv=csv_text,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", default="findings.csv")
    parser.add_argument("--playbook-id", default=DEFAULT_PLAYBOOK_ID)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--max-acu", type=int)
    args = parser.parse_args(argv)

    with open(args.findings, encoding="utf-8") as stream:
        prompt = render_prompt(stream.read(), args.playbook_id)
    if args.dry_run:
        print(prompt, end="")
        return 0

    response = create_session(
        prompt,
        playbook_id=None,
        tags=["vuln-remediation", "triage"],
        title="Vulnerability remediation triage",
        max_acu_limit=args.max_acu,
    )
    print(f"Session: {response.get('session_id', '')}")
    print(f"URL: {response.get('url', '')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
