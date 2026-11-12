"""Upload an external Pharos export and launch one Security 2.0 ingestion scan."""

import argparse
import csv
import json
import os
import tempfile
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from devin_api import (DEFAULT_API_BASE, get_scan_status, ingestion_payload, list_scan_findings,
                       remediate_findings, remediation_payload,
                       start_ingestion_scan, upload_attachment)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def finish_scan(scan, args, remediation):
    print(f"Scan: {scan['scan_id']}")
    if scan.get("url"):
        print(f"URL: {scan['url']}")
    if not (args.wait or args.remediate):
        return 0
    while scan["status"] not in {"completed", "failed", "cancelled"}:
        time.sleep(10)
        scan = get_scan_status(scan["scan_id"])
        print(f"Status: {scan['status']}")
    counts = Counter(f["severity"].upper() for f in list_scan_findings(scan["scan_id"]))
    print("Findings: " + ", ".join(f"{s}={counts[s]}" for s in SEVERITIES))
    if scan["status"] != "completed":
        return 1
    if args.remediate:
        result = remediate_findings(scan["scan_id"], **remediation)
        session_id = result["session_id"]
        base = urlsplit(os.environ.get("DEVIN_API_BASE", DEFAULT_API_BASE))
        url = f"{base.scheme}://{base.netloc}/sessions/{session_id.removeprefix('devin-')}"
        print(f"Planner/fix session: {session_id}\nURL: {url}")
        print(f"Findings picked up: {len(result['finding_ids'])}; skipped_count: {result['skipped_count']}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", default="pharos_export.csv")
    parser.add_argument("--profile-id", default=os.environ.get("DEVIN_INGEST_PROFILE_ID"))
    parser.add_argument("--repo", action="append", help="Full owner/repo; repeatable")
    parser.add_argument("--lob")
    parser.add_argument("--effort", choices=["normal", "deep"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--wait", action="store_true")
    parser.add_argument("--remediate", action="store_true", help="Wait, then launch bulk remediation")
    parser.add_argument("--scan-id", help="Remediate an existing scan, skipping ingestion")
    parser.add_argument("--severity", default="critical,high", help="Comma-separated remediation severities")
    parser.add_argument("--remediate-branch")
    parser.add_argument("--exclude-finding-id", action="append")
    parser.add_argument("--create-as-user-id")
    args = parser.parse_args(argv)
    if args.scan_id and not args.remediate:
        parser.error("--scan-id requires --remediate")
    if args.scan_id and (args.lob or args.repo and len(args.repo) > 1):
        parser.error("Existing-scan remediation accepts at most one --repo and no --lob")
    if not args.scan_id and not args.profile_id:
        parser.error("--profile-id or DEVIN_INGEST_PROFILE_ID is required")
    try:
        remediation = {"severities": [s.strip() for s in args.severity.split(",")],
                       "exclude_finding_ids": args.exclude_finding_id,
                       "branch": args.remediate_branch, "create_as_user_id": args.create_as_user_id}
        if args.scan_id and args.repo:
            remediation["repo_name"] = args.repo[0]
        if args.remediate:
            body = remediation_payload(**remediation)
            if args.dry_run:
                print("Remediation request (only after scan status is completed):")
                print(json.dumps(body, indent=2))
        if args.scan_id:
            if args.dry_run:
                print(f"Existing scan: {args.scan_id}; would check status and wait for completion")
                return 0
            return finish_scan(get_scan_status(args.scan_id), args, remediation)
        with Path(args.export).open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.DictReader(stream)
            fields = reader.fieldnames
            if not fields or not {"asset_repo", "severity", "lob"} <= set(fields):
                raise ValueError("Export requires asset_repo, severity and lob columns")
            rows = [row for row in reader if
                    (not args.repo or row["asset_repo"] in args.repo) and
                    (not args.lob or row["lob"] == args.lob)]
        if not rows:
            raise ValueError("No findings match the export filters")
        if any(not row["asset_repo"].strip() for row in rows):
            raise ValueError("asset_repo must not be empty")
        repos = [{"repo_name": repo} for repo in sorted({row["asset_repo"] for row in rows})]
        payload = ingestion_payload(args.profile_id, ["<uploaded-attachment-url>"],
                                    repos=repos, effort=args.effort)
        print(f"{len(rows)} findings across {len(repos)} repositories")
        print("Repository | " + " | ".join(SEVERITIES))
        counts = Counter((row["asset_repo"], row["severity"]) for row in rows)
        for repo in repos:
            name = repo["repo_name"]
            print(name + " | " + " | ".join(str(counts[name, s]) for s in
                                                SEVERITIES))
        if args.dry_run:
            print(json.dumps(payload, indent=2))
            return 0
        if args.repo or args.lob:
            with tempfile.TemporaryDirectory(prefix="pharos-") as directory:
                path = Path(directory) / "pharos_export.csv"
                with path.open("w", newline="", encoding="utf-8") as stream:
                    writer = csv.DictWriter(stream, fieldnames=fields)
                    writer.writeheader()
                    writer.writerows(rows)
                attachment = upload_attachment(path)
        else:
            attachment = upload_attachment(args.export)
        payload["attachment_urls"] = [attachment["url"]]
        scan = start_ingestion_scan(**payload)
        return finish_scan(scan, args, remediation)
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
