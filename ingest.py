"""Upload an external Pharos export and launch one Security 2.0 ingestion scan."""

import argparse
import csv
import json
import os
import tempfile
import time
from collections import Counter
from pathlib import Path

from devin_api import (get_scan_status, ingestion_payload, list_scan_findings,
                       start_ingestion_scan, upload_attachment)

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", default="pharos_export.csv")
    parser.add_argument("--profile-id", default=os.environ.get("DEVIN_INGEST_PROFILE_ID"))
    parser.add_argument("--repo", action="append", help="Full owner/repo; repeatable")
    parser.add_argument("--lob")
    parser.add_argument("--effort", choices=["normal", "deep"])
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--wait", action="store_true")
    args = parser.parse_args(argv)
    if not args.profile_id:
        parser.error("--profile-id or DEVIN_INGEST_PROFILE_ID is required")
    try:
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
        print(f"Scan: {scan['scan_id']}\nURL: {scan['url']}")
        if args.wait:
            while scan["status"] not in {"completed", "failed", "cancelled"}:
                time.sleep(10)
                scan = get_scan_status(scan["scan_id"], repo_name=repos[0]["repo_name"])
                print(f"Status: {scan['status']}")
            counts = Counter(f["severity"].upper() for f in list_scan_findings(scan["scan_id"]))
            print("Findings: " + ", ".join(f"{s}={counts[s]}" for s in
                                           SEVERITIES))
            return 0 if scan["status"] == "completed" else 1
        return 0
    except (OSError, ValueError, RuntimeError) as exc:
        parser.exit(1, f"Error: {exc}\n")


if __name__ == "__main__":
    raise SystemExit(main())
