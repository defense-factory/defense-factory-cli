"""Devin API calls used by quickstart.py."""
import csv
import os
import time

import requests

API_URL = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v3").rstrip("/")
HEADERS = {"Authorization": f"Bearer {os.environ['DEVIN_API_KEY']}"}


def call(method, org_id, path, **kwargs):
    url = f"{API_URL}/organizations/{org_id}/{path}"
    response = requests.request(method, url, headers=HEADERS, timeout=30, **kwargs)
    response.raise_for_status()
    return response.json()


def start_ingestion_scan(org_id, profile_id, csv_path):
    with open(csv_path, "rb") as f:
        attachment = call("POST", org_id, "attachments", files={"file": f})
    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        repo_names = sorted({row["asset_repo"] for row in csv.DictReader(f)})
    return call("POST", org_id, "code-scans/ingestion", json={
        "profile_id": profile_id,
        "attachment_urls": [attachment["url"]],
        "repos": [{"repo_name": name} for name in repo_names],
    })


def wait_for_scan(org_id, scan_id):
    while True:
        status = call("GET", org_id, f"code-scans/{scan_id}")["status"]
        print(f"Status: {status}")
        if status in ("completed", "failed", "cancelled"):
            return status
        time.sleep(10)


def start_remediation(org_id, scan_id):
    session = call("POST", org_id, f"code-scans/{scan_id}/findings/remediate",
                   json={"select_all": {"severity": ["critical", "high"]}})
    return call("GET", org_id, f"sessions/{session['session_id']}")["url"]
