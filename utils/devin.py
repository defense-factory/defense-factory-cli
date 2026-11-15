import csv
import os
import time
from urllib.parse import urlsplit

import requests

from utils.orgs import ORGS

base = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v3").rstrip("/")
headers = {"Authorization": f"Bearer {os.environ['DEVIN_API_KEY']}"}


def post(url, **kwargs):
    response = requests.post(url, headers=headers, timeout=30, **kwargs)
    response.raise_for_status()
    return response.json()


def org_url(org):
    return f"{base}/organizations/{ORGS[org]['org_id']}"


def start_ingestion(path, org):
    with open(path, "rb") as stream:
        attachment = post(f"{org_url(org)}/attachments", files={"file": (os.path.basename(path), stream)})
    with open(path, newline="", encoding="utf-8-sig") as stream:
        repos = [{"repo_name": r} for r in sorted({row["asset_repo"] for row in csv.DictReader(stream)})]
    scan = post(f"{org_url(org)}/code-scans/ingestion", json={
        "profile_id": ORGS[org]["profile_id"],
        "attachment_urls": [attachment["url"]], "repos": repos})
    print(f"Scan: {scan['scan_id']}")
    if scan.get("url"):
        print(f"URL: {scan['url']}")
    return scan["scan_id"]


def wait_for_scan(scan_id, org):
    while True:
        response = requests.get(f"{org_url(org)}/code-scans/{scan_id}", headers=headers, timeout=30)
        response.raise_for_status()
        status = response.json()["status"]
        print(f"Status: {status}")
        if status in {"completed", "failed", "cancelled"}:
            return status
        time.sleep(10)


def start_remediation(scan_id, org):
    session = post(f"{org_url(org)}/code-scans/{scan_id}/findings/remediate",
                   json={"select_all": {"severity": ["critical", "high"]}})
    host = urlsplit(base)
    session_id = session["session_id"]
    return session_id, f"{host.scheme}://{host.netloc}/sessions/{session_id.removeprefix('devin-')}"
