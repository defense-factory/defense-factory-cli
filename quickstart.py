import csv
import os
import sys
import time
from urllib.parse import urlsplit

import requests

path = sys.argv[1] if len(sys.argv) > 1 else "pharos_export.csv"
base = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v3").rstrip("/")
org = f"{base}/organizations/{os.environ['DEVIN_ORG_ID']}"
headers = {"Authorization": f"Bearer {os.environ['DEVIN_API_KEY']}"}


def post(url, **kwargs):
    response = requests.post(url, headers=headers, timeout=30, **kwargs)
    response.raise_for_status()
    return response.json()


with open(path, "rb") as stream:
    attachment = post(f"{org}/attachments", files={"file": (os.path.basename(path), stream)})
with open(path, newline="", encoding="utf-8-sig") as stream:
    repos = [{"repo_name": r} for r in sorted({row["asset_repo"] for row in csv.DictReader(stream)})]
scan = post(f"{org}/code-scans/ingestion", json={
    "profile_id": os.environ["DEVIN_INGEST_PROFILE_ID"],
    "attachment_urls": [attachment["url"]], "repos": repos})
print(f"Scan: {scan['scan_id']}")
if scan.get("url"):
    print(f"URL: {scan['url']}")
scan_url = f"{org}/code-scans/{scan['scan_id']}"
while True:
    response = requests.get(scan_url, headers=headers, timeout=30)
    response.raise_for_status()
    status = response.json()["status"]
    print(f"Status: {status}")
    if status in {"completed", "failed", "cancelled"}:
        break
    time.sleep(10)
if status != "completed":
    sys.exit(1)
session = post(f"{scan_url}/findings/remediate", json={"select_all": {"severity": ["critical", "high"]}})
host = urlsplit(base)
print(f"Session: {session['session_id']}")
print(f"URL: {host.scheme}://{host.netloc}/sessions/{session['session_id'].removeprefix('devin-')}")
