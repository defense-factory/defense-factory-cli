"""Quick start: Pharos CSV -> Devin ingestion scan -> remediation session."""
import argparse

from utils.devin import start_ingestion_scan, wait_for_scan, start_remediation

# Ingestion profiles live in one org, so each org needs its own profile.
# wealth and qts are placeholder IDs.
ORGS = {
    "pcb": {
        "org_id": "org-44fc0af4f56347e7a64186c8cc882563",
        "profile_id": "csprof-ddebd94392fa43fca3ea63ecd70a9c04",
    },
    "wealth": {
        "org_id": "org-5a1e9c27b3d84f06a2c7e1b98f4d6a30",
        "profile_id": "csprof-7b3e2f91c4a84d5e9f0a6c12d8e4b7a1",
    },
    "qts": {
        "org_id": "org-9d2b7f4e1c6a48b3a5e0f37c2b91d8e6",
        "profile_id": "csprof-2c8a5d17e9f34b60b1d7a4e3f6c09b52",
    },
}

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--org", required=True, choices=ORGS, help="org to run in")
parser.add_argument("csv", nargs="?", default="pharos_export.csv", help="Pharos findings export")
args = parser.parse_args()
org = ORGS[args.org]

# 1. Upload the Pharos CSV and start an ingestion scan with the org's profile.
scan = start_ingestion_scan(org["org_id"], org["profile_id"], args.csv)
print(f"Scan: {scan['url']}")

# 2. Wait for the scan to finish.
status = wait_for_scan(org["org_id"], scan["scan_id"])
if status != "completed":
    raise SystemExit(f"Scan {status}; not starting remediation.")

# 3. Start one remediation session for critical and high findings.
session_url = start_remediation(org["org_id"], scan["scan_id"])
print(f"Remediation session: {session_url}")
