import argparse
import sys

from utils.devin import start_ingestion, wait_for_scan, start_remediation
from utils.orgs import ORGS

parser = argparse.ArgumentParser()
parser.add_argument("--org", required=True, choices=ORGS)
parser.add_argument("path", nargs="?", default="pharos_export.csv")
args = parser.parse_args()

scan_id = start_ingestion(args.path, args.org)
status = wait_for_scan(scan_id, args.org)
if status != "completed":
    sys.exit(1)
session_id, session_url = start_remediation(scan_id, args.org)
print(f"Session: {session_id}")
print(f"URL: {session_url}")
