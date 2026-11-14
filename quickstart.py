import sys

from utils.devin import start_ingestion, wait_for_scan, start_remediation

path = sys.argv[1] if len(sys.argv) > 1 else "pharos_export.csv"
scan_id = start_ingestion(path)
status = wait_for_scan(scan_id)
if status != "completed":
    sys.exit(1)
session_id, session_url = start_remediation(scan_id)
print(f"Session: {session_id}")
print(f"URL: {session_url}")
