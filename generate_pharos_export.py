"""Generate the frozen Pharos demo export without losing report-only findings."""

import csv
from datetime import date, timedelta
from pathlib import Path

APPCODES = {f"ms-{name}-service": f"APP-PCB-{1101 + i}" for i, name in enumerate(
    ["user", "payment", "inventory", "notification"])}
COLUMNS = "pharos_finding_id lob appcode asset_repo manifest_path package installed_version fixed_version cve_id severity cvss title cwe_ids start_line end_line first_seen sla_due pharos_status advisory_url".split()


def generate(source="findings.csv", destination="pharos_export.csv"):
    first_seen = date(2026, 10, 1)
    with Path(source).open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    with Path(destination).open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=COLUMNS)
        writer.writeheader()
        for i, row in enumerate(rows, 1):
            result = {key: row[key] for key in COLUMNS if key in row}
            result.update(pharos_finding_id=f"PHX-{i:06d}", lob="PCB",
                          appcode=APPCODES[row["repo"].split("/")[-1]],
                          asset_repo=row["repo"], manifest_path=row["path"],
                          cve_id=row["vuln_id"], first_seen=str(first_seen),
                          sla_due=str(first_seen + timedelta(days={
                              "CRITICAL": 15, "HIGH": 30, "MEDIUM": 90, "LOW": 180
                          }[row["severity"]])) if row["severity"] != "UNKNOWN" else "",
                          pharos_status="open",
                          advisory_url=row["primary_url"])
            writer.writerow(result)


if __name__ == "__main__":
    generate()
