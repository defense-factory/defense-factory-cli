import csv
from collections import defaultdict


CSV_COLUMNS = [
    "repo",
    "path",
    "package",
    "installed_version",
    "fixed_version",
    "vuln_id",
    "severity",
    "cvss",
    "title",
    "start_line",
    "end_line",
    "relationship",
    "status",
    "cwe_ids",
    "published",
    "primary_url",
    "fix_type",
]
FIX_TYPES = {
    "patch-bump",
    "major-bump",
    "parent-uplift",
    "package-replacement",
    "no-fix",
}


def test_committed_findings_contract():
    with open("findings.csv", newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)

    assert reader.fieldnames == CSV_COLUMNS
    assert len(rows) == 241
    assert all(row["fix_type"] for row in rows)
    assert {row["fix_type"] for row in rows} <= FIX_TYPES

    buckets = set()
    package_types = defaultdict(set)
    for row in rows:
        package_types[(row["repo"], row["package"])].add(row["fix_type"])
        if row["fix_type"] == "no-fix":
            continue
        # Manifest scope groups patch and parent fixes; package scope groups majors.
        scope = (
            row["path"]
            if row["fix_type"] in {"patch-bump", "parent-uplift"}
            else row["package"]
        )
        buckets.add((row["repo"], row["fix_type"], scope))

    assert len(buckets) == 10
    assert all(len(fix_types) == 1 for fix_types in package_types.values())
