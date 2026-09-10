#!/usr/bin/env python3
"""Normalize Trivy or Snyk dependency findings into the demo CSV contract."""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


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
]
DEFAULT_TRIVY_DB = "ghcr.io/aquasecurity/trivy-db"


@dataclass(frozen=True)
class Finding:
    repo: str
    path: str
    package: str
    installed_version: str
    fixed_version: str
    vuln_id: str
    severity: str
    cvss: str
    title: str
    start_line: str
    end_line: str
    relationship: str
    status: str
    cwe_ids: str
    published: str
    primary_url: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _version_key(version: str) -> tuple[int, ...]:
    numbers = re.findall(r"\d+", version)
    if not numbers:
        raise ValueError(f"not a version: {version}")
    return tuple(int(number) for number in numbers)


def _fixed_version(raw: Any, installed: str) -> tuple[str, bool]:
    if not raw:
        return "", False
    if isinstance(raw, list):
        raw = "||".join(str(item) for item in raw if item)
    raw_text = str(raw).strip()
    candidates = [
        candidate.strip()
        for candidate in re.split(r"\s*(?:\|\||,)\s*", raw_text)
        if candidate.strip()
    ]
    try:
        installed_key = _version_key(installed)
        parsed = [(_version_key(candidate), candidate) for candidate in candidates]
    except ValueError:
        return "", True
    greater = [item for item in parsed if item[0] > installed_key]
    if greater:
        return min(greater)[1], False
    return min(parsed)[1], False


def _cvss(value: Any) -> str:
    if not isinstance(value, dict):
        return ""
    for name in ("nvd", "redhat"):
        candidate = value.get(name)
        if isinstance(candidate, dict) and candidate.get("V3Score") is not None:
            return str(candidate["V3Score"])
    for candidate in value.values():
        if isinstance(candidate, dict) and candidate.get("V3Score") is not None:
            return str(candidate["V3Score"])
    return ""


def _path(value: Any) -> str:
    return str(value or "")


def _package_index(result: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    by_id: dict[str, dict[str, Any]] = {}
    by_name_version: dict[tuple[str, str], dict[str, Any]] = {}
    for package in result.get("Packages") or []:
        package_id = package.get("ID")
        if package_id:
            by_id[str(package_id)] = package
        name = package.get("Name")
        version = package.get("Version")
        if name is not None and version is not None:
            by_name_version[(str(name), str(version))] = package
    return by_id, by_name_version


def _package_details(
    item: dict[str, Any],
    by_id: dict[str, dict[str, Any]],
    by_name_version: dict[tuple[str, str], dict[str, Any]],
) -> tuple[str, str, str]:
    package = by_id.get(str(item.get("PkgID", "")))
    if package is None:
        package = by_name_version.get(
            (str(item.get("PkgName", "")), str(item.get("InstalledVersion", "")))
        )
    if package is None:
        return "", "", ""
    locations = package.get("Locations") or []
    location = locations[0] if locations and isinstance(locations[0], dict) else {}
    return (
        str(location.get("StartLine", "") or ""),
        str(location.get("EndLine", "") or ""),
        str(package.get("Relationship", "") or ""),
    )


def _trivy_findings(payload: dict[str, Any], repo: str) -> list[Finding]:
    findings = []
    for result in payload.get("Results", []):
        target = _path(result.get("Target"))
        by_id, by_name_version = _package_index(result)
        for item in result.get("Vulnerabilities") or []:
            fixed, parse_failed = _fixed_version(
                item.get("FixedVersion"), str(item.get("InstalledVersion", ""))
            )
            title = str(item.get("Title", ""))
            if parse_failed and item.get("FixedVersion"):
                title = f"{title} [fixed: {item['FixedVersion']}]".strip()
            start_line, end_line, relationship = _package_details(
                item, by_id, by_name_version
            )
            cwe_ids = ";".join(str(value) for value in (item.get("CweIDs") or []))
            published = str(item.get("PublishedDate") or "")[:10]
            findings.append(
                Finding(
                    repo=repo,
                    path=target,
                    package=str(item.get("PkgName", "")),
                    installed_version=str(item.get("InstalledVersion", "")),
                    fixed_version=fixed,
                    vuln_id=str(item.get("VulnerabilityID", "")),
                    severity=str(item.get("Severity", "UNKNOWN")).upper(),
                    cvss=_cvss(item.get("CVSS")),
                    title=title,
                    start_line=start_line,
                    end_line=end_line,
                    relationship=relationship,
                    status=str(item.get("Status") or ""),
                    cwe_ids=cwe_ids,
                    published=published,
                    primary_url=str(item.get("PrimaryURL") or ""),
                )
            )
    return findings


def _snyk_fixed(item: dict[str, Any]) -> Any:
    if item.get("fixedIn"):
        return item["fixedIn"]
    path = item.get("upgradePath") or []
    versions = []
    for step in path:
        if isinstance(step, list):
            versions.extend(
                entry.get("version")
                for entry in step
                if isinstance(entry, dict) and entry.get("version")
            )
    return versions


def _snyk_findings(payload: dict[str, Any], repo: str) -> list[Finding]:
    findings = []
    for item in payload.get("vulnerabilities", []):
        identifiers = item.get("identifiers") or {}
        vuln_id = (identifiers.get("CVE") or [None])[0] or item.get("id", "")
        installed = str(item.get("version", ""))
        fixed, parse_failed = _fixed_version(_snyk_fixed(item), installed)
        title = str(item.get("title", ""))
        if parse_failed and _snyk_fixed(item):
            title = f"{title} [fixed: {_snyk_fixed(item)}]".strip()
        from_field = item.get("from")
        relationship = ""
        if "from" in item:
            relationship = "direct" if len(from_field or []) <= 2 else "indirect"
        identifiers = item.get("identifiers") or {}
        cwe_ids = ";".join(str(value) for value in (identifiers.get("CWE") or []))
        findings.append(
            Finding(
                repo=repo,
                path=_path(item.get("displayTargetFile")),
                package=str(item.get("packageName", "")),
                installed_version=installed,
                fixed_version=fixed,
                vuln_id=str(vuln_id),
                severity=str(item.get("severity", "UNKNOWN")).upper(),
                cvss=str(item.get("cvssScore", "")),
                title=title,
                start_line="",
                end_line="",
                relationship=relationship,
                status="fixed" if _snyk_fixed(item) else "affected",
                cwe_ids=cwe_ids,
                published=str(item.get("publicationTime") or "")[:10],
                primary_url=str(item.get("url") or ""),
            )
        )
    return findings


def _deduplicate(findings: Iterable[Finding]) -> list[Finding]:
    result = []
    seen = set()
    for finding in findings:
        key = (finding.path, finding.package, finding.vuln_id)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result


def scan(repo_path: str | Path, repo: str, scanner: str = "trivy") -> list[Finding]:
    """Run one scanner and return normalized, deduplicated findings."""

    scanner = scanner.lower()
    if scanner == "trivy":
        command = [
            os.environ.get("TRIVY_BIN", "trivy"),
            "--db-repository",
            os.environ.get("TRIVY_DB_REPOSITORY", DEFAULT_TRIVY_DB),
            "fs",
            "--scanners",
            "vuln",
            "--list-all-pkgs",
            "--format",
            "json",
            "--quiet",
            str(repo_path),
        ]
    elif scanner == "snyk":
        command = ["snyk", "test", "--json", str(repo_path)]
    else:
        raise ValueError(f"unsupported scanner: {scanner}")
    completed = subprocess.run(command, check=True, capture_output=True, text=True)
    payload = json.loads(completed.stdout)
    if scanner == "trivy":
        return _deduplicate(_trivy_findings(payload, repo))
    return _deduplicate(_snyk_findings(payload, repo))


def write_csv(findings: Iterable[Finding], output: str | Path) -> None:
    with open(output, "w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=CSV_COLUMNS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(finding.as_dict() for finding in findings)


def read_csv(path: str | Path) -> list[dict[str, str]]:
    with open(path, newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-path", required=True)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--scanner", choices=("trivy", "snyk"), default=None)
    parser.add_argument("--out", default="findings.csv")
    parser.add_argument("--append", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    scanner = args.scanner or os.environ.get("SCANNER", "trivy")
    findings = scan(args.repo_path, args.repo, scanner)
    if args.append and Path(args.out).exists():
        with open(args.out, newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream)
            fieldnames = set(reader.fieldnames or [])
            missing_columns = [column for column in CSV_COLUMNS if column not in fieldnames]
            if missing_columns:
                raise ValueError(
                    f"Cannot append to stale findings CSV {args.out}; regenerate it with the current scan.py"
                )
            try:
                existing = [Finding(**row) for row in reader]
            except TypeError as exc:
                raise ValueError(
                    f"Cannot append to stale findings CSV {args.out}; regenerate it with the current scan.py"
                ) from exc
        findings = _deduplicate(existing + findings)
    write_csv(findings, args.out)
    print(f"{args.repo}: {len(findings)} findings written to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
