import json

import pytest

import scan


def _row(
    package: str,
    installed: str,
    fixed: str,
    relationship: str = "direct",
    repo: str = "owner/repo",
    path: str = "requirements.txt",
    vuln_id: str = "CVE-1",
) -> dict[str, str]:
    return {
        "repo": repo,
        "path": path,
        "package": package,
        "installed_version": installed,
        "fixed_version": fixed,
        "vuln_id": vuln_id,
        "severity": "HIGH",
        "cvss": "7.5",
        "title": "title",
        "start_line": "",
        "end_line": "",
        "relationship": relationship,
        "status": "affected",
        "cwe_ids": "",
        "published": "",
        "primary_url": "",
    }


def test_classify_rows_uses_max_target_and_range_versions():
    rows = [
        _row("lodash", "4.17.15", ">=4.17.19", vuln_id="CVE-1"),
        _row("lodash", "4.17.15", "4.17.21", vuln_id="CVE-2"),
    ]
    assert scan.classify_rows(rows)[0]["fix_type"] == "patch-bump"

    rows.append(_row("lodash", "4.17.15", "5.0.0", vuln_id="CVE-3"))
    assert scan.classify_rows(rows)[0]["fix_type"] == "major-bump"


def test_classify_rows_relationship_and_no_fix_rules():
    assert scan.classify_rows(
        [_row("demo", "1.0.0", "2.0.0", relationship="indirect")]
    )[0]["fix_type"] == "parent-uplift"
    assert scan.classify_rows(
        [_row("demo", "1.0.0", "2.0.0", relationship="direct")]
    )[0]["fix_type"] == "major-bump"
    assert scan.classify_rows(
        [_row("demo", "1.0.0", "2.0.0", relationship="")]
    )[0]["fix_type"] == "major-bump"
    assert scan.classify_rows(
        [_row("demo", "1.0.0", "", vuln_id="CVE-2")]
    )[0]["fix_type"] == "no-fix"


def test_classify_rows_override_and_go_pseudo_version():
    override = _row(
        "github.com/dgrijalva/jwt-go",
        "v3.2.0+incompatible",
        "v4.0.0",
        path="go.mod",
    )
    pseudo = _row(
        "golang.org/x/crypto",
        "v0.0.0-20201216223049-8b5274cf687f",
        "v0.55.0",
        path="go.mod",
        vuln_id="CVE-2",
    )
    classified = scan.classify_rows([override, pseudo])
    assert classified[0]["fix_type"] == "package-replacement"
    assert classified[1]["fix_type"] == "patch-bump"


def test_reclassify_accepts_repeatable_fix_type_override(tmp_path):
    findings = tmp_path / "findings.csv"
    scan.write_rows_csv([_row("demo", "1.0.0", "1.0.1")], findings)
    assert (
        scan.main(
            [
                "--reclassify",
                str(findings),
                "--fix-type-override",
                "demo=package-replacement",
            ]
        )
        == 0
    )
    assert scan.read_csv(findings)[0]["fix_type"] == "package-replacement"


def test_findings_csv_has_expected_fix_type_groups():
    rows = scan.read_csv("findings.csv")
    groups: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for row in scan.classify_rows(rows):
        if row["fix_type"] != "no-fix":
            groups.setdefault(
                scan.group_key(row, row["fix_type"]), []
            ).append(row)

    expected = {
        ("defense-factory/ms-inventory-service", "package-replacement", "github.com/dgrijalva/jwt-go"): (1, 1),
        ("defense-factory/ms-inventory-service", "patch-bump", "go.mod"): (5, 55),
        ("defense-factory/ms-notification-service", "major-bump", "org.yaml:snakeyaml"): (1, 7),
        ("defense-factory/ms-notification-service", "parent-uplift", "pom.xml"): (7, 37),
        ("defense-factory/ms-notification-service", "patch-bump", "pom.xml"): (8, 68),
        ("defense-factory/ms-payment-service", "major-bump", "cryptography"): (1, 11),
        ("defense-factory/ms-payment-service", "major-bump", "urllib3"): (1, 9),
        ("defense-factory/ms-payment-service", "patch-bump", "requirements.txt"): (2, 5),
        ("defense-factory/ms-user-service", "major-bump", "jsonwebtoken"): (1, 3),
        ("defense-factory/ms-user-service", "patch-bump", "package-lock.json"): (9, 45),
    }
    actual = {
        key: (len({row["package"] for row in found}), len(found))
        for key, found in groups.items()
    }
    assert len(rows) == 241
    assert actual == expected


def test_trivy_normalization_and_fixed_version(monkeypatch):
    fixture = json.dumps(json.load(open("tests/fixtures/trivy_sample.json")))

    class Result:
        stdout = fixture

    monkeypatch.setattr(scan.subprocess, "run", lambda *args, **kwargs: Result())
    findings = scan.scan(".", "owner/repo", "trivy")

    assert findings[0].fixed_version == "4.17.19"
    assert findings[0].severity == "HIGH"
    assert findings[0].cvss == "7.4"
    assert findings[0].start_line == "1204"
    assert findings[0].end_line == "1212"
    assert findings[0].relationship == "direct"
    assert findings[0].cwe_ids == "CWE-400"
    assert findings[0].published == "2021-08-31"
    assert findings[1].fixed_version == ""
    assert findings[1].start_line == ""
    assert findings[1].end_line == ""
    assert findings[1].relationship == ""
    assert findings[2].start_line == ""
    assert findings[2].end_line == ""
    assert findings[2].relationship == ""


def test_snyk_normalization(monkeypatch):
    fixture = json.dumps(json.load(open("tests/fixtures/snyk_sample.json")))

    class Result:
        stdout = fixture

    monkeypatch.setattr(scan.subprocess, "run", lambda *args, **kwargs: Result())
    finding = scan.scan(".", "owner/repo", "snyk")[0]

    assert finding.vuln_id == "CVE-2023-32681"
    assert finding.fixed_version == "2.31.0"
    assert finding.path == "requirements.txt"
    assert finding.relationship == "direct"
    assert finding.status == "fixed"
    assert finding.cwe_ids == "CWE-918"
    assert finding.published == "2023-05-22"
    assert finding.primary_url.endswith("SNYK-PYTHON-REQUESTS-999")


def test_csv_round_trip(tmp_path):
    finding = scan.Finding(
        "owner/repo",
        "go.mod",
        "demo",
        "1.0",
        "1.1",
        "CVE-1",
        "LOW",
        "",
        "title",
        "",
        "",
        "",
        "affected",
        "",
        "",
        "",
    )
    output = tmp_path / "findings.csv"
    scan.write_csv([finding], output)
    assert scan.read_csv(output) == [finding.as_dict()]


def test_append_rejects_stale_csv(tmp_path, monkeypatch):
    output = tmp_path / "stale.csv"
    output.write_text(
        "repo,path,package,installed_version,fixed_version,vuln_id,severity,cvss,title\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(scan, "scan", lambda *args: [])

    with pytest.raises(ValueError, match="stale.csv"):
        scan.main(
            [
                "--repo-path",
                ".",
                "--repo",
                "owner/repo",
                "--out",
                str(output),
                "--append",
            ]
        )
