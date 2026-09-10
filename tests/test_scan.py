import json

import pytest

import scan


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
