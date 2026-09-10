import json

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
    assert findings[1].fixed_version == ""


def test_snyk_normalization(monkeypatch):
    fixture = json.dumps(json.load(open("tests/fixtures/snyk_sample.json")))

    class Result:
        stdout = fixture

    monkeypatch.setattr(scan.subprocess, "run", lambda *args, **kwargs: Result())
    finding = scan.scan(".", "owner/repo", "snyk")[0]

    assert finding.vuln_id == "CVE-2023-32681"
    assert finding.fixed_version == "2.31.0"
    assert finding.path == "requirements.txt"


def test_csv_round_trip(tmp_path):
    finding = scan.Finding("owner/repo", "go.mod", "demo", "1.0", "1.1", "CVE-1", "LOW", "", "title")
    output = tmp_path / "findings.csv"
    scan.write_csv([finding], output)
    assert scan.read_csv(output) == [finding.as_dict()]
