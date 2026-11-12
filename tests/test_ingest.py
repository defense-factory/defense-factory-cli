import csv
from pathlib import Path

import pytest

import ingest
from generate_pharos_export import generate


def test_export_is_deterministic_and_preserves_all_rows(tmp_path):
    output = tmp_path / "export.csv"
    generate(destination=output)
    assert output.read_bytes() == Path("pharos_export.csv").read_bytes()
    rows = list(csv.DictReader(output.open()))
    original = list(csv.DictReader(open("findings.csv")))
    assert len(rows) == len(original) == 241
    assert "fix_type" not in rows[0]
    assert len({r["pharos_finding_id"] for r in rows}) == 241
    for row, source in zip(rows, original):
        assert row["cve_id"] == source["vuln_id"]
        assert row["fixed_version"] == source["fixed_version"]
        assert row["severity"] == source["severity"]
        assert row["lob"] == "PCB"
        assert row["first_seen"] == "2026-10-01"
        assert row["sla_due"] == {"CRITICAL": "2026-10-16", "HIGH": "2026-10-31",
                                  "MEDIUM": "2026-12-30", "LOW": "2027-03-30",
                                  "UNKNOWN": ""}[row["severity"]]


def test_dry_run_never_calls_api(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        raise AssertionError("API called")
    monkeypatch.setattr(ingest, "upload_attachment", forbidden)
    monkeypatch.setattr(ingest, "start_ingestion_scan", forbidden)
    assert ingest.main(["--dry-run", "--profile-id", "csprof-test"]) == 0
    output = capsys.readouterr().out
    assert "241 findings across 4 repositories" in output
    assert "UNKNOWN" in output
    assert '"repos"' in output
    assert '"repo_name": "defense-factory/ms-user-service"' in output


def test_filters_upload_only_selected_rows(monkeypatch):
    uploads, calls = [], []
    paths = []
    def upload(path):
        paths.append(Path(path))
        uploads.extend(csv.DictReader(Path(path).open()))
        return {"url": "https://attachment"}
    def start(**kwargs):
        calls.append(kwargs)
        return {"scan_id": "scan-1", "url": "https://scan", "status": "waiting"}
    monkeypatch.setattr(ingest, "upload_attachment", upload)
    monkeypatch.setattr(ingest, "start_ingestion_scan", start)
    assert ingest.main(["--profile-id", "csprof-test", "--lob", "PCB", "--repo",
                        "defense-factory/ms-user-service", "--repo",
                        "defense-factory/ms-payment-service", "--effort", "deep"]) == 0
    assert {r["asset_repo"] for r in uploads} == {
        "defense-factory/ms-user-service", "defense-factory/ms-payment-service"}
    assert all(r["lob"] == "PCB" for r in uploads)
    assert len(calls) == 1
    assert calls[0]["attachment_urls"] == ["https://attachment"]
    assert calls[0]["effort"] == "deep"
    assert len(calls[0]["repos"]) == 2
    assert not paths[0].exists()


@pytest.mark.parametrize("extra", [["--lob", "missing"], ["--repo", "missing/repo"]])
def test_empty_filter_fails(extra, capsys):
    with pytest.raises(SystemExit) as exc:
        ingest.main(["--profile-id", "test", "--dry-run", *extra])
    assert exc.value.code == 1
    assert "No findings match" in capsys.readouterr().err


def test_bad_csv_fails(tmp_path, capsys):
    path = tmp_path / "bad.csv"
    path.write_text("wrong\nvalue\n")
    with pytest.raises(SystemExit):
        ingest.main(["--export", str(path), "--profile-id", "test", "--dry-run"])
    assert "requires asset_repo" in capsys.readouterr().err


def test_missing_profile_fails(monkeypatch, capsys):
    monkeypatch.delenv("DEVIN_INGEST_PROFILE_ID", raising=False)
    with pytest.raises(SystemExit) as exc:
        ingest.main(["--dry-run"])
    assert exc.value.code == 2
    assert "profile-id or DEVIN_INGEST_PROFILE_ID" in capsys.readouterr().err


def test_upload_failure_does_not_start_scan(monkeypatch, capsys):
    def upload(path):
        raise RuntimeError("Upload denied")
    def forbidden(**kwargs):
        raise AssertionError("Scan started after failed upload")
    monkeypatch.setattr(ingest, "upload_attachment", upload)
    monkeypatch.setattr(ingest, "start_ingestion_scan", forbidden)
    with pytest.raises(SystemExit) as exc:
        ingest.main(["--profile-id", "test"])
    assert exc.value.code == 1
    assert "Upload denied" in capsys.readouterr().err


@pytest.mark.parametrize("status,code", [("completed", 0), ("failed", 1), ("cancelled", 1)])
def test_wait_reports_terminal_findings(monkeypatch, capsys, status, code):
    monkeypatch.setenv("DEVIN_INGEST_PROFILE_ID", "from-env")
    monkeypatch.setattr(ingest, "upload_attachment", lambda path: {"url": "https://file"})
    def start(**kwargs):
        assert kwargs["profile_id"] == "from-env"
        return {"scan_id": "scan-1", "url": "https://scan", "status": "waiting"}
    monkeypatch.setattr(ingest, "start_ingestion_scan", start)
    monkeypatch.setattr(ingest.time, "sleep", lambda _: None)
    monkeypatch.setattr(ingest, "get_scan_status", lambda *a, **k: {
        "scan_id": "scan-1", "status": status})
    monkeypatch.setattr(ingest, "list_scan_findings", lambda _: [{"severity": "high"}])
    assert ingest.main(["--wait"]) == code
    assert "HIGH=1" in capsys.readouterr().out


@pytest.mark.parametrize("existing", [True, False])
@pytest.mark.parametrize("terminal", ["completed", "failed", "cancelled"])
def test_remediation_waits_and_gates_on_completion(monkeypatch, capsys, existing, terminal):
    events = []
    def forbidden(*args, **kwargs):
        raise AssertionError("Existing scan must skip upload/ingestion")
    monkeypatch.setattr(ingest, "upload_attachment", forbidden if existing else lambda _: {"url": "file"})
    monkeypatch.setattr(ingest, "start_ingestion_scan", forbidden if existing else lambda **k: {
        "scan_id": "scan-1", "status": "running", "url": "https://scan"})
    states = iter(["running", terminal] if existing else [terminal])
    def status(scan_id):
        state = next(states)
        events.append(state)
        return {"scan_id": scan_id, "status": state}
    def remediate(scan_id, **kwargs):
        assert events[-1] == "completed"
        assert kwargs["severities"] == ["critical", "high"]
        events.append("remediate")
        return {"session_id": "devin-planner123", "finding_ids": ["f-1", "f-2"], "skipped_count": 3}
    monkeypatch.setattr(ingest, "get_scan_status", status)
    monkeypatch.setattr(ingest, "remediate_findings", remediate)
    monkeypatch.setattr(ingest, "list_scan_findings", lambda _: [])
    monkeypatch.setattr(ingest.time, "sleep", lambda _: None)
    monkeypatch.setenv("DEVIN_API_BASE", "https://deployment.example/api/v3")
    args = ["--scan-id", "scan-1"] if existing else ["--profile-id", "test"]
    assert ingest.main([*args, "--remediate"]) == (0 if terminal == "completed" else 1)
    assert ("remediate" in events) == (terminal == "completed")
    if terminal == "completed":
        output = capsys.readouterr().out
        assert "https://deployment.example/sessions/planner123" in output
        assert "Findings picked up: 2; skipped_count: 3" in output


def test_existing_completed_scan_options(monkeypatch):
    monkeypatch.delenv("DEVIN_INGEST_PROFILE_ID", raising=False)
    monkeypatch.setattr(ingest, "get_scan_status", lambda _: {"scan_id": "old", "status": "completed"})
    monkeypatch.setattr(ingest, "list_scan_findings", lambda _: [])
    calls = []
    def remediate(scan_id, **kwargs):
        calls.append((scan_id, kwargs))
        return {"session_id": "fix", "finding_ids": ["f"], "skipped_count": 0}
    monkeypatch.setattr(ingest, "remediate_findings", remediate)
    assert ingest.main(["--scan-id", "old", "--remediate", "--repo", "owner/repo",
        "--severity", "high,low", "--remediate-branch", "fix/cve", "--exclude-finding-id", "f-1",
        "--exclude-finding-id", "f-2", "--create-as-user-id", "user-1"]) == 0
    assert calls == [("old", {"severities": ["high", "low"], "repo_name": "owner/repo",
        "branch": "fix/cve", "exclude_finding_ids": ["f-1", "f-2"], "create_as_user_id": "user-1"})]


@pytest.mark.parametrize("existing", [True, False])
def test_remediation_dry_run_no_calls(monkeypatch, capsys, existing):
    def forbidden(*a, **k):
        raise AssertionError("API called during dry-run")
    for name in ["upload_attachment", "start_ingestion_scan", "get_scan_status",
                 "list_scan_findings", "remediate_findings"]:
        monkeypatch.setattr(ingest, name, forbidden)
    args = ["--scan-id", "old"] if existing else ["--profile-id", "test"]
    assert ingest.main([*args, "--dry-run", "--remediate"]) == 0
    output = capsys.readouterr().out
    assert '"select_all"' in output
    assert '"critical"' in output and '"high"' in output
    assert ('"attachment_urls"' in output) == (not existing)


def test_invalid_remediation_severity(capsys):
    with pytest.raises(SystemExit) as exc:
        ingest.main(["--scan-id", "old", "--remediate", "--dry-run", "--severity", ""])
    assert exc.value.code == 1
    assert "non-empty sequence" in capsys.readouterr().err
