import json

import verify
from verify import _pull_request_url, reconcile


def test_reconcile_all_fixed():
    result = reconcile(["CVE-1", "CVE-2"], ["CVE-1", "CVE-2"], set())
    assert result["actually_absent"] == ["CVE-1", "CVE-2"]
    assert result["unfixed"] == []
    assert result["false_claims"] == []


def test_reconcile_partially_fixed():
    result = reconcile(["CVE-1", "CVE-2"], ["CVE-1"], {"CVE-2"})
    assert result["actually_absent"] == ["CVE-1"]
    assert result["unfixed"] == ["CVE-2"]


def test_reconcile_false_claim():
    result = reconcile(["CVE-1"], ["CVE-1"], {"CVE-1"})
    assert result["actually_absent"] == []
    assert result["false_claims"] == ["CVE-1"]


def test_pull_request_url_uses_matching_v3_pull_request():
    session = {
        "pull_requests": [
            {"pr_url": "https://github.com/other/repo/pull/2"},
            {"pr_url": "https://github.com/owner/repo/pull/1"},
        ]
    }
    assert _pull_request_url(session, "owner/repo") == "https://github.com/owner/repo/pull/1"


def _run_case(
    tmp_path, monkeypatch, details, structured, scanned_by_url, session_pull_requests=None
):
    state_path = tmp_path / "state.json"
    state_path.write_text(
        json.dumps({"scanner": "trivy", "repos": {"owner/repo": details}}),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        verify,
        "_poll",
        lambda session_id, poll_interval, timeout: (
            {
                "status": "exit",
                "structured_output": structured,
                "pull_requests": session_pull_requests or [],
            },
            True,
        ),
    )
    monkeypatch.setattr(
        verify,
        "_scan_pr",
        lambda repo, pr_url, scanner, workdir: (scanned_by_url[pr_url], "branch"),
    )
    report = tmp_path / "report.md"
    code = verify.run(str(state_path), timeout=1, report=str(report))
    return code, report.read_text(encoding="utf-8")


def test_multi_pr_reconcile_and_false_claim_does_not_mask_other_group(
    tmp_path, monkeypatch
):
    details = {
        "session_id": "s1",
        "vuln_ids": ["CVE-1", "CVE-2"],
        "groups": [
            {"fix_type": "major-bump", "scope": "one", "vuln_ids": ["CVE-1"]},
            {"fix_type": "patch-bump", "scope": "two", "vuln_ids": ["CVE-2"]},
        ],
    }
    structured = {
        "pull_requests": [
            {
                "fix_type": "major-bump",
                "pr_url": "https://github.com/owner/repo/pull/1",
                "fixed": ["CVE-1"],
                "not_fixed": [],
                "tests_passed": True,
                "rescan_attempts": 1,
            },
            {
                "fix_type": "patch-bump",
                "pr_url": "https://github.com/owner/repo/pull/2",
                "fixed": ["CVE-2"],
                "not_fixed": [],
                "tests_passed": True,
                "rescan_attempts": 1,
            },
        ],
        "not_fixed": [],
    }
    code, report = _run_case(
        tmp_path,
        monkeypatch,
        details,
        structured,
        {
            "https://github.com/owner/repo/pull/1": ["CVE-1"],
            "https://github.com/owner/repo/pull/2": [],
        },
    )
    assert code == 1
    assert "false claims CVE-1" in report
    assert "CVE-2" in report
    assert report.count("| owner/repo |") == 2


def test_missing_vulnerability_is_a_coverage_discrepancy(tmp_path, monkeypatch):
    details = {
        "session_id": "s1",
        "vuln_ids": ["CVE-1", "CVE-2"],
        "groups": [
            {"fix_type": "patch-bump", "scope": "requirements.txt", "vuln_ids": ["CVE-1", "CVE-2"]}
        ],
    }
    structured = {
        "pull_requests": [
            {
                "fix_type": "patch-bump",
                "pr_url": "https://github.com/owner/repo/pull/3",
                "fixed": ["CVE-1"],
                "not_fixed": [],
                "tests_passed": True,
                "rescan_attempts": 1,
            }
        ],
        "not_fixed": [],
    }
    code, report = _run_case(
        tmp_path,
        monkeypatch,
        details,
        structured,
        {"https://github.com/owner/repo/pull/3": []},
    )
    assert code == 1
    assert "missing coverage vuln_ids CVE-2" in report


def test_legacy_pr_url_shape_still_verifies_with_discrepancy(tmp_path, monkeypatch):
    details = {"session_id": "s1", "vuln_ids": ["CVE-1"]}
    structured = {
        "pr_url": "https://github.com/owner/repo/pull/4",
        "fixed": ["CVE-1"],
        "not_fixed": [],
        "tests_passed": True,
    }
    code, report = _run_case(
        tmp_path,
        monkeypatch,
        details,
        structured,
        {"https://github.com/owner/repo/pull/4": []},
    )
    assert code == 0
    assert "legacy single pr_url structured-output shape" in report
    assert "| owner/repo |" in report


def test_missing_structured_output_with_pr_url_is_degraded_not_fatal(
    tmp_path, monkeypatch
):
    details = {"session_id": "s1", "vuln_ids": ["CVE-1"]}
    code, report = _run_case(
        tmp_path,
        monkeypatch,
        details,
        {},
        {"https://github.com/owner/repo/pull/5": []},
        session_pull_requests=[
            {"pr_url": "https://github.com/owner/repo/pull/5"}
        ],
    )
    assert code == 0
    assert "degraded verification" in report
