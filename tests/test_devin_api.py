import pytest

import devin_api


def test_missing_key_fails_fast(monkeypatch):
    monkeypatch.delenv("DEVIN_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DEVIN_API_KEY"):
        devin_api.create_session("prompt")


def test_missing_org_fails_fast(monkeypatch):
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.delenv("DEVIN_ORG_ID", raising=False)
    with pytest.raises(RuntimeError, match="DEVIN_ORG_ID"):
        devin_api.create_session("prompt")


def test_create_session_uses_bearer_auth(monkeypatch):
    calls = []

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"session_id": "session-1", "status": "new"}

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return Response()

    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setenv("DEVIN_ORG_ID", "org-test")
    monkeypatch.setattr(devin_api.requests, "request", request)
    result = devin_api.create_session("do the work", playbook_id="playbook")

    assert result["session_id"] == "session-1"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer test-key"
    assert calls[0][0:2] == (
        "POST",
        "https://api.devin.ai/v3/organizations/org-test/sessions",
    )
    assert calls[0][2]["json"]["structured_output_required"] is True
    assert "idempotent" not in calls[0][2]["json"]


@pytest.fixture
def api_mock(monkeypatch):
    calls = []
    responses = []
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setenv("DEVIN_ORG_ID", "org-test")
    monkeypatch.setenv("DEVIN_API_BASE", "https://api.example/v3")
    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        if "files" in kwargs:
            calls[-1][2]["uploaded_bytes"] = kwargs["files"]["file"][1].read()
        status, body = responses.pop(0)
        class Response:
            status_code = status
            text = "error"
            def json(self):
                return body
        return Response()
    monkeypatch.setattr(devin_api.requests, "request", request)
    monkeypatch.setattr(devin_api.time, "sleep", lambda _: None)
    return calls, responses


def test_upload_multipart_and_retry(tmp_path, api_mock):
    calls, responses = api_mock
    path = tmp_path / "findings.csv"
    path.write_bytes(b"demo,csv\n")
    result = {"attachment_id": "att-1", "name": path.name, "url": "https://file"}
    responses.extend([(500, {}), (200, result)])
    assert devin_api.upload_attachment(path) == result
    assert calls[0][:2] == ("POST", "https://api.example/v3/organizations/org-test/attachments")
    for _, _, kwargs in calls:
        assert "Content-Type" not in kwargs["headers"]
        assert kwargs["headers"]["Authorization"] == "Bearer test-key"
        assert kwargs["uploaded_bytes"] == b"demo,csv\n"
        assert kwargs["files"]["file"][0] == "findings.csv"


@pytest.mark.parametrize("repo_arg", [{"repo_name": "owner/repo"},
                                      {"repos": [{"repo_name": "owner/one"},
                                                 {"repo_name": "owner/two"}]}])
def test_ingestion_body(api_mock, repo_arg):
    calls, responses = api_mock
    result = {"scan_id": "scan-1", "url": "https://scan", "status": "waiting"}
    responses.append((201, result))
    assert devin_api.start_ingestion_scan("csprof-test", ["https://file"],
                                         effort="deep", platform="linux", **repo_arg) == result
    assert calls[0][:2] == ("POST", "https://api.example/v3/organizations/org-test/code-scans/ingestion")
    assert calls[0][2]["json"] == {"profile_id": "csprof-test",
        "attachment_urls": ["https://file"], "effort": "deep", "platform": "linux", **repo_arg}


@pytest.mark.parametrize("kwargs", [{}, {"repos": []}, {"repos": [{}]},
    {"repo_name": ""}, {"repo_name": "one", "repos": [{"repo_name": "two"}]},
    {"repos": [{"repo_name": "repo"}] * 201}, {"repo_name": "one", "effort": "bad"}])
def test_invalid_ingestion_input(kwargs):
    with pytest.raises(ValueError):
        devin_api.start_ingestion_scan("csprof-test", [], **kwargs)


def test_backlog_error(api_mock):
    _, responses = api_mock
    responses.append((409, {}))
    with pytest.raises(RuntimeError, match="backlog is at capacity.*retry later"):
        devin_api.start_ingestion_scan("profile", [], repo_name="owner/repo")


def test_direct_status_and_paginated_findings(api_mock):
    calls, responses = api_mock
    responses.extend([(200, {"scan_id": "target", "status": "completed"}),
                      (200, {"items": [{"severity": "high"}], "has_next_page": True,
                             "end_cursor": "findings-next"}),
                      (200, {"items": []})])
    assert devin_api.get_scan_status("target")["status"] == "completed"
    assert calls[0][:2] == ("GET", "https://api.example/v3/organizations/org-test/code-scans/target")
    assert devin_api.list_scan_findings("target") == [{"severity": "high"}]
    assert calls[1][2]["params"] == {"first": 200, "scan_id": "target"}
    assert calls[2][2]["params"]["after"] == "findings-next"


def test_scan_not_found(api_mock):
    _, responses = api_mock
    responses.append((404, {}))
    with pytest.raises(RuntimeError, match="404"):
        devin_api.get_scan_status("absent")


def test_bulk_remediation_body(api_mock):
    calls, responses = api_mock
    result = {"session_id": "devin-planner", "finding_ids": ["finding-1"], "skipped_count": 2}
    responses.append((200, result))
    assert devin_api.remediate_findings("scan-1", ["critical", "medium"],
        repo_name="owner/repo", exclude_finding_ids=["finding-2"], branch="fix/cves",
        create_as_user_id="user-1") == result
    assert calls[0][:2] == ("POST", "https://api.example/v3/organizations/org-test/code-scans/scan-1/findings/remediate")
    assert calls[0][2]["json"] == {
        "select_all": {"severity": ["critical", "medium"], "repo_name": "owner/repo"},
        "exclude_finding_ids": ["finding-2"], "branch": "fix/cves", "create_as_user_id": "user-1"}


def test_bulk_defaults(api_mock):
    calls, responses = api_mock
    responses.append((200, {}))
    devin_api.remediate_findings("scan-1")
    assert calls[0][2]["json"] == {"select_all": {"severity": ["critical", "high"]}}


@pytest.mark.parametrize("severities", [[], (), ["unknown"], ["HIGH"], "high", None])
def test_invalid_bulk_severity(severities):
    with pytest.raises(ValueError, match="non-empty sequence"):
        devin_api.remediate_findings("scan-1", severities)


def test_bulk_400_has_actionable_message(api_mock):
    _, responses = api_mock
    responses.append((400, {}))
    with pytest.raises(RuntimeError, match="no matching findings or more than 1000"):
        devin_api.remediate_findings("scan-1")
