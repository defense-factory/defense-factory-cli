import pytest

import devin_api


def test_missing_key_fails_fast(monkeypatch):
    monkeypatch.delenv("DEVIN_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DEVIN_API_KEY"):
        devin_api.get_session("session-1")


def test_missing_org_fails_fast(monkeypatch):
    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.delenv("DEVIN_ORG_ID", raising=False)
    with pytest.raises(RuntimeError, match="DEVIN_ORG_ID"):
        devin_api.get_session("session-1")


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


def test_get_session_uses_org_scoped_v3_path(monkeypatch):
    calls = []

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"session_id": "session-1", "status": "running"}

    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setenv("DEVIN_ORG_ID", "org-test")
    monkeypatch.setattr(
        devin_api.requests,
        "request",
        lambda method, url, **kwargs: (calls.append((method, url)) or Response()),
    )
    devin_api.get_session("session-1")

    assert calls == [
        (
            "GET",
            "https://api.devin.ai/v3/organizations/org-test/sessions/session-1",
        )
    ]


def test_session_status_helpers():
    assert not devin_api.is_session_done({"status": "new"})
    assert not devin_api.is_session_done({"status": "running", "status_detail": "working"})
    finished = {"status": "running", "status_detail": "finished"}
    assert devin_api.is_session_done(finished)
    assert devin_api.is_session_successful(finished)
    assert devin_api.is_session_done({"status": "exit"})
    assert devin_api.is_session_successful({"status": "exit"})
    assert devin_api.is_session_done({"status": "error"})
    assert not devin_api.is_session_successful({"status": "error"})
