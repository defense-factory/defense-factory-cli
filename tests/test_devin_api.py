import pytest

import devin_api


def test_missing_key_fails_fast(monkeypatch):
    monkeypatch.delenv("DEVIN_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="DEVIN_API_KEY"):
        devin_api.get_session("session-1")


def test_create_session_uses_bearer_auth(monkeypatch):
    calls = []

    class Response:
        status_code = 200
        text = ""

        def json(self):
            return {"session_id": "session-1", "url": "https://devin.ai/s/session-1"}

    def request(method, url, **kwargs):
        calls.append((method, url, kwargs))
        return Response()

    monkeypatch.setenv("DEVIN_API_KEY", "test-key")
    monkeypatch.setattr(devin_api.requests, "request", request)
    result = devin_api.create_session("do the work", playbook_id="playbook")

    assert result["session_id"] == "session-1"
    assert calls[0][2]["headers"]["Authorization"] == "Bearer test-key"
    assert calls[0][0:2] == ("POST", "https://api.devin.ai/v1/sessions")
