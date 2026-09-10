"""Small client for the Devin sessions API."""

from __future__ import annotations

import os
import time
from typing import Any

import requests


DEFAULT_API_BASE = "https://api.devin.ai/v3"
TERMINAL_STATUSES = {"exit", "error", "suspended"}


def _credentials() -> tuple[str, str, str]:
    key = os.environ.get("DEVIN_API_KEY")
    if not key:
        raise RuntimeError(
            "DEVIN_API_KEY is not set; provide it before creating or polling Devin sessions"
        )
    org_id = os.environ.get("DEVIN_ORG_ID")
    if not org_id:
        raise RuntimeError(
            "DEVIN_ORG_ID is not set; provide it before creating or polling Devin sessions"
        )
    return os.environ.get("DEVIN_API_BASE", DEFAULT_API_BASE).rstrip("/"), key, org_id


def _request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    base, key, _ = _credentials()
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {key}"
    headers.setdefault("Content-Type", "application/json")
    for attempt in range(3):
        response = requests.request(
            method,
            f"{base}{path}",
            headers=headers,
            timeout=30,
            **kwargs,
        )
        if response.status_code == 429 or response.status_code >= 500:
            if attempt < 2:
                time.sleep(2**attempt)
                continue
        if response.status_code >= 400:
            raise RuntimeError(
                f"Devin API {response.status_code} for {method} {path}: {response.text}"
            )
        return response.json()
    raise RuntimeError(f"Devin API retries exhausted for {method} {path}")


def create_session(
    prompt: str,
    playbook_id: str | None = None,
    tags: list[str] | None = None,
    title: str | None = None,
    structured_output_schema: dict[str, Any] | None = None,
    structured_output_required: bool = True,
    max_acu_limit: int | None = None,
    repos: list[str] | None = None,
) -> dict[str, Any]:
    base, _, org_id = _credentials()
    payload: dict[str, Any] = {
        "prompt": prompt,
        "playbook_id": playbook_id,
        "tags": tags,
        "title": title,
        "structured_output_schema": structured_output_schema,
        "structured_output_required": structured_output_required,
        "max_acu_limit": max_acu_limit,
        "repos": repos,
    }
    return _request(
        "POST",
        f"/organizations/{org_id}/sessions",
        json={key: value for key, value in payload.items() if value is not None},
    )


def get_session(session_id: str) -> dict[str, Any]:
    _, _, org_id = _credentials()
    return _request("GET", f"/organizations/{org_id}/sessions/{session_id}")


def is_session_done(session: dict[str, Any]) -> bool:
    """True when polling should stop."""
    status = session.get("status")
    if status in TERMINAL_STATUSES:
        return True
    return status == "running" and session.get("status_detail") == "finished"


def is_session_successful(session: dict[str, Any]) -> bool:
    """True when the session completed its work rather than dying."""
    status = session.get("status")
    if status == "exit":
        return True
    return status == "running" and session.get("status_detail") == "finished"
