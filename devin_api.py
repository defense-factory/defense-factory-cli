"""Small client for the Devin sessions API."""

from __future__ import annotations

import os
import time
from typing import Any

import requests


DEFAULT_API_BASE = "https://api.devin.ai/v1"


def _credentials() -> tuple[str, str]:
    key = os.environ.get("DEVIN_API_KEY")
    if not key:
        raise RuntimeError(
            "DEVIN_API_KEY is not set; provide it before creating or polling Devin sessions"
        )
    return os.environ.get("DEVIN_API_BASE", DEFAULT_API_BASE).rstrip("/"), key


def _request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    base, key = _credentials()
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
    idempotent: bool = True,
    max_acu_limit: int | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "prompt": prompt,
        "playbook_id": playbook_id,
        "tags": tags,
        "title": title,
        "structured_output_schema": structured_output_schema,
        "idempotent": idempotent,
        "max_acu_limit": max_acu_limit,
    }
    return _request(
        "POST",
        "/sessions",
        json={key: value for key, value in payload.items() if value is not None},
    )


def get_session(session_id: str) -> dict[str, Any]:
    return _request("GET", f"/sessions/{session_id}")
