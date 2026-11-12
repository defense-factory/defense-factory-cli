"""Small client for the Devin sessions API."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()


DEFAULT_API_BASE = "https://api.devin.ai/v3"


def _credentials() -> tuple[str, str, str]:
    key = os.environ.get("DEVIN_API_KEY")
    if not key:
        raise RuntimeError(
            "DEVIN_API_KEY is not set; provide it before creating Devin sessions"
        )
    org_id = os.environ.get("DEVIN_ORG_ID")
    if not org_id:
        raise RuntimeError(
            "DEVIN_ORG_ID is not set; provide it before creating Devin sessions"
        )
    return os.environ.get("DEVIN_API_BASE", DEFAULT_API_BASE).rstrip("/"), key, org_id


def _request(method: str, path: str, **kwargs: Any) -> dict[str, Any]:
    base, key, _ = _credentials()
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {key}"
    if "files" not in kwargs:
        headers.setdefault("Content-Type", "application/json")
    for attempt in range(3):
        for _, stream in kwargs.get("files", {}).values():
            stream.seek(0)
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
            if response.status_code == 400 and path.endswith("/findings/remediate"):
                raise RuntimeError(
                    "Bulk remediation rejected (400): no matching findings or more than "
                    f"1000 matches; narrow the selection. API detail: {response.text}"
                )
            if response.status_code == 409 and path.endswith("/code-scans/ingestion"):
                raise RuntimeError("Devin scan backlog is at capacity (409); retry later.")
            raise RuntimeError(
                f"Devin API {response.status_code} for {method} {path}: {response.text}"
            )
        return response.json()
    raise RuntimeError(f"Devin API retries exhausted for {method} {path}")


def upload_attachment(path: str | Path) -> dict[str, Any]:
    _, _, org_id = _credentials()
    path = Path(path)
    with path.open("rb") as stream:
        return _request("POST", f"/organizations/{org_id}/attachments",
                        files={"file": (path.name, stream)})


def ingestion_payload(profile_id, attachment_urls, repos=None, repo_name=None,
                      effort=None, platform=None):
    if not profile_id:
        raise ValueError("profile_id is required")
    if (repos is None) == (repo_name is None):
        raise ValueError("Provide exactly one of repos or repo_name")
    if repos is not None and (not 1 <= len(repos) <= 200 or any(
            not isinstance(repo, dict) or not repo.get("repo_name") for repo in repos)):
        raise ValueError("repos must contain 1 to 200 objects with repo_name")
    if repo_name is not None and (not isinstance(repo_name, str) or not repo_name.strip()):
        raise ValueError("repo_name must be a nonempty string")
    if effort is not None and effort not in {"normal", "deep"}:
        raise ValueError("effort must be normal or deep")
    payload = {"profile_id": profile_id, "attachment_urls": attachment_urls}
    payload.update({"repos": repos} if repos is not None else {"repo_name": repo_name})
    for key, value in (("effort", effort), ("platform", platform)):
        if value is not None:
            payload[key] = value
    return payload


def start_ingestion_scan(profile_id, attachment_urls, repos=None, repo_name=None,
                         effort=None, platform=None):
    payload = ingestion_payload(profile_id, attachment_urls, repos, repo_name, effort, platform)
    _, _, org_id = _credentials()
    return _request("POST", f"/organizations/{org_id}/code-scans/ingestion", json=payload)


def _scan_pages(resource, **params):
    _, _, org_id = _credentials()
    params = {**params, "first": 200}
    while True:
        page = _request("GET", f"/organizations/{org_id}/code-scans/{resource}",
                        params=dict(params))
        yield from page["items"]
        if not page.get("has_next_page"):
            break
        params["after"] = page["end_cursor"]


def get_scan_status(scan_id):
    _, _, org_id = _credentials()
    return _request("GET", f"/organizations/{org_id}/code-scans/{scan_id}")


def remediation_payload(severities=("critical", "high"), repo_name=None,
                        exclude_finding_ids=None, branch=None, create_as_user_id=None):
    if isinstance(severities, str) or not severities or any(
            severity not in {"critical", "high", "medium", "low"} for severity in severities):
        raise ValueError("severities must be a non-empty sequence of critical/high/medium/low")
    selection = {"severity": list(severities)}
    if repo_name is not None:
        selection["repo_name"] = repo_name
    payload = {"select_all": selection}
    for key, value in (("exclude_finding_ids", exclude_finding_ids), ("branch", branch),
                       ("create_as_user_id", create_as_user_id)):
        if value is not None:
            payload[key] = value
    return payload


def remediate_findings(scan_id, severities=("critical", "high"), repo_name=None,
                       exclude_finding_ids=None, branch=None, create_as_user_id=None):
    """Start remediation; callers must first verify that the scan completed."""
    payload = remediation_payload(severities, repo_name, exclude_finding_ids,
                                  branch, create_as_user_id)
    _, _, org_id = _credentials()
    return _request("POST", f"/organizations/{org_id}/code-scans/{scan_id}/findings/remediate",
                    json=payload)


def list_scan_findings(scan_id):
    return list(_scan_pages("findings", scan_id=scan_id))


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
    _, _, org_id = _credentials()
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
