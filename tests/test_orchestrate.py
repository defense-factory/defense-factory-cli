import orchestrate


def test_prompt_contains_repo_table_and_verification():
    row = {
        column: value
        for column, value in zip(
            orchestrate.CSV_COLUMNS,
            ["owner/repo", "requirements.txt", "requests", "1", "2", "CVE-1", "HIGH", "7.5", "Title"],
        )
    }
    prompt = orchestrate.render_prompt("owner/repo", [row])
    assert "Remediate the dependency vulnerabilities in owner/repo" in prompt
    assert "| repo | path | package |" in prompt
    assert "CVE-1" in prompt
    assert "fixed and not_fixed per vuln_id" in prompt


def test_dry_run_does_not_create_sessions(tmp_path, monkeypatch, capsys):
    findings = tmp_path / "findings.csv"
    findings.write_text(
        "repo,path,package,installed_version,fixed_version,vuln_id,severity,cvss,title\n"
        "owner/repo,package.json,demo,1,2,CVE-1,HIGH,7.0,Title\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(orchestrate, "create_session", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError()))
    orchestrate.run_orchestration(str(findings), "playbook", dry_run=True)
    assert "owner/repo" in capsys.readouterr().out


def test_orchestration_creates_one_session_per_repo(tmp_path, monkeypatch):
    findings = tmp_path / "findings.csv"
    findings.write_text(
        "repo,path,package,installed_version,fixed_version,vuln_id,severity,cvss,title\n"
        "owner/one,package.json,demo,1,2,CVE-1,HIGH,7.0,Title\n"
        "owner/two,requirements.txt,demo,1,2,CVE-2,MEDIUM,5.0,Title\n",
        encoding="utf-8",
    )
    calls = []

    def fake_create(prompt, playbook_id, **kwargs):
        calls.append((prompt, playbook_id, kwargs))
        return {"session_id": f"s-{len(calls)}", "url": "https://devin/session"}

    monkeypatch.setattr(orchestrate, "create_session", fake_create)
    state_path = tmp_path / "state.json"
    state = orchestrate.run_orchestration(
        str(findings), "playbook", state_path=str(state_path)
    )

    assert len(calls) == 2
    assert calls[0][2]["tags"][0] == "vuln-remediation"
    assert "CVE-1" in calls[0][0]
    assert state["repos"]["owner/two"]["vuln_ids"] == ["CVE-2"]
