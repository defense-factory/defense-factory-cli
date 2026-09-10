import orchestrate


def test_prompt_contains_repo_table_and_verification():
    row = {
        column: value
        for column, value in zip(
            orchestrate.CSV_COLUMNS,
            [
                "owner/repo",
                "requirements.txt",
                "requests",
                "1",
                "1.1",
                "CVE-1",
                "HIGH",
                "7.5",
                "Title",
                "",
                "",
                "direct",
                "fixed",
                "CWE-1",
                "2024-01-01",
                "https://example.com/CVE-1",
            ],
        )
    }
    prompt = orchestrate.render_prompt("owner/repo", [row])
    assert "Remediate the dependency vulnerabilities in owner/repo" in prompt
    assert "| fix_type | vuln_id | package | installed_version |" in prompt
    assert "PR plan (one PR per group, in this order):" in prompt
    assert "patch-bump: requirements.txt" in prompt
    assert "CVE-1" in prompt
    assert "fixed and not_fixed per vuln_id" in prompt
    assert "up to 3 attempts" in prompt


def test_fix_type_groups_patch_first_and_deterministic():
    def row(package, fixed, severity, path="requirements.txt", relationship="direct"):
        return {
            "repo": "owner/repo",
            "path": path,
            "package": package,
            "installed_version": "1.0.0",
            "fixed_version": fixed,
            "vuln_id": f"CVE-{package}",
            "severity": severity,
            "cvss": "",
            "title": "",
            "relationship": relationship,
        }

    groups = orchestrate.fix_type_groups(
        [
            row("major", "2.0.0", "CRITICAL", "major.json"),
            row("patch", "1.0.1", "LOW"),
            row("parent", "2.0.0", "HIGH", "pom.xml", "indirect"),
        ]
    )
    assert [(fix_type, scope) for fix_type, scope, _ in groups] == [
        ("patch-bump", "requirements.txt"),
        ("major-bump", "major"),
        ("parent-uplift", "pom.xml"),
    ]


def test_fix_type_groups_preserves_existing_classification():
    row = {
        "repo": "owner/repo",
        "path": "requirements.txt",
        "package": "demo",
        "installed_version": "1.0.0",
        "fixed_version": "2.0.0",
        "fix_type": "patch-bump",
        "vuln_id": "CVE-1",
        "severity": "HIGH",
    }
    assert orchestrate.fix_type_groups([row])[0][0] == "patch-bump"


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
    assert state["repos"]["owner/two"]["groups"][0]["fix_type"] == "major-bump"
