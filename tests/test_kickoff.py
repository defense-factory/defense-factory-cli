import kickoff


CSV_TEXT = """repo,path,package,installed_version,fixed_version,vuln_id,severity,cvss,title,start_line,end_line,relationship,status,cwe_ids,published,primary_url,fix_type
owner/one,requirements.txt,requests,2.25.1,2.31.0,CVE-1,HIGH,7.5,Request issue,3,3,direct,fixed,,,patch-bump
owner/two,pom.xml,snakeyaml,1.0.0,2.0.0,CVE-2,CRITICAL,9.8,YAML issue,,,indirect,affected,,,parent-uplift
"""


def test_render_prompt_includes_counts_bucket_key_and_rows():
    prompt = kickoff.render_prompt(CSV_TEXT, "playbook-test")

    assert "playbook-test" in prompt
    assert "2 findings across 2 repositories" in prompt
    assert "(repo, fix_type, scope)" in prompt
    assert "owner/one,requirements.txt,requests" in prompt
    assert "owner/two,pom.xml,snakeyaml" in prompt


def test_dry_run_does_not_create_session(tmp_path, monkeypatch, capsys):
    findings = tmp_path / "findings.csv"
    findings.write_text(CSV_TEXT, encoding="utf-8")
    monkeypatch.setattr(
        kickoff,
        "create_session",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError()),
    )

    assert kickoff.main(["--findings", str(findings), "--dry-run"]) == 0
    assert "2 findings across 2 repositories" in capsys.readouterr().out


def test_non_dry_run_creates_one_triage_session(tmp_path, monkeypatch):
    findings = tmp_path / "findings.csv"
    findings.write_text(CSV_TEXT, encoding="utf-8")
    calls = []

    def fake_create(prompt, **kwargs):
        calls.append((prompt, kwargs))
        return {"session_id": "session-1", "url": "https://devin/session-1"}

    monkeypatch.setattr(kickoff, "create_session", fake_create)

    assert kickoff.main(["--findings", str(findings), "--max-acu", "10"]) == 0
    assert len(calls) == 1
    prompt, kwargs = calls[0]
    assert "owner/one,requirements.txt,requests" in prompt
    assert kwargs["playbook_id"] is None
    assert kwargs["tags"] == ["vuln-remediation", "triage"]
    assert kwargs["title"] == "Vulnerability remediation triage"
    assert kwargs["max_acu_limit"] == 10
    assert kwargs.get("structured_output_schema") is None
