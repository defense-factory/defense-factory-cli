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
