# Defense Factory CLI

This repository is a small, framework-free orchestration demo for dependency
vulnerability remediation.

```text
┌──────────────────┐   ┌──────────────┐   ┌────────────────────┐
│ Four service     │   │ scan.py      │   │ findings.csv       │
│ repositories     ├──►│ Trivy/Snyk  ├──►│ normalized records  │
└──────────────────┘   └──────────────┘   └─────────┬──────────┘
                                                    │
                                      ┌─────────────▼─────────────┐
                                      │ orchestrate.py             │
                                      │ one Devin session per repo │
                                      └─────────────┬─────────────┘
                                                    │
                                      ┌─────────────▼─────────────┐
                                      │ Remediation PRs             │
                                      └─────────────┬─────────────┘
                                                    │
                                      ┌─────────────▼─────────────┐
                                      │ verify.py                   │
                                      │ fetch, rescan, report.md    │
                                      └─────────────────────────────┘
```

## Prerequisites

- Python 3.9 or newer and the packages in `requirements.txt`
- Trivy installed and available on `PATH` for offline Trivy scans
- `DEVIN_API_KEY` for real orchestration and verification
- Enterprise deployments should set `DEVIN_API_BASE` to their deployment's
  API base URL; the client defaults to `https://api.devin.ai/v1`.

The default Devin playbook is
`playbook-90cdbb371d5a4807babf957b36130aff` (“Remediate Dependency
Vulnerabilities”, macro `!remediate_vulns`).

## Four-command demo

From this directory, run these four commands:

1. Scan the four local service repositories:

   ```bash
   rm -f findings.csv
   python scan.py --repo-path ../ms-user-service --repo defense-factory/ms-user-service --out findings.csv
   python scan.py --repo-path ../ms-payment-service --repo defense-factory/ms-payment-service --out findings.csv --append
   python scan.py --repo-path ../ms-inventory-service --repo defense-factory/ms-inventory-service --out findings.csv --append
   python scan.py --repo-path ../ms-notification-service --repo defense-factory/ms-notification-service --out findings.csv --append
   ```

2. Start one remediation session per repository:

   ```bash
   python orchestrate.py --findings findings.csv --playbook-id playbook-90cdbb371d5a4807babf957b36130aff --state runs/latest.json
   ```

3. After sessions finish, verify their PR branches and write the report:

   ```bash
   python verify.py --state runs/latest.json --report report.md
   ```

4. Open `report.md` to review the per-repository results:

   ```bash
   less report.md
   ```

For a safe preview that does not require `DEVIN_API_KEY`, append `--dry-run`
to the orchestration command. It renders the exact data prompt that each
session would receive.

## Scanner swap

`SCANNER=trivy|snyk` selects the default scanner, while `--scanner` overrides
it for an individual scan. Trivy uses its local vulnerability database and
defaults to the GHCR repository `ghcr.io/aquasecurity/trivy-db`; override it
with `TRIVY_DB_REPOSITORY` when needed. Snyk requires an account, a
`SNYK_TOKEN`, and network access to `api.snyk.io`.

Both scanners are normalized to this CSV schema, in this exact order:

| Column | Meaning |
| --- | --- |
| `repo` | owner/name repository identifier |
| `path` | manifest or lockfile target |
| `package` | vulnerable package |
| `installed_version` | installed package version |
| `fixed_version` | lowest available version above installed, if known |
| `vuln_id` | CVE or scanner vulnerability identifier |
| `severity` | normalized uppercase severity |
| `cvss` | preferred CVSS v3 score |
| `title` | scanner finding title |
| `start_line` | first line of the vulnerable package declaration, when available |
| `end_line` | last line of the vulnerable package declaration, when available |
| `relationship` | direct, indirect, root, or blank when unavailable |
| `status` | scanner status such as `fixed` or `affected` |
| `cwe_ids` | semicolon-separated CWE identifiers |
| `published` | advisory publication date |
| `primary_url` | primary advisory URL |

Findings are deduplicated by `(path, package, vuln_id)`. Scanner findings
produce CSV rows; scanner execution failures return a nonzero exit status.
Trivy supplies line numbers for npm and pip dependencies, supplies them for
Maven dependencies declared directly in `pom.xml`, and does not supply them
for Go modules. Blank Go or Maven-transitive `start_line`/`end_line` values
are therefore expected rather than a scanning error.

## Devin structured output

Every session is asked to return:

```json
{
  "repo": "owner/name",
  "pr_url": "https://github.com/owner/name/pull/1",
  "branch": "remediation-branch",
  "fixed": ["CVE-2023-32681"],
  "not_fixed": [{"vuln_id": "CVE-2020-14343", "reason": "No compatible fix"}],
  "tests_passed": true,
  "scanner_findings_remaining": 0,
  "notes": "optional"
}
```

`verify.py` treats this as a claim, fetches the PR branch, rescans it, and
reports false claims or unfinished sessions. If structured output is absent,
it falls back to the session's `pull_request.url` and marks the verification
as degraded in the discrepancies section.

## Talk track

1. **Scan:** normalize real Trivy or Snyk results into one CSV contract.
2. **Orchestrate:** group findings by repository and send one focused prompt
   to the remediation playbook for each repo.
3. **Remediate:** each Devin session upgrades dependencies, runs tests, and
   opens a PR.
4. **Verify:** fetch each PR branch, rescan it, reconcile claimed versus
   actually absent vulnerability IDs, and present `report.md`.