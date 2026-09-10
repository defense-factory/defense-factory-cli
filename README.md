# Defense Factory CLI

This repository is a small, framework-free vulnerability-remediation demo.
The committed findings artifact feeds one Devin triage session:

```text
┌────────────────────┐   ┌─────────────────────────────┐
│ findings.csv       ├──►│ kickoff.py                  │
│ frozen demo input  │   │ one Devin triage session    │
└────────────────────┘   └──────────────┬──────────────┘
                                        │
                          ┌─────────────▼─────────────┐
                          │ Child session per bucket   │
                          │ remediate and self-verify  │
                          └────────────────────────────┘
```

The triage session sorts findings into `(repo, fix_type, scope)` buckets,
starts one child session per bucket, waits for the children, and posts a
summary. Buckets in the same repository run in parallel from the default
branch, so independent children can encounter a lockfile conflict when their
pull requests are merged.

## Prerequisites

- Python 3.9 or newer and the packages in `requirements.txt`
- `DEVIN_API_KEY` and `DEVIN_ORG_ID` for a real triage session
- The client targets Devin API v3 and defaults to
  `https://api.devin.ai/v3`
- Enterprise deployments should set `DEVIN_API_BASE` to
  `https://<host>/api/v3`

The child sessions use the
`playbook-90cdbb371d5a4807babf957b36130aff` playbook
("Remediate a Vulnerability Bucket").

## One-step demo

The demo starts from the committed `findings.csv` artifact:

```bash
python kickoff.py --findings findings.csv
```

Use `--dry-run` to print the complete triage prompt without creating a
session:

```bash
python kickoff.py --findings findings.csv --dry-run
```

The triage session prints the bucket table, dispatches one child per bucket in
a single session-creation call, waits for all children, and posts a final
summary.

## Frozen findings CSV

`findings.csv` is a committed, deterministic input artifact with 241 findings.
This demo does not regenerate it. If the artifact ever needs to be
regenerated, run Trivy by hand for each service repository:

```bash
trivy fs --scanners vuln --list-all-pkgs --format json --quiet <repo>
```

The CSV columns are in this exact order:

| Column | Meaning |
| --- | --- |
| `repo` | owner/name repository identifier |
| `path` | manifest or lockfile target |
| `package` | vulnerable package |
| `installed_version` | installed package version |
| `fixed_version` | lowest available version above installed, if known |
| `vuln_id` | CVE or vulnerability identifier |
| `severity` | normalized uppercase severity |
| `cvss` | preferred CVSS v3 score |
| `title` | finding title |
| `start_line` | first line of the vulnerable package declaration, when available |
| `end_line` | last line of the vulnerable package declaration, when available |
| `relationship` | direct, indirect, root, or blank when unavailable |
| `status` | status such as `fixed` or `affected` |
| `cwe_ids` | semicolon-separated CWE identifiers |
| `published` | advisory publication date |
| `primary_url` | primary advisory URL |
| `fix_type` | remediation strategy for the package or manifest |

## Triage buckets

The findings use five fix types:

- `patch-bump`: update a compatible dependency version.
- `major-bump`: update a direct dependency across a major version.
- `parent-uplift`: update a parent or other indirect dependency to bring the
  vulnerable package along.
- `package-replacement`: replace an abandoned or otherwise unsuitable package.
- `no-fix`: report-only finding with no fixed version available.

The bucket scope is:

- `path` (the manifest or lockfile) for `patch-bump` and `parent-uplift`.
- `package` for `major-bump` and `package-replacement`.

`no-fix` rows are excluded from child buckets and included in the triage
summary as report-only findings.

## Child rescan gate

Each child session owns one bucket and must run the repository tests and
re-scan after dependency edits. PR creation is gated on every input
`vuln_id` being resolved or unfixable, with up to 3 attempts. Each attempt is
written to `scan-attempt-<n>.json` and prints a per-vulnerability
`resolved`, `still-present`, or `unfixable` verdict. The triage summary
includes each child's fixed and not-fixed findings, test result, and rescan
attempt count.

## Talk track

1. **Committed findings:** use the frozen `findings.csv` demo input.
2. **Triage:** one Devin session sorts findings and fans out one child per
   `(repo, fix_type, scope)` bucket.
3. **Remediate and self-verify:** children update dependencies, run tests, pass
   the playbook's Trivy rescan gate, and the triage session summarizes totals.

Exit code: 0
