---
description: RBC non-negotiable CVE remediation standards
trigger: always_on
---

For CVE remediation, use the `rbc-cve-remediation` skill.
Change only dependencies needed for the finding and associated compatibility edits.
Never disable tests/scanners or add suppressions to pass. Pin the lowest fixed
version resolving the CVE unless a major bump is needed. Run repository tests
and `trivy fs` rescan; include results in the PR.

PR titles start with `[CVE-REMEDIATION]`. Bodies include Pharos finding IDs,
CVE IDs, appcode, before/after versions, test and rescan evidence, and a rollback
note. Never merge. With no fixed version, do not open a PR: document a
risk-acceptance candidate for the RBC exception process, with owner, compensating
controls and review date; central security must approve any exception.
Apply LOB organization plugin conventions in addition to this baseline.
