# RBC enterprise remediation baseline (demo)

Owned by RBC Central Security. Required enterprise-wide: an enterprise admin
adds this git-hosted plugin to the enterprise managed manifest's
`requiredPlugins` in Customize. Files alone do not enforce enterprise policy.

Install from `defense-factory/defense-factory-cli`, subdirectory
`plugins/rbc-enterprise-remediation`. Example managed-manifest entry:

```json
{"requiredPlugins": [{"source": "git-subdir", "url": "https://github.com/defense-factory/defense-factory-cli.git", "path": "plugins/rbc-enterprise-remediation"}]}
```

Propose changes by PR to this repository, requesting central security review.
After approval, admins refresh the plugin (or update a pinned SHA). LOB teams
extend this baseline in org-scoped plugins, not by weakening enterprise rules.
RBC exception-process references are demo policy placeholders, not approvals.
