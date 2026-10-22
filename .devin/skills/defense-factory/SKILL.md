---
name: defense-factory
description: Start a Defense Factory vulnerability-remediation triage session from a findings CSV.
argument-hint: "[findings.csv] [--dry-run] [--playbook-id <id>] [--max-acu <n>]"
allowed-tools:
  - read
  - exec
  - glob
---

Run the Defense Factory CLI triage session.

1. Check that `DEVIN_API_KEY` and `DEVIN_ORG_ID` are set in the environment; if either is missing, stop and tell the user how to set them.
2. Determine the user's intent from the slash command arguments:
   - Optional findings file path; default to `findings.csv` if omitted.
   - Optional `--dry-run` flag to render the triage prompt without creating a session.
   - Optional `--playbook-id <id>` to override the default remediation playbook.
   - Optional `--max-acu <n>` to set a maximum ACU limit on the triage session.
3. Build the command: `python kickoff.py --findings <file>` plus any provided flags, then execute it in the repository root.
4. Print the key result:
   - For `--dry-run`, print the rendered prompt.
   - For a live run, print the session ID and URL returned by the API.
5. If the command fails, explain the failure clearly and do not retry automatically.

Use only the existing `kickoff.py` entry point; do not reimplement the bucketing or remediation logic inside the skill.
