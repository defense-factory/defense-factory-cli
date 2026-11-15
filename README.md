# Defense Factory quick start

Upload a Pharos findings CSV to Devin Ingestion Mode, create one multi-repo
scan, wait for completion, then start remediation for critical/high findings.
The CLI prints scan and session links; it does not wait for remediation or merge PRs.
The CSV must include `asset_repo`; the ingestion profile must interpret its fields.
The steps live in `quickstart.py`; `utils/devin.py` handles ingestion and API calls.

## Setup

Use Python 3.10+:

```bash
python -m pip install -r requirements.txt
export DEVIN_API_KEY='<service-user-key>'
```

Alternatively, copy `.env.example` to `.env`, fill in the key, and run
`set -a; source .env; set +a`. No dotenv loader is used.
The API base (`API_URL` in `utils/devin.py`) is hardcoded to the test-aaron enterprise.

Permissions: `UseDevinSessions`, `UseCodeScans`, `ViewCodeScans`, and `manage_findings` on the scan.

## Run

```bash
python quickstart.py --org pcb pharos_export.csv
```

`--org` (`pcb`, `wealth`, `qts`) picks the Devin org and its ingestion profile
from `ORGS` in `quickstart.py`; ingestion profiles are org-level, so each org needs its own.
Only `pcb` is real; `wealth` and `qts` are placeholder IDs. Omitting the path uses `pharos_export.csv`. Failed/cancelled scans exit nonzero
without remediation. Remediation is billed to the caller; rerunning can start new sessions.

Remediation sessions load the [enterprise plugin](plugins/rbc-enterprise-remediation/README.md)
and [PCB LOB plugin](plugins/lob-pcb-cve-remediation/README.md) in `plugins/`.
An admin must install/configure them first; this CLI does not install plugins.
