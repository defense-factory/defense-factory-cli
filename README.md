# Defense Factory quick start

Upload a Pharos findings CSV to Devin Ingestion Mode, create one multi-repo
scan, wait for completion, then start remediation for critical/high findings.
The CLI prints scan and session links; it does not wait for remediation or merge PRs.
The CSV must include `asset_repo`; the ingestion profile must interpret its fields.

## Setup

Use Python 3.10+:

```bash
python -m pip install -r requirements.txt
export DEVIN_API_KEY='<service-user-key>'
export DEVIN_ORG_ID=org-44fc0af4f56347e7a64186c8cc882563
export DEVIN_API_BASE=https://test-aaron.devinenterprise.com/api/v3
export DEVIN_INGEST_PROFILE_ID=csprof-ddebd94392fa43fca3ea63ecd70a9c04
```

Alternatively, copy `.env.example` to `.env`, fill in the key, and run
`set -a; source .env; set +a`. No dotenv loader is used.
`DEVIN_API_BASE` defaults to `https://api.devin.ai/v3` when unset.

Permissions: `UseDevinSessions`, `UseCodeScans`, `ViewCodeScans`, and `manage_findings` on the scan.

## Run

```bash
python quickstart.py pharos_export.csv
```

Omitting the path uses `pharos_export.csv`. Failed/cancelled scans exit nonzero
without remediation. Remediation is billed to the caller; rerunning can start new sessions.

Remediation sessions load the [enterprise plugin](plugins/rbc-enterprise-remediation/README.md)
and [PCB LOB plugin](plugins/lob-pcb-cve-remediation/README.md) in `plugins/`.
An admin must install/configure them first; this CLI does not install plugins.
