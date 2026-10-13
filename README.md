# Ring Signature Monero CLSAG

A Python threshold-rule auditing demonstration and a standalone browser console using Monero/CLSAG-inspired naming.

**Scope:** This repository does **not** implement Monero CLSAG signing, signature verification, ring construction, key images, double-spend detection, transaction anonymity, or post-quantum cryptography. It does not certify Monero, NIST, ISO, CAP, CLSI, or HIPAA compliance. The worker names refer to generic numeric thresholds and descriptor checks.

## Features

- Three rule workers classify primary metric values above 25, secondary metric values above 12 or an enabled critical flag, and status-descriptor keywords.
- Python supervisor and CLI produce alert dossiers; FastAPI exposes the same audit evaluation.
- HMAC-SHA256 chain signs evaluation metadata in process memory. Integrity verification recomputes each HMAC with the process's secret key.
- CSV batch input, deterministic mock chat, and regression tests.
- A standalone JavaScript console under `web/index.html` applies the worker thresholds without a backend and exports JSON. With FastAPI running, the same console is served at `/`.

**Limitations:** The browser output is an explicitly labeled threshold demonstration and does not produce cryptographic audit records. Backend audit history resides only in process memory and disappears on restart. An ephemeral secret makes prior signatures unverifiable across restarts. Sensitive-data detection is regex-based and incomplete: do not enter sensitive data or treat this tool as clinically or cryptographically validated.

## Browser use

Open `web/index.html` directly. GitHub Actions can publish it to GitHub Pages; the repository's Pages source must be set to GitHub Actions. The browser demonstration uses JavaScript and needs neither Pyodide nor server-side Python. It does not intentionally store data or make network requests; files exported from the browser are saved to the user's device.

## Python setup

Requires Python 3.9 or later. From the repository root:

```bash
python -m pip install -e ".[server,test]"
python -m pytest -v
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --status DISCORDANT
python cli.py batch -i sample.csv -o results.csv
python cli.py verify-audit
python cli.py serve --host 127.0.0.1 --port 8000
```

Visit `http://127.0.0.1:8000/` for the console. Backend endpoints include `POST /api/audit`, `POST /api/chat`, `GET /health`, and `GET /metrics`.

The audit-log endpoint `GET /api/audit/logs` requires `AUDIT_LOGS_API_KEY` to be set and a matching `X-Audit-Api-Key` request header. Without configuration it denies all requests. Set a high-entropy `AUDIT_SECRET_KEY` for stable in-process signatures. **There is no general API authentication or rate limiting:** bind to localhost or use a secure authenticated reverse proxy.

## Docker

```bash
export AUDIT_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
docker compose up --build
```

Compose binds to localhost and refuses to start without an audit secret. The container runs without root privileges.

## Batch format

Expected CSV columns are `task_id`, `target_identifier`, `primary_metric`, `secondary_metric`, `status_descriptor`, and `is_critical_flag`. See `sample.csv`. Invalid records are skipped with warnings. Input and output paths must differ.

## Protocol references

For actual CLSAG cryptography, consult and use the Monero implementation rather than this demonstration:

- [Monero CLSAG implementation](https://github.com/monero-project/monero/blob/master/src/ringct/rctSigs.cpp)
- [Zero to Monero, second edition](https://web.getmonero.org/library/Zero-to-Monero-2-0-0.pdf)

**Technology:** Python, Pydantic v2, optional FastAPI/Uvicorn, HTML and JavaScript, GitHub Actions. The browser console targets modern desktop and mobile browsers. **License:** [MIT](LICENSE).
