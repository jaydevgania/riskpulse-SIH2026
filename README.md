# RiskPulse

RiskPulse is a local-first FastAPI application that turns an **authorised, passive** external-domain assessment into an explainable security posture score, a modelled annual exposure estimate in INR, and a prioritised mitigation plan.

It was built from the SIH 2026 architecture blueprint as an executable MVP, not a presentation-only prototype.

## What works today

- Passive public-signal collection: DNS SPF/DMARC, `security.txt`, certificate-validation/expiry, response headers and certificate-transparency hostname counts.
- SSRF guardrails: domains must resolve only to public Internet IP addresses; no ports, credentials, directory discovery or exploit attempts are used.
- Transparent deterministic weighted scoring with coverage reporting. A failed external service reduces confidence rather than creating a risk finding.
- ₹ modelled Annual Loss Expectancy (ALE), clearly labelled as a planning heuristic rather than legal, insurance or actuarial advice.
- Exact 0/1 investment portfolio optimiser using an indicative India-priced controls catalogue and non-additive risk reduction.
- SQLite-persisted scans, score trend and a per-domain SHA-256 hash chain with verification endpoint.
- APScheduler continuous monitoring (minimum 5-minute cadence) and a complete browser dashboard.
- Optional Claude-powered board narrative. Without a key, an explicit deterministic report is used.

## Run locally

Requires Python 3.11+.

```powershell
cd work\riskpulse
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). The interactive API documentation is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs).

To enable board-report generation, create `.env` from `.env.example`, set `ANTHROPIC_API_KEY`, and export it in your shell before starting the server. The deterministic scoring, report, monitoring and export features will function without a key but board narrative generation requires it.

## Vercel deployment

This repository includes a minimal Vercel configuration so the dashboard (frontend) and API (backend) can be hosted together.

Files added for Vercel:
- `vercel.json` — routes and builds. It routes `/api/*` to the Python ASGI function and serves `app/static` as the site root.
- `api/index.py` — a tiny serverless entrypoint that exposes the FastAPI app.

Environment variables (set these in Vercel > Project > Settings > Environment Variables):
- `RISKPULSE_DATABASE_URL` — recommended: external DB connection string (Postgres/MySQL). If omitted the app falls back to SQLite (ephemeral on serverless).
- `ANTHROPIC_API_KEY` — optional, for board-report generation.
- `DISABLE_MONITORING` — set to `true` to disable in-process background monitoring when running on serverless (recommended).

Quick deploy steps:
1. Push `master`/`main` to GitHub.
2. Create a new Vercel project and import this repository.
3. Add the environment variables above in Vercel.
4. Deploy and test:
   - Site root should serve the dashboard (`index.html`).
   - `GET /api/health` should return `{"status":"ok","service":"RiskPulse","version":"1.0.0"}`.

Important caveats:
- Persistence: the default SQLite fallback (`data/riskpulse.db`) is ephemeral on serverless platforms — it will not persist across function invocations or deployments. Use an external database (Postgres/MySQL) for production and set `RISKPULSE_DATABASE_URL` accordingly.
- Scheduler: APScheduler (monitoring) requires a long-running process. For serverless deployments set `DISABLE_MONITORING=true` so the repository uses a no-op scheduler. For reliable monitoring, run the scheduler on a long-running host (Cloud Run, Render, Railway, a VM) or schedule external calls to the API to trigger monitoring tasks.

Optional env examples for Vercel:
```
RISKPULSE_DATABASE_URL = postgres://user:pass@host:5432/riskpulse
ANTHROPIC_API_KEY = sk-...
DISABLE_MONITORING = true
```

## Tests

```powershell
python -m pytest -q
```

## Safety and product boundaries

The app requires a user acknowledgement that they own or are authorised to assess the domain. Its recon layer is deliberately limited to public, passive metadata and a single HTTPS request. It is not intended for intrusive testing or unauthorised scanning.

The DPDP/CERT-In information in the interface is an operational-readiness framing only. Before public launch, obtain current Indian legal review, calibrate the exposure model with claims/loss data and follow local regulations.
