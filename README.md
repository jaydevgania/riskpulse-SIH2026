# RiskPulse

RiskPulse is a local-first FastAPI application that turns an **authorised, passive** external-domain assessment into an explainable security posture score, a modelled annual exposure estimate in Indian rupees, and a budget-constrained control plan.

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

To enable board-report generation, create `.env` from `.env.example`, set `ANTHROPIC_API_KEY`, and export it in your shell before starting the server. The deterministic scoring, report, monitoring and dashboard do not require an AI key.

## Tests

```powershell
python -m pytest -q
```

## Safety and product boundaries

The app requires a user acknowledgement that they own or are authorised to assess the domain. Its recon layer is deliberately limited to public, passive metadata and a single HTTPS request. It is neither a penetration test nor a compliance determination.

The DPDP/CERT-In information in the interface is an operational-readiness framing only. Before public launch, obtain current Indian legal review, calibrate the exposure model with claims/loss data, add authentication and tenant isolation, move scheduler work to durable workers, and deploy the local integrity-chain head to independently controlled storage or a public anchor.
