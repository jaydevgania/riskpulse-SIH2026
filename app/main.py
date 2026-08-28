from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.config import APP_NAME, APP_VERSION, DATABASE_PATH
from app.models import MonitoringRequest, MonitoringUpdate, OptimiseRequest, ScanRequest
from app.services.database import Database
from app.services.recon import DomainSafetyError, assert_public_target
from app.services.risk_service import RiskService
from app.services.scheduler import MonitoringScheduler


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    database = Database(DATABASE_PATH)
    database.initialise()
    risk_service = RiskService(database)
    scheduler = MonitoringScheduler(database, risk_service)
    app.state.database = database
    app.state.risk_service = risk_service
    app.state.scheduler = scheduler
    scheduler.start()
    yield
    scheduler.shutdown()


app = FastAPI(
    title="RiskPulse API",
    version=APP_VERSION,
    description="Passive external cyber-risk prioritisation for Indian MSMEs.",
    lifespan=lifespan,
)
STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/assets", StaticFiles(directory=STATIC_DIR), name="assets")


def service(request: Request) -> RiskService:
    return request.app.state.risk_service


def database(request: Request) -> Database:
    return request.app.state.database


@app.get("/", include_in_schema=False)
async def dashboard() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": APP_NAME, "version": APP_VERSION}


async def scan_endpoint(payload: ScanRequest, request: Request) -> dict:
    if not payload.authorized:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You must confirm ownership or authorisation before a passive domain assessment.",
        )
    try:
        return await service(request).scan(payload.domain, payload.revenue_band)
    except DomainSafetyError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="The scan could not complete. External checks may be temporarily unavailable; please retry.",
        ) from None


@app.post("/api/scan", name="run_passive_scan")
@app.post("/scan", include_in_schema=False)
async def create_scan(payload: ScanRequest, request: Request) -> dict:
    return await scan_endpoint(payload, request)


@app.get("/api/scan/{scan_id}")
@app.get("/scan/{scan_id}", include_in_schema=False)
async def get_scan(scan_id: int, request: Request) -> dict:
    scan = database(request).get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return scan


@app.get("/api/trend/{domain}")
@app.get("/trend/{domain}", include_in_schema=False)
async def get_trend(domain: str, request: Request) -> dict:
    try:
        normalised = service(request).normalise_domain(domain)
    except DomainSafetyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"domain": normalised, "items": database(request).trend(normalised)}


@app.get("/api/ledger/verify/{domain}")
@app.get("/ledger/verify/{domain}", include_in_schema=False)
async def ledger_verify(domain: str, request: Request) -> dict:
    try:
        normalised = service(request).normalise_domain(domain)
    except DomainSafetyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"domain": normalised, **database(request).verify_ledger(normalised)}


@app.post("/api/optimize")
@app.post("/optimize", include_in_schema=False)
async def optimise(payload: OptimiseRequest, request: Request) -> dict:
    result = service(request).optimise_scan(payload.scan_id, payload.budget_inr)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return result


@app.get("/api/report/{scan_id}")
@app.get("/report/{scan_id}", include_in_schema=False)
async def get_report(scan_id: int, request: Request) -> dict:
    scan = database(request).get_scan(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {"scan_id": scan_id, "domain": scan["domain"], **scan["board_report"]}


@app.post("/api/monitor", status_code=status.HTTP_201_CREATED)
async def create_monitoring(payload: MonitoringRequest, request: Request) -> dict:
    if not payload.authorized:
        raise HTTPException(status_code=403, detail="You must confirm authorisation before enabling monitoring.")
    try:
        normalised = service(request).normalise_domain(payload.domain)
        await asyncio.to_thread(assert_public_target, normalised)
    except DomainSafetyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    record = database(request).upsert_monitoring(normalised, payload.revenue_band.value, payload.interval_minutes)
    request.app.state.scheduler.sync()
    return record


@app.get("/api/monitor")
async def list_monitoring(request: Request) -> dict:
    return {"items": database(request).list_monitoring()}


@app.patch("/api/monitor/{monitoring_id}")
async def update_monitoring(monitoring_id: int, payload: MonitoringUpdate, request: Request) -> dict:
    record = database(request).set_monitoring(monitoring_id, payload.enabled)
    if record is None:
        raise HTTPException(status_code=404, detail="Monitoring subscription not found.")
    request.app.state.scheduler.sync()
    return record
