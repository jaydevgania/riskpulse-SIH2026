from __future__ import annotations

import logging
from typing import Any

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.services.database import Database
from app.services.risk_service import RiskService


logger = logging.getLogger(__name__)


class MonitoringScheduler:
    def __init__(self, database: Database, risk_service: RiskService) -> None:
        self.database = database
        self.risk_service = risk_service
        self.scheduler = AsyncIOScheduler()

    def start(self) -> None:
        self.scheduler.start()
        self.sync()

    def shutdown(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)

    def sync(self) -> None:
        active_ids: set[str] = set()
        for subscription in self.database.list_monitoring(enabled_only=True):
            job_id = self._job_id(subscription["id"])
            active_ids.add(job_id)
            self.scheduler.add_job(
                self._run_subscription,
                "interval",
                minutes=subscription["interval_minutes"],
                id=job_id,
                args=[subscription],
                replace_existing=True,
                max_instances=1,
                coalesce=True,
                misfire_grace_time=120,
            )
        for job in self.scheduler.get_jobs():
            if job.id.startswith("monitor-") and job.id not in active_ids:
                self.scheduler.remove_job(job.id)

    async def _run_subscription(self, subscription: dict[str, Any]) -> None:
        try:
            await self.risk_service.scan(subscription["domain"], subscription["revenue_band"])
            self.database.mark_monitoring_run(subscription["id"])
            logger.info("Completed continuous posture scan for %s", subscription["domain"])
        except Exception:
            logger.exception("Continuous posture scan failed for %s", subscription["domain"])

    @staticmethod
    def _job_id(monitoring_id: int) -> str:
        return f"monitor-{monitoring_id}"
