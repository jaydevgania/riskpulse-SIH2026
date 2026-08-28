from __future__ import annotations

from typing import Any

from app.models import RevenueBand
from app.services.database import Database
from app.services.optimizer import optimise
from app.services.quantify import quantify
from app.services.recon import collect_signals, normalise_domain
from app.services.report import board_report
from app.services.scoring import score


class RiskService:
    def __init__(self, database: Database) -> None:
        self.database = database

    async def scan(self, domain_input: str, revenue_band: RevenueBand | str) -> dict[str, Any]:
        revenue = RevenueBand(revenue_band)
        signals = await collect_signals(domain_input)
        scoring = score(signals)
        quantified = quantify(scoring["score"], revenue)
        optimisation = optimise(
            budget_inr=50_000,
            current_ale=quantified["ale_inr"],
            finding_ids={item["id"] for item in scoring["findings"]},
        )
        report = await board_report(signals["domain"], scoring, quantified, optimisation)
        result: dict[str, Any] = {
            "domain": signals["domain"],
            "revenue_band": revenue.value,
            "signals": signals,
            "scoring": scoring,
            "quantified": quantified,
            "optimisation": optimisation,
            "board_report": report,
        }
        result.update(self.database.save_scan(result))
        return result

    def optimise_scan(self, scan_id: int, budget_inr: int) -> dict[str, Any] | None:
        scan = self.database.get_scan(scan_id)
        if scan is None:
            return None
        return optimise(
            budget_inr=budget_inr,
            current_ale=scan["quantified"]["ale_inr"],
            finding_ids={item["id"] for item in scan["scoring"]["findings"]},
        )

    @staticmethod
    def normalise_domain(domain_input: str) -> str:
        return normalise_domain(domain_input)
