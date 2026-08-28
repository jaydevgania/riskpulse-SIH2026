from __future__ import annotations

from itertools import combinations
from typing import Any


CONTROL_CATALOG: list[dict[str, Any]] = [
    {"id": "dmarc", "name": "DMARC deployment & monitoring", "cost_inr": 18_000, "reduction": 0.13, "tags": {"dmarc", "spf"}},
    {"id": "mfa", "name": "Company-wide MFA rollout", "cost_inr": 28_000, "reduction": 0.16, "tags": {"access", "generic"}},
    {"id": "backup", "name": "Immutable backup baseline", "cost_inr": 36_000, "reduction": 0.15, "tags": {"generic"}},
    {"id": "edr", "name": "Managed endpoint protection", "cost_inr": 48_000, "reduction": 0.18, "tags": {"generic"}},
    {"id": "ir", "name": "6-hour incident response playbook", "cost_inr": 22_000, "reduction": 0.10, "tags": {"readiness", "generic"}},
    {"id": "training", "name": "Phishing-resistant workforce training", "cost_inr": 15_000, "reduction": 0.09, "tags": {"spf", "dmarc", "generic"}},
    {"id": "headers", "name": "Web security-header hardening", "cost_inr": 12_000, "reduction": 0.07, "tags": {"headers", "security_txt"}},
    {"id": "patching", "name": "Managed patch & vulnerability programme", "cost_inr": 42_000, "reduction": 0.14, "tags": {"tech", "tls", "generic"}},
    {"id": "logging", "name": "Centralised security logging", "cost_inr": 30_000, "reduction": 0.11, "tags": {"readiness", "generic"}},
    {"id": "vcio", "name": "Quarterly virtual CISO review", "cost_inr": 55_000, "reduction": 0.12, "tags": {"generic"}},
]


def _adjusted_reduction(control: dict[str, Any], finding_ids: set[str]) -> float:
    """Prefer controls relevant to observed passive signals without hiding generic value."""
    if control["tags"] & finding_ids:
        return control["reduction"]
    if "generic" in control["tags"]:
        return round(control["reduction"] * 0.8, 4)
    return round(control["reduction"] * 0.45, 4)


def optimise(
    budget_inr: int, current_ale: int, finding_ids: set[str] | None = None
) -> dict[str, Any]:
    """Exact 0/1 selection over the compact control catalogue (2^10 candidates)."""
    findings = finding_ids or set()
    candidates = []
    for item in CONTROL_CATALOG:
        candidate = dict(item)
        candidate["adjusted_reduction"] = _adjusted_reduction(candidate, findings)
        candidates.append(candidate)

    best: tuple[int, int, list[dict[str, Any]], float] | None = None
    for size in range(len(candidates) + 1):
        for selection in combinations(candidates, size):
            spend = sum(control["cost_inr"] for control in selection)
            if spend > budget_inr:
                continue
            combined_reduction = 1.0
            for control in selection:
                combined_reduction *= 1 - control["adjusted_reduction"]
            reduction_fraction = 1 - combined_reduction
            reduction_inr = round(current_ale * reduction_fraction)
            candidate_score = (reduction_inr, -spend)
            if best is None or candidate_score > (best[0], -best[1]):
                best = (reduction_inr, spend, list(selection), reduction_fraction)

    assert best is not None
    reduction_inr, spend, selected, reduction_fraction = best
    results = [
        {
            "id": control["id"],
            "name": control["name"],
            "cost_inr": control["cost_inr"],
            "ale_reduction_inr": round(current_ale * control["adjusted_reduction"]),
            "relevance": "Observed-signal aligned" if control["tags"] & findings else "Baseline resilience",
        }
        for control in selected
    ]
    return {
        "selected": results,
        "spend": spend,
        "budget_inr": budget_inr,
        "unspent_inr": budget_inr - spend,
        "ale_before": current_ale,
        "ale_after": max(0, current_ale - reduction_inr),
        "ale_reduction_inr": reduction_inr,
        "reduction_percent": round(reduction_fraction * 100, 1),
        "roi_multiple": round(reduction_inr / spend, 2) if spend else 0,
        "method": "Exact 0/1 portfolio search using non-additive risk reduction.",
    }
