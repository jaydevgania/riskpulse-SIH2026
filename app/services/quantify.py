from __future__ import annotations

from typing import Any

from app.models import RevenueBand


REVENUE_BANDS: dict[RevenueBand, dict[str, int | str]] = {
    RevenueBand.STARTER: {"label": "Under ₹1 crore", "representative_revenue": 7_500_000},
    RevenueBand.GROWING: {"label": "₹1–10 crore", "representative_revenue": 55_000_000},
    RevenueBand.ESTABLISHED: {"label": "₹10–50 crore", "representative_revenue": 300_000_000},
    RevenueBand.SCALE: {"label": "₹50–250 crore", "representative_revenue": 1_500_000_000},
    RevenueBand.ENTERPRISE: {"label": "Over ₹250 crore", "representative_revenue": 4_000_000_000},
}

# A safeguard-related DPDP ceiling is used only as a conservative upper bound in
# a transparent model. This is intentionally not presented as a legal forecast.
DPDP_MODEL_CAP_INR = 2_500_000_000


def likelihood_for_score(score: int) -> tuple[str, float]:
    if score >= 90:
        return "Low", 0.05
    if score >= 75:
        return "Guarded", 0.12
    if score >= 60:
        return "Elevated", 0.22
    if score >= 40:
        return "High", 0.38
    return "Critical", 0.60


def quantify(score: int, revenue_band: RevenueBand | str) -> dict[str, Any]:
    band = RevenueBand(revenue_band)
    band_meta = REVENUE_BANDS[band]
    representative_revenue = int(band_meta["representative_revenue"])
    likelihood_band, probability = likelihood_for_score(score)

    # A 25% annual-revenue disruption proxy, with a ₹25 lakh minimum, produces
    # a comparable planning denominator while remaining capped at the stated ceiling.
    business_impact_proxy = max(2_500_000, round(representative_revenue * 0.25))
    exposure = min(business_impact_proxy, DPDP_MODEL_CAP_INR)
    ale = round(probability * exposure)

    return {
        "ale_inr": ale,
        "likelihood_band": likelihood_band,
        "p_breach": probability,
        "exposure_inr": exposure,
        "revenue_band": band.value,
        "assumptions": [
            f"Revenue input is represented by the midpoint proxy for {band_meta['label']}.",
            "Business-impact proxy is 25% of representative annual revenue, with a ₹25 lakh floor.",
            "Exposure is capped at ₹250 crore for model consistency; it is not a predicted penalty.",
            "Annual Loss Expectancy is a prioritisation estimate, not legal or actuarial advice.",
        ],
    }
