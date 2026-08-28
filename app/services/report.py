from __future__ import annotations

import os
from typing import Any

from app.config import ANTHROPIC_API_KEY


def deterministic_report(
    domain: str, scoring: dict[str, Any], quantified: dict[str, Any], optimisation: dict[str, Any]
) -> str:
    top = scoring["findings"][:3]
    findings = (
        "; ".join(f"{item['signal']}: {item['narrative']}" for item in top)
        if top
        else "No high-impact public posture gaps were observed in the checked signals."
    )
    actions = ", ".join(item["name"] for item in optimisation["selected"][:3]) or "define a baseline control plan"
    return (
        f"{domain} has an external posture score of {scoring['score']}/100 based on "
        f"{scoring['coverage']['checks_observed']} passive public checks. Its modelled annual exposure is "
        f"₹{quantified['ale_inr']:,} ({quantified['likelihood_band'].lower()} likelihood). "
        f"The most important observations are: {findings} Prioritise {actions}. "
        "This is an external prioritisation snapshot, not a penetration test, legal opinion, or insurance quote."
    )


async def board_report(
    domain: str, scoring: dict[str, Any], quantified: dict[str, Any], optimisation: dict[str, Any]
) -> dict[str, Any]:
    """Use Claude when deliberately configured; retain an accountable local fallback."""
    fallback = deterministic_report(domain, scoring, quantified, optimisation)
    if not ANTHROPIC_API_KEY:
        return {"content": fallback, "source": "deterministic", "notice": "Set ANTHROPIC_API_KEY to enable an AI-written board narrative."}

    try:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        prompt = {
            "domain": domain,
            "score": scoring["score"],
            "observed_checks": scoring["coverage"],
            "findings": [
                {key: item[key] for key in ("severity", "signal", "narrative", "recommendation")}
                for item in scoring["findings"]
            ],
            "modelled_annual_exposure_inr": quantified["ale_inr"],
            "likelihood": quantified["likelihood_band"],
            "recommended_controls": optimisation["selected"],
        }
        response = await client.messages.create(
            model=os.getenv("ANTHROPIC_MODEL", "claude-3-5-haiku-latest"),
            max_tokens=450,
            temperature=0.2,
            system=(
                "Write a short, calm board brief for an Indian MSME owner. Use only supplied facts. "
                "Do not claim legal compliance, a confirmed breach, or a predicted regulatory penalty. "
                "State that the monetary number is a modelled prioritisation estimate."
            ),
            messages=[{"role": "user", "content": f"Create the brief from this assessment data: {prompt}"}],
        )
        text = "".join(block.text for block in response.content if getattr(block, "type", "") == "text").strip()
        if text:
            return {"content": text, "source": "ai", "notice": "AI narrative grounded in the collected passive signals."}
    except Exception:
        # Never expose vendor/network details to a board user, and never lose a report
        # merely because the optional narrative provider is unavailable.
        pass
    return {"content": fallback, "source": "deterministic", "notice": "AI narrative was unavailable; the auditable fallback is shown."}
