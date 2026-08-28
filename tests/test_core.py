from __future__ import annotations

from pathlib import Path

from app.models import RevenueBand
from app.services.database import Database
from app.services.ledger import GENESIS_HASH, hash_report, verify_chain
from app.services.optimizer import optimise
from app.services.quantify import quantify
from app.services.scoring import score


def test_quantification_increases_with_worse_score() -> None:
    low_risk = quantify(92, RevenueBand.GROWING)
    high_risk = quantify(35, RevenueBand.GROWING)
    assert high_risk["ale_inr"] > low_risk["ale_inr"]
    assert high_risk["likelihood_band"] == "Critical"


def test_optimiser_respects_budget_and_is_not_additive() -> None:
    result = optimise(50_000, 1_000_000, {"dmarc", "spf", "headers"})
    assert result["spend"] <= 50_000
    assert 0 < result["ale_reduction_inr"] < 1_000_000
    assert result["roi_multiple"] > 0


def test_ledger_detects_tampered_payload() -> None:
    first = {"domain": "example.com", "score": 80}
    first_hash = hash_report(first, GENESIS_HASH)
    second = {"domain": "example.com", "score": 72}
    second_hash = hash_report(second, first_hash)
    good = verify_chain([
        {"id": 1, "prev_hash": GENESIS_HASH, "report_hash": first_hash, "integrity_payload": first},
        {"id": 2, "prev_hash": first_hash, "report_hash": second_hash, "integrity_payload": second},
    ])
    tampered = verify_chain([
        {"id": 1, "prev_hash": GENESIS_HASH, "report_hash": first_hash, "integrity_payload": first},
        {"id": 2, "prev_hash": first_hash, "report_hash": second_hash, "integrity_payload": {"domain": "example.com", "score": 99}},
    ])
    assert good["intact"] is True
    assert tampered["intact"] is False


def test_scoring_does_not_penalise_unavailable_signal() -> None:
    signals = {
        "mail": {"status": "unavailable"}, "security_txt": {"status": "unavailable"},
        "http": {"status": "unavailable"}, "tls": {"status": "unavailable"},
        "certificate_transparency": {"status": "unavailable"},
    }
    result = score(signals)
    assert result["score"] == 100
    assert result["coverage"]["confidence_percent"] == 0
    assert not result["findings"]


def test_database_persists_and_verifies_scan(tmp_path: Path) -> None:
    database = Database(tmp_path / "test.db")
    database.initialise()
    result = {
        "domain": "example.com", "revenue_band": "1cr_to_10cr", "signals": {},
        "scoring": {"score": 77, "findings": [], "coverage": {}, "methodology": "test"},
        "quantified": {"ale_inr": 1_000, "likelihood_band": "Guarded", "exposure_inr": 10_000, "p_breach": .1, "assumptions": []},
        "optimisation": {"selected": [], "spend": 0},
        "board_report": {"content": "test", "source": "deterministic", "notice": "test"},
    }
    saved = database.save_scan(result)
    stored = database.get_scan(saved["scan_id"])
    assert stored is not None
    assert stored["domain"] == "example.com"
    assert database.verify_ledger("example.com")["intact"] is True
