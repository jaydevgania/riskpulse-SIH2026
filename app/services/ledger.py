from __future__ import annotations

import hashlib
import json
from typing import Any


GENESIS_HASH = "0" * 64


def canonicalise(payload: dict[str, Any]) -> str:
    """Create a stable representation so a report has one reproducible hash."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def hash_report(payload: dict[str, Any], previous_hash: str | None = None) -> str:
    previous = previous_hash or GENESIS_HASH
    material = f"{previous}:{canonicalise(payload)}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()


def verify_chain(records: list[dict[str, Any]]) -> dict[str, Any]:
    breaks: list[dict[str, Any]] = []
    expected_previous = GENESIS_HASH
    for record in records:
        stored_previous = record.get("prev_hash") or GENESIS_HASH
        expected_hash = hash_report(record["integrity_payload"], expected_previous)
        if stored_previous != expected_previous or record["report_hash"] != expected_hash:
            breaks.append(
                {
                    "scan_id": record["id"],
                    "expected_previous_hash": expected_previous,
                    "expected_report_hash": expected_hash,
                }
            )
        expected_previous = record["report_hash"]
    return {"intact": not breaks, "breaks": breaks, "records_checked": len(records)}
