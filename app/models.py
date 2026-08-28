from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class RevenueBand(str, Enum):
    STARTER = "under_1cr"
    GROWING = "1cr_to_10cr"
    ESTABLISHED = "10cr_to_50cr"
    SCALE = "50cr_to_250cr"
    ENTERPRISE = "over_250cr"


class ScanRequest(BaseModel):
    domain: str = Field(..., examples=["example.com"], max_length=253)
    revenue_band: RevenueBand = RevenueBand.GROWING
    authorized: bool = Field(
        ...,
        description="Confirms that the requester owns or is authorised to assess this domain.",
    )

    @field_validator("domain")
    @classmethod
    def reject_blank_domain(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("A domain is required.")
        return value.strip()


class OptimiseRequest(BaseModel):
    scan_id: int = Field(..., gt=0)
    budget_inr: int = Field(..., ge=1, le=10_000_000)


class MonitoringRequest(BaseModel):
    domain: str = Field(..., max_length=253)
    revenue_band: RevenueBand = RevenueBand.GROWING
    authorized: bool
    interval_minutes: int = Field(default=60, ge=5, le=10_080)


class MonitoringUpdate(BaseModel):
    enabled: bool
