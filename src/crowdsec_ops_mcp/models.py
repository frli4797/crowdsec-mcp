from __future__ import annotations

from pydantic import BaseModel


class Decision(BaseModel):
    ip: str
    scope: str = "Ip"
    action: str
    reason: str | None = None
    scenario: str | None = None
    country: str | None = None
    as_name: str | None = None
    until: str | None = None
    origin: str | None = None


class CrowdSecAlert(BaseModel):
    ip: str | None = None
    scenario: str | None = None
    country: str | None = None
    as_name: str | None = None
    created_at: str | None = None
    message: str | None = None
    events_count: int | None = None


class Recommendation(BaseModel):
    action: str
    rationale: str
    confidence: str
