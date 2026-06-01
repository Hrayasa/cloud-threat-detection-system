from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AlertResponse(BaseModel):
    """Alert response schema."""

    model_config = ConfigDict(from_attributes=True)

    id: int
    threat_type: str
    severity: str
    source_ip: str
    log_message: str
    risk_score: int
    mitre_technique_id: str
    mitre_technique_name: str
    status: str
    created_at: datetime


class MessageResponse(BaseModel):
    """Generic message response for triage endpoints."""

    model_config = ConfigDict(from_attributes=True)

    message: str