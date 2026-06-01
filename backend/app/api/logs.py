from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.alert import Alert
from app.schemas.logs import LogUploadRequest
from app.services.threat_detection import (
    DetectionReport,
    threat_detection_engine,
)

router = APIRouter(prefix="/logs", tags=["logs"])


@router.post("/upload", status_code=status.HTTP_200_OK)
def upload_logs(
    payload: LogUploadRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """
    Process uploaded logs, run threat detection,
    and persist detected alerts.
    """

    messages: list[str] = [
        entry.message for entry in payload.logs
    ]

    report: DetectionReport = (
        threat_detection_engine.evaluate_logs(messages)
    )

    persisted_alerts: list[Alert] = []

    try:
        for alert in report.alerts:

            alert_record = Alert(
                threat_type=alert.threat_type,
                severity=alert.severity,
                source_ip=alert.source_ip or "unknown",
                log_message=alert.description,
                risk_score=alert.risk_score,
                mitre_technique_id=alert.mitre_technique_id,
                mitre_technique_name=alert.mitre_technique_name,
                status="OPEN",
            )

            db.add(alert_record)
            db.flush()

            persisted_alerts.append(alert_record)

        db.commit()

    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist detected alerts",
        ) from None

    response_alerts: list[dict[str, Any]] = [
        {
            "id": alert_record.id,
            "threat_type": alert_record.threat_type,
            "severity": alert_record.severity,
            "source_ip": alert_record.source_ip,
            "log_message": alert_record.log_message,
            "risk_score": alert_record.risk_score,
            "mitre_technique_id": alert_record.mitre_technique_id,
            "mitre_technique_name": alert_record.mitre_technique_name,
            "status": alert_record.status,
            "created_at": alert_record.created_at,
        }
        for alert_record in persisted_alerts
    ]

    return {
        "processed_events": report.processed_events,
        "alerts_detected": len(response_alerts),
        "alerts": response_alerts,
    }