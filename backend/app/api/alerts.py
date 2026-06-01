from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import Alert
from app.schemas.alert import AlertResponse
from app.schemas.alert import MessageResponse

router = APIRouter(
    prefix="/alerts",
    tags=["alerts"],
)


@router.get(
    "/",
    response_model=list[AlertResponse],
    status_code=status.HTTP_200_OK,
)
def list_alerts(
    db: Session = Depends(get_db),
) -> list[AlertResponse]:
    """
    Return all alerts ordered by newest first.
    """

    alerts = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .all()
    )

    return [
        AlertResponse.model_validate(alert)
        for alert in alerts
    ]


@router.get(
    "/high",
    response_model=list[AlertResponse],
    status_code=status.HTTP_200_OK,
)
def list_high_severity_alerts(
    db: Session = Depends(get_db),
) -> list[AlertResponse]:
    """
    Return all HIGH severity alerts.
    """

    alerts = (
        db.query(Alert)
        .filter(Alert.severity == "high")
        .order_by(Alert.created_at.desc())
        .all()
    )

    return [
        AlertResponse.model_validate(alert)
        for alert in alerts
    ]


@router.get(
    "/critical",
    response_model=list[AlertResponse],
    status_code=status.HTTP_200_OK,
)
def list_critical_alerts(
    db: Session = Depends(get_db),
) -> list[AlertResponse]:
    """
    Return all CRITICAL severity alerts.
    """

    alerts = (
        db.query(Alert)
        .filter(Alert.severity == "critical")
        .order_by(Alert.created_at.desc())
        .all()
    )

    return [
        AlertResponse.model_validate(alert)
        for alert in alerts
    ]


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    status_code=status.HTTP_200_OK,
)
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
) -> AlertResponse:
    """
    Return a single alert by ID.
    """

    alert = (
        db.query(Alert)
        .filter(Alert.id == alert_id)
        .first()
    )

    if alert is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found",
        )

    return AlertResponse.model_validate(alert)



@router.patch("/{alert_id}/acknowledge", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def acknowledge_alert(alert_id: int, db: Session = Depends(get_db)) -> MessageResponse:
    """Acknowledge an alert (OPEN -> ACKNOWLEDGED)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.status != "OPEN":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Alert not in OPEN state")
    alert.status = "ACKNOWLEDGED"
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return MessageResponse.model_validate({"message": "Alert acknowledged"})


@router.patch("/{alert_id}/suppress", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def suppress_alert(alert_id: int, db: Session = Depends(get_db)) -> MessageResponse:
    """Suppress an alert (OPEN -> SUPPRESSED)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.status != "OPEN":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Alert not in OPEN state")
    alert.status = "SUPPRESSED"
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return MessageResponse.model_validate({"message": "Alert suppressed"})


@router.patch("/{alert_id}/escalate", response_model=MessageResponse, status_code=status.HTTP_200_OK)
def escalate_alert(alert_id: int, db: Session = Depends(get_db)) -> MessageResponse:
    """Escalate an alert (OPEN -> ESCALATED)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    if alert.status != "OPEN":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Alert not in OPEN state")
    alert.status = "ESCALATED"
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return MessageResponse.model_validate({"message": "Alert escalated"})