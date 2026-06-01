from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
    )

    threat_type: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    severity: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
    )

    log_message: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    risk_score: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )

    mitre_technique_id: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="T0000",
    )

    mitre_technique_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="Unknown",
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="OPEN",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=utcnow,
    )