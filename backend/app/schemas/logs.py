from __future__ import annotations

from pydantic import BaseModel


class LogRecord(BaseModel):
    """Represents a parsed log line."""

    message: str


class LogUploadRequest(BaseModel):
    """Request payload for uploading logs."""

    logs: list[LogRecord]