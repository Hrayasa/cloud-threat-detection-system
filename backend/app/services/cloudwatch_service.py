from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings


@dataclass(slots=True)
class CloudWatchLogEntry:
    """Structured CloudWatch log event payload."""

    timestamp: datetime
    message: str
    stream_name: str
    event_id: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


class CloudWatchService:
    """AWS CloudWatch integration for infrastructure monitoring."""

    def __init__(self, region_name: str | None = None, client: boto3.client | None = None) -> None:
        resolved_region = region_name or settings.aws_region
        if client is not None:
            self._client = client
        else:
            self._client = boto3.client(
                "logs",
                region_name=resolved_region,
                aws_access_key_id=settings.aws_access_key_id,
                aws_secret_access_key=settings.aws_secret_access_key,
            )

    @property
    def client(self) -> Any:
        """Return the underlying CloudWatch Logs client."""

        return self._client

    def fetch_log_events(
        self,
        log_group_name: str,
        log_stream_name: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        filter_pattern: str | None = None,
    ) -> list[CloudWatchLogEntry]:
        """Fetch log events from CloudWatch Logs with pagination and filtering."""

        log_streams = self._list_log_streams(log_group_name, log_stream_name)
        entries: list[CloudWatchLogEntry] = []

        for stream in log_streams:
            try:
                paginator = self.client.get_paginator("filter_log_events")
                page_iterator = paginator.paginate(
                    logGroupName=log_group_name,
                    logStreamNames=[stream],
                    startTime=self._to_epoch_ms(start_time),
                    endTime=self._to_epoch_ms(end_time),
                    filterPattern=filter_pattern,
                )
                for page in page_iterator:
                    for event in page.get("events", []):
                        entries.append(
                            CloudWatchLogEntry(
                                timestamp=datetime.fromtimestamp(event["timestamp"] / 1000, tz=timezone.utc),
                                message=event["message"],
                                stream_name=stream,
                                event_id=event.get("eventId"),
                                attributes={
                                    "ingestionTime": event.get("ingestionTime"),
                                    "logStreamName": event.get("logStreamName"),
                                },
                            )
                        )
            except (ClientError, BotoCoreError) as exc:
                raise RuntimeError(f"Failed to read CloudWatch logs for stream {stream}") from exc

        return entries

    def extract_failed_ssh_logins(self, entries: Iterable[CloudWatchLogEntry]) -> list[dict[str, Any]]:
        """Extract failed SSH login attempts from structured log entries."""

        failed_attempts: list[dict[str, Any]] = []
        for entry in entries:
            message = entry.message.lower()
            if "failed password" in message or "authentication failure" in message:
                failed_attempts.append(
                    {
                        "timestamp": entry.timestamp.isoformat(),
                        "stream_name": entry.stream_name,
                        "message": entry.message,
                        "source_ip": self._extract_ip_address(entry.message),
                    }
                )
        return failed_attempts

    def extract_suspicious_ips(self, entries: Iterable[CloudWatchLogEntry]) -> list[str]:
        """Extract suspicious source IP addresses from parsed log entries."""

        suspicious_ips: list[str] = []
        seen_ips: set[str] = set()

        for entry in entries:
            ip_address = self._extract_ip_address(entry.message)
            if ip_address and ip_address not in seen_ips:
                suspicious_ips.append(ip_address)
                seen_ips.add(ip_address)

        return suspicious_ips

    def _list_log_streams(self, log_group_name: str, log_stream_name: str | None) -> list[str]:
        """List matching log streams for a CloudWatch log group."""

        try:
            paginator = self.client.get_paginator("describe_log_streams")
            stream_names: list[str] = []
            pages = paginator.paginate(logGroupName=log_group_name)
            for page in pages:
                for stream in page.get("logStreams", []):
                    name = stream.get("logStreamName")
                    if name and (log_stream_name is None or name == log_stream_name):
                        stream_names.append(name)
            return stream_names
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(f"Failed to list CloudWatch log streams for {log_group_name}") from exc

    @staticmethod
    def _extract_ip_address(message: str) -> str | None:
        """Extract an IP address from a message using simple regex logic."""

        import re

        match = re.search(r"(?:\d{1,3}\.){3}\d{1,3}", message)
        if match:
            return match.group(0)
        return None

    @staticmethod
    def _to_epoch_ms(time_value: datetime | None) -> int | None:
        """Convert a datetime to epoch milliseconds in UTC."""

        if time_value is None:
            return None
        if time_value.tzinfo is None:
            time_value = time_value.replace(tzinfo=timezone.utc)
        return int(time_value.timestamp() * 1000)


cloudwatch_service = CloudWatchService()

__all__ = ["CloudWatchLogEntry", "CloudWatchService", "cloudwatch_service"]
