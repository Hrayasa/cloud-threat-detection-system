from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class ParsedLogEvent:
    """Result of parsing a Linux auth log line."""

    event_type: str
    raw_message: str
    timestamp: str | None = None
    source_ip: str | None = None
    username: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    malformed: bool = False


class LinuxAuthLogParser:
    """Secure regex-based parser for Linux authentication log lines."""

    FAILED_SSH_PATTERN = re.compile(
        r"(?:sshd\[\d+\]:\s*)?Failed password for (?:invalid user )?(?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )

    SUCCESSFUL_SSH_PATTERN = re.compile(
        r"(?:sshd\[\d+\]:\s*)?Accepted password for (?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )

    GENERIC_LOGIN_SUCCESS_PATTERN = re.compile(
        r"User login success(?:ful)?(?: for (?P<username>\S+))? from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )

    INVALID_USER_PATTERN = re.compile(
        r"(?:sshd\[\d+\]:\s*)?Invalid user (?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
        re.IGNORECASE,
    )

    SUDO_PREFIX_PATTERN = re.compile(
        r"sudo(?:\(\w+\))?:\s*(?P<username>\S+)\s*:",
        re.IGNORECASE,
    )

    def parse(self, line: str) -> ParsedLogEvent:
        """Parse a single authentication log line into a structured event."""

        if not line or not line.strip():
            return ParsedLogEvent(
                event_type="malformed",
                raw_message=line,
                malformed=True,
            )

        normalized = line.strip()

        match = self.FAILED_SSH_PATTERN.search(normalized)
        if match:
            return ParsedLogEvent(
                event_type="failed_ssh_login",
                raw_message=normalized,
                source_ip=match.group("ip"),
                username=match.group("username"),
                details={"attempt": "failed_password"},
            )

        match = self.SUCCESSFUL_SSH_PATTERN.search(normalized)
        if match:
            return ParsedLogEvent(
                event_type="successful_ssh_login",
                raw_message=normalized,
                source_ip=match.group("ip"),
                username=match.group("username"),
                details={"attempt": "accepted_password"},
            )

        match = self.GENERIC_LOGIN_SUCCESS_PATTERN.search(normalized)
        if match:
            return ParsedLogEvent(
                event_type="successful_ssh_login",
                raw_message=normalized,
                source_ip=match.group("ip"),
                username=match.group("username"),
                details={"attempt": "generic_login_success"},
            )

        match = self.INVALID_USER_PATTERN.search(normalized)
        if match:
            return ParsedLogEvent(
                event_type="invalid_user",
                raw_message=normalized,
                source_ip=match.group("ip"),
                username=match.group("username"),
                details={"reason": "invalid_user"},
            )

        sudo_match = self.SUDO_PREFIX_PATTERN.search(normalized)
        if sudo_match:
            remainder = normalized[sudo_match.end():]

            tty_match = re.search(
                r"TTY=(?P<tty>\S+)",
                remainder,
                re.IGNORECASE,
            )

            pwd_match = re.search(
                r"PWD=(?P<pwd>\S+)",
                remainder,
                re.IGNORECASE,
            )

            user_match = re.search(
                r"USER=(?P<target_user>\S+)",
                remainder,
                re.IGNORECASE,
            )

            command_match = re.search(
                r"COMMAND=(?P<command>.+)$",
                remainder,
                re.IGNORECASE,
            )

            return ParsedLogEvent(
                event_type="sudo_privilege_escalation",
                raw_message=normalized,
                username=sudo_match.group("username"),
                details={
                    "tty": tty_match.group("tty") if tty_match else None,
                    "pwd": pwd_match.group("pwd") if pwd_match else None,
                    "target_user": user_match.group("target_user") if user_match else None,
                    "command": command_match.group("command") if command_match else None,
                },
            )

        return ParsedLogEvent(
            event_type="unmatched",
            raw_message=normalized,
            malformed=True,
        )

    def parse_dict(self, line: str) -> dict[str, Any]:
        """Return a structured dictionary representation of a parsed log line."""

        parsed = self.parse(line)

        return {
            "event_type": parsed.event_type,
            "raw_message": parsed.raw_message,
            "timestamp": parsed.timestamp,
            "source_ip": parsed.source_ip,
            "username": parsed.username,
            "details": parsed.details,
            "malformed": parsed.malformed,
        }

    def detect_repeated_ip_attempts(
        self,
        lines: list[str],
        threshold: int = 5,
    ) -> dict[str, Any]:
        """Count repeated source IPs from failed SSH login patterns."""

        counts: dict[str, int] = {}

        for line in lines:
            parsed = self.parse(line)

            if (
                parsed.event_type == "failed_ssh_login"
                and parsed.source_ip
            ):
                counts[parsed.source_ip] = (
                    counts.get(parsed.source_ip, 0) + 1
                )

        repeated: list[dict[str, Any]] = []

        for ip_address, count in counts.items():
            if count >= threshold:
                repeated.append(
                    {
                        "source_ip": ip_address,
                        "attempt_count": count,
                        "threshold": threshold,
                    }
                )

        return {
            "repeated_ip_attempts": repeated,
        }


parser = LinuxAuthLogParser()