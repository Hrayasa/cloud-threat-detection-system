# Threat Detections

This document describes the implemented detections, their purpose, logic, and examples.

## Brute Force Login Attempts

- Detection Name: Brute Force Login Attempts
- Purpose: Detect repeated failed authentication attempts from a single source IP that may indicate credential stuffing or brute-force attacks.
- Threat Scenario: Multiple failed SSH authentication attempts for one or more usernames originating from the same IP within a short window.
- MITRE ATT&CK Technique: T1110 — Brute Force
- Severity: Variable (medium → critical) depending on count and scoring
- Risk Score: Computed as base 35 + 12 * (attempts over configured threshold), capped at 100.

Detection Logic:

- Parse log lines for `failed_ssh_login` events (via `LinuxAuthLogParser`).
- Count failed attempts per source IP.
- If count >= `DetectionThresholds.brute_force_threshold` (default 5), generate a `ThreatAlert` with evidence containing sample events.

Alert Output Example:

```json
{
  "threat_type": "brute_force_login_attempts",
  "severity": "high",
  "risk_score": 71,
  "mitre_technique_id": "T1110",
  "description": "Repeated failed login attempts detected from source IP 192.168.1.10. 7 failures observed.",
  "source_ip": "192.168.1.10",
  "evidence": { "failed_attempts": 7, "sample_events": [ ... ] }
}
```

Example Logs (that trigger detection):

- "Failed password for invalid user root from 192.168.1.10"
- "Failed password for admin from 192.168.1.10"

## Impossible Travel

- Detection Name: Impossible Travel
- Purpose: Detect activity from widely separated geographic locations for the same observation window which may indicate account compromise or credential reuse.
- Threat Scenario: A user or IP appears in logs resolved to disparate locations (demo uses `KNOWN_IP_LOCATIONS` map).
- MITRE ATT&CK Technique: T1078 — Valid Accounts
- Severity: High
- Risk Score: Fixed at 85 for current implementation.

Detection Logic:

- Resolve source IPs to locations using `KNOWN_IP_LOCATIONS` (PoC map).
- If two or more distinct locations appear in a single upload, generate an `ImpossibleTravel` alert with evidence listing locations and sample events.

Alert Output Example:

```json
{
  "threat_type": "impossible_travel",
  "severity": "high",
  "risk_score": 85,
  "mitre_technique_id": "T1078",
  "description": "User activity observed from Bangalore and New York within a short observation window.",
  "locations": ["Bangalore","New York"],
  "evidence": { "sample_events": [ ... ] }
}
```

Example Logs (that trigger detection):

- "Accepted password for alice from 192.168.1.10" (Bangalore)
- "Accepted password for alice from 8.8.8.8" (New York)
