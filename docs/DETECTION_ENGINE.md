# Detection Engine

This document describes the design and operation of the rule-based detection engine implemented in `backend/app/services/threat_detection.py`.

## Detection Engine Design

- Engine class: `ThreatDetectionEngine` – orchestrates parsing and rule evaluation.
- Parser: `LinuxAuthLogParser` converts raw log lines to `ParsedLogEvent` instances.
- Rules: Modular classes implementing the `DetectionRule` protocol with an `evaluate(events, thresholds)` method.
- Thresholds: `DetectionThresholds` dataclass centralizes tunable values such as brute-force thresholds and window sizes.

## Rule Execution Flow

1. Incoming raw lines are parsed into `ParsedLogEvent`.
2. For each rule in `ThreatDetectionEngine.rules`, `rule.evaluate(parsed_events, thresholds)` is invoked.
3. Rules return `ThreatAlert` objects which contain severity, risk score, MITRE information, evidence, and metadata.
4. Alerts are sorted and returned inside a `DetectionReport`.

## Rule Registration

Rules are currently registered in the engine constructor:

```py
self.rules = [
    BruteForceLoginRule(),
    ImpossibleTravelRule(),
    SuspiciousIPAccessRule(),
    UnusualLoginFrequencyRule(),
    PotentialPrivilegeEscalationRule(),
]
```

To add a new rule:

1. Create a class implementing `evaluate(events, thresholds) -> list[ThreatAlert]`.
2. Add an instance to the engine's `rules` list or implement a dynamic plugin loader.

## Detection Pipeline

- Parse -> Evaluate rules -> Generate ThreatAlert -> Log alert -> Build DetectionReport -> Persist via API.

## Risk Scoring Methodology

- Risk scores are numeric (0-100) computed per rule based on severity heuristics and counts. Examples:
  - Brute force: base 35 + 12*(attempts over threshold)
  - Impossible travel: fixed high score (85)

- Risk scores map to severities via `_classify_severity`:
  - >= 80 -> `critical`
  - >= 60 -> `high`
  - >= 40 -> `medium`
  - < 40 -> `low`

## MITRE ATT&CK Enrichment

- Rules set `mitre_technique_id` and `mitre_technique_name` using `MITRE_MAPPING` in the module. See `docs/MITRE_MAPPING.md` for mapping rationale.

## Alert Creation Process

- `ThreatAlert` dataclass is used to model alerts; it contains `to_dict()` and `to_alert_record()` helpers used by API layer to persist alerts.

## Implemented Rules

- Brute Force Login Attempts (`BruteForceLoginRule`) — counts failed SSH login attempts per source IP and generates alerts when a threshold is exceeded.
- Impossible Travel (`ImpossibleTravelRule`) — identifies events from geographically distinct known IP addresses within the same upload.

## Examples

- Brute force example event list leads to a `ThreatAlert` with `threat_type` `brute_force_login_attempts`, a computed `risk_score`, and `mitre_technique_id` `T1110`.
