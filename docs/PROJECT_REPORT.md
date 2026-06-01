# Project Report

## Executive Summary

The Cloud Threat Detection System is a compact, explainable detection engine and API service designed to demonstrate threat detection engineering concepts and provide a simple platform for experimentation. It is not a full SIEM/XDR, but a focused service for ingesting auth logs, running rule-based detections, and persisting triageable alerts.

## Problem Statement

Security teams and engineers need reproducible, inspectable detection examples that can be extended to cloud datasets. Large SIEMs can be complex and opaque; this project aims to be educational and extensible while covering real-world detection patterns.

## Project Goals

- Provide a minimal production-like service demonstrating log ingestion, detection, enrichment, and alerting.
- Implement clear, testable detection rules (brute force, impossible travel).
- Ensure API-first design to integrate with other tooling and UIs.

## Architecture

See `docs/ARCHITECTURE.md`. The implementation separates API, detection engine, and persistence.

## Threat Detection Strategy

- Rule-based detection using a deterministic parser for auth logs.
- Tunable thresholds are centralized in `DetectionThresholds`.
- Risk scoring produces explainable severity and ranking for triage.

## Authentication Design

- JWT for stateless access control.
- Access and refresh tokens are issued at registration/login.
- Middleware decodes tokens and exposes claims on `request.state` for downstream logic.

## Database Design

- Minimal schema for `users` and `alerts` implemented in SQLAlchemy models. Alerts store minimal details required for triage and auditing.

## Detection Engine

- The engine is modular; new rules can be added by implementing the `DetectionRule` protocol and returning `ThreatAlert` objects.

## MITRE ATT&CK Integration

- Alerts are enriched with MITRE technique IDs and human-friendly names. This helps security reviewers classify detections and link to playbooks.

## Alert Lifecycle Management

- Alerts are created as `OPEN` and can be triaged via `/alerts/{id}/acknowledge`, `/suppress`, and `/escalate`.

## Testing Results

- Unit tests in `backend/tests` validate parser behavior and detection logic (see `test_threat_detection.py`, `test_main.py`).

## Performance Considerations

- Rule evaluation is CPU-bound per upload; the engine is synchronous but can be run as part of a worker pool or behind a queue for high-volume ingestion.

## Limitations

- Geo-resolution is a PoC map (`KNOWN_IP_LOCATIONS`) — production requires IP geolocation service.
- No alert deduplication across separate uploads.
- No RBAC beyond a basic `role` field.

## Future Enhancements

- See `docs/ROADMAP.md` for roadmap items including CloudTrail detections, dashboard, CI/CD, and RBAC.

## Conclusion

This project provides a practical, extensible starting point for engineers and security practitioners to explore detection engineering, build custom rules, and integrate detection outputs into broader toolchains.
