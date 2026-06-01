# Cloud Threat Detection System

## Project Overview

The Cloud Threat Detection System is a lightweight, API-first threat detection service implemented in Python using FastAPI. It provides rule-based detection for common infra-level threats (e.g., brute force, impossible travel), persistent alerting backed by PostgreSQL, and an audit-friendly alert triage workflow.

## Problem Statement

Cloud environments generate large volumes of logs. Security teams need easy-to-run, explainable detection tooling that demonstrates detection engineering concepts without the complexity of full SIEM/XDR platforms. This project is focused on teaching, experimentation, and rapid extension for cloud-focused detections.

## Solution Overview

This project ingests authentication and infrastructure logs, runs a set of rule-based detectors, scores and enriches alerts (including MITRE ATT&CK mapping), then persists alerts to PostgreSQL for triage via a simple HTTP API.

## Key Features

- User registration, authentication, and JWT-based access control
- Log upload API for batched detection runs
- Rule-based detection engine with risk scoring
- Persisted alerts and triage endpoints (acknowledge, suppress, escalate)
- MITRE ATT&CK technique enrichment for detected alerts
- Lightweight, modular, and easy to extend detection rules

## System Architecture

See `docs/ARCHITECTURE.md` for diagrams and component responsibilities.

## Detection Pipeline

1. Client POSTs logs to `POST /logs/upload`.
2. `ThreatDetectionEngine` parses logs with `LinuxAuthLogParser`.
3. Each detection rule evaluates parsed events and returns `ThreatAlert` objects.
4. Alerts are risk-scored, enriched with MITRE mappings, persisted to PostgreSQL and returned in the API response.

## MITRE ATT&CK Mapping Table

Reference: `docs/MITRE_MAPPING.md` (includes rationales for mapped techniques).

## Alert Lifecycle Workflow

Alerts are created with status `OPEN`. Triage endpoints allow changing status to `ACKNOWLEDGED`, `SUPPRESSED`, or `ESCALATED`. See `POST /alerts/{id}/acknowledge`, `PATCH /alerts/{id}/suppress`, `PATCH /alerts/{id}/escalate`.

## Technology Stack

- Python 3.11+
- FastAPI
- SQLAlchemy
- PostgreSQL
- Pydantic
- JWT (custom auth service)

## Installation Guide

1. Clone the repository.
2. Create a Python virtual environment and activate it.
3. Install dependencies (project uses standard FastAPI stack).

Example (Unix-like):

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt  # if provided
```

See `backend/.env.example` for environment variables (DB connection, JWT secrets).

## Local Development Setup

1. Provision a local PostgreSQL instance (Docker recommended).
2. Create the `DATABASE_URL` in `.env` and run migrations (SQLAlchemy models are in `backend/app/models`).
3. Run the API with `uvicorn app.main:app --reload --host 0.0.0.0 --port 8000` from `backend`.

## API Documentation

Interactive API docs are available at `/docs` (Swagger UI) when the service is running. See `docs/API_REFERENCE.md` for full endpoint descriptions, request/response schemas, and examples.

## Security Engineering Concepts

- Principle of least privilege is applied to service-level roles.
- JWT tokens are used for stateless authentication; refresh tokens enable long-lived sessions.
- Input validation is enforced with Pydantic models to mitigate injection vectors.
- Alerts are persisted with minimal sensitive data (raw logs are stored only inside `log_message`).

## Example Alert Output

Example alert returned by the detection pipeline:

```json
{
  "threat_type": "brute_force_login_attempts",
  "severity": "high",
  "risk_score": 71,
  "mitre_technique_id": "T1110",
  "mitre_technique_name": "Brute Force",
  "description": "Repeated failed login attempts detected from source IP 192.168.1.10. 7 failures observed.",
  "source_ip": "192.168.1.10",
  "username": "admin",
  "evidence": {"failed_attempts": 7},
  "generated_at": "2026-06-01T12:00:00Z"
}
```

## Example API Requests

- Register:

```bash
curl -X POST http://localhost:8000/auth/register -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"s3cureP@ssw0rd"}'
```

- Upload logs:

```bash
curl -X POST http://localhost:8000/logs/upload -H "Content-Type: application/json" \
  -d '{"logs":[{"message":"Failed password for invalid user root from 192.168.1.10"}]}'
```

## Future Roadmap

See `docs/ROADMAP.md` for planned features including CloudTrail, IAM monitoring, and a web dashboard.

## Contribution Guidelines

See `docs/CONTRIBUTING.md` for contribution instructions, code style, and PR process.

## License

This repository is released under the MIT License. See `LICENSE` (placeholder).

## Authors

- Project maintainer(s): Cloud Threat Detection System contributors
