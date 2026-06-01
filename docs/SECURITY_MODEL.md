# Security Model

This document explains the security controls and threat model considered for the Cloud Threat Detection System.

## Authentication

- JWT-based authentication with access and refresh tokens.
- Tokens are created by `auth_service` and validated in middleware (`jwt_context_middleware` in `main.py`).
- Access tokens should be short-lived; refresh tokens are used to request new access tokens.

## Authorization

- Lightweight role field (`role`) in `User` model; current APIs assume a single `user` role. Future RBAC should gate triage actions to roles like `analyst` or `manager`.

## Token Lifecycle

- `access_token` — short TTL used for API authorization.
- `refresh_token` — longer TTL used to mint new access tokens via `POST /auth/refresh`.

## Input Validation

- Pydantic models validate incoming requests (`schemas/*`) and reject extra fields when configured.

## Database Security

- Use parameterized queries via SQLAlchemy to protect against injection.
- Secure database credentials using environment variables (see `backend/.env.example`).

## API Security

- CORS is configurable via `ALLOWED_ORIGINS` (defaults to `*` in development). For production restrict allowed origins.
- Structured logging avoids printing secrets. Avoid storing raw sensitive credentials in logs.

## Threat Detection Security Model

- The detection engine is deterministic and processes input logs; treat it as untrusted input handling — use strict parsing and avoid executing logged commands.

## Alert Integrity

- Alerts include generated timestamps and evidence samples to ensure reproducibility.
- For stronger integrity guarantees consider signing alerts before persistence and using append-only storage.
