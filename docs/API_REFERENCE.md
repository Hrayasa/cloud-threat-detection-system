# API Reference

Interactive API docs are available at `/docs` when the service is running. Below are the primary endpoints, their purpose, request/response schemas, and examples implemented in code.

## Authentication APIs

### POST /auth/register
- Purpose: Create a new user and return access + refresh tokens.
- Request Schema: `RegisterRequest` { `email` (string), `password` (string, min 8) }
- Response Schema: `TokenResponse` { `access_token`, `refresh_token`, `token_type`, `expires_in` }

Example Request:

```http
POST /auth/register
Content-Type: application/json

{ "email": "user@example.com", "password": "s3cureP@ss" }
```

Example Response (201):

```json
{ "access_token":"...","refresh_token":"...","token_type":"bearer","expires_in":3600 }
```

Errors:
- 409 Conflict – email already registered
- 500 Internal Server Error – DB error

### POST /auth/login
- Purpose: Authenticate and obtain tokens.
- Request Schema: `LoginRequest` { `email`, `password` }
- Response Schema: `TokenResponse`

Errors:
- 401 Unauthorized – invalid credentials

### POST /auth/refresh
- Purpose: Exchange a refresh token for a new access token.
- Request Schema: `RefreshTokenRequest` { `refresh_token` }
- Response Schema: `TokenResponse`

Errors:
- 401 Unauthorized – invalid refresh token

### GET /auth/me
- Purpose: Example protected endpoint returning token subject.
- Authentication: Bearer access token required.
- Response Schema: `ProtectedResponse` { `message`, `subject` }

## Logs APIs

### POST /logs/upload
- Purpose: Upload batched logs for detection and persist detected alerts.
- Request Schema: `LogUploadRequest` { `logs`: [ { `message`: string } ] }
- Response Schema: JSON with `processed_events`, `alerts_detected`, and `alerts` array.

Example Request:

```http
POST /logs/upload
Content-Type: application/json

{ "logs": [ { "message": "Failed password for invalid user root from 192.168.1.10" } ] }
```

Example Response (200):

```json
{
  "processed_events": 1,
  "alerts_detected": 1,
  "alerts": [ { "id": 1, "threat_type":"brute_force_login_attempts", "severity":"high", "source_ip":"192.168.1.10", "log_message":"...", "risk_score":71, "mitre_technique_id":"T1110", "mitre_technique_name":"Brute Force", "status":"OPEN", "created_at":"..." } ]
}
```

Errors:
- 500 Internal Server Error – failed to persist alerts

## Alert APIs

### GET /alerts
- Purpose: List all alerts (newest first).
- Response Schema: list of `AlertResponse` objects.

### GET /alerts/{id}
- Purpose: Retrieve a single alert by ID.
- Response Schema: `AlertResponse`
- Errors: 404 Not Found – alert not found

### PATCH /alerts/{id}/acknowledge
- Purpose: Mark an `OPEN` alert as `ACKNOWLEDGED`.
- Response Schema: `MessageResponse` { `message` }
- Errors: 404 Not Found, 400 Bad Request when not `OPEN`.

### PATCH /alerts/{id}/suppress
- Purpose: Mark an `OPEN` alert as `SUPPRESSED`.

### PATCH /alerts/{id}/escalate
- Purpose: Mark an `OPEN` alert as `ESCALATED`.

For all triage endpoints responses are `MessageResponse` and errors include 404/400 as implemented in `backend/app/api/alerts.py`.
