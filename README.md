# Cloud Threat Detection System

A cloud-native threat detection platform built with FastAPI and PostgreSQL.

## Features

- JWT Authentication
- User Registration and Login
- Alert Management API
- Log Upload API
- Brute Force Detection (MITRE ATT&CK T1110)
- Impossible Travel Detection (MITRE ATT&CK T1078)
- Risk Scoring Engine
- Swagger/OpenAPI Documentation
- PostgreSQL Persistence

## Tech Stack

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- JWT Authentication
- Swagger UI

## Detection Rules

### Brute Force Login Attempts (T1110)

Detects repeated failed login attempts from the same IP address within a configurable time window.

### Impossible Travel (T1078)

Detects successful logins from geographically distant locations within an unrealistic travel timeframe.

## API Documentation

Swagger UI:

```text
http://localhost:8000/docs
```

## Running Locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Author

Hrishikesh Rayasa
