# Diagrams

This file holds mermaid diagrams describing the system architecture, authentication flow, detection flow, alert lifecycle, and database relationships.

## System Architecture

```mermaid
graph LR
  Client --> API[FastAPI API]
  API --> DETECT[ThreatDetectionEngine]
  DETECT --> Parser[LinuxAuthLogParser]
  API --> DB[(PostgreSQL)]
```

## Authentication Flow

```mermaid
sequenceDiagram
  participant C as Client
  participant API
  participant Auth as AuthService
  C->>API: POST /auth/login
  API->>Auth: verify credentials
  Auth-->>API: access + refresh tokens
  API-->>C: tokens
```

## Detection Flow

```mermaid
sequenceDiagram
  participant C as Client
  participant API
  participant DET as Engine
  participant Parser
  C->>API: POST /logs/upload
  API->>DET: evaluate_logs(raw_lines)
  DET->>Parser: parse(line)
  DET->>DET: evaluate rules
  DET-->>API: DetectionReport
  API->>DB: persist alerts
```

## Alert Lifecycle

```mermaid
stateDiagram-v2
  [*] --> OPEN
  OPEN --> ACKNOWLEDGED: acknowledge
  OPEN --> SUPPRESSED: suppress
  OPEN --> ESCALATED: escalate
  ACKNOWLEDGED --> [*]
  SUPPRESSED --> [*]
  ESCALATED --> [*]
```

## Database Relationships

```mermaid
erDiagram
  USERS {
    integer id PK
    string email
    string hashed_password
    string role
  }
  ALERTS {
    integer id PK
    string threat_type
    string severity
    string source_ip
    text log_message
  }
  USERS ||--o{ ALERTS: creates
```
