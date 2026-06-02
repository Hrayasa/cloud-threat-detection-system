````markdown
<p align="center">
  <img src="assets/banner.png" alt="Cloud Threat Detection System">
</p>

# Cloud Threat Detection System

## Project Overview

Cloud Threat Detection System is an API-first security monitoring platform built to demonstrate modern detection engineering concepts. The platform ingests authentication logs, analyzes suspicious activity, maps detections to MITRE ATT&CK techniques, and generates actionable security alerts.

The project focuses on the core components commonly found in security monitoring and threat detection platforms:

- Log ingestion and normalization
- Threat detection and analysis
- MITRE ATT&CK enrichment
- Alert lifecycle management
- JWT-based authentication
- RESTful APIs with OpenAPI documentation

The goal is to provide a lightweight, extensible foundation for cloud security monitoring while showcasing detection engineering principles used in modern Security Operations Centers (SOC).

---

## Key Features

### Authentication & Security

- JWT-based authentication and authorization
- User registration and login
- Protected API endpoints
- Refresh token support
- Secure password hashing

### Threat Detection

- Brute Force Login Detection
- Rule-based Detection Engine
- Risk-based Alert Generation
- MITRE ATT&CK Technique Mapping
- Extensible Detection Framework

### Alert Management

- Alert Creation and Storage
- Alert Acknowledgement Workflow
- Alert Suppression Workflow
- Alert Escalation Workflow
- Severity-based Classification

### API Platform

- FastAPI-powered REST APIs
- Interactive Swagger Documentation
- OpenAPI 3.1 Specification
- Modular Service Architecture

### Data Persistence

- PostgreSQL Integration
- SQLAlchemy ORM
- Structured Alert Storage
- User Management Database

---

## Architecture

![Architecture](assets\architecture-diagram.png)

The platform follows a modular detection engineering architecture designed around separation of concerns.

Authentication logs are ingested through API endpoints and normalized by the log parser. Events are forwarded to the detection engine where security rules evaluate suspicious behaviour. Matching detections are enriched with MITRE ATT&CK mappings before alerts are generated and persisted to PostgreSQL.

Analysts can then triage alerts through acknowledgement, suppression, and escalation workflows.

---

## Technology Stack

| Category | Technology |
|----------|------------|
| Backend Framework | FastAPI |
| Programming Language | Python 3.12 |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Authentication | JWT |
| API Documentation | Swagger UI / OpenAPI |
| Testing | Pytest |
| Security Framework | MITRE ATT&CK |
| Cloud Integration | AWS CloudWatch (Extensible) |

---

## Detection Pipeline

```text
Authentication Logs
        │
        ▼
    Log Parser
        │
        ▼
 Threat Detection Engine
        │
        ▼
 MITRE ATT&CK Mapping
        │
        ▼
 Alert Generation
        │
        ▼
 PostgreSQL Storage
        │
        ▼
 Analyst Triage Workflow
````

### Workflow

1. Authentication logs are uploaded through the API.
2. Logs are normalized into a structured format.
3. Detection rules analyze suspicious activity.
4. Matching detections are mapped to MITRE ATT&CK techniques.
5. Alerts are generated with severity levels.
6. Alerts are stored in PostgreSQL.
7. Analysts can acknowledge, suppress, or escalate alerts.

---

## Screenshots

### Platform Architecture

![Architecture](assets/architecture-diagram.png)

System architecture illustrating log ingestion, detection processing, MITRE mapping, and alert management workflows.

### Swagger API Documentation

![Swagger](assets/api-swagger.png)

Interactive API documentation automatically generated using FastAPI and OpenAPI.

### Alert Dashboard

![Alerts](assets/alerts-dashboard.png)

Visualization of generated alerts, severity distribution, and security monitoring workflows.

### MITRE ATT&CK Mapping

![MITRE](assets/mitre-mapping.png)

Implemented ATT&CK technique mappings used by the detection engine.

---

## MITRE ATT&CK Mapping

| Detection          | ATT&CK ID | Technique      |
| ------------------ | --------- | -------------- |
| Brute Force Login  | T1110     | Brute Force    |
| Impossible Travel* | T1078     | Valid Accounts |

* Planned enhancement demonstrating framework extensibility.

---

## Alert Lifecycle

```text
OPEN
 │
 ├── ACKNOWLEDGED
 │
 ├── SUPPRESSED
 │
 └── ESCALATED
```

### Alert Status Actions

| Action      | Purpose                                |
| ----------- | -------------------------------------- |
| Acknowledge | Alert has been reviewed                |
| Suppress    | Alert intentionally muted              |
| Escalate    | Requires higher-priority investigation |

---

## API Endpoints

### Authentication

| Method | Endpoint       |
| ------ | -------------- |
| POST   | /auth/register |
| POST   | /auth/login    |
| POST   | /auth/refresh  |
| GET    | /auth/me       |

### Log Ingestion

| Method | Endpoint     |
| ------ | ------------ |
| POST   | /logs/upload |

### Alert Management

| Method | Endpoint                       |
| ------ | ------------------------------ |
| GET    | /alerts                        |
| GET    | /alerts/high                   |
| GET    | /alerts/critical               |
| GET    | /alerts/{alert_id}             |
| PATCH  | /alerts/{alert_id}/acknowledge |
| PATCH  | /alerts/{alert_id}/suppress    |
| PATCH  | /alerts/{alert_id}/escalate    |

---

## Local Development Setup

### Clone Repository

```bash
git clone https://github.com/Hrayasa/cloud-threat-detection-system.git
cd cloud-threat-detection-system/backend
```

### Create Virtual Environment

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Configure Environment Variables

Create a `.env` file:

```env
DATABASE_URL=postgresql://username:password@localhost/threatdb
SECRET_KEY=your-secret-key
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

### Run Application

```bash
uvicorn app.main:app --reload
```

### Access Documentation

```text
http://127.0.0.1:8000/docs
```

---

## Example Alert Output

```json
{
  "alert_id": 101,
  "title": "Brute Force Login Attempt",
  "severity": "High",
  "mitre_attack_id": "T1110",
  "technique": "Brute Force",
  "status": "OPEN",
  "source_ip": "192.168.1.100",
  "failed_attempts": 15,
  "timestamp": "2026-06-01T14:30:00Z"
}
```

---

## Project Structure

```text
cloud-threat-detection-system/
│
├── backend/
│   ├── app/
│   │   ├── api/
│   │   ├── core/
│   │   ├── database/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── utils/
│   │
│   ├── tests/
│   ├── assets/
│   └── requirements.txt
│
├── docs/
│   ├── API_REFERENCE.md
│   ├── ARCHITECTURE.md
│   ├── CONTRIBUTING.md
│   ├── DETECTION_ENGINE.md
│   ├── DIFFERENTIATION.md
│   ├── MITRE_MAPPING.md
│   ├── PROJECT_REPORT.md
│   ├── ROADMAP.md
│   ├── SECURITY_MODEL.md
│   └── THREAT_DETECTIONS.md
│
└── README.md
```

---

## Wazuh Differentiation

This project is intentionally positioned as a lightweight API-first threat detection platform focused on detection engineering concepts, MITRE ATT&CK enrichment, alert triage workflows, and cloud security monitoring.

| Feature                     | This Project | Wazuh   |
| --------------------------- | ------------ | ------- |
| Lightweight Deployment      | ✓            | ✗       |
| API-First Architecture      | ✓            | Partial |
| Detection Engineering Focus | ✓            | Partial |
| MITRE ATT&CK Mapping        | ✓            | ✓       |
| Alert Lifecycle Management  | ✓            | ✓       |
| Enterprise SIEM Features    | ✗            | ✓       |
| Agent-Based Monitoring      | ✗            | ✓       |
| Compliance Frameworks       | ✗            | ✓       |

The purpose of this project is educational and engineering-focused, demonstrating how modern threat detection systems are designed and implemented rather than competing directly with enterprise SIEM platforms.

---

## Future Roadmap

### Detection Enhancements

* Impossible Travel Detection
* Credential Stuffing Detection
* Privilege Escalation Detection
* Suspicious API Activity Detection

### Platform Enhancements

* Real-time Alert Streaming
* Web Dashboard
* Role-Based Access Control
* Multi-Tenant Support

### Cloud Integrations

* AWS CloudWatch Integration
* Azure Monitor Integration
* Google Cloud Logging Integration

### DevOps & Deployment

* Docker Support
* Kubernetes Deployment
* GitHub Actions CI/CD
* Automated Security Testing

---

## Documentation

Detailed project documentation is available in the `/docs` directory:

* API Reference
* Architecture Guide
* Detection Engine Documentation
* MITRE ATT&CK Mapping
* Security Model
* Threat Detection Design
* Project Roadmap
* Project Report

---

## Contributing

Contributions, feature requests, and improvements are welcome.

Please review:

```text
docs/CONTRIBUTING.md
```

before submitting changes.

---

## License

This project is released under the MIT License.

---

## Author

**Hrishikesh Rayasa**

M.Tech Computer Science & Engineering (Networks)
Manipal Institute of Technology

GitHub: https://github.com/Hrayasa

```
```
