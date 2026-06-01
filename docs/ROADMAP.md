# Roadmap

## Current Version

v1.0.0 — baseline rule-based detection engine with JWT authentication and alert persistence.

## Planned Features

- CloudTrail Detections — parse AWS CloudTrail events and detect suspicious IAM activity.
- Security Group Monitoring — detect overly permissive security group rules and rule changes.
- IAM Monitoring — detect new access keys, policy changes, and privilege escalations.
- Docker Support — provide container-aware parsing for host/container logs.
- CI/CD Pipeline — add tests, linting, and automated release workflow.
- Unit Test Expansion — increase coverage for all detectors and API edge cases.
- Dashboard UI — lightweight web UI for alert triage and visualization.
- Role-Based Access Control — fine-grained RBAC for triage and management actions.
- Real-Time Alert Streaming — integrate with Kafka or websockets for real-time workflows.

## Milestones

1. v1.1 — Add CloudTrail detector and unit tests
2. v1.2 — Add RBAC and role-protected triage endpoints
3. v2.0 — Dashboard UI and streaming support
