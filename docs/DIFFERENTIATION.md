# Differentiation from Wazuh

This section explains how the Cloud Threat Detection System differs from Wazuh without claiming superiority.

## Positioning

- Lightweight: This project is intentionally small and focuses on clarity and extendability for detection engineering education and PoC work.
- API-first: Designed as a service that exposes detection results via RESTful APIs and is easy to integrate into other tooling.
- Detection Engineering Focused: Emphasizes modular, testable detection rules and clear risk scoring logic rather than full endpoint/asset management.
- Educational: The parser, rules, and scoring are implemented in a way that is easy to read and extend for learning and experimentation.
- Cloud Security Focused: Prioritizes cloud-centric detection scenarios like IAM events and CloudTrail extensibility planned in the roadmap.

## How Wazuh Differs

- Wazuh is a full SIEM/XDR solution which includes log collection, rule management, endpoint monitoring, compliance modules, and more. It is feature-rich and production-grade for enterprise deployments.
- This project is intentionally narrow in scope — it demonstrates detection concepts, provides an API-first interface, and is intended to be easy to extend or embed in larger architectures.

Use this project as a learning and prototyping platform and integrate it with larger ecosystems (including SIEMs like Wazuh) when broad coverage and enterprise features are required.
