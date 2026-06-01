# MITRE ATT&CK Mapping

This file documents the MITRE ATT&CK technique mappings used by implemented detection rules and the rationale for each mapping.

## Mapping Table

- **T1110 - Brute Force**
  - Detection Rule: `brute_force_login_attempts`
  - Threat Category: Credential access
  - Description: Detects repeated failed authentication attempts from a single source IP which is a classic indicator of brute-force or credential stuffing attacks. Mapping chosen because the attack targets credential guessing and fits T1110.

- **T1078 - Valid Accounts**
  - Detection Rule: `impossible_travel`
  - Threat Category: Initial Access / Persistence (depending on follow-up activity)
  - Description: The detection highlights valid account usage from geographically disparate locations which often indicates credential compromise and subsequent misuse of valid accounts. Mapping chosen because the technique describes adversaries using valid account credentials.

## Why These Mappings

- Brute force attempts are directly associated with T1110 because they represent automated or manual attempts to discover valid credentials.
- Impossible travel indicates possible unauthorized use of valid credentials (T1078) — the detection observes valid logins (or successful authentication events) with inconsistent geo-context.

## Extending Mapping

When adding new rules, include the MITRE technique ID and reason in `MITRE_MAPPING` in `backend/app/services/threat_detection.py` and update this document explaining the mapping rationale.
