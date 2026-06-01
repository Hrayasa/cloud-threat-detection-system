from app.services.threat_detection import DetectionThresholds, ThreatAlert, ThreatDetectionEngine


def test_rule_based_engine_generates_expected_alerts() -> None:
    thresholds = DetectionThresholds(
        brute_force_threshold=2,
        suspicious_ip_threshold=2,
        unusual_login_frequency_threshold=3,
        privilege_escalation_threshold=1,
    )
    engine = ThreatDetectionEngine(thresholds=thresholds)

    sample_logs = [
        "Jan  1 00:00:01 host sshd[123]: Failed password for invalid user admin from 10.0.0.5 port 2222 ssh2",
        "Jan  1 00:00:02 host sshd[124]: Failed password for invalid user admin from 10.0.0.5 port 2222 ssh2",
        "Jan  1 00:00:03 host sshd[125]: Accepted password for alice from 10.0.0.6 port 2222 ssh2",
        "Jan  1 00:00:04 host sshd[126]: Accepted password for alice from 10.0.0.6 port 2222 ssh2",
        "Jan  1 00:00:05 host sshd[127]: Accepted password for alice from 10.0.0.6 port 2222 ssh2",
        "Jan  1 00:00:06 host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
    ]

    report = engine.evaluate_logs(sample_logs)

    assert report.processed_events == len(sample_logs)
    assert report.total_alerts >= 4
    assert any(
        alert.threat_type == "brute_force_login_attempts"
        and alert.source_ip == "10.0.0.5"
        for alert in report.alerts
    )
    assert any(
        alert.threat_type == "unusual_login_frequency"
        and alert.username == "alice"
        for alert in report.alerts
    )
    assert any(
        alert.threat_type == "potential_privilege_escalation"
        and alert.metadata.get("target_user") == "root"
        for alert in report.alerts
    )
    assert report.summary["total_alerts"] == report.total_alerts


def test_alert_serialization_supports_alert_payloads() -> None:
    alert = ThreatAlert(
        threat_type="potential_privilege_escalation",
        severity="critical",
        risk_score=90,
        description="Privilege escalation detected via sudo command.",
        source_ip="192.168.1.15",
        username="alice",
        evidence={"target_user": "root", "command": "/bin/bash"},
        metadata={"rule": "potential_privilege_escalation"},
    )

    payload = alert.to_alert_record()

    assert payload["threat_type"] == "potential_privilege_escalation"
    assert payload["severity"] == "critical"
    assert payload["risk_score"] == 90
    assert payload["source_ip"] == "192.168.1.15"
    assert payload["metadata"]["rule"] == "potential_privilege_escalation"
