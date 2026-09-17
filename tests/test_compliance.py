from datetime import datetime, timedelta, timezone

from sentinova_threatlens.api.auth import issue_token, verify_token
from sentinova_threatlens.compliance import stix_bundle, validate_transition
from sentinova_threatlens.services.alerting import AlertRuleEngine
from sentinova_threatlens.severity import calculate_severity, is_expired


def test_weighted_score_is_bounded_and_reproducible() -> None:
    record = {"confidence_score": 90, "threat_type": "exploit", "last_seen": "2099-01-01T00:00:00+00:00", "metadata": {"cvss_score": 9.8}}
    score = calculate_severity(record)
    assert 0 <= score <= 100
    assert score == calculate_severity(record)


def test_expiration_supports_absolute_and_ttl() -> None:
    expired = {"last_seen": (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat(), "metadata": {"ttl_seconds": 60}}
    assert is_expired(expired)


def test_incident_lifecycle_is_strict() -> None:
    validate_transition("new", "acknowledged")
    try:
        validate_transition("new", "closed")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid transition accepted")


def test_token_round_trip_and_stix_bundle() -> None:
    token = issue_token("alice", "Analyst", ["read"], "secret")
    assert verify_token(token, "secret").subject == "alice"
    bundle = stix_bundle([{"ioc_value": "1.2.3.4", "normalized_data": {"ioc_type": "IP", "confidence_score": 80}}])
    assert bundle["type"] == "bundle"
    assert bundle["objects"][0]["spec_version"] == "2.1"


def test_alert_rules_match_multiple_dimensions() -> None:
    record = {"source_name": "AbuseIPDB", "severity_score": 90, "normalized_data": {"ioc_type": "IP", "threat_type": "C2", "metadata": {"tlp": "Amber"}}}
    rules = [{"id": 1, "name": "critical-ip", "enabled": True, "conditions": {"min_score": 80, "ioc_type": ["IP"], "tlp": ["Amber"]}, "routing": {"users": ["alice"]}}]
    assert AlertRuleEngine().evaluate(record, rules)[0].route == ["alice"]