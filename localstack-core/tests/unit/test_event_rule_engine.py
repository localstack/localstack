import json
import pytest
from localstack import config
from localstack.services.events.event_rule_engine import matches_event, validate_event_pattern


@pytest.mark.event_rule_engine
def test_matches_event_java_engine():
    config.EVENT_RULE_ENGINE = "java"
    
    # Test dictionary input
    event_pattern = {
        "source": ["aws.ec2"],
        "detail-type": ["EC2 Instance State-change Notification"]
    }
    event = {
        "source": "aws.ec2",
        "detail-type": "EC2 Instance State-change Notification",
        "detail": {"state": "running"}
    }
    assert matches_event(event_pattern, event) is True

    # Test string input
    event_pattern_str = json.dumps(event_pattern)
    event_str = json.dumps(event)
    assert matches_event(event_pattern_str, event_str) is True


@pytest.mark.event_rule_engine
def test_matches_event_python_engine():
    config.EVENT_RULE_ENGINE = "python"
    
    # Test dictionary input
    event_pattern = {
        "source": ["aws.ec2"],
        "detail-type": ["EC2 Instance State-change Notification"]
    }
    event = {
        "source": "aws.ec2",
        "detail-type": "EC2 Instance State-change Notification",
        "detail": {"state": "running"}
    }
    assert matches_event(event_pattern, event) is True

    # Test string input
    event_pattern_str = json.dumps(event_pattern)
    event_str = json.dumps(event)
    assert matches_event(event_pattern_str, event_str) is True


@pytest.mark.event_rule_engine
def test_validate_event_pattern():
    # Valid patterns
    valid_patterns = [
        {"source": ["aws.ec2"]},
        {"detail-type": ["EC2 Instance State-change Notification"]},
        json.dumps({"source": ["aws.ec2"]})
    ]
    
    for pattern in valid_patterns:
        assert validate_event_pattern(pattern) is True

    # Invalid patterns
    invalid_patterns = [
        "not a valid pattern",
        123,
        None,
        []
    ]
    
    for pattern in invalid_patterns:
        assert validate_event_pattern(pattern) is False
