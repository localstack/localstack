import json

import pytest

from localstack.aws.api.events import InvalidEventPatternException
from localstack.utils.event_matcher import matches_event

EVENT_PATTERN_DICT = {
    "source": ["aws.ec2"],
    "detail-type": ["EC2 Instance State-change Notification"],
}
EVENT_DICT = {
    "source": "aws.ec2",
    "detail-type": "EC2 Instance State-change Notification",
    "detail": {"state": "running"},
}
EVENT_PATTERN_STR = json.dumps(EVENT_PATTERN_DICT)
EVENT_STR = json.dumps(EVENT_DICT)


def test_matches_event_strings():
    assert matches_event(EVENT_PATTERN_STR, EVENT_STR)


def test_matches_event_dicts():
    assert matches_event(EVENT_PATTERN_DICT, EVENT_STR)


def test_matches_event_mixed_inputs():
    """Test with mixed string/dict inputs"""
    assert matches_event(EVENT_PATTERN_STR, EVENT_DICT)
    assert matches_event(EVENT_PATTERN_DICT, EVENT_STR)


def test_matches_event_non_matching_pattern():
    """Test with non-matching pattern"""
    non_matching_pattern = {"source": ["aws.s3"], "detail-type": ["S3 Event"]}
    assert not matches_event(non_matching_pattern, EVENT_DICT)


def test_matches_event_invalid_json():
    """Test with invalid JSON strings"""
    with pytest.raises(InvalidEventPatternException):
        matches_event("{invalid-json}", EVENT_STR)


def test_matches_event_missing_fields():
    """Test with missing required fields"""
    incomplete_event = {"source": "aws.ec2"}
    assert not matches_event(EVENT_PATTERN_DICT, incomplete_event)


def test_matches_event_pattern_matching():
    """Test various pattern matching scenarios based on AWS examples

    Examples taken from:
    - EventBridge: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html
    - SNS Filtering: https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html
    """
    test_cases = [
        # Exact matching
        (
            {"source": ["aws.ec2"], "detail-type": ["EC2 Instance State-change Notification"]},
            {"source": "aws.ec2", "detail-type": "EC2 Instance State-change Notification"},
            True,
        ),
        # Prefix matching in detail field
        (
            {"source": ["aws.ec2"], "detail": {"state": [{"prefix": "run"}]}},
            {"source": "aws.ec2", "detail": {"state": "running"}},
            True,
        ),
        # Multiple possible values
        (
            {"source": ["aws.ec2"], "detail": {"state": ["pending", "running"]}},
            {"source": "aws.ec2", "detail": {"state": "running"}},
            True,
        ),
        # Anything-but matching
        (
            {"source": ["aws.ec2"], "detail": {"state": [{"anything-but": "terminated"}]}},
            {"source": "aws.ec2", "detail": {"state": "running"}},
            True,
        ),
    ]

    for pattern, event, expected in test_cases:
        assert matches_event(pattern, event) == expected


def test_matches_event_case_sensitivity():
    """Test case sensitivity in matching"""
    case_different_event = {
        "source": "AWS.ec2",
        "detail-type": "EC2 Instance State-Change Notification",
    }
    assert not matches_event(EVENT_PATTERN_DICT, case_different_event)
