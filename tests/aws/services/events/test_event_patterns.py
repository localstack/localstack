import json

import pytest

from localstack.testing.pytest import markers

REFERENCE_DATE: str = (
    "2022-07-13T13:48:01Z"  # v1.0.0 commit timestamp cf26bd9199354a9a55e0b65e312ceee4c407f6c0
)

sample1 = {
    "Label": "sample1",
    "Event": {
        "id": "1",
        "source": "order",
        "detail-type": "Test",
        "account": "$account",
        "region": "$region",
        "time": "$time",
    },
    "EventPattern": {
        "source": ["order"],
        "detail-type": ["Test"],
    },
}


@pytest.mark.parametrize("request_template", [sample1])
@markers.aws.unknown
def test_test_event_pattern(aws_client, snapshot, account_id, region_name, request_template):
    event = apply_event_template(request_template["Event"], account_id, region_name)
    event_pattern = request_template["EventPattern"]
    print(event)
    response = aws_client.events.test_event_pattern(
        Event=json.dumps(event),
        EventPattern=json.dumps(event_pattern),
    )
    label = request_template["Label"]
    snapshot.match(label, response)


def apply_event_template(event_template, account_id, region_name):
    replacements = {
        # replacement variable => replacement value
        "$account": account_id,
        "$region": region_name,
        "$time": REFERENCE_DATE,
    }
    for key, value in event_template.items():
        # Apply replacements for strings
        if isinstance(value, str):
            for replace_variable, replace_value in replacements.items():
                if replace_variable in value:
                    event_template[key] = value.replace(replace_variable, replace_value)
        # Recurse into dicts
        elif isinstance(value, dict):
            event_template[key] = apply_event_template(value, account_id, region_name)
    return event_template
