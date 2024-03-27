import json
import os
from pathlib import Path
from typing import List, Tuple

import json5
import pytest

from localstack.testing.pytest import markers

THIS_FOLDER: str = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_DIR = os.path.join(THIS_FOLDER, "event_pattern_templates")
COMPLEX_MULTI_KEY_EVENT_PATTERN = os.path.join(
    REQUEST_TEMPLATE_DIR, "complex_multi_key_event_pattern.json"
)
COMPLEX_MULTI_KEY_EVENT = os.path.join(REQUEST_TEMPLATE_DIR, "complex_multi_key_event.json")
REFERENCE_DATE: str = (
    "2022-07-13T13:48:01Z"  # v1.0.0 commit timestamp cf26bd9199354a9a55e0b65e312ceee4c407f6c0
)


def load_request_templates(directory_path: str) -> List[Tuple[dict, str]]:
    json5_files = list_files_with_suffix(directory_path, ".json5")
    return [load_request_template(file_path) for file_path in json5_files]


def load_request_template(file_path: str) -> Tuple[dict, str]:
    with open(file_path, "r") as df:
        template = json5.load(df)
    return template, Path(file_path).stem


def list_files_with_suffix(directory_path: str, suffix: str) -> List[str]:
    files = []
    for root, _, filenames in os.walk(directory_path):
        for filename in filenames:
            if filename.endswith(suffix):
                absolute_filepath = os.path.join(root, filename)
                files.append(absolute_filepath)

    return files


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


# TODO: having an easy way to filter would be nice => just a list of names would make it easy to comment them out
request_template_tuples = load_request_templates(REQUEST_TEMPLATE_DIR)


@pytest.mark.parametrize(
    "request_template,label", request_template_tuples, ids=[t[1] for t in request_template_tuples]
)
@markers.aws.validated
def test_test_event_pattern(aws_client, snapshot, account_id, region_name, request_template, label):
    """This parametrized test handles three outcomes:
    a) MATCH (default): The EventPattern matches the Event yielding true as result.
    b) NO MATCH (_NEG suffix): The EventPattern does NOT match the Event yielding false as result.
    c) EXCEPTION (_EXC suffix): The EventPattern is invalid and raises an exception.
    """
    event = apply_event_template(request_template["Event"], account_id, region_name)
    event_pattern = request_template["EventPattern"]

    if label.endswith("_EXC"):
        with pytest.raises(Exception) as e:
            aws_client.events.test_event_pattern(
                Event=json.dumps(event),
                EventPattern=json.dumps(event_pattern),
            )
            exception_info = {"exception_type": type(e), "exception_message": str(e)}
            snapshot.match(label, exception_info)
    else:
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(event),
            EventPattern=json.dumps(event_pattern),
        )

        # Validate the test intention: The _NEG suffix indicates negative tests (i.e., a pattern not matching the event)
        if label.endswith("_NEG"):
            assert not response["Result"]
        else:
            assert response["Result"]


@markers.aws.validated
def test_test_event_pattern_with_multi_key(aws_client):
    """Test the special case of a duplicate JSON key separately because it requires working around the
    uniqueness constraints of the JSON5 library and Python dicts, which would already de-deduplicate the key "location".
    This example is based on the following AWS documentation:
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-complex-example
    """

    with open(COMPLEX_MULTI_KEY_EVENT, "r") as event_file, open(
        COMPLEX_MULTI_KEY_EVENT_PATTERN, "r"
    ) as event_pattern_file:
        event = event_file.read()
        event_pattern = event_pattern_file.read()

        response = aws_client.events.test_event_pattern(
            Event=event,
            EventPattern=event_pattern,
        )
        assert response["Result"]


@markers.aws.validated
def test_test_event_pattern_with_escape_characters(aws_client):
    r"""Test the special case of using escape characters separately because it requires working around JSON escaping.
    Escape characters are explained in the AWS documentation:
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns-content-based-filtering.html#eb-filtering-wildcard-matching
    * "The string \* represents the literal * character"
    * "The string \\ represents the literal \ character"
    """

    event = r'{"id": "1", "source": "test-source", "detail-type": "test-detail-type", "account": "123456789012", "region": "us-east-2", "time": "2022-07-13T13:48:01Z", "detail": {"escape_star": "*", "escape_backslash": "\\"}}'
    # TODO: devise better testing strategy for * because the wildcard matches everything and "\\*" does not match.
    event_pattern = r'{"detail": {"escape_star": ["*"], "escape_backslash": ["\\"]}}'

    response = aws_client.events.test_event_pattern(
        Event=event,
        EventPattern=event_pattern,
    )
    assert response["Result"]
