import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Tuple

import json5
import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers

THIS_FOLDER: str = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_DIR = os.path.join(THIS_FOLDER, "event_pattern_templates")
COMPLEX_MULTI_KEY_EVENT_PATTERN = os.path.join(
    REQUEST_TEMPLATE_DIR, "complex_multi_key_event_pattern.json"
)
COMPLEX_MULTI_KEY_EVENT = os.path.join(REQUEST_TEMPLATE_DIR, "complex_multi_key_event.json")


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


request_template_tuples = load_request_templates(REQUEST_TEMPLATE_DIR)

SKIP_LABELS = [
    # Failing exception tests:
    "arrays_empty_EXC",
    "content_numeric_EXC",
    "content_numeric_operatorcasing_EXC",
    "content_numeric_syntax_EXC",
    "content_wildcard_complex_EXC",
    "int_nolist_EXC",
    "operator_case_sensitive_EXC",
    "string_nolist_EXC",
    # Failing tests:
    "complex_or",
    "content_anything_but_ignorecase",
    "content_anything_but_ignorecase_list",
    "content_anything_suffix",
    "content_exists_false",
    "content_ignorecase",
    "content_ignorecase_NEG",
    "content_ip_address",
    "content_numeric_and",
    "content_prefix_ignorecase",
    "content_suffix",
    "content_suffix_ignorecase",
    "content_wildcard_nonrepeating",
    "content_wildcard_repeating",
    "content_wildcard_simplified",
    "dot_joining_event",
    "dot_joining_pattern",
    "exists_dynamodb_NEG",
    "nested_json_NEG",
    "or-exists",
    "or-exists-parent",
]


# TODO: extend these test cases based on the open source docs + tests: https://github.com/aws/event-ruler
#  For example, "JSON Array Matching", "And and Or Relationship among fields with Ruler", rule validation,
#  and exception handling.
@pytest.mark.parametrize(
    "request_template,label", request_template_tuples, ids=[t[1] for t in request_template_tuples]
)
@markers.aws.validated
def test_test_event_pattern(aws_client, snapshot, request_template, label):
    """This parametrized test handles three outcomes:
    a) MATCH (default): The EventPattern matches the Event yielding true as result.
    b) NO MATCH (_NEG suffix): The EventPattern does NOT match the Event yielding false as result.
    c) EXCEPTION (_EXC suffix): The EventPattern is invalid and raises an exception.
    """
    if label in SKIP_LABELS and not is_aws_cloud():
        pytest.skip("Not yet implemented")

    event = request_template["Event"]
    event_pattern = request_template["EventPattern"]

    if label.endswith("_EXC"):
        with pytest.raises(Exception) as e:
            aws_client.events.test_event_pattern(
                Event=json.dumps(event),
                EventPattern=json.dumps(event_pattern),
            )
        exception_info = {"exception_type": type(e.value), "exception_message": e.value.response}
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


@markers.aws.validated
def test_event_pattern_source(aws_client, snapshot, account_id, region_name):
    response = aws_client.events.test_event_pattern(
        Event=json.dumps(
            {
                "id": "1",
                "source": "order",
                "detail-type": "Test",
                "account": account_id,
                "region": region_name,
                "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ),
        EventPattern=json.dumps(
            {
                "source": ["order"],
                "detail-type": ["Test"],
            }
        ),
    )
    snapshot.match("eventbridge-test-event-pattern-response", response)

    # negative test, source is not matched
    response = aws_client.events.test_event_pattern(
        Event=json.dumps(
            {
                "id": "1",
                "source": "order",
                "detail-type": "Test",
                "account": account_id,
                "region": region_name,
                "time": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
        ),
        EventPattern=json.dumps(
            {
                "source": ["shipment"],
                "detail-type": ["Test"],
            }
        ),
    )
    snapshot.match("eventbridge-test-event-pattern-response-no-match", response)
