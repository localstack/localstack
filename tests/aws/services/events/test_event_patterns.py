import json
import os
from pathlib import Path
from typing import List, Tuple

import json5
import pytest

from localstack.testing.pytest import markers

THIS_FOLDER: str = os.path.dirname(os.path.realpath(__file__))
REQUEST_TEMPLATE_DIR = os.path.join(THIS_FOLDER, "event_pattern_templates")
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
    event = apply_event_template(request_template["Event"], account_id, region_name)
    event_pattern = request_template["EventPattern"]

    # Handling both success and error cases enables parity testing all types of event/pattern configs
    try:
        response = aws_client.events.test_event_pattern(
            Event=json.dumps(event),
            EventPattern=json.dumps(event_pattern),
        )
        snapshot.match(label, response)

        # Validate the test intention: The _NEG suffix indicates negative tests (i.e., a pattern not matching the event)
        if label.endswith("_NEG"):
            assert not response["Result"]
        else:
            assert response["Result"]
    except Exception as e:
        exception_info = {"exception_type": type(e), "exception_message": str(e)}
        snapshot.match(label, exception_info)

        # Validate the test intention: The _EXC suffix indicates an exception test (i.e., an invalid pattern)
        assert label.endswith("_EXC")
