import json
import statistics
import time

import pytest

# from aws.services.events.test_event_patterns import request_template_tuples
from localstack.services.events.event_ruler import matches_rule
from localstack.services.events.models import (
    InvalidEventPatternException as InternalInvalidEventPatternException,
)
from localstack.services.events.v1.utils import matches_event


def do_something():
    return True


def does_match_python(event, event_pattern) -> bool:
    event_pattern_dict = json.loads(event_pattern)
    event_dict = json.loads(event)
    return matches_event(event_pattern_dict, event_dict)


def does_match_java(event, event_pattern) -> bool | None:
    try:
        return matches_rule(event, event_pattern)
    except InternalInvalidEventPatternException:
        return None


def does_match_sim() -> None:
    time.sleep(0.0003)


SKIP_LABELS_JAVA = ["content_wildcard_complex_EXC"]
SKIP_LABELS_PYTHON = [
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


# TODO: add engine parametrization
# @pytest.mark.parametrize(
#     "request_template,label", request_template_tuples, ids=[t[1] for t in request_template_tuples]
# )
def notest_event_pattern(benchmark, request_template, label):
    if label in SKIP_LABELS_PYTHON:
        pytest.skip("Not yet implemented")

    event_str = json.dumps(request_template["Event"])
    event_pattern_str = json.dumps(request_template["EventPattern"])

    # Parametrization: https://github.com/ionelmc/pytest-benchmark/issues/48
    benchmark.group = label
    result = benchmark.pedantic(
        does_match_python,
        args=(event_str, event_pattern_str),
        rounds=10000,
        warmup_rounds=0,
        iterations=1,
    )

    # Validate the test intention: The _NEG suffix indicates negative tests (i.e., a pattern not matching the event)
    if label.endswith("_EXC"):
        assert result is None
    elif label.endswith("_NEG"):
        assert result is not None and not result
    else:
        assert result


def test_event_single(benchmark):
    # request_template = request_template_tuples[5][0]
    # label = request_template_tuples[5][1]
    # event_str = json.dumps(request_template["Event"])
    # event_pattern_str = json.dumps(request_template["EventPattern"])

    # benchmark.group = label
    benchmark.pedantic(
        does_match_sim,
        # args=(event_str, event_pattern_str),
        rounds=10000,
        warmup_rounds=0,
        iterations=1,
    )


def test_event_single_manual():
    label = "sim"

    results = []
    for i in range(10000):
        # record start time
        time_start = time.perf_counter()
        # execute the function
        # does_match_java(event_str, event_pattern_str)
        does_match_sim()
        # record end time
        time_end = time.perf_counter()
        # calculate the duration
        time_duration = time_end - time_start
        # report the duration
        results.append(time_duration)

    print(f"Median runtime for {label}")
    print(statistics.median(results))

    print(f"Mean runtime for {label}")
    print(statistics.mean(results))

    # TODO: validate properly
    print("Operations per second")
    print(60 / statistics.mean(results))
