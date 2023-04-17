"""
Basic opt-in performance tests for Lambda. Usage:
1) Set TEST_PERFORMANCE=1
2) Set TEST_PERFORMANCE_RESULTS_DIR=$HOME/Downloads if you want to export performance results as CSV
3) Adjust repeat=1000 to configure the number of repetitions
"""

import csv
import os
import pathlib
import statistics
import timeit
from datetime import datetime

import pytest

from localstack import config
from localstack.aws.api.lambda_ import Runtime
from localstack.config import is_env_true
from localstack.utils.strings import short_uid
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO

# These performance tests are opt-in because we currently do not track performance systematically.
if not is_env_true("TEST_PERFORMANCE"):
    pytest.skip("Skip slow and resource-intensive tests", allow_module_level=True)


def test_invoke_warm_start(create_lambda_function, aws_client):
    function_name = f"echo-func-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    def invoke():
        aws_client.awslambda.invoke(FunctionName=function_name)

    # Cold start
    invoke()

    # Warm starts
    repeat = 100
    timings = timeit.repeat(invoke, number=1, repeat=repeat)
    print("")
    print(f" EXECUTION TIME (s) for {repeat} repetitions ".center(80, "="))
    print(format_summary(timings))
    export_csv(timings, "test_invoke_warm_start")


def test_invoke_cold_start(create_lambda_function, aws_client, monkeypatch):
    monkeypatch.setattr(config, "LAMBDA_KEEPALIVE_MS", 0)
    function_name = f"echo-func-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
    )

    def invoke():
        aws_client.awslambda.invoke(FunctionName=function_name)

    # Initial cold start could be even slower due to init downloading
    invoke()

    # Cold starts caused by keep alive 0
    repeat = 100
    # Optionally sleep in between repetitions
    sleep_s = 4
    timings = timeit.repeat(
        invoke, number=1, repeat=repeat, setup=f"import time; time.sleep({sleep_s})"
    )
    print("")
    print(f" EXECUTION TIME (s) for {repeat} repetitions ".center(80, "="))
    print(format_summary(timings))
    export_csv(timings, "test_invoke_cold_start")


def format_summary(timings: [float]) -> str:
    """Format summary statistics in seconds."""
    stats = [
        f"{min(timings)} (min)",
        f"{statistics.median(timings)} (median)",
        f"""{statistics.quantiles(timings, n=100, method="inclusive")[98]} (p99)""",
        f"{max(timings)} (max)",
    ]
    return ", ".join(stats)


def export_csv(timings: [float], label: str = "") -> None:
    """Export the given timings into a csv file if the environment variable TEST_PERFORMANCE_RESULTS_DIR is set."""
    if results_dir := os.environ.get("TEST_PERFORMANCE_RESULTS_DIR"):
        timestamp = datetime.now().strftime("%Y-%m-%dT%H-%M-%S")
        file_name = f"{timestamp}_{label}.csv"
        file_path = pathlib.Path(results_dir) / file_name
        file = open(file_path, "w")
        data = [[value] for value in timings]
        with file:
            write = csv.writer(file)
            write.writerows(data)
