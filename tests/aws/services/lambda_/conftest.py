import os
from pathlib import Path

import pytest
from _pytest.python import Metafunc

from localstack.testing.aws.lambda_utils import (
    ParametrizedLambda,
    _get_lambda_invocation_events,
    generate_tests,
    package_for_lang,
)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "multiruntime: Multi runtime",
    )


def pytest_generate_tests(metafunc: Metafunc):
    generate_tests(metafunc)


@pytest.fixture
def multiruntime_lambda(aws_client, request, lambda_su_role) -> ParametrizedLambda:
    scenario, runtime, handler = request.param

    zip_file_path = package_for_lang(
        scenario=scenario, runtime=runtime, root_folder=Path(os.path.dirname(__file__))
    )
    param_lambda = ParametrizedLambda(
        lambda_client=aws_client.lambda_,
        scenario=scenario,
        runtime=runtime,
        handler=handler,
        zip_file_path=zip_file_path,
        role=lambda_su_role,
    )

    yield param_lambda

    param_lambda.destroy()


@pytest.fixture
def dummylayer():
    with open(os.path.join(os.path.dirname(__file__), "layers/testlayer.zip"), "rb") as fd:
        yield fd.read()


@pytest.fixture
def get_lambda_logs_event(aws_client):
    def _get_lambda_logs_event(function_name, expected_num_events, retries=30):
        return _get_lambda_invocation_events(
            logs_client=aws_client.logs,
            function_name=function_name,
            expected_num_events=expected_num_events,
            retries=retries,
        )

    return _get_lambda_logs_event
