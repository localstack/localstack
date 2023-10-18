import os
from pathlib import Path

import pytest
from _pytest.python import Metafunc

from localstack.testing.aws.lambda_utils import ParametrizedLambda, generate_tests, package_for_lang


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
