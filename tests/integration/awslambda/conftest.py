from typing import Optional

import mypy_boto3_lambda
import pytest
from _pytest.nodes import Item


def pytest_runtest_protocol(item: Item, nextitem: Optional[Item]) -> Optional[object]:

    for i in item.iter_markers("multiruntime"):
        if i.args:
            raise ValueError("doofus")

        scenario = i.kwargs["scenario"]
        runtimes = i.kwargs["runtimes"]

        # TODO: build values and ids (python => python3.7,3.8.....)

        marker = pytest.mark.parametrize(
            argvalues=[],
            argnames=[("scenario", "runtime", "handler")],
            indirect=True,
            ids=[],
        )

        item.add_marker(marker=marker)

        break

class ParametrizedLambda:

    def create_function(self, *args, **kwargs):
        return kwargs["FunctionName"]


    def destroy(self):
        self.lambda_client.delete_function(self.function_name)


@pytest.fixture
def multiruntime_lambda(lambda_client, scenario, runtime, handler) -> "mypy_boto3_lambda.LambdaClient":
    # TODO packaging

    param_lambda =  ParametrizedLambda(
        lambda_client,
        scenario,
        runtime,
        handler
    )

    yield param_lambda

    param_lambda.destroy()


