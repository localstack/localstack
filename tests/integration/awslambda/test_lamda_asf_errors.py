import pytest
from botocore.config import Config

from localstack.aws.api.lambda_ import Runtime
from localstack.utils.strings import short_uid
from tests.integration.awslambda.test_lambda import TEST_LAMBDA_PYTHON_ECHO


def test_stuff(snapshot, lambda_client, create_boto_client, create_lambda_function, lambda_su_role):
    """some parts could probably be split apart (e.g. overwriting with update)"""
    lambda_client = create_boto_client(
        "lambda", additional_config=Config(parameter_validation=False)
    )
    function_name = f"fn-eventinvoke-{short_uid()}"
    create_lambda_function(
        handler_file=TEST_LAMBDA_PYTHON_ECHO,
        func_name=function_name,
        runtime=Runtime.python3_9,
        role=lambda_su_role,
    )

    with pytest.raises(lambda_client.exceptions.ClientError) as e:
        lambda_client.put_function_event_invoke_config(
            FunctionName=function_name,
            MaximumRetryAttempts=-1,
        )
    snapshot.match("put_retries_invalid_-1", e.value.response)
