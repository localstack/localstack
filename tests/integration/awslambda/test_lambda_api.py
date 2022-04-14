# ALL TESTS IN HERE ARE VALIDATED AGAINST AWS CLOUD
import logging
import os.path

import pytest

from localstack.utils.strings import short_uid
from localstack.utils.sync import retry, wait_until

LOG = logging.Logger(__name__)

role_assume_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

role_policy = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": ["*"],
        }
    ],
}

lambda_asf_only = pytest.mark.skipif(
    os.environ.get("PROVIDER_OVERRIDE_LAMBDA") != "asf", reason="Skip for non-asf provider"
)


# TODO: move this to fixtures / reconcile with other fixture usage
@pytest.fixture
def create_lambda_function_aws(
    lambda_client,
):
    lambda_arns = []

    def _create_lambda_function(**kwargs):
        def _create_function():
            resp = lambda_client.create_function(**kwargs)
            lambda_arns.append(resp["FunctionArn"])

            def _is_not_pending():
                try:
                    result = (
                        lambda_client.get_function(FunctionName=resp["FunctionName"])[
                            "Configuration"
                        ]["State"]
                        != "Pending"
                    )
                    return result
                except Exception as e:
                    LOG.error(e)
                    raise

            wait_until(_is_not_pending)
            return resp

        # @AWS, takes about 10s until the role/policy is "active", until then it will fail
        # localstack should normally not require the retries and will just continue here
        return retry(_create_function, retries=3, sleep=4)

    yield _create_lambda_function

    for arn in lambda_arns:
        try:
            lambda_client.delete_function(FunctionName=arn)
        except Exception:
            LOG.debug(f"Unable to delete function {arn=} in cleanup")


# 1. AWS mit --snapshot-update
# 2. AWS mit --snapshot-verify
# 3. localstack mit --snapshot-verify


@pytest.mark.snapshot
@pytest.mark.aws_compatible
class TestLambdaAsfApi:
    def test_basic_invoke(
        self, lambda_client, create_lambda_function_aws, lambda_su_role, snapshot
    ):
        fn_name = f"ls-fn-{short_uid()}"
        with open(os.path.join(os.path.dirname(__file__), "functions/echo.zip"), "rb") as f:
            response = create_lambda_function_aws(
                FunctionName=fn_name,
                Handler="index.handler",
                Code={"ZipFile": f.read()},
                PackageType="Zip",
                Role=lambda_su_role,
                Runtime="python3.9",
            )
            snapshot.match("lambda_create_fn", response)

        get_fn_result = lambda_client.get_function(FunctionName=fn_name)
        snapshot.match("lambda_get_fn", get_fn_result)

        invoke_result = lambda_client.invoke(FunctionName=fn_name, Payload=bytes("{}", "utf-8"))
        snapshot.match("lambda_invoke_result", invoke_result)
