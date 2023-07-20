import json
import os

import aws_cdk as cdk
import aws_cdk.aws_lambda as awslambda
import pytest

from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import to_str

FN_CODE = """
def handler(event, context):
    return {"hello": "world"}

"""


class TestBasicLambda:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        # stack definition
        stack = cdk.Stack(cdk.App(), "LambdaTestStack")
        fn = awslambda.Function(
            stack,
            "Fn",
            code=awslambda.InlineCode(code=FN_CODE),
            handler="index.handler",
            runtime=awslambda.Runtime.PYTHON_3_10,  # noqa
        )
        cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()

    def test_scenario_validate_infra(self, aws_client, infrastructure):
        lambda_client = aws_client.awslambda
        function_name = infrastructure.get_stack_outputs(stack_name="LambdaTestStack")[
            "FunctionName"
        ]
        invoke_result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        assert json.loads(to_str(invoke_result["Payload"].read())) == {"hello": "world"}

    # TODO: more tests/validations


class TestBasicLambdaInS3:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        aws_client.s3.create_bucket(Bucket="lambda-s3-bucket")
        aws_client.s3.upload_file(
            Filename=os.path.join(os.path.dirname(__file__), "./fn/handler.zip"),
            Bucket="lambda-s3-bucket",
            Key="handler.zip",
        )

        # stack definition
        stack = cdk.Stack(cdk.App(), "LambdaTestStack")
        bucket = cdk.aws_s3.Bucket.from_bucket_name(stack, "bucket", "lambda-s3-bucket")
        fn = awslambda.Function(
            stack,
            "Fn",
            code=awslambda.S3Code(bucket=bucket, key="handler.zip"),
            handler="handler.handler",
            runtime=awslambda.Runtime.PYTHON_3_10,  # noqa
        )
        cdk.CfnOutput(stack, "FunctionName", value=fn.function_name)

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        provisioner.provision()
        yield provisioner
        provisioner.teardown()
        # TODO: clear & delete bucket manually

    def test_scenario_validate_infra(self, aws_client, infrastructure):
        lambda_client = aws_client.awslambda
        function_name = infrastructure.get_stack_outputs(stack_name="LambdaTestStack")[
            "FunctionName"
        ]
        invoke_result = lambda_client.invoke(FunctionName=function_name, Payload=b"{}")
        assert json.loads(to_str(invoke_result["Payload"].read())) == {"hello": "world"}
