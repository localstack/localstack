import os

import aws_cdk as cdk
import pytest
from aws_cdk import aws_dynamodb as dynamodb
from aws_cdk import aws_lambda as awslambda

from localstack.testing.pytest import markers
from localstack.testing.scenario.cdk_lambda_helper import load_python_lambda_to_s3

# from localstack.utils.files import load_file

FN_CODE = """
def handler(event, ctx):
    print("hello world from inline code")
    print(event)
"""


class TestSomethingElse:
    STACK_NAME = "AnotherStack"
    CODE_PATH = os.path.join(os.path.dirname(__file__), "functions/simpletest.py")

    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, infrastructure_setup, aws_client):
        infra = infrastructure_setup("AnotherSample", force_synth=True)

        stack = cdk.Stack(infra.cdk_app, self.STACK_NAME)

        fn1 = awslambda.Function(
            stack,
            "InlineLambda",
            handler="index.handler",
            code=awslambda.InlineCode(code=FN_CODE),
            # or
            # code=awslambda.Code.from_inline(FN_CODE),
            # or load from file path:
            # code=awslambda.InlineCode(code=load_file(self.CODE_PATH)),
            runtime=awslambda.Runtime.PYTHON_3_11,
        )

        # only if you need additional libs, upload a zip to s3:
        asset_bucket = infra.get_asset_bucket()
        key = "lambda_source.zip"
        infra.add_custom_setup(
            lambda: load_python_lambda_to_s3(
                aws_client.s3,
                bucket_name=asset_bucket,
                key_name=key,
                code_path=self.CODE_PATH,
                additional_python_packages=["requests"],
            )
        )

        # to reference the bucket, it must be a CDK construct:
        bucket = cdk.aws_s3.Bucket.from_bucket_name(
            stack,
            "bucket_name",
            bucket_name=infra.get_asset_bucket_cdk(stack),
        )

        fn2 = awslambda.Function(
            stack,
            "ComplexLambda",
            handler="index.handler",
            code=awslambda.S3Code(bucket=bucket, key=key),  # TODO simulate failing stack (key)
            runtime=awslambda.Runtime.PYTHON_3_11,
        )

        table = dynamodb.Table(
            stack,
            "SampleTable",
            partition_key=dynamodb.Attribute(name="id", type=dynamodb.AttributeType.NUMBER),
            removal_policy=cdk.RemovalPolicy.DESTROY,  # TODO removal policy!
            billing_mode=dynamodb.BillingMode.PROVISIONED,
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES,
        )

        table.grant_full_access(fn2)
        cdk.CfnOutput(stack, "table_name", value=table.table_name)

        cdk.CfnOutput(stack, "fn_name1", value=fn1.function_name)
        cdk.CfnOutput(stack, "fn_name2", value=fn2.function_name)

        with infra.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    def test_setup(self, infrastructure, aws_client):
        outputs = infrastructure.get_stack_outputs(self.STACK_NAME)
        # TODO test something
        assert outputs
