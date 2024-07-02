import json

import pytest

from localstack.aws.api.lambda_ import Runtime
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid

from .test_lambda import TEST_LAMBDA_PYTHON_ECHO


class TestLambdaPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_function_in_different_partitions(
        self,
        account_id,
        aws_client_factory,
        create_lambda_function,
        region,
        partition,
        dummylayer,
    ):
        lambda_client = aws_client_factory(region_name=region).lambda_

        function_name = f"test-region-{short_uid()}"
        function = create_lambda_function(
            client=lambda_client,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )["CreateFunctionResponse"]

        function_arn = function["FunctionArn"]
        assert (
            function_arn == f"arn:{partition}:lambda:{region}:{account_id}:function:{function_name}"
        )

        runtime_version_config_arn = function["RuntimeVersionConfig"]["RuntimeVersionArn"]
        assert (
            runtime_version_config_arn
            == f"arn:{partition}:lambda:{region}::runtime:8eeff65f6809a3ce81507fe733fe09b835899b99481ba22fd75b5a7338290ec1"
        )

        alias_arn = lambda_client.create_alias(
            FunctionName=function_arn,
            Name="my-alias",
            FunctionVersion="$LATEST",
        )["AliasArn"]
        assert (
            alias_arn
            == f"arn:{partition}:lambda:{region}:{account_id}:function:{function_name}:my-alias"
        )

        layer_name = f"test-layer-{short_uid()}"
        layer = lambda_client.publish_layer_version(
            LayerName=layer_name, Content={"ZipFile": dummylayer}
        )
        assert (
            layer["LayerArn"] == f"arn:{partition}:lambda:{region}:{account_id}:layer:{layer_name}"
        )
        assert (
            layer["LayerVersionArn"]
            == f"arn:{partition}:lambda:{region}:{account_id}:layer:{layer_name}:1"
        )

        layer = lambda_client.get_layer_version(LayerName=layer_name, VersionNumber=1)
        assert (
            layer["LayerArn"] == f"arn:{partition}:lambda:{region}:{account_id}:layer:{layer_name}"
        )

        # tags
        lambda_client.tag_resource(Resource=function_arn, Tags={"fn": "yes"})

        assert lambda_client.list_tags(Resource=function_arn)["Tags"] == {"fn": "yes"}

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_code_signing_config_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        lambda_client = aws_client_factory(region_name=region).lambda_

        arn = lambda_client.create_code_signing_config(
            Description="Testing CodeSigning Config",
            AllowedPublishers={
                "SigningProfileVersionArns": [
                    f"arn:aws:signer:{region}:{account_id}:/signing-profiles/test",
                ]
            },
            CodeSigningPolicies={"UntrustedArtifactOnDeployment": "Enforce"},
        )["CodeSigningConfig"]["CodeSigningConfigArn"]
        assert arn.startswith(
            f"arn:{partition}:lambda:{region}:{account_id}:code-signing-config:csc-"
        )

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_permissions_in_different_partitions(
        self, account_id, create_lambda_function, aws_client_factory, region, partition
    ):
        lambda_client = aws_client_factory(region_name=region).lambda_

        function_name = f"test-region-{short_uid()}"
        create_lambda_function(
            client=lambda_client,
            handler_file=TEST_LAMBDA_PYTHON_ECHO,
            func_name=function_name,
            runtime=Runtime.python3_12,
        )

        resp = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="1",
            Action="lambda:GetFunction",
            Principal=f"arn:{partition}:iam:some_user",
        )["Statement"]
        statement = json.loads(resp)
        assert statement["Principal"] == {"AWS": f"arn:{partition}:iam:some_user"}

        resp = lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="2",
            Action="lambda:GetFunction",
            Principal="111122223333",
        )["Statement"]
        statement = json.loads(resp)
        assert statement["Principal"] == {"AWS": f"arn:{partition}:iam::111122223333:root"}
