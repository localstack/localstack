import os

import pytest
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.services.cloudformation.engine.template_deployer import MOCK_REFERENCE
from localstack.testing.pytest import markers
from localstack.utils import testutil
from localstack.utils.strings import short_uid


@pytest.mark.parametrize("attribute_name", ["TopicName", "TopicArn"])
@markers.aws.validated
def test_nested_getatt_ref(deploy_cfn_template, aws_client, attribute_name, snapshot):
    topic_name = f"test-topic-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_getatt_ref.yaml"
        ),
        parameters={"MyParam": topic_name, "CustomOutputName": attribute_name},
    )
    snapshot.match("outputs", deployment.outputs)
    topic_arn = deployment.outputs["MyTopicArn"]

    # Verify the nested GetAtt Ref resolved correctly
    custom_ref = deployment.outputs["MyTopicCustom"]
    if attribute_name == "TopicName":
        assert custom_ref == topic_name

    if attribute_name == "TopicArn":
        assert custom_ref == topic_arn

    # Verify resource was created
    topic_arns = [t["TopicArn"] for t in aws_client.sns.list_topics()["Topics"]]
    assert topic_arn in topic_arns


@markers.aws.validated
def test_sub_resolving(deploy_cfn_template, aws_client, snapshot):
    """
    Tests different cases for Fn::Sub resolving

    https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/intrinsic-function-reference-sub.html


    TODO: cover all supported functions for VarName / VarValue:
        Fn::Base64
        Fn::FindInMap
        Fn::GetAtt
        Fn::GetAZs
        Fn::If
        Fn::ImportValue
        Fn::Join
        Fn::Select
        Ref

    """
    topic_name = f"test-topic-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic-name>"))

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_sub_resovling.yaml"
        ),
        parameters={"MyParam": topic_name},
    )
    snapshot.match("outputs", deployment.outputs)
    topic_arn = deployment.outputs["MyTopicArn"]

    # Verify the parts in the Fn::Sub string are resolved correctly.
    sub_output = deployment.outputs["MyTopicSub"]
    param, ref, getatt_topicname, getatt_topicarn = sub_output.split("|")
    assert param == topic_name
    assert ref == topic_arn
    assert getatt_topicname == topic_name
    assert getatt_topicarn == topic_arn

    map_sub_output = deployment.outputs["MyTopicSubWithMap"]
    att_in_map, ref_in_map, static_in_map = map_sub_output.split("|")
    assert att_in_map == topic_name
    assert ref_in_map == topic_arn
    assert static_in_map == "something"

    # Verify resource was created
    topic_arns = [t["TopicArn"] for t in aws_client.sns.list_topics()["Topics"]]
    assert topic_arn in topic_arns


@markers.aws.only_localstack
def test_reference_unsupported_resource(deploy_cfn_template, aws_client):
    """
    This test verifies that templates can be deployed even when unsupported resources are references
    Make sure to update the template as coverage of resources increases.
    """

    deployment = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cfn_ref_unsupported.yml"
        ),
    )

    ref_of_unsupported = deployment.outputs["reference"]
    value_of_unsupported = deployment.outputs["parameter"]
    assert ref_of_unsupported == MOCK_REFERENCE
    assert value_of_unsupported == f"The value of the attribute is: {MOCK_REFERENCE}"


@markers.aws.validated
@skip_if_legacy_engine()
def test_redeploy_cdk_with_reference(
    aws_client, account_id, create_lambda_function, deploy_cfn_template, snapshot, cleanups
):
    """
    Test a user scenario with a lambda function that fails to redeploy

    """
    # perform cdk bootstrap
    template_file = os.path.join(
        os.path.dirname(__file__), "../../../templates/cdk_bootstrap_v28.yaml"
    )
    qualifier = short_uid()
    bootstrap_stack = deploy_cfn_template(
        template_path=template_file,
        parameters={
            "CloudFormationExecutionPolicies": "",
            "FileAssetsBucketKmsKeyId": "AWS_MANAGED_KEY",
            "PublicAccessBlockConfiguration": "true",
            "TrustedAccounts": "",
            "TrustedAccountsForLookup": "",
            "Qualifier": qualifier,
        },
    )

    lambda_bucket = bootstrap_stack.outputs["BucketName"]

    # upload the lambda function
    lambda_src_1 = """
    def handler(event, context):
        return {"status": "ok"}
    """
    lambda_src_2 = """
    def handler(event, context):
        return {"status": "foo"}
    """

    function_name = f"function-{short_uid()}"
    cleanups.append(lambda: aws_client.lambda_.delete_function(FunctionName=function_name))

    def deploy_or_update_lambda(content: str, lambda_key: str):
        archive = testutil.create_lambda_archive(content)
        with open(archive, "rb") as infile:
            aws_client.s3.put_object(Bucket=lambda_bucket, Key=lambda_key, Body=infile)

        lambda_exists = False
        try:
            aws_client.lambda_.get_function(FunctionName=function_name)
            lambda_exists = True
        except Exception:
            # TODO: work out the proper exception
            pass

        if lambda_exists:
            aws_client.lambda_.update_function_code(
                FunctionName=function_name,
                S3Bucket=lambda_bucket,
                S3Key=lambda_key,
            )
        else:
            aws_client.lambda_.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Handler="handler",
                Code={
                    "S3Bucket": lambda_bucket,
                    "S3Key": lambda_key,
                },
                # The role does not matter
                Role=f"arn:aws:iam::{account_id}:role/LambdaExecutionRole",
            )
        aws_client.lambda_.get_waiter("function_active_v2").wait(FunctionName=function_name)

    lambda_key_1 = f"{short_uid()}.zip"
    deploy_or_update_lambda(lambda_src_1, lambda_key_1)

    # deploy the template the first time
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cdk-lambda-redeploy.json"
        ),
        parameters={
            "DeployBucket": lambda_bucket,
            "DeployKey": lambda_key_1,
            "BootstrapVersion": f"/cdk-bootstrap/{qualifier}/version",
        },
    )

    lambda_key_2 = f"{short_uid()}.zip"
    deploy_or_update_lambda(lambda_src_2, lambda_key_2)

    # deploy the template the second time
    deploy_cfn_template(
        stack_name=stack.stack_id,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/cdk-lambda-redeploy.json"
        ),
        is_update=True,
        parameters={
            "DeployBucket": lambda_bucket,
            "DeployKey": lambda_key_2,
            "BootstrapVersion": "28",
        },
    )
