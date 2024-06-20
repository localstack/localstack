import json
import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@markers.aws.validated
def test_bucketpolicy(deploy_cfn_template, aws_client, snapshot):
    snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
    bucket_name = f"ls-bucket-{short_uid()}"
    snapshot.match("bucket", {"BucketName": bucket_name})
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucketpolicy.yaml"
        ),
        parameters={"BucketName": bucket_name},
        template_mapping={"include_policy": True},
    )
    response = aws_client.s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
    snapshot.match("get-policy-true", response)

    deploy_cfn_template(
        is_update=True,
        stack_name=deploy_result.stack_id,
        parameters={"BucketName": bucket_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucketpolicy.yaml"
        ),
        template_mapping={"include_policy": False},
    )
    with pytest.raises(ClientError) as err:
        aws_client.s3.get_bucket_policy(Bucket=bucket_name)
    snapshot.match("no-policy", err.value.response)


@markers.aws.validated
def test_bucket_autoname(deploy_cfn_template, aws_client):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucket_autoname.yaml"
        )
    )
    descr_response = aws_client.cloudformation.describe_stacks(StackName=result.stack_id)
    output = descr_response["Stacks"][0]["Outputs"][0]
    assert output["OutputKey"] == "BucketNameOutput"
    assert result.stack_name.lower() in output["OutputValue"]


@markers.aws.validated
def test_bucket_versioning(deploy_cfn_template, aws_client):
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_versioned_bucket.yaml"
        )
    )
    assert "BucketName" in result.outputs
    bucket_name = result.outputs["BucketName"]
    bucket_version = aws_client.s3.get_bucket_versioning(Bucket=bucket_name)
    assert bucket_version["Status"] == "Enabled"


@markers.aws.validated
def test_website_configuration(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.s3_api())

    bucket_name_generated = f"ls-bucket-{short_uid()}"

    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucket_website_config.yaml"
        ),
        parameters={"BucketName": bucket_name_generated},
    )

    bucket_name = result.outputs["BucketNameOutput"]
    assert bucket_name_generated == bucket_name
    website_url = result.outputs["WebsiteURL"]
    assert website_url.startswith(f"http://{bucket_name}.s3-website")
    response = aws_client.s3.get_bucket_website(Bucket=bucket_name)

    snapshot.match("get_bucket_website", response)


@markers.aws.validated
def test_cors_configuration(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.s3_api())

    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_cors_bucket.yaml"
        ),
    )
    bucket_name_optional = result.outputs["BucketNameAllParameters"]
    cors_info = aws_client.s3.get_bucket_cors(Bucket=bucket_name_optional)
    snapshot.match("cors-info-optional", cors_info)

    bucket_name_required = result.outputs["BucketNameOnlyRequired"]
    cors_info = aws_client.s3.get_bucket_cors(Bucket=bucket_name_required)
    snapshot.match("cors-info-only-required", cors_info)


@markers.aws.validated
def test_object_lock_configuration(deploy_cfn_template, snapshot, aws_client):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.s3_api())

    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_object_lock_config.yaml"
        ),
    )
    bucket_name_optional = result.outputs["LockConfigAllParameters"]
    cors_info = aws_client.s3.get_object_lock_configuration(Bucket=bucket_name_optional)
    snapshot.match("object-lock-info-with-configuration", cors_info)

    bucket_name_required = result.outputs["LockConfigOnlyRequired"]
    cors_info = aws_client.s3.get_object_lock_configuration(Bucket=bucket_name_required)
    snapshot.match("object-lock-info-only-enabled", cors_info)


@markers.aws.validated
def test_cfn_handle_s3_notification_configuration(
    aws_client,
    deploy_cfn_template,
    snapshot,
):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_notification_sqs.yml"
        ),
    )
    rs = aws_client.s3.get_bucket_notification_configuration(Bucket=stack.outputs["BucketName"])
    snapshot.match("get_bucket_notification_configuration", rs)

    stack.destroy()

    with pytest.raises(ClientError) as ctx:
        aws_client.s3.get_bucket_notification_configuration(Bucket=stack.outputs["BucketName"])
    snapshot.match("get_bucket_notification_configuration_error", ctx.value.response)

    snapshot.add_transformer(snapshot.transform.key_value("Id"))
    snapshot.add_transformer(snapshot.transform.key_value("QueueArn"))
    snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
