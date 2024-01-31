import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@markers.aws.unknown
def test_bucketpolicy(deploy_cfn_template, aws_client):
    bucket_name = f"ls-bucket-{short_uid()}"
    deploy_result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucketpolicy.yaml"
        ),
        parameters={"BucketName": bucket_name},
        template_mapping={"include_policy": True},
    )
    bucket_policy = aws_client.s3.get_bucket_policy(Bucket=bucket_name)["Policy"]
    assert bucket_policy

    deploy_cfn_template(
        is_update=True,
        stack_name=deploy_result.stack_id,
        parameters={"BucketName": bucket_name},
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/s3_bucketpolicy.yaml"
        ),
        template_mapping={"include_policy": False},
    )
    with pytest.raises(Exception) as err:
        aws_client.s3.get_bucket_policy(Bucket=bucket_name).get("Policy")

    assert err.value.response["Error"]["Code"] == "NoSuchBucketPolicy"


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


@markers.aws.unknown
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
