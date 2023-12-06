import os

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@markers.aws.needs_fixing
def test_nested_stack(deploy_cfn_template, s3_create_bucket, aws_client):
    # upload template to S3
    artifacts_bucket = f"cf-artifacts-{short_uid()}"
    artifacts_path = "stack.yaml"
    s3_create_bucket(Bucket=artifacts_bucket, ACL="public-read")
    aws_client.s3.put_object(
        Bucket=artifacts_bucket,
        Key=artifacts_path,
        Body=load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/template5.yaml")
        ),
    )

    # deploy template
    param_value = short_uid()
    stack_bucket_name = f"test-{param_value}"  # this is the bucket name generated by template5

    deploy_cfn_template(
        template=load_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/template6.yaml")
        )
        % (artifacts_bucket, artifacts_path),
        parameters={"GlobalParam": param_value},
    )

    # assert that nested resources have been created
    def assert_bucket_exists():
        response = aws_client.s3.head_bucket(Bucket=stack_bucket_name)
        assert 200 == response["ResponseMetadata"]["HTTPStatusCode"]

    retry(assert_bucket_exists)


@markers.aws.validated
def test_nested_stack_output_refs(deploy_cfn_template, s3_create_bucket, aws_client):
    """test output handling of nested stacks incl. referencing the nested output in the parent stack"""
    bucket_name = s3_create_bucket()
    nested_bucket_name = f"test-bucket-nested-{short_uid()}"
    key = f"test-key-{short_uid()}"
    aws_client.s3.upload_file(
        os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-output-refs.nested.yaml"
        ),
        Bucket=bucket_name,
        Key=key,
    )
    result = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-output-refs.yaml"
        ),
        template_mapping={
            "s3_bucket_url": f"/{bucket_name}/{key}",
            "nested_bucket_name": nested_bucket_name,
        },
        max_wait=120,  # test is flaky, so we need to wait a bit longer
    )

    nested_stack_id = result.outputs["CustomNestedStackId"]
    nested_stack_details = aws_client.cloudformation.describe_stacks(StackName=nested_stack_id)
    nested_stack_outputs = nested_stack_details["Stacks"][0]["Outputs"]
    assert "InnerCustomOutput" not in result.outputs
    assert (
        nested_bucket_name
        == [
            o["OutputValue"] for o in nested_stack_outputs if o["OutputKey"] == "InnerCustomOutput"
        ][0]
    )
    assert f"{nested_bucket_name}-suffix" == result.outputs["CustomOutput"]


@pytest.mark.skip(reason="Nested stacks don't work properly")
@markers.aws.validated
def test_nested_with_nested_stack(deploy_cfn_template, s3_create_bucket, aws_client):
    bucket_name = s3_create_bucket()
    bucket_to_create_name = f"test-bucket-{short_uid()}"
    domain = "amazonaws.com" if is_aws_cloud() else "localhost.localstack.cloud:4566"

    nested_stacks = ["nested_child.yml", "nested_parent.yml"]
    urls = []

    for nested_stack in nested_stacks:
        aws_client.s3.upload_file(
            os.path.join(os.path.dirname(__file__), "../../../templates/", nested_stack),
            Bucket=bucket_name,
            Key=nested_stack,
        )

        urls.append(f"https://{bucket_name}.s3.{domain}/{nested_stack}")

    outputs = deploy_cfn_template(
        max_wait=120 if is_aws_cloud() else None,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/nested_grand_parent.yml"
        ),
        parameters={
            "ChildStackURL": urls[0],
            "ParentStackURL": urls[1],
            "BucketToCreate": bucket_to_create_name,
        },
    ).outputs

    assert f"arn:aws:s3:::{bucket_to_create_name}" == outputs["parameterValue"]


@markers.aws.validated
@pytest.mark.skip(reason="UPDATE isn't working on nested stacks")
def test_lifecycle_nested_stack(deploy_cfn_template, s3_create_bucket, aws_client):
    bucket_name = s3_create_bucket()
    nested_bucket_name = f"test-bucket-nested-{short_uid()}"
    altered_nested_bucket_name = f"test-bucket-nested-{short_uid()}"
    key = f"test-key-{short_uid()}"

    aws_client.s3.upload_file(
        os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-output-refs.nested.yaml"
        ),
        Bucket=bucket_name,
        Key=key,
    )

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-output-refs.yaml"
        ),
        template_mapping={
            "s3_bucket_url": f"/{bucket_name}/{key}",
            "nested_bucket_name": nested_bucket_name,
        },
    )
    assert aws_client.s3.head_bucket(Bucket=nested_bucket_name)

    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-output-refs.yaml"
        ),
        template_mapping={
            "s3_bucket_url": f"/{bucket_name}/{key}",
            "nested_bucket_name": altered_nested_bucket_name,
        },
        max_wait=120 if is_aws_cloud() else None,
    )

    assert aws_client.s3.head_bucket(Bucket=altered_nested_bucket_name)

    stack.destroy()

    def _assert_bucket_is_deleted():
        try:
            aws_client.s3.head_bucket(Bucket=altered_nested_bucket_name)
            return False
        except ClientError:
            return True

    retry(_assert_bucket_is_deleted, retries=5, sleep=2, sleep_before=2)


@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..Role.Description",
        "$..Role.MaxSessionDuration",
        "$..Role.AssumeRolePolicyDocument..Action",
    ]
)
@markers.aws.validated
def test_nested_output_in_params(deploy_cfn_template, s3_create_bucket, snapshot, aws_client):
    """
    Deploys a Stack with two nested stacks (sub1 and sub2) with a dependency between each other sub2 depends on sub1.
    The `sub2` stack uses an output parameter of `sub1` as an input parameter.

    Resources:
        - Stack
        - 2x Nested Stack
        - SNS Topic
        - IAM role with policy (sns:Publish)

    """
    # upload template to S3 for nested stacks
    template_bucket = f"cfn-root-{short_uid()}"
    sub1_path = "sub1.yaml"
    sub2_path = "sub2.yaml"
    s3_create_bucket(Bucket=template_bucket, ACL="public-read")
    aws_client.s3.put_object(
        Bucket=template_bucket,
        Key=sub1_path,
        Body=load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/nested-stack-outputref/sub1.yaml"
            )
        ),
    )
    aws_client.s3.put_object(
        Bucket=template_bucket,
        Key=sub2_path,
        Body=load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/nested-stack-outputref/sub2.yaml"
            )
        ),
    )
    topic_name = f"test-topic-{short_uid()}"
    role_name = f"test-role-{short_uid()}"

    if os.environ.get("TEST_TARGET") == "AWS_CLOUD":
        base_path = "https://s3.amazonaws.com"
    else:
        base_path = "http://localhost:4566"

    deploy_cfn_template(
        template=load_file(
            os.path.join(
                os.path.dirname(__file__), "../../../templates/nested-stack-outputref/root.yaml"
            )
        ),
        parameters={
            "Sub1TemplateUrl": f"{base_path}/{template_bucket}/{sub1_path}",
            "Sub2TemplateUrl": f"{base_path}/{template_bucket}/{sub2_path}",
            "TopicName": topic_name,
            "RoleName": role_name,
        },
    )
    # validations
    snapshot.add_transformer(snapshot.transform.key_value("RoleId", "role-id"))
    snapshot.add_transformer(snapshot.transform.regex(topic_name, "<topic>"))
    snapshot.add_transformer(snapshot.transform.regex(role_name, "<role-name>"))

    snapshot.add_transformer(snapshot.transform.cloudformation_api())

    get_role_response = aws_client.iam.get_role(RoleName=role_name)
    snapshot.match("get_role_response", get_role_response)
    role_policies = aws_client.iam.list_role_policies(RoleName=role_name)
    snapshot.match("role_policies", role_policies)
    policy_name = role_policies["PolicyNames"][0]
    actual_policy = aws_client.iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
    snapshot.match("actual_policy", actual_policy)

    sns_pager = aws_client.sns.get_paginator("list_topics")
    topics = sns_pager.paginate().build_full_result()["Topics"]
    filtered_topics = [t["TopicArn"] for t in topics if topic_name in t["TopicArn"]]
    assert len(filtered_topics) == 1


@markers.aws.validated
def test_nested_stacks_conditions(deploy_cfn_template, s3_create_bucket, aws_client):
    """
    see: TestCloudFormationConditions.test_condition_on_outputs

    equivalent to the condition test but for a nested stack
    """
    bucket_name = s3_create_bucket()
    nested_bucket_name = f"test-bucket-nested-{short_uid()}"
    key = f"test-key-{short_uid()}"

    aws_client.s3.upload_file(
        os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-conditions.nested.yaml"
        ),
        Bucket=bucket_name,
        Key=key,
    )

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/nested-stack-conditions.yaml"
        ),
        template_mapping={
            "s3_bucket_url": f"/{bucket_name}/{key}",
            "s3_bucket_name": nested_bucket_name,
        },
    )

    assert stack.outputs["ProdBucket"] == f"{nested_bucket_name}-prod"
    assert aws_client.s3.head_bucket(Bucket=stack.outputs["ProdBucket"])
