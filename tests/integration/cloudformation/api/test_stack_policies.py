import json
import os

import botocore.exceptions
import pytest
import yaml

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_policy_lifecycle(cfn_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        ),
    )
    policy = {
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
    obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy", obtained_policy)

    policy = {
        "Statement": [{"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
    obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy_updated", obtained_policy)

    policy = {}
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
    obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy_deleted", obtained_policy)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_set_policy_with_url(
    deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        ),
    )
    bucket_name = s3_create_bucket()
    key = "policy.json"
    domain = "amazonaws.com" if is_aws_cloud() else "localhost.localstack.cloud:4566"

    s3_client.upload_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_policy.json"),
        Bucket=bucket_name,
        Key=key,
    )

    url = f"https://{bucket_name}.s3.{domain}/{key}"

    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyURL=url)
    obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy", obtained_policy)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_set_invalid_policy_with_url(
    deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        ),
    )
    bucket_name = s3_create_bucket()
    key = "policy.json"
    domain = "amazonaws.com" if is_aws_cloud() else "localhost.localstack.cloud:4566"

    s3_client.upload_file(
        os.path.join(os.path.dirname(__file__), "../../templates/invalid_stack_policy.json"),
        Bucket=bucket_name,
        Key=key,
    )

    url = f"https://{bucket_name}.s3.{domain}/{key}"

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyURL=url)

    error_response = ex.value.response
    snapshot.match("error", error_response)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_set_empty_policy_with_url(
    deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        ),
    )
    bucket_name = s3_create_bucket()
    key = "policy.json"
    domain = "amazonaws.com" if is_aws_cloud() else "localhost.localstack.cloud:4566"

    s3_client.upload_file(
        os.path.join(os.path.dirname(__file__), "../../templates/empty_policy.json"),
        Bucket=bucket_name,
        Key=key,
    )

    url = f"https://{bucket_name}.s3.{domain}/{key}"

    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyURL=url)
    obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy", obtained_policy)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_set_policy_both_policy_and_url(
    deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
        ),
    )

    domain = "amazonaws.com" if is_aws_cloud() else "localhost.localstack.cloud:4566"
    bucket_name = s3_create_bucket()
    key = "policy.json"

    s3_client.upload_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_policy.json"),
        Bucket=bucket_name,
        Key=key,
    )

    url = f"https://{bucket_name}.s3.{domain}/{key}"

    policy = {
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.set_stack_policy(
            StackName=stack.stack_name, StackPolicyBody=json.dumps(policy), StackPolicyURL=url
        )

    error_response = ex.value.response
    snapshot.match("error", error_response)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_empty_policy(cfn_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/stack_policy_test.yaml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )
    policy = {}

    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

    policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
    snapshot.match("policy", policy)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_invalid_policy(cfn_client, deploy_cfn_template):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/stack_policy_test.yaml"
        ),
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )

    with pytest.raises(botocore.exceptions.ClientError) as ex:
        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=short_uid())

    error_response = ex.value.response["Error"]
    assert error_response["Code"] == "ValidationError"
    assert "Error validating stack policy: Invalid stack policy" in error_response["Message"]


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
@pytest.mark.parametrize("resource_type", ["AWS::S3::Bucket", "AWS::SNS::Topic"])
def test_prevent_update(resource_type, cfn_client, deploy_cfn_template):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_policy_test.yaml")
    )
    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"ResourceType": [resource_type]}},
            },
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        ]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"},
            {"ParameterKey": "BucketName", "ParameterValue": f"new-bucket-{short_uid()}"},
        ],
    )

    def _assert_failing_update_state():
        events = cfn_client.describe_stack_events(StackName=stack.stack_name)["StackEvents"]
        failed_event_updates = [
            event for event in events if event["ResourceStatus"] == "UPDATE_FAILED"
        ]
        assert failed_event_updates
        for failed_event_update in failed_event_updates:
            failed_by_policy = (
                "Action denied by stack policy" in failed_event_update["ResourceStatusReason"]
                or "Action not allowed by stack policy"
                in failed_event_update["ResourceStatusReason"]
            ) and failed_event_update["ResourceType"] == resource_type
            failed_by_collateral = (
                "Resource update cancelled" in failed_event_update["ResourceStatusReason"]
            )

            # if the policy prevents one resource to update the whole update fails
            assert failed_by_policy or failed_by_collateral

    try:
        retry(_assert_failing_update_state, retries=5, sleep=2, sleep_before=2)
    finally:
        progress_is_finished = False
        while not progress_is_finished:
            status = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
                "StackStatus"
            ]
            progress_is_finished = "PROGRESS" not in status
        cfn_client.delete_stack(StackName=stack.stack_name)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
@pytest.mark.parametrize(
    "resource",
    [{"id": "bucket123", "type": "AWS::S3::Bucket"}, {"id": "topic123", "type": "AWS::SNS::Topic"}],
)
def test_prevent_deletion(resource, cfn_client, deploy_cfn_template):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_policy_test.yaml")
    )
    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "Update:Delete",
                "Principal": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"ResourceType": [resource["type"]]}},
            }
        ]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

    template_dict = yaml.load(template)
    del template_dict["Resources"][resource["id"]]
    template = yaml.dump(template_dict)

    cfn_client.update_stack(
        StackName=stack.stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"},
            {"ParameterKey": "BucketName", "ParameterValue": f"new-bucket-{short_uid()}"},
        ],
    )

    def _assert_failing_update_state():
        events = cfn_client.describe_stack_events(StackName=stack.stack_name)["StackEvents"]
        failed_event_update = [
            event
            for event in events
            if "ResourceStatusReason" in event
            and "Action denied by stack policy" in event["ResourceStatusReason"]
        ]
        assert failed_event_update

    try:
        retry(_assert_failing_update_state, retries=6, sleep=2, sleep_before=2)
    finally:
        progress_is_finished = False
        while not progress_is_finished:
            status = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
                "StackStatus"
            ]
            progress_is_finished = "PROGRESS" not in status
        cfn_client.delete_stack(StackName=stack.stack_name)


@pytest.mark.aws_validated
@pytest.mark.skip(reason="Not implemented")
def test_update_with_policy(deploy_cfn_template, cfn_client):
    template = load_file(
        os.path.join(os.path.dirname(__file__), "../../templates/stack_policy_test.yaml")
    )
    stack = deploy_cfn_template(
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )
    policy = {
        "Statement": [
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "*",
                "Condition": {"StringEquals": {"ResourceType": ["AWS::EC2::Subnet"]}},
            },
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        ]
    }
    cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
    deploy_cfn_template(
        is_update=True,
        stack_name=stack.stack_name,
        template=template,
        parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
    )
