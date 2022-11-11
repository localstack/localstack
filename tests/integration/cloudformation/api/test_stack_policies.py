import json
import os

import botocore.exceptions
import pytest

from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


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


# @pytest.mark.parametrize("resource_type, resource_id", ["AWS::S3::Bucket", "AWS::SNS::Topic"], ["bucket123", "topic123"])
# def test_delete_by_type(resource_type, resource_id, cfn_client, deploy_cfn_template):
#     template = load_file(
#         os.path.join(os.path.dirname(__file__), "../../templates/stack_policy_test.yaml")
#     )
#     stack = deploy_cfn_template(
#         template=template,
#         parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
#     )
#     policy = {
#         "Statement": [
#             {
#                 "Effect": "Deny",
#                 "Action": "Update:*",
#                 "Principal": "*",
#                 "Resource": "*",
#                 "Condition": {"StringEquals": {"ResourceType": [resource_type]}},
#             }
#         ]
#     }
#     cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
#
#     cfn_client.update_stack(
#         StackName=stack.stack_name,
#         TemplateBody=template,
#     )
#
#
#     def _assert_failing_update_state():
#         events = cfn_client.describe_stack_events(StackName=stack.stack_name)["StackEvents"]
#         failed_event_update = [
#             event for event in events if event["ResourceStatus"] == "UPDATE_FAILED"
#         ]
#         assert failed_event_update
#         assert "Action denied by stack policy" in failed_event_update[0]["ResourceStatusReason"]
#
#     try:
#         retry(_assert_failing_update_state, retries=5, sleep=2, sleep_before=2)
#     finally:
#         progress_is_finished = False
#         while not progress_is_finished:
#             status = cfn_client.describe_stacks(StackName=stack.stack_name)["Stacks"][0][
#                 "StackStatus"
#             ]
#             progress_is_finished = "PROGRESS" not in status
#         cfn_client.delete_stack(StackName=stack.stack_name)
