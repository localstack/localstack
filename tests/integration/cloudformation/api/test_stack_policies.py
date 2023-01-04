import json
import os

import botocore.exceptions
import pytest
import yaml

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry


def get_events_canceled_by_policy(cfn_client, stack_name):
    events = cfn_client.describe_stack_events(StackName=stack_name)["StackEvents"]

    failed_events_by_policy = [
        event
        for event in events
        if "ResourceStatusReason" in event
        and (
            "Action denied by stack policy" in event["ResourceStatusReason"]
            or "Action not allowed by stack policy" in event["ResourceStatusReason"]
            or "Resource update cancelled" in event["ResourceStatusReason"]
        )
    ]

    return failed_events_by_policy


def delete_stack_after_process(cfn_client, stack_name):
    progress_is_finished = False
    while not progress_is_finished:
        status = cfn_client.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        progress_is_finished = "PROGRESS" not in status
    cfn_client.delete_stack(StackName=stack_name)


class TestStackPolicy:
    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_policy_lifecycle(self, cfn_client, deploy_cfn_template, snapshot):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/sns_topic_simple.yaml"
            ),
        )

        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("initial_policy", obtained_policy)

        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}
            ]
        }
        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))
        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("policy", obtained_policy)

        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}
            ]
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
        self, deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
    ):
        """Test to validate the setting of a Stack Policy through an URL"""
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
        self, deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
    ):
        """Test to validate the error response resulting of setting an invalid Stack Policy through an URL"""
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
        self, deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
    ):
        """Test to validate the setting of an empty Stack Policy through an URL"""
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
        self, deploy_cfn_template, cfn_client, s3_client, s3_create_bucket, snapshot
    ):

        """Test to validate the API behavior when trying to set a Stack policy using both the body and the URL"""

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
            "Statement": [
                {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}
            ]
        }

        with pytest.raises(botocore.exceptions.ClientError) as ex:
            cfn_client.set_stack_policy(
                StackName=stack.stack_name, StackPolicyBody=json.dumps(policy), StackPolicyURL=url
            )

        error_response = ex.value.response
        snapshot.match("error", error_response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_empty_policy(self, cfn_client, deploy_cfn_template, snapshot):
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
    def test_not_json_policy(self, cfn_client, deploy_cfn_template, snapshot):
        """Test to validate the error response when setting and Invalid Policy"""
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/stack_policy_test.yaml"
            ),
            parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
        )

        with pytest.raises(botocore.exceptions.ClientError) as ex:
            cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=short_uid())

        error_response = ex.value.response
        snapshot.match("error", error_response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_different_principal_attribute(self, cfn_client, deploy_cfn_template, snapshot):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
            ),
            parameters={"TopicName": f"topic-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "Update:*",
                    "Principal": short_uid(),
                    "Resource": "*",
                }
            ]
        }
        with pytest.raises(botocore.exceptions.ClientError) as ex:
            cfn_client.set_stack_policy(
                StackName=stack.stack_name, StackPolicyBody=json.dumps(policy)
            )

        error_response = ex.value.response["Error"]
        snapshot.match("error", error_response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_different_action_attribute(self, cfn_client, deploy_cfn_template, snapshot):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml"
            ),
            parameters={"TopicName": f"topic-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "Delete:*",
                    "Principal": short_uid(),
                    "Resource": "*",
                }
            ]
        }
        with pytest.raises(botocore.exceptions.ClientError) as ex:
            cfn_client.set_stack_policy(
                StackName=stack.stack_name, StackPolicyBody=json.dumps(policy)
            )

        error_response = ex.value.response
        snapshot.match("error", error_response)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    @pytest.mark.parametrize("resource_type", ["AWS::S3::Bucket", "AWS::SNS::Topic"])
    def test_prevent_update(self, resource_type, cfn_client, deploy_cfn_template):
        """
        Test to validate the correct behavior of the update operation on a Stack with a Policy that prevents an update
        for a specific resource type
        """
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
            # if the policy prevents one resource to update the whole update fails
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        try:
            retry(_assert_failing_update_state, retries=5, sleep=2, sleep_before=2)
        finally:
            delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    @pytest.mark.parametrize(
        "resource",
        [
            {"id": "bucket123", "type": "AWS::S3::Bucket"},
            {"id": "topic123", "type": "AWS::SNS::Topic"},
        ],
    )
    def test_prevent_deletion(self, resource, cfn_client, deploy_cfn_template):
        """
        Test to validate that CFn won't delete resources during an update operation that are protected by the Stack
        Policy
        """
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
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        try:
            retry(_assert_failing_update_state, retries=6, sleep=2, sleep_before=2)
        finally:
            delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_prevent_modifying_with_policy_specifying_resource_id(
        self, deploy_cfn_template, cfn_client
    ):
        """
        Test to validate that CFn won't modify a resource protected by a stack policy that specifies the resource
        using the logical Resource Id
        """
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")
        )
        stack = deploy_cfn_template(
            template=template,
            parameters={"ApiName": f"api-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "Update:Modify",
                    "Principal": "*",
                    "Resource": "LogicalResourceId/Api",
                }
            ]
        }

        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

        cfn_client.update_stack(
            TemplateBody=template,
            StackName=stack.stack_name,
            Parameters=[
                {"ParameterKey": "ApiName", "ParameterValue": f"new-api-{short_uid()}"},
            ],
        )

        def _assert_failing_update_state():
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        try:
            retry(_assert_failing_update_state, retries=6, sleep=2, sleep_before=2)
        finally:
            delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_prevent_replacement(self, deploy_cfn_template, cfn_client):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
        )

        stack = deploy_cfn_template(
            template=template,
            parameters={"TopicName": f"topic-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "Update:Replace",
                    "Principal": "*",
                    "Resource": "*",
                }
            ]
        }

        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": f"bucket-{short_uid()}"},
            ],
        )

        def _assert_failing_update_state():
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        try:
            retry(_assert_failing_update_state, retries=6, sleep=2, sleep_before=2)
        finally:
            delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_update_with_policy(self, deploy_cfn_template, cfn_client):
        """
        Test to validate the completion of a stack update that is allowed by the Stack Policy
        """
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

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_update_with_empty_policy(self, deploy_cfn_template, cfn_client, is_stack_updated):
        """
        Test to validate the behavior of a stack update that has an empty Stack Policy
        """
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/stack_policy_test.yaml")
        )
        stack = deploy_cfn_template(
            template=template,
            parameters={"TopicName": f"topic-{short_uid()}", "BucketName": f"bucket-{short_uid()}"},
        )
        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody="{}")

        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"},
                {"ParameterKey": "BucketName", "ParameterValue": f"new-bucket-{short_uid()}"},
            ],
        )

        def _assert_stack_is_updated():
            assert is_stack_updated(stack.stack_name)

        retry(_assert_stack_is_updated, retries=5, sleep=2, sleep_before=1)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    @pytest.mark.parametrize("reverse_statements", [False, True])
    def test_update_with_overlapping_policies(
        self, reverse_statements, deploy_cfn_template, cfn_client, is_stack_updated
    ):
        """
        This test validates the behaviour when two statements in  policy contradict each other.
        According to the AWS triage, the last statement is the one that is followed.
        """
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
        )
        stack = deploy_cfn_template(
            template=template,
            parameters={"TopicName": f"topic-{short_uid()}"},
        )

        statements = [
            {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
        ]

        if reverse_statements:
            statements.reverse()

        policy = {"Statement": statements}

        cfn_client.set_stack_policy(StackName=stack.stack_name, StackPolicyBody=json.dumps(policy))

        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"},
            ],
        )

        def _assert_stack_is_updated():
            assert is_stack_updated(stack.stack_name)

        def _assert_failing_update_state():
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        retry(
            _assert_stack_is_updated if not reverse_statements else _assert_failing_update_state,
            retries=5,
            sleep=2,
            sleep_before=2,
        )

        delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_create_stack_with_policy(self, cfn_client, snapshot, cleanup_stacks):
        stack_name = f"stack-{short_uid()}"

        policy = {
            "Statement": [
                {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            ]
        }

        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/sns_topic_parameter.yml")
        )

        cfn_client.create_stack(
            StackName=stack_name,
            StackPolicyBody=json.dumps(policy),
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "TopicName", "ParameterValue": f"new-topic-{short_uid()}"}
            ],
        )

        obtained_policy = cfn_client.get_stack_policy(StackName=stack_name)
        snapshot.match("policy", obtained_policy)
        cleanup_stacks([stack_name])

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_set_policy_with_update_operation(
        self, cfn_client, deploy_cfn_template, is_stack_updated, snapshot, cleanup_stacks
    ):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")
        )
        stack = deploy_cfn_template(
            template=template,
            parameters={"ApiName": f"api-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            ]
        }

        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "ApiName", "ParameterValue": f"api-{short_uid()}"},
            ],
            StackPolicyBody=json.dumps(policy),
        )

        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("policy", obtained_policy)

        # This part makes sure that the policy being set during the last update doesn't affect the requested changes
        def _assert_stack_is_updated():
            assert is_stack_updated(stack.stack_name)

        retry(_assert_stack_is_updated, retries=5, sleep=2, sleep_before=1)

        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("policy_after_update", obtained_policy)

        delete_stack_after_process(cfn_client, stack.stack_name)

    @pytest.mark.aws_validated
    @pytest.mark.skip(reason="Not implemented")
    def test_policy_during_update(
        self, cfn_client, deploy_cfn_template, is_stack_updated, snapshot, cleanup_stacks
    ):
        template = load_file(
            os.path.join(os.path.dirname(__file__), "../../templates/simple_api.yaml")
        )
        stack = deploy_cfn_template(
            template=template,
            parameters={"ApiName": f"api-{short_uid()}"},
        )

        policy = {
            "Statement": [
                {"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            ]
        }

        cfn_client.update_stack(
            StackName=stack.stack_name,
            TemplateBody=template,
            Parameters=[
                {"ParameterKey": "ApiName", "ParameterValue": f"api-{short_uid()}"},
            ],
            StackPolicyDuringUpdateBody=json.dumps(policy),
        )

        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("policy_during_update", obtained_policy)

        def _assert_update_failed():
            assert get_events_canceled_by_policy(cfn_client, stack.stack_name)

        retry(_assert_update_failed, retries=5, sleep=2, sleep_before=1)

        obtained_policy = cfn_client.get_stack_policy(StackName=stack.stack_name)
        snapshot.match("policy_after_update", obtained_policy)

        delete_stack_after_process(cfn_client, stack.stack_name)
