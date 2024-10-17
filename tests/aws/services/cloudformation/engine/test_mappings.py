import os

import pytest

from localstack.testing.pytest import markers
from localstack.utils.files import load_file
from localstack.utils.strings import short_uid

THIS_DIR = os.path.dirname(__file__)


@markers.snapshot.skip_snapshot_verify
class TestCloudFormationMappings:
    @markers.aws.validated
    def test_simple_mapping_working(self, aws_client, deploy_cfn_template):
        """
        A very simple test to deploy a resource with a name depending on a value that needs to be looked up from the mapping
        """
        topic_name = f"test-topic-{short_uid()}"
        deployment = deploy_cfn_template(
            template_path=os.path.join(THIS_DIR, "../../../templates/mappings/simple-mapping.yaml"),
            parameters={
                "TopicName": topic_name,
                "TopicNameSuffixSelector": "A",
            },
        )
        # verify that CloudFormation includes the resource
        stack_resources = aws_client.cloudformation.describe_stack_resources(
            StackName=deployment.stack_id
        )
        assert stack_resources["StackResources"]

        expected_topic_name = f"{topic_name}-suffix-a"

        # verify actual resource deployment
        assert [
            t
            for t in aws_client.sns.get_paginator("list_topics")
            .paginate()
            .build_full_result()["Topics"]
            if expected_topic_name in t["TopicArn"]
        ]

    @markers.aws.validated
    @pytest.mark.skip(reason="not implemented")
    def test_mapping_with_nonexisting_key(self, aws_client, cleanups, snapshot):
        """
        Tries to deploy a resource with a dependency on a mapping key
        which is not included in the Mappings section and thus can't be resolved
        """
        topic_name = f"test-topic-{short_uid()}"
        stack_name = f"test-stack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        template_body = load_file(
            os.path.join(THIS_DIR, "../../../templates/mappings/simple-mapping.yaml")
        )

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName="initial",
                TemplateBody=template_body,
                ChangeSetType="CREATE",
                Parameters=[
                    {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                    {"ParameterKey": "TopicNameSuffixSelector", "ParameterValue": "C"},
                ],
            )
        snapshot.match("mapping_nonexisting_key_exc", e.value.response)

    @markers.aws.validated
    @pytest.mark.skip(reason="not implemented")
    def test_mapping_with_invalid_refs(self, aws_client, deploy_cfn_template, cleanups, snapshot):
        """
        The Mappings section can only include static elements (strings and lists).
        In this test one value is instead a `Ref` which should be rejected by the service

        Also note the overlap with the `test_mapping_with_nonexisting_key` case here.
        Even though we specify a non-existing key here again (`C`), the returned error is for the invalid structure.
        """
        topic_name = f"test-topic-{short_uid()}"
        stack_name = f"test-stack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        template_body = load_file(
            os.path.join(THIS_DIR, "../../../templates/mappings/simple-mapping-invalid-ref.yaml")
        )

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName="initial",
                TemplateBody=template_body,
                ChangeSetType="CREATE",
                Parameters=[
                    {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                    {"ParameterKey": "TopicNameSuffixSelector", "ParameterValue": "C"},
                    {"ParameterKey": "TopicNameSuffix", "ParameterValue": "suffix-c"},
                ],
            )
        snapshot.match("mapping_invalid_ref_exc", e.value.response)

    @markers.aws.validated
    @pytest.mark.skip(reason="not implemented")
    def test_mapping_maximum_nesting_depth(self, aws_client, cleanups, snapshot):
        """
        Tries to deploy a template containing a mapping with a nesting depth of 3.
        The maximum depth is 2 so it should fail

        """
        topic_name = f"test-topic-{short_uid()}"
        stack_name = f"test-stack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        template_body = load_file(
            os.path.join(THIS_DIR, "../../../templates/mappings/simple-mapping-nesting-depth.yaml")
        )

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName="initial",
                TemplateBody=template_body,
                ChangeSetType="CREATE",
                Parameters=[
                    {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                    {"ParameterKey": "TopicNameSuffixSelector", "ParameterValue": "A"},
                ],
            )
        snapshot.match("mapping_maximum_level_exc", e.value.response)

    @markers.aws.validated
    @pytest.mark.skip(reason="not implemented")
    def test_mapping_minimum_nesting_depth(self, aws_client, cleanups, snapshot):
        """
        Tries to deploy a template containing a mapping with a nesting depth of 1.
        The required depth is 2, so it should fail for a single level
        """
        topic_name = f"test-topic-{short_uid()}"
        stack_name = f"test-stack-{short_uid()}"
        cleanups.append(lambda: aws_client.cloudformation.delete_stack(StackName=stack_name))
        template_body = load_file(
            os.path.join(THIS_DIR, "../../../templates/mappings/simple-mapping-single-level.yaml")
        )

        with pytest.raises(aws_client.cloudformation.exceptions.ClientError) as e:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName="initial",
                TemplateBody=template_body,
                ChangeSetType="CREATE",
                Parameters=[
                    {"ParameterKey": "TopicName", "ParameterValue": topic_name},
                    {"ParameterKey": "TopicNameSuffixSelector", "ParameterValue": "A"},
                ],
            )
        snapshot.match("mapping_minimum_level_exc", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "map_key,should_error",
        [
            ("A", False),
            ("B", True),
        ],
        ids=["should-deploy", "should-not-deploy"],
    )
    def test_mapping_ref_map_key(self, deploy_cfn_template, aws_client, map_key, should_error):
        topic_name = f"topic-{short_uid()}"
        stack = deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../../templates/mappings/mapping-ref-map-key.yaml"
            ),
            parameters={
                "MapName": "MyMap",
                "MapKey": map_key,
                "TopicName": topic_name,
            },
        )

        topic_arn = stack.outputs.get("TopicArn")
        if should_error:
            assert topic_arn is None
        else:
            assert topic_arn is not None

            aws_client.sns.get_topic_attributes(TopicArn=topic_arn)

    @markers.aws.validated
    def test_aws_refs_in_mappings(self, deploy_cfn_template, account_id):
        """
        This test asserts that Pseudo references aka "AWS::" are supported inside a mapping inside a Conditional.
        It's worth remembering that even with references being supported, AWS rejects names that are not alphanumeric
        in Mapping name or the second level key.
        """
        stack_name = f"Stack{short_uid()}"
        stack = deploy_cfn_template(
            template_path=os.path.join(
                THIS_DIR, "../../../templates/mappings/mapping-aws-ref-map-key.yaml"
            ),
            stack_name=stack_name,
            template_mapping={"StackName": stack_name},
        )
        assert stack.outputs.get("TopicArn")
