import json

import pytest
from botocore.exceptions import ClientError
from localstack_snapshot.snapshots.transformer import RegexTransformer
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid, short_uid


@skip_if_legacy_engine()
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        # Before/After Context
        "$..Capabilities",
        "$..IncludeNestedStacks",
        "$..Scope",
        "$..Details",
        "$..Parameters",
        "$..Replacement",
        "$..PolicyAction",
    ]
)
class TestChangeSetConditions:
    @markers.aws.validated
    def test_condition_update_removes_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "true"]}},
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                }
            },
        }
        template_2 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "false"]}},
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                },
                "TopicPlaceholder": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_condition_update_adds_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "false"]}},
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                },
                "TopicPlaceholder": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2},
                },
            },
        }
        template_2 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "true"]}},
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                },
                "TopicPlaceholder": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_condition_add_new_negative_condition_to_existent_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1},
                },
            },
        }
        template_2 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "false"]}},
            "Resources": {
                "SNSTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                },
                "TopicPlaceholder": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_condition_add_new_positive_condition_to_existent_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Resources": {
                "SNSTopic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1},
                },
            },
        }
        template_2 = {
            "Conditions": {"CreateTopic": {"Fn::Equals": ["true", "true"]}},
            "Resources": {
                "SNSTopic1": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name1},
                },
                "SNSTopic2": {
                    "Type": "AWS::SNS::Topic",
                    "Condition": "CreateTopic",
                    "Properties": {"TopicName": name2},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_missing_condition(self, snapshot, aws_client):
        template = {
            "Resources": {
                "MyVpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/24",
                        "Tags": [
                            {
                                "Fn::If": ["MissingCondition", "AWS::NoValue", "AWS::NoValue"],
                            },
                        ],
                    },
                },
            }
        }

        cs_name = f"cs-{short_uid()}"
        stack_name = f"stack-{short_uid()}"
        with pytest.raises(ClientError) as exc_info:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName=cs_name,
                ChangeSetType="CREATE",
                TemplateBody=json.dumps(template),
            )

        snapshot.match("error", exc_info.value.response)
