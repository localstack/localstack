import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid


@pytest.mark.skipif(condition=not is_v2_engine(), reason="Requires the V2 engine")
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
        "$..ChangeSetId",  # An issue for the WIP executor
        # Before/After Context
        "$..Capabilities",
        "$..NotificationARNs",
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
    @pytest.mark.skip(
        reason=(
            "The inclusion of response parameters in executor is in progress, "
            "currently it cannot delete due to missing topic arn in the request"
        )
    )
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
    @pytest.mark.skip(
        reason="The inclusion of response parameters in executor is in progress, "
        "currently it cannot delete due to missing topic arn in the request"
    )
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
