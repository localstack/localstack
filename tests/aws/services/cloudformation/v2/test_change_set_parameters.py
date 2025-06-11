import pytest
from localstack_snapshot.snapshots.transformer import RegexTransformer

from localstack.services.cloudformation.v2.utils import is_v2_engine
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid


@pytest.mark.skipif(
    condition=not is_v2_engine() and not is_aws_cloud(), reason="Requires the V2 engine"
)
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "per-resource-events..*",
        "delete-describe..*",
        #
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
class TestChangeSetParameters:
    @markers.aws.validated
    def test_update_parameter_default_value(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": name1}},
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": {"Ref": "TopicName"}},
                },
            },
        }
        template_2 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": name2}},
            "Resources": template_1["Resources"],
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_update_parameter_with_added_default_value(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Parameters": {"TopicName": {"Type": "String"}},
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": {"Ref": "TopicName"}},
                },
            },
        }
        template_2 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": name2}},
            "Resources": template_1["Resources"],
        }
        capture_update_process(snapshot, template_1, template_2, p1={"TopicName": name1})

    @markers.aws.validated
    def test_update_parameter_with_removed_default_value(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": name1}},
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": {"Ref": "TopicName"}},
                },
            },
        }
        template_2 = {
            "Parameters": {"TopicName": {"Type": "String"}},
            "Resources": template_1["Resources"],
        }
        capture_update_process(snapshot, template_1, template_2, p2={"TopicName": name2})

    @markers.aws.validated
    def test_update_parameter_default_value_with_dynamic_overrides(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": "default-value-1"}},
            "Resources": {
                "Foo": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": {"Ref": "TopicName"}},
                },
            },
        }
        template_2 = {
            "Parameters": {"TopicName": {"Type": "String", "Default": "default-value-2"}},
            "Resources": template_1["Resources"],
        }
        capture_update_process(
            snapshot, template_1, template_2, p1={"TopicName": name1}, p2={"TopicName": name2}
        )
