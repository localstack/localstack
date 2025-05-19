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
class TestChangeSetDependsOn:
    @markers.aws.validated
    def test_update_depended_resource(
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
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                    "DependsOn": "Topic1",
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1-updated"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                    "DependsOn": "Topic1",
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_update_depended_resource_list(
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
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                    "DependsOn": ["Topic1"],
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1-updated"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                    "DependsOn": ["Topic1"],
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_multiple_dependencies_addition(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        namen = f"topic-name-n-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        snapshot.add_transformer(RegexTransformer(namen, "topic-name-n"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topicn": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": namen, "DisplayName": "display-value-n"},
                    "DependsOn": ["Topic1"],
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topicn": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": namen, "DisplayName": "display-value-n"},
                    "DependsOn": ["Topic1", "Topic2"],
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_multiple_dependencies_deletion(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        namen = f"topic-name-n-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        snapshot.add_transformer(RegexTransformer(namen, "topic-name-n"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name2, "DisplayName": "display-value-2"},
                },
                "Topicn": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": namen, "DisplayName": "display-value-n"},
                    "DependsOn": ["Topic1", "Topic2"],
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topicn": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": namen, "DisplayName": "display-value-n"},
                    "DependsOn": ["Topic1"],
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)
