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
class TestChangeSetMappings:
    @markers.aws.validated
    def test_mapping_leaf_update(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-2"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_update(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"KeyNew": {"Val": "display-value-2"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "KeyNew", "Val"]},
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_addition_with_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {
                "SNSMapping": {"Key1": {"Val": "display-value-1", "ValNew": "display-value-new"}}
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "ValNew"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_addition_with_resource(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                }
            },
        }
        template_2 = {
            "Mappings": {
                "SNSMapping": {
                    "Key1": {
                        "Val": "display-value-1",
                    },
                    "Key2": {
                        "Val": "display-value-1",
                        "ValNew": "display-value-new",
                    },
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "ValNew"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_deletion_with_resource_remap(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {
                "SNSMapping": {"Key1": {"Val": "display-value-1", "ValNew": "display-value-new"}}
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "ValNew"]},
                    },
                },
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_mapping_key_deletion_with_resource_remap(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Mappings": {
                "SNSMapping": {
                    "Key1": {
                        "Val": "display-value-1",
                    },
                    "Key2": {"Val": "display-value-2"},
                }
            },
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key2", "Val"]},
                    },
                },
            },
        }
        template_2 = {
            "Mappings": {"SNSMapping": {"Key1": {"Val": "display-value-1"}}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::FindInMap": ["SNSMapping", "Key1", "Val"]},
                    },
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)
