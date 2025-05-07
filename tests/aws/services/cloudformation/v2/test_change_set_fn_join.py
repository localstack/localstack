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
class TestChangeSetFnJoin:
    # TODO: Test behaviour with different argument types.

    @markers.aws.validated
    def test_update_string_literal_delimiter_empty(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["", ["v1", "test"]]},
                    },
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["v1", "test"]]},
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: aws appears to not display the "DisplayName" as
            # previously having an empty name during the update.
            "describe-change-set-2-prop-values..Changes..ResourceChange.BeforeContext.Properties.DisplayName"
        ]
    )
    def test_update_string_literal_arguments_empty(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": {"Fn::Join": ["", []]}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["", ["v1", "test"]]},
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_update_string_literal_argument(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["v1", "test"]]},
                    },
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["v2", "test"]]},
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_update_string_literal_delimiter(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["v1", "test"]]},
                    },
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["_", ["v2", "test"]]},
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: AWS appears to not detect the changed DisplayName field during update.
            "describe-change-set-2-prop-values..Changes",
        ]
    )
    def test_update_refence_argument(
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
                    "Properties": {"TopicName": name1, "DisplayName": "display-name-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {
                            "Fn::Join": ["-", ["prefix", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
                        },
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-name-2"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {
                            "Fn::Join": ["-", ["prefix", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
                        },
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: AWS appears to not detect the changed DisplayName field during update.
            "describe-change-set-2-prop-values..Changes",
        ]
    )
    def test_indirect_update_refence_argument(
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
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["display", "name", "1"]]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {
                            "Fn::Join": ["-", ["prefix", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
                        },
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Join": ["-", ["display", "name", "2"]]},
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {
                            "Fn::Join": ["-", ["prefix", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
                        },
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)
