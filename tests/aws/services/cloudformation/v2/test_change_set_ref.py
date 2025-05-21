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
class TestChangeSetRef:
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: preproc is not able to resolve references to deployed resources' physical id
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName"
        ]
    )
    @markers.aws.validated
    def test_resource_addition(
        self,
        snapshot,
        capture_update_process,
    ):
        # Add a new resource (Topic2) that uses Ref to reference Topic1.
        # For SNS topics, Ref typically returns the Topic ARN.
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
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: preproc is not able to resolve references to deployed resources' physical id
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName"
        ]
    )
    @markers.aws.validated
    def test_direct_attribute_value_change(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the DisplayName of Topic1 from "display-value-1" to "display-value-2"
        # while Topic2 references Topic1 using Ref. This verifies that the update process
        # correctly reflects the change when using Ref-based dependency resolution.
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
                        "DisplayName": "display-value-1",
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
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
                        "DisplayName": "display-value-2",
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: preproc is not able to resolve references to deployed resources' physical id
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName"
        ]
    )
    @markers.aws.validated
    def test_direct_attribute_value_change_in_ref_chain(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the DisplayName of Topic1 from "display-value-1" to "display-value-2"
        # while ensuring that chained references via Ref update appropriately.
        # Topic2 references Topic1 using Ref, and Topic3 references Topic2.
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        name3 = f"topic-name-3-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        snapshot.add_transformer(RegexTransformer(name3, "topic-name-3"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
                "Topic3": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name3,
                        "DisplayName": {"Ref": "Topic2"},
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
                        "DisplayName": "display-value-2",  # Updated value triggers change along the chain
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
                "Topic3": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name3,
                        "DisplayName": {"Ref": "Topic2"},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: preproc is not able to resolve references to deployed resources' physical id
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName"
        ]
    )
    @markers.aws.validated
    def test_direct_attribute_value_change_with_dependent_addition(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the DisplayName property of Topic1 while adding Topic2 that
        # uses Ref to reference Topic1.
        # Initially, only Topic1 exists with DisplayName "display-value-1".
        # In the update, Topic1 is updated to "display-value-2" and Topic2 is added,
        # referencing Topic1 via Ref.
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
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-2"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    # @pytest.mark.skip(reason="")
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: preproc is not able to resolve references to deployed resources' physical id
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName",
            # Reason: the preprocessor currently appears to mask the change to the resource as the
            # physical id is equal to the logical id. Adding support for physical id resolution
            # should address this limitation
            "describe-change-set-2..Changes",
            "describe-change-set-2-prop-values..Changes",
        ]
    )
    @markers.aws.validated
    def test_immutable_property_update_causes_resource_replacement(
        self,
        snapshot,
        capture_update_process,
    ):
        # Changing TopicName in Topic1 from an initial value to an updated value
        # represents an immutable property update. This forces the replacement of Topic1.
        # Topic2 references Topic1 using Ref. After replacement, Topic2's Ref resolution
        # should pick up the new Topic1 attributes without error.
        name1 = f"topic-name-1-{long_uid()}"
        name1_update = f"updated-topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name1_update, "updated-topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": "value",
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name1_update,
                        "DisplayName": "new_value",
                    },
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Ref": "Topic1"},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_supported_pseudo_parameter(
        self,
        snapshot,
        capture_update_process,
    ):
        topic_name_1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(topic_name_1, "topic_name_1"))
        topic_name_2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(topic_name_2, "topic_name_2"))
        snapshot.add_transformer(RegexTransformer("amazonaws.com", "url_suffix"))
        snapshot.add_transformer(RegexTransformer("localhost.localstack.cloud", "url_suffix"))
        template_1 = {
            "Resources": {
                "Topic1": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": topic_name_1}},
            }
        }
        template_2 = {
            "Resources": {
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": topic_name_2,
                        "Tags": [
                            {"Key": "Partition", "Value": {"Ref": "AWS::Partition"}},
                            {"Key": "AccountId", "Value": {"Ref": "AWS::AccountId"}},
                            {"Key": "Region", "Value": {"Ref": "AWS::Region"}},
                            {"Key": "StackName", "Value": {"Ref": "AWS::StackName"}},
                            {"Key": "StackId", "Value": {"Ref": "AWS::StackId"}},
                            {"Key": "URLSuffix", "Value": {"Ref": "AWS::URLSuffix"}},
                        ],
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)
