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
        "$..StatusReason",
    ]
)
class TestChangeSetFnSplit:
    @markers.aws.validated
    def test_fn_split_add_to_static_property(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name1.replace("-", "_"), "topic_name_1"))
        template_1 = {
            "Resources": {
                "Topic1": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": name1}}
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": [
                                "_",
                                {"Fn::Split": ["-", "part1-part2-part3"]},
                            ]
                        }
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_split_remove_from_static_property(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name1.replace("-", "_"), "topic_name_1"))
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": [
                                "_",
                                {"Fn::Split": ["-", "part1-part2-part3"]},
                            ]
                        }
                    },
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": name1}}
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_split_change_delimiter(
        self,
        snapshot,
        capture_update_process,
    ):
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {"Fn::Join": ["_", {"Fn::Split": ["-", "a-b--c::d"]}]}
                    },
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {"Fn::Join": ["_", {"Fn::Split": [":", "a-b--c::d"]}]}
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_split_change_source_string_only(
        self,
        snapshot,
        capture_update_process,
    ):
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Join": ["_", {"Fn::Split": ["-", "a-b"]}]}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {"Fn::Join": ["_", {"Fn::Split": ["-", "x-y-z"]}]}
                    },
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_split_with_ref_as_string_source(
        self,
        snapshot,
        capture_update_process,
    ):
        param_name = "DelimiterParam"
        template_1 = {
            "Parameters": {param_name: {"Type": "String", "Default": "hello-world"}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": ["_", {"Fn::Split": ["-", {"Ref": param_name}]}]
                        }
                    },
                }
            },
        }
        template_2 = {
            "Parameters": {param_name: {"Type": "String", "Default": "foo-bar-baz"}},
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": ["_", {"Fn::Split": ["-", {"Ref": param_name}]}]
                        }
                    },
                }
            },
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: AWS incorrectly does not list the second and third topic as
            # needing modifying, however it needs to
            "describe-change-set-2-prop-values..Changes",
        ]
    )
    @markers.aws.validated
    def test_fn_split_with_get_att(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        name2 = f"topic-name-2-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        snapshot.add_transformer(RegexTransformer(name1.replace("-", "_"), "topic_name_1"))
        snapshot.add_transformer(RegexTransformer(name2, "topic-name-2"))
        snapshot.add_transformer(RegexTransformer(name2.replace("-", "_"), "topic_name_2"))

        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": name1},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": [
                                "_",
                                {"Fn::Split": ["-", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]},
                            ]
                        }
                    },
                },
            }
        }

        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": name2},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Join": [
                                "_",
                                {"Fn::Split": ["-", {"Fn::GetAtt": ["Topic1", "DisplayName"]}]},
                            ]
                        }
                    },
                },
            }
        }

        capture_update_process(snapshot, template_1, template_2)


class TestSplitValidations:
    @markers.aws.validated
    @skip_if_legacy_engine
    def test_validate_split_arguments_len(self, aws_client, snapshot):
        template = {
            "Resources": {
                "Parameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Fn::Split": {"Ref": "AWS::Region"}},
                    },
                }
            }
        }

        with pytest.raises(ClientError) as ex:
            aws_client.cloudformation.create_change_set(
                StackName=f"st-{short_uid()}",
                ChangeSetName=f"ch-{short_uid()}",
                ChangeSetType="CREATE",
                TemplateBody=json.dumps(template),
            )

        snapshot.match("validation", ex.value.response)
