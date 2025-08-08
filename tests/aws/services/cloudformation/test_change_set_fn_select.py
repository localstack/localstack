from localstack_snapshot.snapshots.transformer import RegexTransformer
from tests.aws.services.cloudformation.conftest import skip_if_v1_provider

from localstack.testing.pytest import markers
from localstack.utils.strings import long_uid


@skip_if_v1_provider(reason="Requires the V2 engine")
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
class TestChangeSetFnSelect:
    @markers.aws.validated
    def test_fn_select_add_to_static_property(
        self,
        snapshot,
        capture_update_process,
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))
        template_1 = {
            "Resources": {
                "Topic1": {"Type": "AWS::SNS::Topic", "Properties": {"DisplayName": name1}}
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Select": [1, ["1st", "2nd", "3rd"]]}},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_select_remove_from_static_property(
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
                    "Properties": {"DisplayName": {"Fn::Select": [1, ["1st", "2nd", "3rd"]]}},
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
    def test_fn_select_change_in_selection_list(
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
                    "Properties": {"DisplayName": {"Fn::Select": [1, ["1st", "2nd"]]}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Select": [1, ["1st", "new-2nd", "3rd"]]}},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_select_change_in_selection_index_only(
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
                    "Properties": {"DisplayName": {"Fn::Select": [1, ["1st", "2nd"]]}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Select": [0, ["1st", "2nd"]]}},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_select_change_in_selected_element_type_ref(
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
                    "Properties": {"DisplayName": {"Fn::Select": [0, ["1st"]]}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Select": [0, [{"Ref": "AWS::StackName"}]]}},
                }
            }
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
    def test_fn_select_change_get_att_reference(
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
                    "Properties": {"DisplayName": name1},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "DisplayName": {
                            "Fn::Select": [0, [{"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
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
                            "Fn::Select": [0, [{"Fn::GetAtt": ["Topic1", "DisplayName"]}]]
                        }
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)
