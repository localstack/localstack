import os

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
class TestChangeSetFnGetAttr:
    @markers.aws.validated
    def test_resource_addition(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the Value property of a resource to a different literal
        # while keeping the dependency via Fn::GetAtt intact.
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
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @pytest.mark.skip(reason="See FIXME in aws_sns_provider::delete")
    @markers.aws.validated
    def test_resource_deletion(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the Value property of a resource to a different literal
        # while keeping the dependency via Fn::GetAtt intact.
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
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1, "DisplayName": "display-value-1"},
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: AWS incorrectly does not list the second topic as
            #  needing modifying, however it needs to
            "describe-change-set-2-prop-values..Changes",
        ]
    )
    @markers.aws.validated
    def test_direct_attribute_value_change(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the Value property of a resource to a different literal
        # while keeping the dependency via Fn::GetAtt intact.
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
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
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
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
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
    def test_direct_attribute_value_change_in_get_attr_chain(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the Value property of a resource to a different literal
        # while keeping the dependency via Fn::GetAtt intact.
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
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
                "Topic3": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name3,
                        "DisplayName": {"Fn::GetAtt": ["Topic2", "DisplayName"]},
                    },
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
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
                "Topic3": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name3,
                        "DisplayName": {"Fn::GetAtt": ["Topic2", "DisplayName"]},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: AWS appears to incorrectly evaluate the new resource's DisplayName property
            #  to the old value of the resource being referenced. The describer instead masks
            #  this value with KNOWN_AFTER_APPLY. The update graph would be able to compute the
            #  correct new value, however in an effort to match the general behaviour of AWS CFN
            #  this is being masked as it is updated.
            "$..Changes..ResourceChange.AfterContext.Properties.DisplayName",
        ]
    )
    @markers.aws.validated
    def test_direct_attribute_value_change_with_dependent_addition(
        self,
        snapshot,
        capture_update_process,
    ):
        # Modify the Value property of a resource to a different literal
        # while keeping the dependency via Fn::GetAtt intact.
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
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_immutable_property_update_causes_resource_replacement(
        self,
        snapshot,
        capture_update_process,
    ):
        # Changing TopicName in Topic1 from represents an immutable property update.
        # This should force the resource to be replaced, rather than updated in place.
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
                    "Properties": {"TopicName": name1, "DisplayName": "value"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"TopicName": name1_update, "DisplayName": "new_value"},
                },
                "Topic2": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": name2,
                        "DisplayName": {"Fn::GetAtt": ["Topic1", "DisplayName"]},
                    },
                },
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    @pytest.mark.parametrize("template_name", ["getatt_validation.yml", "getatt_validation2.yml"])
    def test_invalid_structure(self, snapshot, deploy_cfn_template, aws_client, template_name):
        cs_name = f"cs-{short_uid()}"
        stack_name = f"stack-{short_uid()}"

        with open(
            os.path.join(os.path.dirname(__file__), f"../../templates/{template_name}")
        ) as infile:
            template_body = infile.read()

        with pytest.raises(ClientError) as exc_info:
            aws_client.cloudformation.create_change_set(
                StackName=stack_name,
                ChangeSetName=cs_name,
                ChangeSetType="CREATE",
                TemplateBody=template_body,
                Parameters=[
                    {
                        "ParameterKey": "MyParameterValue",
                        "ParameterValue": "BadResourceName",
                    },
                ],
            )

        snapshot.match("error", exc_info.value.response)
