import copy
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

    @markers.aws.validated
    def test_parameter_type_change(self, snapshot, capture_update_process):
        snapshot.add_transformer(snapshot.transform.key_value("PhysicalResourceId"))

        template1 = {
            "Parameters": {
                "Value": {
                    "Type": "Number",
                },
            },
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": {"Ref": "Value"},
                    },
                },
            },
        }
        template2 = copy.deepcopy(template1)
        template2["Parameters"]["Value"]["Type"] = "String"

        capture_update_process(
            snapshot, template1, template2, p1={"Value": "123"}, p2={"Value": "456"}
        )

    @markers.aws.validated
    def test_invalid_parameter_type(self, snapshot, aws_client):
        template = {
            "Parameters": {
                "Value": {
                    "Type": "Number",
                },
            },
            "Resources": {
                "MyParameter": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Type": "String",
                        "Value": short_uid(),
                    },
                },
            },
        }

        stack_name = f"stack-{short_uid()}"
        cs_name = f"cs-{short_uid()}"
        with pytest.raises(ClientError) as exc_info:
            aws_client.cloudformation.create_change_set(
                ChangeSetName=cs_name,
                StackName=stack_name,
                ChangeSetType="CREATE",
                TemplateBody=json.dumps(template),
                Parameters=[
                    {"ParameterKey": "Value", "ParameterValue": "not-a-number"},
                ],
            )

        snapshot.match("error", exc_info.value.response)
