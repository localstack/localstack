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
    ]
)
class TestChangeSetFnBase64:
    @markers.aws.validated
    def test_fn_base64_add_to_static_property(
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
                    "Properties": {"DisplayName": {"Fn::Base64": "HelloWorld"}},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)

    @markers.aws.validated
    def test_fn_base64_remove_from_static_property(
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
                    "Properties": {"DisplayName": {"Fn::Base64": "HelloWorld"}},
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
    def test_fn_base64_change_input_string(
        self,
        snapshot,
        capture_update_process,
    ):
        template_1 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Base64": "OldValue"}},
                }
            }
        }
        template_2 = {
            "Resources": {
                "Topic1": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {"DisplayName": {"Fn::Base64": "NewValue"}},
                }
            }
        }
        capture_update_process(snapshot, template_1, template_2)
