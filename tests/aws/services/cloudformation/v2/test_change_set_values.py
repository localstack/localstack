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
class TestChangeSetValues:
    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            # Reason: on deletion the LogGroupName being deleted is known,
            #         however AWS is describing it as known-after-apply.
            #         more evidence on this masking approach is needed
            #         for implementing a generalisable solution.
            #         Nevertheless, the output being served by the engine
            #         now is not incorrect as it lists the correct name.
            "describe-change-set-2-prop-values..Changes..ResourceChange.BeforeContext.Properties.LogGroupName"
        ]
    )
    def test_property_empy_list(
        self,
        snapshot,
        capture_update_process,
    ):
        test_name = f"test-name-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(test_name, "test-name"))
        template_1 = {
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": test_name}},
                "Role": {
                    "Type": "AWS::Logs::LogGroup",
                    "Properties": {
                        # To ensure Tags is marked as "created" and not "unchanged", the use of GetAttr forces
                        #  the access of a previously unavailable resource.
                        "LogGroupName": {"Fn::GetAtt": ["Topic", "TopicName"]},
                        "Tags": [],
                    },
                },
            }
        }
        template_2 = {
            "Resources": {
                "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": test_name}},
            }
        }
        capture_update_process(snapshot, template_1, template_2)
