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
class TestChangeSetFnTransform:
    @markers.aws.validated
    @pytest.mark.parametrize("include_format", ["yml", "json"])
    def test_embedded_fn_transform_include(
        self, include_format, snapshot, capture_update_process, s3_bucket, aws_client, tmp_path
    ):
        name1 = f"topic-name-1-{long_uid()}"
        snapshot.add_transformer(RegexTransformer(name1, "topic-name-1"))

        bucket = s3_bucket
        file = tmp_path / "bucket_definition.yml"

        if include_format == "json":
            template = '{"Topic2":{"Type":"AWS::SNS::Topic","Properties":{"TopicName": "topic-2"}}}'
        else:
            template = """
            Topic2:
                Type: AWS::SNS::Topic
                Properties:
                    TopicName: topic-2
            """

        file.write_text(data=template)
        aws_client.s3.upload_file(
            Bucket=bucket,
            Key="template",
            Filename=str(file.absolute()),
        )

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
                    "Properties": {
                        "TopicName": name1,
                        "DisplayName": {"Fn::Sub": "The stack name is ${AWS::StackName}"},
                    },
                },
                "Fn::Transform": {
                    "Name": "AWS::Include",
                    "Parameters": {"Location": f"s3://{bucket}/template"},
                },
            },
        }
        capture_update_process(snapshot, template_1, template_2)
