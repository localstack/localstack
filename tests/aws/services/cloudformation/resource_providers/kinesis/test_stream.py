import os

from localstack.aws.connect import ServiceLevelClientFactory
from localstack.testing.pytest import markers


class TestKinesis:
    @markers.aws.unknown
    def test_default_creation(
        self, deploy_cfn_template, aws_client: ServiceLevelClientFactory, snapshot
    ):
        stack = deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__),
                "templates/kinesis_default.yaml",
            ),
        )
        stream_response = aws_client.kinesis.list_streams(ExclusiveStartStreamName=stack.stack_name)

        stream_names = stream_response["StreamNames"]
        assert len(stream_names) > 0

        found = False
        for stream_name in stream_names:
            if stack.stack_name in stream_name:
                found = True
                break
        assert found
