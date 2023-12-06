import os.path

from localstack.testing.pytest import markers


@markers.aws.validated
def test_logstream(deploy_cfn_template, snapshot, aws_client):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/logs_group_and_stream.yaml"
        )
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    group_name = stack.outputs["LogGroupNameOutput"]
    stream_name = stack.outputs["LogStreamNameOutput"]

    snapshot.match("outputs", stack.outputs)

    streams = aws_client.logs.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    assert aws_client.logs.meta.partition == streams[0]["arn"].split(":")[1]
    snapshot.match("describe_log_streams", streams)
