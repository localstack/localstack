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


@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=["$..logGroups..logGroupArn", "$..logGroups..logGroupClass", "$..logGroups..retentionInDays"]
)
def test_cfn_handle_log_group_resource(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../../templates/logs_group.yml"
        )
    )

    log_group_prefix = stack.outputs["LogGroupNameOutput"]

    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    snapshot.match("describe_log_groups", response)
    snapshot.add_transformer(snapshot.transform.key_value("logGroupName"))

    stack.destroy()
    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    assert len(response["logGroups"]) == 0
