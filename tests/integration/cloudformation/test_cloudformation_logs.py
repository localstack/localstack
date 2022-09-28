import os.path


def test_logstream(logs_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/logs_group_and_stream.yaml"
        )
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    group_name = stack.outputs["LogGroupNameOutput"]
    stream_name = stack.outputs["LogStreamNameOutput"]

    snapshot.match("outputs", stack.outputs)

    streams = logs_client.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    assert logs_client.meta.partition == streams[0]["arn"].split(":")[1]
    snapshot.match("describe_log_streams", streams)
