import os.path


def test_logstream(logs_client, deploy_cfn_template, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/logs_group_and_stream.yaml"
        )
    )
    # approach 1: cloudformation_api + custom transformer for key_value "LogGroupNameOutput"
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    # approach 2: cloudformation_api + two custom replacements with priority for LogStreamNameOutput
    # snapshot.add_transformer(snapshot.transform.cloudformation_api())
    # snapshot.add_transformer(snapshot.transform.key_value("LogStreamNameOutput"), priority=-1)
    # snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    # approach 3: two custom transformer:
    # snapshot.add_transformer(snapshot.transform.key_value("LogStreamNameOutput"))
    # snapshot.add_transformer(snapshot.transform.key_value("LogGroupNameOutput"))

    group_name = stack.outputs["LogGroupNameOutput"]
    stream_name = stack.outputs["LogStreamNameOutput"]

    # lets assert this by snapshot -> it's not aws response, but outputs is a dict, so we can use it here
    # assert group_name
    # assert stream_name
    snapshot.match("outputs", stack.outputs)

    streams = logs_client.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    # this is already asserted by snapshot and can be removed
    # assert len(streams) == 1
    # assert streams[0]["logStreamName"] == stream_name
    # assert re.match(
    #    r"arn:(aws|aws-cn|aws-iso|aws-iso-b|aws-us-gov):logs:.+:.+:log-group:.+:log-stream:.+",
    #    streams[0]["arn"],
    # )
    assert logs_client.meta.partition == streams[0]["arn"].split(":")[1]
    snapshot.match("describe_log_streams", streams)
