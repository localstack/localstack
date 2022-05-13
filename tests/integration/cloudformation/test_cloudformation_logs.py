import os.path
import re


def test_logstream(logs_client, deploy_cfn_template):
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/logs_group_and_stream.yaml"
        )
    )

    group_name = stack.outputs["LogGroupNameOutput"]
    stream_name = stack.outputs["LogStreamNameOutput"]
    assert group_name
    assert stream_name

    streams = logs_client.describe_log_streams(
        logGroupName=group_name, logStreamNamePrefix=stream_name
    )["logStreams"]
    assert len(streams) == 1
    assert streams[0]["logStreamName"] == stream_name
    assert re.match(
        r"arn:(aws|aws-cn|aws-iso|aws-iso-b|aws-us-gov):logs:.+:.+:log-group:.+:log-stream:.+",
        streams[0]["arn"],
    )
    assert logs_client.meta.partition == streams[0]["arn"].split(":")[1]
