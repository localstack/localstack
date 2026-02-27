import os.path

import pytest
from tests.aws.services.cloudformation.conftest import skip_if_legacy_engine

from localstack.testing.pytest import markers
from localstack.testing.pytest.fixtures import StackDeployError
from localstack.utils.strings import short_uid


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
    paths=["$..logGroups..retentionInDays", "$..logGroups..deletionProtectionEnabled"]
)
def test_cfn_handle_log_group_resource(deploy_cfn_template, aws_client, snapshot):
    log_group_name = f"test-{short_uid()}"

    snapshot.add_transformer(snapshot.transform.regex(log_group_name, "<log-group-name>"))

    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "../../../templates/logs_group.yml"),
        parameters={"LogGroupName": log_group_name},
    )

    log_group_prefix = stack.outputs["LogGroupNameOutput"]
    snapshot.match("outputs", stack.outputs)

    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    snapshot.match("describe_log_groups", response)

    stack.destroy()
    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=log_group_prefix)
    assert len(response["logGroups"]) == 0


@markers.aws.validated
@skip_if_legacy_engine()
def test_handle_existing_log_group(deploy_cfn_template, aws_client, snapshot, cleanups):
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    snapshot.add_transformer(snapshot.transform.key_value("ParameterValue"))

    log_group_name = f"logs-{short_uid()}"

    # create the log group
    aws_client.logs.create_log_group(logGroupName=log_group_name)
    cleanups.append(lambda: aws_client.logs.delete_log_group(logGroupName=log_group_name))

    with pytest.raises(StackDeployError) as exc_info:
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "../../../templates/logs_group.yml"
            ),
            parameters={"LogGroupName": log_group_name},
        )

    snapshot.match("failed-stack-describe", exc_info.value.describe_result)
