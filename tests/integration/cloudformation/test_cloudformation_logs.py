import re

from localstack.utils import testutil
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_logstream(
    cfn_client,
    logs_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("logs_group_and_stream.yaml"),
        ChangeSetType="CREATE",
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))
        assert (
            cfn_client.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
            == "CREATE_COMPLETE"
        )

        descr_response = cfn_client.describe_stacks(StackName=stack_id)
        outputs = {o["OutputKey"]: o["OutputValue"] for o in descr_response["Stacks"][0]["Outputs"]}
        group_name = outputs["LogGroupNameOutput"]
        stream_name = outputs["LogStreamNameOutput"]
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
        assert testutil.response_arn_matches_partition(cfn_client, streams[0]["arn"])

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
