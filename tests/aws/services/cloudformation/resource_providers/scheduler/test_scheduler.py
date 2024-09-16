import os

import pytest

from localstack.testing.aws.util import in_default_partition
from localstack.testing.pytest import markers


@pytest.mark.skipif(
    not in_default_partition(), reason="Test not applicable in non-default partitions"
)
@markers.aws.validated
@markers.snapshot.skip_snapshot_verify(
    paths=[
        "$..DriftInformation",
        "$..Metadata",
        "$..ActionAfterCompletion",
        "$..ScheduleExpressionTimezone",
    ]
)
def test_schedule_and_group(deploy_cfn_template, aws_client, snapshot):
    stack = deploy_cfn_template(
        template_path=os.path.join(os.path.dirname(__file__), "templates/schedule.yml")
    )

    snapshot.add_transformer(
        snapshot.transform.key_value("PhysicalResourceId", "physical_resource_id")
    )
    snapshot.add_transformer(snapshot.transform.cloudformation_api())
    schedule = aws_client.cloudformation.describe_stack_resource(
        StackName=stack.stack_name, LogicalResourceId="MySchedule"
    )["StackResourceDetail"]
    snapshot.match("Schedule", schedule)

    group = aws_client.cloudformation.describe_stack_resource(
        StackName=stack.stack_name, LogicalResourceId="MyScheduleGroup"
    )["StackResourceDetail"]
    snapshot.match("Group", group)

    schedule = aws_client.scheduler.get_schedule(
        Name=stack.outputs["ScheduleName"], GroupName=stack.outputs["ScheduleGroupName"]
    )
    snapshot.match("ScheduleDesc", schedule)

    group = aws_client.scheduler.get_schedule_group(Name=stack.outputs["ScheduleGroupName"])
    snapshot.match("GroupDesc", group)
