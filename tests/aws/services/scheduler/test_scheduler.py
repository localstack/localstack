import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import in_default_partition
from localstack.testing.pytest import markers
from localstack.utils.common import short_uid


@pytest.mark.skipif(
    not in_default_partition(), reason="Test not applicable in non-default partitions"
)
@markers.aws.validated
def test_list_schedules(aws_client):
    # simple smoke test to assert that the provider is available, without creating any schedules
    result = aws_client.scheduler.list_schedules()
    assert isinstance(result.get("Schedules"), list)


@markers.aws.validated
def test_tag_resource(aws_client, events_scheduler_create_schedule_group, snapshot):
    name = short_uid()
    schedule_group_arn = events_scheduler_create_schedule_group(name)

    response = aws_client.scheduler.tag_resource(
        ResourceArn=schedule_group_arn,
        Tags=[
            {
                "Key": "TagKey",
                "Value": "TagValue",
            }
        ],
    )

    response = aws_client.scheduler.list_tags_for_resource(ResourceArn=schedule_group_arn)

    assert response["Tags"][0]["Key"] == "TagKey"
    assert response["Tags"][0]["Value"] == "TagValue"

    snapshot.match("list-tagged-schedule", response)


@markers.aws.validated
def test_untag_resource(aws_client, events_scheduler_create_schedule_group, snapshot):
    name = short_uid()
    tags = [
        {
            "Key": "TagKey",
            "Value": "TagValue",
        }
    ]
    schedule_group_arn = events_scheduler_create_schedule_group(name, Tags=tags)

    response = aws_client.scheduler.untag_resource(
        ResourceArn=schedule_group_arn, TagKeys=["TagKey"]
    )

    response = aws_client.scheduler.list_tags_for_resource(ResourceArn=schedule_group_arn)

    assert response["Tags"] == []

    snapshot.match("list-untagged-schedule", response)


@markers.aws.validated
@pytest.mark.parametrize(
    "schedule_expression",
    [
        "cron(0 1 * * * *)",
        "cron(7 20 * * NOT *)",
        "cron(INVALID)",
        "cron(0 dummy ? * MON-FRI *)",
        "cron(71 8 1 * ? *)",
        "cron()",
        "rate(10 seconds)",
        "rate(10 years)",
        "rate()",
        "rate(10)",
        "rate(10 minutess)",
        "rate(foo minutes)",
        "rate(-10 minutes)",
        "rate( 10 minutes )",
        " rate(10 minutes)",
        "at(2021-12-31T23:59:59Z)",
        "at(2021-12-31)",
    ],
)
def tests_create_schedule_with_invalid_schedule_expression(
    schedule_expression, aws_client, region_name, account_id, snapshot
):
    rule_name = f"rule-{short_uid()}"

    with pytest.raises(ClientError) as e:
        aws_client.scheduler.create_schedule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            FlexibleTimeWindow={
                "MaximumWindowInMinutes": 4,
                "Mode": "FLEXIBLE",
            },
            Target={
                "Arn": f"arn:aws:lambda:{region_name}:{account_id}:function:dummy",
                "RoleArn": f"arn:aws:iam::{account_id}:role/role-name",
            },
        )
    snapshot.match("invalid-schedule-expression", e.value.response)
