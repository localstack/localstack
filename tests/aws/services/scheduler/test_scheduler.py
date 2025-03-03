import json
import time

import pytest
from botocore.exceptions import ClientError

from localstack.testing.aws.util import in_default_partition, is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.aws.arns import get_partition
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


@markers.aws.validated
def tests_create_schedule_with_valid_schedule_expression(
    create_role, aws_client, region_name, account_id, cleanups, snapshot
):
    role_name = f"test-role-{short_uid()}"
    scheduler_name = f"test-scheduler-{short_uid()}"
    lambda_function_name = f"test-lambda-function-{short_uid()}"
    schedule_expression = "at(2022-12-31T23:59:59)"

    snapshot.add_transformer(snapshot.transform.key_value("ScheduleArn"))

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "scheduler.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }

    role = aws_client.iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Description="IAM Role for EventBridge Scheduler to invoke Lambda.",
    )
    role_arn = role["Role"]["Arn"]

    lambda_arn = f"arn:aws:lambda:{region_name}:{account_id}:function:{lambda_function_name}"
    policy_arn = (
        f"arn:{get_partition(aws_client.iam.meta.region_name)}:iam::aws:policy/AWSLambdaExecute"
    )

    aws_client.iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    # Allow some time for IAM role propagation (only needed in AWS)
    if is_aws_cloud():
        time.sleep(10)

    response = aws_client.scheduler.create_schedule(
        Name=scheduler_name,
        ScheduleExpression=schedule_expression,
        FlexibleTimeWindow={
            "MaximumWindowInMinutes": 4,
            "Mode": "FLEXIBLE",
        },
        Target={"Arn": lambda_arn, "RoleArn": role_arn},
    )

    # cleanup
    cleanups.append(
        lambda: aws_client.iam.delete_role_policy(RoleName=role_name, PolicyName=policy_arn)
    )
    cleanups.append(lambda: aws_client.iam.delete_role(RoleName=role_name))
    cleanups.append(lambda: aws_client.scheduler.delete_schedule(Name=scheduler_name))

    snapshot.match("valid-schedule-expression", response)
