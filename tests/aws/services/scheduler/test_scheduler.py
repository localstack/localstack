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
    schedule_group_arn = events_scheduler_create_schedule_group(name)["ScheduleGroupArn"]

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
    schedule_group_arn = events_scheduler_create_schedule_group(name, Tags=tags)["ScheduleGroupArn"]

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
class TestSchedule:
    @markers.aws.validated
    @pytest.mark.parametrize("with_client_token", [True, False])
    @pytest.mark.parametrize("with_description", [True, False])
    @pytest.mark.parametrize("action_after_completion", ["NONE", "DELETE"])
    @pytest.mark.parametrize("state", ["ENABLED", "DISABLED"])
    @pytest.mark.parametrize("flexible_time_window_mode", ["OFF", "FLEXIBLE"])
    def test_create_schedule(
        self,
        with_client_token,
        with_description,
        action_after_completion,
        state,
        flexible_time_window_mode,
        sqs_as_events_schedule_target,
        events_scheduler_create_schedule,
        snapshot,
    ):
        name = f"test-schedule-{short_uid()}"
        kwargs = {"ActionAfterCompletion": action_after_completion, "State": state}
        if with_client_token:
            kwargs["ClientToken"] = f"test-client_token-{short_uid()}"
        if with_description:
            kwargs["Description"] = "Test description"

        flexible_time_window = {
            "Mode": flexible_time_window_mode,
        }
        if flexible_time_window_mode == "FLEXIBLE":
            flexible_time_window["MaximumWindowInMinutes"] = 60

        schedule_expression = "rate(1 minute)"
        queue_url, queue_arn, role_arn = sqs_as_events_schedule_target()
        target = {"Arn": queue_arn, "Input": '{"key": "value"}', "RoleArn": role_arn}

        response = events_scheduler_create_schedule(
            name, flexible_time_window, schedule_expression, target, **kwargs
        )

        snapshot.add_transformer(snapshot.transform.regex(name, "<name>"))
        snapshot.match("create-schedule", response)

    @markers.aws.validated
    @pytest.mark.parametrize("with_client_token", [True, False])
    @pytest.mark.parametrize("with_description", [True, False])
    @pytest.mark.parametrize("action_after_completion", ["NONE", "DELETE"])
    @pytest.mark.parametrize("state", ["ENABLED", "DISABLED"])
    @pytest.mark.parametrize("flexible_time_window_mode", ["OFF", "FLEXIBLE"])
    def test_get_schedule(
        self,
        with_client_token,
        with_description,
        action_after_completion,
        state,
        flexible_time_window_mode,
        sqs_as_events_schedule_target,
        events_scheduler_create_schedule,
        aws_client,
        snapshot,
    ):
        name = f"test-schedule-{short_uid()}"
        kwargs = {"ActionAfterCompletion": action_after_completion, "State": state}
        if with_client_token:
            kwargs["ClientToken"] = f"test-client_token-{short_uid()}"
        if with_description:
            kwargs["Description"] = "Test description"

        flexible_time_window = {
            "Mode": flexible_time_window_mode,
        }
        if flexible_time_window_mode == "FLEXIBLE":
            flexible_time_window["MaximumWindowInMinutes"] = 60

        schedule_expression = "rate(1 minute)"
        queue_url, queue_arn, role_arn = sqs_as_events_schedule_target()
        target = {"Arn": queue_arn, "Input": '{"key": "value"}', "RoleArn": role_arn}

        schedule_arn = events_scheduler_create_schedule(
            name, flexible_time_window, schedule_expression, target, **kwargs
        )["ScheduleArn"]

        response = aws_client.scheduler.get_schedule(Name=name)

        assert response["Arn"] == schedule_arn
        assert response["Name"] == name

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(name, "<name>"),
                snapshot.transform.regex(role_arn, "<role-arn>"),
                snapshot.transform.regex(queue_arn, "<queue-arn>"),
            ]
        )
        snapshot.match("get-schedule", response)

    @markers.aws.validated
    def test_get_schedule_not_found(self, aws_client, snapshot):
        with pytest.raises(Exception) as exc:
            aws_client.scheduler.get_schedule(Name="not-existing-schedule-name")

        assert exc.typename == "ResourceNotFoundException"

        snapshot.match("get-schedule-not-found", exc.value.response)

    @markers.aws.validated
    def test_list_schedules(
        self, aws_client, sqs_as_events_schedule_target, events_scheduler_create_schedule, snapshot
    ):
        name_one = f"test-schedule-one-{short_uid()}"
        name_two = f"test-schedule-two-{short_uid()}"

        flexible_time_window = {
            "Mode": "OFF",
        }
        schedule_expression = "rate(1 minute)"
        queue_url, queue_arn, role_arn = sqs_as_events_schedule_target()
        target = {"Arn": queue_arn, "Input": '{"key": "value"}', "RoleArn": role_arn}

        schedule_arn_one = events_scheduler_create_schedule(
            name_one, flexible_time_window, schedule_expression, target
        )["ScheduleArn"]
        schedule_arn_two = events_scheduler_create_schedule(
            name_two, flexible_time_window, schedule_expression, target
        )["ScheduleArn"]

        response = aws_client.scheduler.list_schedules()

        assert len(response["Schedules"]) == 2

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(name_one, "<schedule-one-name>"),
                snapshot.transform.regex(name_two, "<schedule-two-name>"),
                snapshot.transform.regex(schedule_arn_one, "<schedule-one-arn>"),
                snapshot.transform.regex(schedule_arn_two, "<schedule-two-arn>"),
                snapshot.transform.regex(queue_arn, "<target-sqs-queue-arn>"),
            ]
        )
        snapshot.match("list-schedules", response)

    @markers.aws.validated
    def test_list_schedules_non(self, aws_client, snapshot):
        response = aws_client.scheduler.list_schedules()

        assert len(response["Schedules"]) == 0

        snapshot.match("list-schedules-non", response)

    @markers.aws.validated
    @pytest.mark.parametrize("initially_with_client_token", [True, False])
    @pytest.mark.parametrize("initially_with_description", [True, False])
    @pytest.mark.parametrize(
        "combinations_action_after_completion", [["NONE", "DELETE"], ["NONE", "DELETE"]]
    )
    @pytest.mark.parametrize(
        "combinations_state", [["ENABLED", "DISABLED"], ["ENABLED", "DISABLED"]]
    )
    @pytest.mark.parametrize("initial_flexible_time_window_mode", ["OFF", "FLEXIBLE"])
    def test_update_schedule(
        self,
        initially_with_client_token,
        initially_with_description,
        combinations_action_after_completion,
        combinations_state,
        initial_flexible_time_window_mode,
        sqs_as_events_schedule_target,
        events_scheduler_create_schedule,
        aws_client,
        snapshot,
    ):
        name = f"test-schedule-{short_uid()}"
        kwargs_initial = {
            "ActionAfterCompletion": combinations_action_after_completion[0],
            "State": combinations_state[0],
        }
        kwargs_update = {
            "ActionAfterCompletion": combinations_action_after_completion[1],
            "State": combinations_state[1],
        }

        client_token = f"test-client_token-{short_uid()}"
        if initially_with_client_token:
            kwargs_initial["ClientToken"] = client_token
        else:
            kwargs_update["ClientToken"] = client_token

        description = "Test description"
        if initially_with_description:
            kwargs_initial["Description"] = description
        else:
            kwargs_update["Description"] = description

        flexible_time_window = {
            "MaximumWindowInMinutes": 60,
            "Mode": "FLEXIBLE",
        }
        not_flexible_time_window = {
            "Mode": "OFF",
        }
        if initial_flexible_time_window_mode == "FLEXIBLE":
            initial_flexible_time_window = flexible_time_window
            update_flexible_time_window = not_flexible_time_window
        else:
            initial_flexible_time_window = not_flexible_time_window
            update_flexible_time_window = flexible_time_window

        initial_schedule_expression = "rate(1 minute)"
        update_schedule_expression = "rate(2 minute)"

        _, initial_queue_arn, initial_role_arn = sqs_as_events_schedule_target()
        initial_target = {
            "Arn": initial_queue_arn,
            "Input": '{"key": "value"}',
            "RoleArn": initial_role_arn,
        }

        _, update_queue_arn, update_role_arn = sqs_as_events_schedule_target()
        update_target = {
            "Arn": update_queue_arn,
            "Input": '{"otherkey": "othervalue"}',
            "RoleArn": update_role_arn,
        }

        response = events_scheduler_create_schedule(
            name,
            initial_flexible_time_window,
            initial_schedule_expression,
            initial_target,
            **kwargs_initial,
        )

        # get initial schedule description
        response = aws_client.scheduler.get_schedule(Name=name)

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(name, "<name>"),
                snapshot.transform.regex(client_token, "<client-token>"),
                snapshot.transform.regex(initial_queue_arn, "<initial-target-queue-arn>"),
                snapshot.transform.regex(initial_role_arn, "<initial-target-role-arn>"),
            ]
        )
        snapshot.match("initial-schedule", response)

        response = aws_client.scheduler.update_schedule(
            Name=name,
            FlexibleTimeWindow=update_flexible_time_window,
            ScheduleExpression=update_schedule_expression,
            Target=update_target,
            **kwargs_update,
        )

        snapshot.match("update-schedule", response)

        # get updated schedule description
        response = aws_client.scheduler.get_schedule(Name=name)

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(update_queue_arn, "<update-target-queue-arn>"),
                snapshot.transform.regex(update_role_arn, "<update-target-role-arn>"),
            ]
        )
        snapshot.match("updated-schedule", response)

    @markers.aws.validated
    def test_delete_schedule(self, aws_client, events_scheduler_create_schedule, snapshot):
        name = f"test-schedule-{short_uid()}"
        events_scheduler_create_schedule(name)

        response = aws_client.scheduler.delete_schedule(Name=name)

        response = aws_client.scheduler.list_schedules()

        assert len(response["Schedules"]) == 0

        snapshot.match("delete-schedule", response)

    @markers.aws.validated
    def test_delete_schedule_not_found(self, aws_client, snapshot):
        with pytest.raises(Exception) as exc:
            aws_client.scheduler.delete_schedule(Name="not-existing-schedule-name")

        assert exc.typename == "ResourceNotFoundException"

        snapshot.match("delete-schedule-not-found", exc.value.response)


class TestScheduleGroupe:
    @markers.aws.validated
    @pytest.mark.parametrize("with_tags", [True, False])
    @pytest.mark.parametrize("with_client_token", [True, False])
    def test_create_schedule_group(
        self, with_tags, with_client_token, events_scheduler_create_schedule_group, snapshot
    ):
        name = f"test-schedule-group-{short_uid()}"
        kwargs = {}
        if with_client_token:
            kwargs["ClientToken"] = f"test-client_token-{short_uid()}"
        if with_tags:
            kwargs["Tags"] = [
                {
                    "Key": "TagKey",
                    "Value": "TagValue",
                }
            ]
        response = events_scheduler_create_schedule_group(
            name,
            **kwargs,
        )

        snapshot.add_transformer(snapshot.transform.regex(name, "<name>"))
        snapshot.match("create-schedule-group", response)

    @markers.aws.validated
    @pytest.mark.parametrize("with_tags", [True, False])
    def test_get_schedule_group(
        self, with_tags, aws_client, events_scheduler_create_schedule_group, snapshot
    ):
        name = f"test-schedule-group-{short_uid()}"
        kwargs = {"Tags": [{"Key": "TagKey", "Value": "TagValue"}]} if with_tags else {}
        schedule_group_arn = events_scheduler_create_schedule_group(name, **kwargs)[
            "ScheduleGroupArn"
        ]

        response = aws_client.scheduler.get_schedule_group(Name=name)

        assert response["Arn"] == schedule_group_arn
        assert response["Name"] == name

        snapshot.add_transformer(snapshot.transform.regex(name, "<name>"))
        snapshot.match("get-schedule-group", response)

    @markers.aws.validated
    def test_get_schedule_group_not_found(self, aws_client, snapshot):
        with pytest.raises(Exception) as exc:
            aws_client.scheduler.get_schedule_group(Name="not-existing-name")

        assert exc.typename == "ResourceNotFoundException"

        snapshot.match("get-schedule-group-not-found", exc.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize("with_tags", [True, False])
    def test_list_schedule_groups(
        self, with_tags, aws_client, events_scheduler_create_schedule_group, snapshot
    ):
        kwargs = {"Tags": [{"Key": "TagKey", "Value": "TagValue"}]} if with_tags else {}
        name_one = f"test-schedule-groupe-one-{short_uid()}"
        events_scheduler_create_schedule_group(name_one, **kwargs)

        name_two = f"test-schedule-groupe-two-{short_uid()}"
        events_scheduler_create_schedule_group(name_two, **kwargs)

        response = aws_client.scheduler.list_schedule_groups()

        assert len(response["ScheduleGroups"]) == 3  # default schedule group + 2 created

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(name_one, "<name-groupe-one>"),
                snapshot.transform.regex(name_two, "<name-groupe-two>"),
            ]
        )
        snapshot.match("list-schedule-groups", response)

    @markers.aws.validated
    def test_list_schedule_groups_not_found(self, aws_client, snapshot):
        response = aws_client.scheduler.list_schedule_groups()

        assert len(response["ScheduleGroups"]) == 1  # default schedule group

        snapshot.match("list-schedule-groups-not-found", response)
