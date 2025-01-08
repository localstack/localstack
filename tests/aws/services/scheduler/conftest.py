import logging
import time

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)


@pytest.fixture
def events_scheduler_create_schedule(aws_client, sqs_as_events_schedule_target):
    schedule_names = []

    def _events_scheduler_create_schedule(
        name, flexible_time_window=None, schedule_expression=None, target=None, **kwargs
    ):
        if not name:
            name = f"events-test-schedule-{short_uid()}"
        if not flexible_time_window:
            flexible_time_window = {
                "Mode": "OFF",
            }
        if not schedule_expression:
            schedule_expression = "rate(1 minute)"
        if not target:
            _, queue_arn, role_arn = sqs_as_events_schedule_target()
            target = {"Arn": queue_arn, "Input": '{"key": "value"}', "RoleArn": role_arn}

        response = aws_client.scheduler.create_schedule(
            Name=name,
            FlexibleTimeWindow=flexible_time_window,
            ScheduleExpression=schedule_expression,
            Target=target,
            **kwargs,
        )
        schedule_names.append(name)

        return response

    yield _events_scheduler_create_schedule

    def _wait_for_schedule_deletion(schedule_name):
        try:
            aws_client.scheduler.get_schedule_group(Name=schedule_name)
        except Exception:
            LOG.info("Schedule %s deleted", schedule_name)
            return

        raise Exception(f"Schedule {schedule_name} not deleted")

    for schedule_name in schedule_names:
        try:
            aws_client.scheduler.delete_schedule(Name=schedule_name)
        except Exception:
            LOG.info("Failed to delete schedule %s", schedule_name)

        # wait for resource to be deleted
        retry(
            _wait_for_schedule_deletion,
            retries=20,
            sleep=2,
            schedule_name=schedule_name,
        )


@pytest.fixture
def events_scheduler_create_schedule_group(aws_client):
    schedule_group_names = []

    def _events_scheduler_create_schedule_group(name, **kwargs):
        if not name:
            name = f"events-test-schedule-groupe-{short_uid()}"
        response = aws_client.scheduler.create_schedule_group(Name=name, **kwargs)
        schedule_group_names.append(name)

        return response

    yield _events_scheduler_create_schedule_group

    def _wait_for_schedule_group_deletion(schedule_group_name):
        try:
            aws_client.scheduler.get_schedule_group(Name=schedule_group_name)
        except Exception:
            LOG.info("Schedule group %s deleted", schedule_group_name)
            return

        raise Exception(f"Schedule group {schedule_group_name} not deleted")

    for schedule_group_name in schedule_group_names:
        try:
            aws_client.scheduler.delete_schedule_group(Name=schedule_group_name)
        except Exception:
            LOG.info("Failed to delete schedule group %s", schedule_group_name)

        # wait for resource to be deleted
        retry(
            _wait_for_schedule_group_deletion,
            retries=20,
            sleep=2,
            schedule_group_name=schedule_group_name,
        )


@pytest.fixture
def sqs_as_events_schedule_target(aws_client, sqs_get_queue_arn, create_iam_role_with_policy):
    queue_urls = []

    def _sqs_as_events_schedule_target(queue_name: str | None = None) -> tuple[str, str, str]:
        if not queue_name:
            queue_name = f"tests-queue-{short_uid()}"
        sqs_client = aws_client.sqs
        queue_url = sqs_client.create_queue(QueueName=queue_name)["QueueUrl"]
        queue_urls.append(queue_url)
        queue_arn = sqs_get_queue_arn(queue_url)

        role_name = f"events-scheduler-role-{short_uid()}"
        policy_name = f"events-scheduler-policy-{short_uid()}"
        role_definition = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "scheduler.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        policy_definition = {
            "Version": "2012-10-17",
            "Id": f"sqs-eventbridge-{short_uid()}",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "sqs:SendMessage",
                    "Resource": queue_arn,
                }
            ],
        }
        role_arn = create_iam_role_with_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            RoleDefinition=role_definition,
            PolicyDefinition=policy_definition,
        )

        if is_aws_cloud():
            # wait for the role to be available
            time.sleep(10)

        return queue_url, queue_arn, role_arn

    yield _sqs_as_events_schedule_target

    for queue_url in queue_urls:
        try:
            aws_client.sqs.delete_queue(QueueUrl=queue_url)
        except Exception as e:
            LOG.debug("error cleaning up queue %s: %s", queue_url, e)
