import json
import logging
import time

import pytest

from localstack.testing.aws.util import is_aws_cloud
from localstack.utils.strings import short_uid

LOG = logging.getLogger(__name__)


@pytest.fixture
def events_scheduler_create_schedule_group(aws_client):
    schedule_group_arns = []

    def _events_scheduler_create_schedule_group(name, **kwargs):
        if not name:
            name = f"events-test-schedule-groupe-{short_uid()}"
        response = aws_client.scheduler.create_schedule_group(Name=name, **kwargs)
        schedule_group_arn = response["ScheduleGroupArn"]
        schedule_group_arns.append(schedule_group_arn)

        return schedule_group_arn

    yield _events_scheduler_create_schedule_group

    for schedule_group_arn in schedule_group_arns:
        try:
            aws_client.scheduler.delete_schedule_group(ScheduleGroupArn=schedule_group_arn)
        except Exception:
            LOG.info("Failed to delete schedule group %s", schedule_group_arn)


@pytest.fixture(scope="module")
def scheduler_role(aws_client):
    role_name = f"test-scheduler-role-{short_uid()}"
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
    )
    role_arn = role["Role"]["Arn"]

    if is_aws_cloud():
        time.sleep(10)

    yield role_arn

    try:
        aws_client.iam.delete_role(RoleName=role_name)
    except Exception:
        LOG.debug("Failed to delete role %s", role_name)
