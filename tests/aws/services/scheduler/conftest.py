import logging

import pytest

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
