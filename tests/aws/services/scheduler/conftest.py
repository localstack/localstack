import logging

import pytest

from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)


@pytest.fixture
def events_scheduler_create_schedule_group(aws_client):
    schedule_group_names = []

    def _events_scheduler_create_schedule_group(name, **kwargs):
        if not name:
            name = f"events-test-schedule-groupe-{short_uid()}"
        response = aws_client.scheduler.create_schedule_group(Name=name, **kwargs)
        schedule_group_arn = response["ScheduleGroupArn"]
        schedule_group_names.append(name)

        return schedule_group_arn

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
