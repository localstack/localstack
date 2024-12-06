import pytest

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
