import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.test_events import TEST_EVENT_PATTERN


@markers.aws.validated
@pytest.mark.parametrize("resource_to_tag", ["event_bus", "rule"])
def tests_tag_untag_resource(
    resource_to_tag, events_create_event_bus, events_put_rule, aws_client, snapshot
):
    bus_name = f"test_bus-{short_uid()}"
    response = events_create_event_bus(Name=bus_name)
    event_bus_arn = response["EventBusArn"]

    rule_name = f"test_rule-{short_uid()}"
    response = events_put_rule(
        Name=rule_name,
        EventBusName=bus_name,
        EventPattern=json.dumps(TEST_EVENT_PATTERN),
    )
    rule_arn = response["RuleArn"]

    if resource_to_tag == "event_bus":
        resource_arn = event_bus_arn
    if resource_to_tag == "rule":
        resource_arn = rule_arn

    tag_key_2 = "tag2"
    response_tag_resource = aws_client.events.tag_resource(
        ResourceARN=resource_arn,
        Tags=[
            {
                "Key": "tag1",
                "Value": "value1",
            },
            {
                "Key": tag_key_2,
                "Value": "value2",
            },
        ],
    )
    snapshot.match("tag_resource", response_tag_resource)

    response = aws_client.events.list_tags_for_resource(ResourceARN=resource_arn)
    snapshot.match("list_tagged_rule", response)

    response_untag_resource = aws_client.events.untag_resource(
        ResourceARN=resource_arn,
        TagKeys=[tag_key_2],
    )
    snapshot.match("untag_resource", response_untag_resource)

    response = aws_client.events.list_tags_for_resource(ResourceARN=resource_arn)
    snapshot.match("list_untagged_rule", response)
