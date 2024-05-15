import json

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.test_events import TEST_EVENT_PATTERN


class TestRuleTags:
    @markers.aws.validated
    def tests_tag_untag_resource(self, events_put_rule, aws_client, snapshot):
        bus_name = f"test_bus-{short_uid()}"
        aws_client.events.create_event_bus(Name=bus_name)

        rule_name = f"test_rule-{short_uid()}"
        response = events_put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
        )
        rule_arn = response["RuleArn"]

        tag_key_2 = "tag2"
        response_tag_resource = aws_client.events.tag_resource(
            ResourceARN=rule_arn,
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

        response = aws_client.events.list_tags_for_resource(ResourceARN=rule_arn)
        snapshot.match("list_tagged_rule", response)

        response_untag_resource = aws_client.events.untag_resource(
            ResourceARN=rule_arn,
            TagKeys=[tag_key_2],
        )
        snapshot.match("untag_resource", response_untag_resource)

        response = aws_client.events.list_tags_for_resource(ResourceARN=rule_arn)
        snapshot.match("list_untagged_rule", response)
