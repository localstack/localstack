import json

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from tests.aws.services.events.test_events import TEST_EVENT_PATTERN


class TestEventsPartitions:
    # We only have access to the AWS partition, not CHINA/US-GOV/etc
    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_event_bus_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        events_client = aws_client_factory(region_name=region).events
        bus_name = f"bus-{short_uid()}"
        arn = events_client.create_event_bus(
            Name=bus_name,
            Tags=[{"Key": "name", "Value": bus_name}],
        )["EventBusArn"]
        assert arn == f"arn:{partition}:events:{region}:{account_id}:event-bus/{bus_name}"

        tags = events_client.list_tags_for_resource(ResourceARN=arn)["Tags"]
        assert tags == [{"Key": "name", "Value": bus_name}]

        events_client.delete_event_bus(Name=bus_name)

    @markers.aws.manual_setup_required
    @pytest.mark.parametrize("region,partition", [("us-east-1", "aws"), ("cn-north-1", "aws-cn")])
    def test_event_rules_in_different_partitions(
        self, account_id, aws_client_factory, region, partition
    ):
        events_client = aws_client_factory(region_name=region).events
        bus_name = f"bus-{short_uid()}"
        events_client.create_event_bus(Name=bus_name)["EventBusArn"]

        rule_name = f"test-rule-{short_uid()}"
        rule_arn = events_client.put_rule(
            Name=rule_name,
            EventBusName=bus_name,
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            Tags=[{"Key": "name", "Value": rule_name}],
        )["RuleArn"]
        assert (
            rule_arn == f"arn:{partition}:events:{region}:{account_id}:rule/{bus_name}/{rule_name}"
        )

        tags = events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert tags == [{"Key": "name", "Value": rule_name}]

        rule_name = f"test-rule-{short_uid()}"
        rule_arn = events_client.put_rule(
            Name=rule_name,
            EventBusName="default",
            EventPattern=json.dumps(TEST_EVENT_PATTERN),
            Tags=[{"Key": "name", "Value": "default"}],
        )["RuleArn"]
        assert rule_arn == f"arn:{partition}:events:{region}:{account_id}:rule/{rule_name}"

        tags = events_client.list_tags_for_resource(ResourceARN=rule_arn)["Tags"]
        assert tags == [{"Key": "name", "Value": "default"}]

        events_client.delete_event_bus(Name=bus_name)
