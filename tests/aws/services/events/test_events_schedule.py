from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid


class TestScheduleRate:
    @markers.aws.validated
    def test_put_rule_with_schedule(self, events_put_rule, aws_client, snapshot):
        rule_name = f"rule-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

        response = events_put_rule(Name=rule_name, ScheduleExpression="rate(1 minute)")
        snapshot.match("put-rule", response)

        response = aws_client.events.list_rules(NamePrefix=rule_name)

        snapshot.match("list-rules", response)
