import pytest
from botocore.exceptions import ClientError

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

    @markers.aws.validated
    @pytest.mark.parametrize(
        "schedule_expression",
        [
            "rate(10 seconds)",
            "rate(10 years)",
            "rate(1 minutes)",
            "rate(1 hours)",
            "rate(1 days)",
            "rate(10 minute)",
            "rate(10 hour)",
            "rate(10 day)",
            "rate()",
            "rate(10)",
            "rate(10 minutess)",
            "rate(foo minutes)",
            "rate(0 minutes)",
            "rate(-10 minutes)",
            "rate(10 MINUTES)",
            "rate( 10 minutes )",
            " rate(10 minutes)",
        ],
    )
    def test_put_rule_with_invalid_schedule(self, schedule_expression, aws_client):
        with pytest.raises(ClientError) as e:
            aws_client.events.put_rule(
                Name=f"rule-{short_uid()}", ScheduleExpression=schedule_expression
            )

        assert e.value.response["Error"] == {
            "Code": "ValidationException",
            "Message": "Parameter ScheduleExpression is not valid.",
        }
