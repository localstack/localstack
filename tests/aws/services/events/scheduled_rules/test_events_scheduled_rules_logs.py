import json
import logging

import pytest

from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

LOG = logging.getLogger(__name__)


@pytest.fixture
def logs_log_group(aws_client):
    name = f"test-log-group-{short_uid()}"
    aws_client.logs.create_log_group(logGroupName=name)
    yield name
    aws_client.logs.delete_log_group(logGroupName=name)


@pytest.fixture
def add_logs_resource_policy_for_rule(aws_client):
    policies = []

    def _provide_access(rule_arn: str, log_group_arn: str):
        policy_name = f"test-policy-{short_uid()}"

        policy = aws_client.logs.put_resource_policy(
            policyName=policy_name,
            policyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowPutEvents",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": ["logs:PutLogEvents", "logs:CreateLogStream"],
                            "Resource": log_group_arn,
                        },
                    ],
                }
            ),
        )

        policies.append(policy_name)

        return policy

    yield _provide_access

    for policy_name in policies:
        aws_client.logs.delete_resource_policy(policyName=policy_name)


@markers.aws.validated
def test_scheduled_rule_logs(
    logs_log_group,
    events_put_rule,
    trigger_scheduled_rule,
    add_logs_resource_policy_for_rule,
    aws_client,
    snapshot,
):
    schedule_expression = "rate(1 minute)"
    rule_name = f"rule-{short_uid()}"
    snapshot.add_transformer(snapshot.transform.regex(rule_name, "<rule-name>"))

    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=logs_log_group)
    log_group_arn = response["logGroups"][0]["arn"]

    rule_arn = events_put_rule(Name=rule_name, ScheduleExpression=schedule_expression)["RuleArn"]
    add_logs_resource_policy_for_rule(rule_arn, log_group_arn)

    # TODO: add target to test InputTransformer
    aws_client.events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "1", "Arn": log_group_arn},
        ],
    )

    trigger_scheduled_rule(rule_arn)

    # wait for log stream to be created
    def _get_log_stream():
        return aws_client.logs.describe_log_streams(logGroupName=logs_log_group)["logStreams"][0]

    retry(_get_log_stream, 60)

    # collect events from log streams in group
    def _get_events():
        _events = []

        for log_stream in aws_client.logs.describe_log_streams(logGroupName=logs_log_group)[
            "logStreams"
        ]:
            _response = aws_client.logs.get_log_events(
                logGroupName=logs_log_group, logStreamName=log_stream["logStreamName"], limit=10
            )
            _events.extend(_response.get("events", []))

        if len(_events) < 1:
            raise AssertionError(f"Expected at least two events in log stream, was {_events}")
        return _events

    events = retry(_get_events, retries=5)

    snapshot.match("log-evens", events)
