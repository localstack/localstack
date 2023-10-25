import json
import logging

import pytest

from localstack.testing.aws.eventbus_utils import trigger_scheduled_rule
from localstack.testing.pytest import markers
from localstack.testing.snapshots.transformer_utility import TransformerUtility
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
@markers.snapshot.skip_snapshot_verify(
    paths=[
        # tokens and IDs cannot be properly transformed
        "$..eventId",
        "$..uploadSequenceToken",
        # FIXME: storedBytes should be implemented
        "$..storedBytes",
    ]
)
def test_scheduled_rule_logs(
    logs_log_group,
    events_put_rule,
    add_logs_resource_policy_for_rule,
    aws_client,
    snapshot,
):
    schedule_expression = "rate(1 minute)"
    rule_name = f"rule-{short_uid()}"
    snapshot.add_transformers_list(
        [
            snapshot.transform.regex(rule_name, "<rule-name>"),
            snapshot.transform.regex(logs_log_group, "<log-group-name>"),
        ]
    )
    snapshot.add_transformer(TransformerUtility.logs_api())

    response = aws_client.logs.describe_log_groups(logGroupNamePrefix=logs_log_group)
    log_group_arn = response["logGroups"][0]["arn"]

    rule_arn = events_put_rule(Name=rule_name, ScheduleExpression=schedule_expression)["RuleArn"]
    add_logs_resource_policy_for_rule(rule_arn, log_group_arn)

    # TODO: add target to test InputTransformer
    aws_client.events.put_targets(
        Rule=rule_name,
        Targets=[
            {"Id": "1", "Arn": log_group_arn},
            {"Id": "2", "Arn": log_group_arn},
        ],
    )

    trigger_scheduled_rule(rule_arn)

    # wait for log stream to be created
    def _get_log_stream():
        result = (
            aws_client.logs.get_paginator("describe_log_streams")
            .paginate(logGroupName=logs_log_group)
            .build_full_result()
        )
        assert len(result["logStreams"]) >= 2
        # FIXME: this is a check against a flake in LocalStack
        # sometimes the logStreams are created but not yet populated with events, so the snapshot fails
        # assert that the stream has the events before returning
        assert result["logStreams"][0]["firstEventTimestamp"]
        return result["logStreams"]

    log_streams = retry(_get_log_stream, 60)
    log_streams.sort(key=lambda stream: stream["creationTime"])
    snapshot.match("log-streams", log_streams)

    # collect events from log streams in group
    def _get_events():
        _events = []

        _response = (
            aws_client.logs.get_paginator("filter_log_events")
            .paginate(logGroupName=logs_log_group)
            .build_full_result()
        )
        _events.extend(_response["events"])

        if len(_events) < 2:
            raise AssertionError(
                f"Expected at least two events in log group streams, was {_events}"
            )
        return _events

    events = retry(_get_events, retries=5)

    events.sort(key=lambda event: event["timestamp"])

    snapshot.match("log-events", events)
