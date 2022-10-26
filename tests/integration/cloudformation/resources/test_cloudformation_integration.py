import json
import os

from localstack.utils.strings import short_uid
from localstack.utils.sync import wait_until


def test_events_sqs_sns_lambda(logs_client, events_client, sns_client, deploy_cfn_template):
    function_name = f"function-{short_uid()}"
    queue_name = f"queue-{short_uid()}"
    topic_name = f"topic-{short_uid()}"
    bus_name = f"bus-{short_uid()}"
    rule_name = f"function-{short_uid()}"

    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../../templates/integration_events_sns_sqs_lambda.yaml"
        ),
        parameters={
            "FunctionName": function_name,
            "QueueName": queue_name,
            "TopicName": topic_name,
            "BusName": bus_name,
            "RuleName": rule_name,
        },
    )

    assert len(stack.outputs) == 7
    lambda_name = stack.outputs["FnName"]
    bus_name = stack.outputs["EventBusName"]

    topic_arn = stack.outputs["TopicArn"]
    result = sns_client.get_topic_attributes(TopicArn=topic_arn)["Attributes"]
    assert json.loads(result.get("Policy")) == {
        "Statement": [
            {
                "Action": "sns:Publish",
                "Effect": "Allow",
                "Principal": {"Service": "events.amazonaws.com"},
                "Resource": topic_arn,
                "Sid": "0",
            }
        ],
        "Version": "2012-10-17",
    }

    # put events
    events_client.put_events(
        Entries=[
            {
                "DetailType": "test-detail-type",
                "Detail": '{"app": "localstack"}',
                "EventBusName": bus_name,
            },
        ]
    )

    def _check_lambda_invocations():
        groups = logs_client.describe_log_groups(logGroupNamePrefix=f"/aws/lambda/{lambda_name}")
        streams = logs_client.describe_log_streams(
            logGroupName=groups["logGroups"][0]["logGroupName"]
        )
        assert (
            0 < len(streams) <= 2
        )  # should be 1 or 2 because of the two potentially simultaneous calls

        all_events = []
        for s in streams["logStreams"]:
            events = logs_client.get_log_events(
                logGroupName=groups["logGroups"][0]["logGroupName"],
                logStreamName=s["logStreamName"],
            )["events"]
            all_events.extend(events)

        assert [e for e in all_events if topic_name in e["message"]]
        assert [e for e in all_events if queue_name in e["message"]]
        return True

    assert wait_until(_check_lambda_invocations)
