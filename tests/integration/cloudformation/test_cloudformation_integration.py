import json
import os

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until


def test_events_sqs_sns_lambda(logs_client, events_client, sns_client, deploy_cfn_template):
    ref_id = short_uid()
    stack = deploy_cfn_template(
        template_path=os.path.join(
            os.path.dirname(__file__), "../templates/integration_events_sns_sqs_lambda.yaml"
        ),
        template_mapping={"ref_id": ref_id},
    )

    assert len(stack.outputs) == 7
    lambda_name = stack.outputs["FnName"]
    bus_name = stack.outputs["EventBusName"]

    # verify SNS topic policy is present
    topic_arn = aws_stack.sns_topic_arn(f"topic-{ref_id}")  # TODO: make this an output
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

    # verifying functions have been called and the respective log groups/streams were created
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

        assert [e for e in all_events if f"topic-{ref_id}" in e["message"]]
        assert [e for e in all_events if f"queue-{ref_id}" in e["message"]]
        return True

    assert wait_until(_check_lambda_invocations)
