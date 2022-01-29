import json

from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.utils import load_template


def test_events_sqs_sns_lambda(
    cfn_client,
    logs_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    events_client,
    sns_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    ref_id = short_uid()
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template("integration_events_sns_sqs_lambda.yaml", ref_id=ref_id),
        ChangeSetType="CREATE",
        Capabilities=["CAPABILITY_IAM"],
    )
    change_set_id = response["Id"]
    stack_id = response["StackId"]

    try:
        wait_until(is_change_set_created_and_available(change_set_id))
        cfn_client.execute_change_set(ChangeSetName=change_set_id)
        wait_until(is_stack_created(stack_id))
        describe_response = cfn_client.describe_stacks(StackName=stack_id)
        stack = describe_response["Stacks"][0]
        assert stack["StackStatus"] == "CREATE_COMPLETE"
        assert len(stack["Outputs"]) == 7
        lambda_name = [o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "FnName"][0]
        bus_name = [o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "EventBusName"][
            0
        ]

        # verify SNS topic policy is present
        topic_arn = aws_stack.sns_topic_arn(f"topic-{ref_id}")
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
            groups = logs_client.describe_log_groups(
                logGroupNamePrefix=f"/aws/lambda/{lambda_name}"
            )
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

            assert [e for e in all_events if "enterprise-topic" in e["message"]]
            assert [e for e in all_events if "enterprise-queue" in e["message"]]
            return True

        wait_until(_check_lambda_invocations)

    finally:
        cleanup_changesets([change_set_id])
        cleanup_stacks([stack_id])
