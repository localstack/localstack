from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_events_sqs_sns_lambda(
    cfn_client,
    logs_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    events_client,
):
    stack_name = f"stack-{short_uid()}"
    change_set_name = f"change-set-{short_uid()}"
    response = cfn_client.create_change_set(
        StackName=stack_name,
        ChangeSetName=change_set_name,
        TemplateBody=load_template_raw("integration_events_sns_sqs_lambda.yaml"),
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
        events_client.put_events(
            Entries=[
                {
                    "DetailType": "test-detail-type",
                    "Detail": '{"app": "localstack"}',
                    "EventBusName": bus_name,
                },
            ]
        )

        # verifying lambdas have been called and the respective log groups/streams were created
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
