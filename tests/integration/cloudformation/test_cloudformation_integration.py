from localstack.utils.common import short_uid
from localstack.utils.generic.wait_utils import wait_until
from tests.integration.cloudformation.test_cloudformation_changesets import load_template_raw


def test_s3_sns_lambda(
    cfn_client,
    logs_client,
    cleanup_stacks,
    cleanup_changesets,
    is_change_set_created_and_available,
    is_stack_created,
    events_client,
    sqs_client,
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
        assert len(stack["Outputs"]) == 6
        topic_arn = [o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "TopicArn"][0]
        assert topic_arn
        assert "us-gov" in topic_arn
        queue_url = [o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "QueueUrl"][0]
        event_bus_name = [
            o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "EventBusName"
        ][0]
        events_client.put_events(
            Entries=[
                {
                    "DetailType": "test",
                    "Detail": '{"something": "otherthing"}',
                    "EventBusName": event_bus_name,
                },
            ]
        )

        # queue_url = [o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "QueueUrl"][0]
        # event_bus_name = [
        #     o["OutputValue"] for o in stack["Outputs"] if o["OutputKey"] == "EventBusName"
        # ][0]
        # events_client.put_events(Entries=[
        #     {
        #         "Source": 'enterprise-test',
        #         "DetailType": 'test',
        #         "Detail": "something",
        #         "EventBusName": event_bus_name,
        #     },
        # ])

        msgs = sqs_client.receive_message(QueueUrl=queue_url)
        assert len(msgs["Messages"]) > 0

    finally:
        pass
        # cleanup_changesets([change_set_id])
        # cleanup_stacks([stack_id])
