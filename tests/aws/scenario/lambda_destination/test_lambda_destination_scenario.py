import json

import aws_cdk as cdk
import aws_cdk.aws_lambda as awslambda
import aws_cdk.aws_sns as sns
import pytest

from localstack.aws.api.lambda_ import InvocationType
from localstack.aws.connect import connect_to
from localstack.testing.pytest import markers
from localstack.testing.scenario.provisioning import InfraProvisioner
from localstack.utils.strings import short_uid, to_bytes
from localstack.utils.sync import wait_until

MAIN_FN_CODE = """
def handler(event, context):
    should_fail = event.get("should_fail", "0") == "1"
    message = event.get("message", "no message received")

    if should_fail:
        raise Exception("Failing per design.")

    return {"lstest_message": message}
"""

COLLECT_FN_CODE = """
import json

def handler(event, context):
    print(json.dumps(event))
    return {"hello": "world"}  # the return value here doesn't really matter
"""


class TestLambdaDestinationScenario:
    @pytest.fixture(scope="class", autouse=True)
    def infrastructure(self, aws_client):
        # stack definition
        stack = cdk.Stack(cdk.App(), "LambdaTestStack")

        collect_fn = awslambda.Function(
            stack,
            "CollectFn",
            code=awslambda.InlineCode(COLLECT_FN_CODE),
            handler="handler.handler",
            runtime=awslambda.Runtime.PYTHON_3_10,  # noqa
        )
        cdk.CfnOutput(stack, "CollectFunctionName", value=collect_fn.function_name)

        # event_bus = events.EventBus(stack, "DestinationBus")
        # queue = sqs.Queue(stack, "DestinationQueue")
        topic = sns.Topic(stack, "DestinationTopic")
        cdk.CfnOutput(stack, "DestinationTopicName", value=topic.topic_name)
        cdk.CfnOutput(stack, "DestinationTopicArn", value=topic.topic_arn)

        fn = awslambda.Function(
            stack,
            "DestinationFn",
            code=awslambda.InlineCode(MAIN_FN_CODE),
            handler="handler.handler",
            runtime=awslambda.Runtime.PYTHON_3_10,  # noqa
        )
        cdk.CfnOutput(stack, "DestinationFunctionName", value=fn.function_name)
        awslambda.EventInvokeConfig(
            stack,
            "TopicEic",
            function=fn,
            on_success=cdk.aws_lambda_destinations.SnsDestination(topic=topic),
            on_failure=cdk.aws_lambda_destinations.SnsDestination(topic=topic),
            retry_attempts=0,
        )
        collect_fn.add_event_source(cdk.aws_lambda_event_sources.SnsEventSource(topic))

        # provisioning
        provisioner = InfraProvisioner(aws_client)
        provisioner.add_cdk_stack(stack)
        with provisioner.provisioner(skip_teardown=False) as prov:
            yield prov

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Configuration.CodeSha256",
            "$..Tags",
            "$..Attributes.DeliveryPolicy",
            "$..Attributes.EffectiveDeliveryPolicy.defaultHealthyRetryPolicy",
            "$..Attributes.EffectiveDeliveryPolicy.guaranteed",
            "$..Attributes.EffectiveDeliveryPolicy.http",
            "$..Attributes.EffectiveDeliveryPolicy.sicklyRetryPolicy",
            "$..Attributes.EffectiveDeliveryPolicy.throttlePolicy",
            "$..Attributes.Policy.Statement..Action",
            "$..Attributes.SubscriptionsConfirmed",
        ]
    )
    def test_infra(self, infrastructure, aws_client, snapshot):
        outputs = infrastructure.get_stack_outputs("LambdaTestStack")
        collect_fn_name = outputs["CollectFunctionName"]
        main_fn_name = outputs["DestinationFunctionName"]
        topic_arn = outputs["DestinationTopicArn"]

        snapshot.add_transformer(snapshot.transform.lambda_api())
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "aws:cloudformation:logical-id", "replaced-value", reference_replacement=False
            ),
            priority=-1,
        )
        snapshot.add_transformer(
            snapshot.transform.key_value(
                "aws:cloudformation:stack-id", "replaced-value", reference_replacement=False
            ),
            priority=-1,
        )

        fn_1 = aws_client.lambda_.get_function(FunctionName=main_fn_name)
        fn_2 = aws_client.lambda_.get_function(FunctionName=collect_fn_name)

        snapshot.match("get_fn_1", fn_1)
        snapshot.match("get_fn_2", fn_2)

        eic = aws_client.lambda_.get_function_event_invoke_config(FunctionName=main_fn_name)
        assert eic["MaximumRetryAttempts"] == 0
        assert eic["DestinationConfig"]["OnSuccess"]["Destination"] == topic_arn
        assert eic["DestinationConfig"]["OnFailure"]["Destination"] == topic_arn

        snapshot.match("event_invoke_config", eic)

        topic_attr = aws_client.sns.get_topic_attributes(TopicArn=topic_arn)
        snapshot.match("topic_attributes", topic_attr)

    @markers.aws.validated
    def test_destination_sns(self, infrastructure, aws_client, snapshot):
        outputs = infrastructure.get_stack_outputs("LambdaTestStack")
        invoke_fn_name = outputs["DestinationFunctionName"]
        collect_fn_name = outputs["CollectFunctionName"]

        msg = f"message-{short_uid()}"

        # Success case
        response = aws_client.lambda_.invoke(
            FunctionName=invoke_fn_name,
            Payload=to_bytes(json.dumps({"message": msg, "should_fail": "0"})),
            InvocationType=InvocationType.Event,
        )
        snapshot.match("successfull_invoke", response)

        # Failure case
        response = aws_client.lambda_.invoke(
            FunctionName=invoke_fn_name,
            Payload=to_bytes(json.dumps({"message": msg, "should_fail": "1"})),
            InvocationType=InvocationType.Event,
        )
        snapshot.match("unsuccessful_invoke", response)

        def wait_for_logs():
            events = connect_to().logs.filter_log_events(
                logGroupName=f"/aws/lambda/{collect_fn_name}"
            )["events"]
            message_events = [e["message"] for e in events if msg in e["message"]]
            return len(message_events) >= 2

        wait_until(wait_for_logs)
