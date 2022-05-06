import json

import aws_cdk as cdk
import pytest

from localstack.utils.sync import wait_until

FN_CODE = """
import json

def handler(event, ctx):
    print(json.dumps(event))
    return {"a": "b"}
"""


class TestLambdaSqsEventSource:

    # setup (1x cloudformation, 1x SDK based)
    # can be switched between "fucntion" and "class" scope depending on what behavior you need
    # try to use class where possible
    # if CI encounters an error here with a "class" scoped fixture it can retry using "function" scope (? implementation ?)
    @pytest.fixture(scope="function")  # TODO: remove fixture dependency and make class scoped
    def stack(self, deploy_cfn_template):
        app = cdk.App()
        stack = cdk.Stack(app, "Stack")

        queue = cdk.aws_sqs.Queue(stack, "myqueue")
        fn = cdk.aws_lambda.Function(
            stack,
            "fn",
            code=cdk.aws_lambda.InlineCode(FN_CODE),
            runtime=cdk.aws_lambda.Runtime.PYTHON_3_8,
            handler="index.handler",
        )
        event_source = cdk.aws_lambda_event_sources.SqsEventSource(queue=queue, batch_size=1)
        fn.add_event_source(event_source)

        cdk.CfnOutput(stack, "QueueUrlOutput", value=queue.queue_url)
        cdk.CfnOutput(stack, "FnNameOutput", value=fn.function_name)
        cdk.CfnOutput(stack, "ESMIdOutput", value=event_source.event_source_mapping_id)

        rendered_template = cdk.assertions.Template.from_stack(stack).to_json()
        deploy_cfn_template(template_file_name="cdk_bootstrap_v10.yaml")

        yield deploy_cfn_template(template=json.dumps(rendered_template))

    def test_resource_states(self, stack, lambda_client, sqs_client, snapshot):
        snapshot.match(
            "queue-attributes",
            sqs_client.get_queue_attributes(QueueUrl=stack.outputs["QueueUrlOutput"]),
        )
        snapshot.match(
            "lambda-get-function",
            lambda_client.get_function(FunctionName=stack.outputs["FnNameOutput"]),
        )
        snapshot.match(
            "esm-get", lambda_client.get_event_source_mapping(UUID=stack.outputs["ESMIdOutput"])
        )

    def test_message_triggers_lambda(self, stack, lambda_client, sqs_client, logs_client):
        sqs_client.send_message(QueueUrl=stack.outputs["QueueUrlOutput"], MessageBody="test-1234")

        # todo create better utils for call verifications
        def check_logs():
            return any(
                "test-1234" in e["message"]
                for e in logs_client.filter_log_events(
                    logGroupName=f'/aws/lambda/{stack.outputs["FnNameOutput"]}'
                )["events"]
            )

        assert wait_until(check_logs)
