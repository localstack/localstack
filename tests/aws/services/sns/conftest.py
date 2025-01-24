import pytest

from localstack.utils.strings import short_uid

LAMBDA_FN_SNS_ENDPOINT = """
import boto3, json, os
def handler(event, *args):
    if "AWS_ENDPOINT_URL" in os.environ:
        sqs_client = boto3.client("sqs", endpoint_url=os.environ["AWS_ENDPOINT_URL"])
    else:
        sqs_client = boto3.client("sqs")

    queue_url = os.environ.get("SQS_QUEUE_URL")
    message = {"event": event}
    sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(message), MessageGroupId="1")
    return {"statusCode": 200}
"""


@pytest.fixture
def create_sns_http_endpoint_and_queue(
    aws_client, account_id, create_lambda_function, sqs_create_queue
):
    lambda_client = aws_client.lambda_

    def _create_sns_http_endpoint():
        function_name = f"lambda_fn_sns_endpoint-{short_uid()}"

        # create SQS queue for results
        queue_name = f"{function_name}.fifo"
        queue_attrs = {"FifoQueue": "true", "ContentBasedDeduplication": "true"}
        queue_url = sqs_create_queue(QueueName=queue_name, Attributes=queue_attrs)
        aws_client.sqs.add_permission(
            QueueUrl=queue_url,
            Label=f"lambda-sqs-{short_uid()}",
            AWSAccountIds=[account_id],
            Actions=["SendMessage"],
        )

        create_lambda_function(
            func_name=function_name,
            handler_file=LAMBDA_FN_SNS_ENDPOINT,
            envvars={"SQS_QUEUE_URL": queue_url},
        )
        create_url_response = lambda_client.create_function_url_config(
            FunctionName=function_name, AuthType="NONE", InvokeMode="BUFFERED"
        )
        aws_client.lambda_.add_permission(
            FunctionName=function_name,
            StatementId="urlPermission",
            Action="lambda:InvokeFunctionUrl",
            Principal="*",
            FunctionUrlAuthType="NONE",
        )
        return create_url_response["FunctionUrl"], queue_url

    return _create_sns_http_endpoint
