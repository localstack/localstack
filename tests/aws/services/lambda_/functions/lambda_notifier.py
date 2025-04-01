import datetime
import json
import os
import time

import boto3

sqs_client = boto3.client("sqs", endpoint_url=os.environ.get("AWS_ENDPOINT_URL"))


def handler(event, context):
    """Example: Send a message to the queue_url provided in notify and then wait for 7 seconds.
    The message includes the value of the environment variable called "FUNCTION_VARIANT".
    aws_client.lambda_.invoke(
        FunctionName=fn_arn,
        InvocationType="Event",
        Payload=json.dumps({"notify": queue_url, "env_var": "FUNCTION_VARIANT", "label": "01-sleep", "wait": 7})
    )

    Parameters:
    * `notify`: SQS queue URL to notify a message
    * `env_var`: Name of the environment variable that should be included in the message
    * `label`: Label to be included in the message
    * `wait`: Time in seconds to sleep
    """
    if queue_url := event.get("notify"):
        message = {
            "request_id": context.aws_request_id,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
        }
        if env_var := event.get("env_var"):
            message[env_var] = os.environ[env_var]
        if label := event.get("label"):
            message["label"] = label
        print(f"Notify message: {message}")
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(message))

    if wait_time := event.get("wait"):
        print(f"Sleeping for {wait_time} seconds ...")
        time.sleep(wait_time)
