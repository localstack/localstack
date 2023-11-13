import json
import os

# import requests
import boto3

# CUSTOM_LOCALSTACK_HOSTNAME = os.environ["CUSTOM_LOCALSTACK_HOSTNAME"]
DOMAIN_ENDPOINT = os.environ["DOMAIN_ENDPOINT"]
RESULTS_BUCKET = os.environ["RESULTS_BUCKET"]
RESULTS_KEY = os.environ["RESULTS_KEY"]
# assert CUSTOM_LOCALSTACK_HOSTNAME in DOMAIN_ENDPOINT

client = boto3.client("s3", endpoint_url=os.environ["AWS_ENDPOINT_URL"])


def handler(event, context):
    print(f"Event handler function {context.function_name} invoked")

    for record in event["Records"]:
        body = json.loads(record["body"])
        message = json.loads(body["Message"])
        print(f"Got message: {message}")

        # wait for cluster ready
        # r = requests.get(
        #     f"http://{DOMAIN_ENDPOINT}/_cluster/health?wait_for_status=yellow,timeout=50s"
        # )
        # r.raise_for_status()

        # assert CUSTOM_LOCALSTACK_HOSTNAME in body["UnsubscribeURL"]

        # write the result to s3
        client.put_object(
            Bucket=RESULTS_BUCKET, Key=RESULTS_KEY, Body=message["message"].encode("utf8")
        )

        # just take the first record for now
        return
