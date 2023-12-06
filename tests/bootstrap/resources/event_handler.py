import json
import os

import boto3
import requests

client = boto3.client("s3", endpoint_url=os.environ["AWS_ENDPOINT_URL"])


def handler(event, context):
    custom_localstack_hostname = os.environ["CUSTOM_LOCALSTACK_HOSTNAME"]
    domain_endpoint = os.environ["DOMAIN_ENDPOINT"]
    results_bucket = os.environ["RESULTS_BUCKET"]
    results_key = os.environ["RESULTS_KEY"]
    assert (
        custom_localstack_hostname in domain_endpoint
    ), f"{custom_localstack_hostname} not in {domain_endpoint}"

    print(f"Event handler function {context.function_name} invoked")

    for record in event["Records"]:
        body = json.loads(record["body"])
        message = json.loads(body["Message"])
        print(f"Got message: {message}")

        # wait for cluster ready
        try:
            r = requests.get(
                f"http://{domain_endpoint}/_cluster/health?wait_for_status=yellow,timeout=50s",
            )
            r.raise_for_status()
        except Exception as e:
            print(f"Error fetching cluster health status: {e!r}")

        assert custom_localstack_hostname in body["UnsubscribeURL"]

        # write the result to s3
        client.put_object(
            Bucket=results_bucket, Key=results_key, Body=message["message"].encode("utf8")
        )

        # just take the first record for now
        return
