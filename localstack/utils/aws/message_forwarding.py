import json
import logging
from typing import Dict

from localstack.services.awslambda.lambda_executors import InvocationException, InvocationResult
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.aws.aws_stack import connect_to_service, firehose_name, get_sqs_queue_url
from localstack.utils.common import long_uid
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import timestamp_millis, to_bytes
from localstack.utils.generic import dict_utils

LOG = logging.getLogger(__name__)


def lambda_result_to_destination(
    func_details: LambdaFunction,
    event: Dict,
    result: InvocationResult,
    is_async: bool,
    error: InvocationException,
):
    if not func_details.destination_enabled():
        return

    payload = {
        "version": "1.0",
        "timestamp": timestamp_millis(),
        "requestContext": {
            "requestId": long_uid(),
            "functionArn": func_details.arn(),
            "condition": "RetriesExhausted",
            "approximateInvokeCount": 1,
        },
        "requestPayload": event,
        "responseContext": {"statusCode": 200, "executedVersion": "$LATEST"},
        "responsePayload": {},
    }

    if result and result.result:
        try:
            payload["requestContext"]["condition"] = "Success"
            payload["responsePayload"] = json.loads(result.result)
        except Exception:
            payload["responsePayload"] = result.result

    if error:
        payload["responseContext"]["functionError"] = "Unhandled"
        # add the result in the response payload
        if error.result is not None:
            payload["responsePayload"] = json.loads(error.result)
        send_event_to_target(func_details.on_failed_invocation, payload)
        return

    if func_details.on_successful_invocation is not None:
        send_event_to_target(func_details.on_successful_invocation, payload)


def send_event_to_target(
    target_arn: str, event: Dict, target_attributes: Dict = None, asynchronous: bool = True
):
    region = target_arn.split(":")[3]

    if ":lambda:" in target_arn:
        from localstack.services.awslambda import lambda_api

        lambda_api.run_lambda(
            func_arn=target_arn, event=event, context={}, asynchronous=asynchronous
        )

    elif ":sns:" in target_arn:
        sns_client = connect_to_service("sns", region_name=region)
        sns_client.publish(TopicArn=target_arn, Message=json.dumps(event))

    elif ":sqs:" in target_arn:
        sqs_client = connect_to_service("sqs", region_name=region)
        queue_url = get_sqs_queue_url(target_arn)
        msg_group_id = dict_utils.get_safe(target_attributes, "$.SqsParameters.MessageGroupId")
        kwargs = {"MessageGroupId": msg_group_id} if msg_group_id else {}
        sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(event), **kwargs)

    elif ":states:" in target_arn:
        stepfunctions_client = connect_to_service("stepfunctions", region_name=region)
        stepfunctions_client.start_execution(stateMachineArn=target_arn, input=json.dumps(event))

    elif ":firehose:" in target_arn:
        delivery_stream_name = firehose_name(target_arn)
        firehose_client = connect_to_service("firehose", region_name=region)
        firehose_client.put_record(
            DeliveryStreamName=delivery_stream_name,
            Record={"Data": to_bytes(json.dumps(event))},
        )

    elif ":events:" in target_arn:
        if ":api-destination/" in target_arn or ":destination/" in target_arn:
            send_event_to_api_destination(target_arn, event)

        else:
            events_client = connect_to_service("events", region_name=region)
            eventbus_name = target_arn.split(":")[-1].split("/")[-1]
            events_client.put_events(
                Entries=[
                    {
                        "EventBusName": eventbus_name,
                        "Source": event.get("source"),
                        "DetailType": event.get("detail-type"),
                        "Detail": event.get("detail"),
                    }
                ]
            )

    elif ":kinesis:" in target_arn:
        partition_key_path = dict_utils.get_safe(
            target_attributes,
            "$.KinesisParameters.PartitionKeyPath",
            default_value="$.id",
        )

        stream_name = target_arn.split("/")[-1]
        partition_key = dict_utils.get_safe(event, partition_key_path, event["id"])
        kinesis_client = connect_to_service("kinesis", region_name=region)

        kinesis_client.put_record(
            StreamName=stream_name,
            Data=to_bytes(json.dumps(event)),
            PartitionKey=partition_key,
        )

    else:
        LOG.warning('Unsupported Events rule target ARN: "%s"' % target_arn)


def send_event_to_api_destination(target_arn, event):
    """Send an event to an EventBridge API destination
    See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html"""

    # ARN format: ...:api-destination/{name}/{uuid}
    region = target_arn.split(":")[3]
    api_destination_name = target_arn.split(":")[-1].split("/")[1]
    events_client = connect_to_service("events", region_name=region)
    destination = events_client.describe_api_destination(Name=api_destination_name)

    # get destination endpoint details
    method = destination.get("HttpMethod", "GET")
    endpoint = destination.get("InvocationEndpoint")
    state = destination.get("ApiDestinationState") or "ACTIVE"

    LOG.debug('Calling EventBridge API destination (state "%s"): %s %s' % (state, method, endpoint))
    headers = {
        # default headers AWS sends with every api destination call
        "User-Agent": "Amazon/EventBridge/ApiDestinations",
        "Content-Type": "application/json; charset=utf-8",
        "Range": "bytes=0-1048575",
        "Accept-Encoding": "gzip,deflate",
        "Connection": "close",
    }

    # add auth headers for target destination
    add_api_destination_authorization(destination, headers, event)

    # TODO: consider option to disable the actual network call to avoid unintended side effects
    # TODO: InvocationRateLimitPerSecond (needs some form of thread-safety, scoped to the api destination)
    result = requests.request(
        method=method, url=endpoint, data=json.dumps(event or {}), headers=headers
    )
    if result.status_code >= 400:
        LOG.debug(
            "Received code %s forwarding events: %s %s" % (result.status_code, method, endpoint)
        )
        if result.status_code == 429 or 500 <= result.status_code <= 600:
            pass  # TODO: retry logic (only retry on 429 and 5xx response status)


def add_api_destination_authorization(destination, headers, event):
    # not yet implemented - may be implemented elsewhere ...
    pass
