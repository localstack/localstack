import json
import logging
import re
import uuid
from typing import Dict

from localstack.services.awslambda.lambda_executors import InvocationException, InvocationResult
from localstack.utils.aws.aws_models import LambdaFunction
from localstack.utils.aws.aws_stack import connect_to_service, firehose_name, get_sqs_queue_url
from localstack.utils.common import long_uid, now_utc
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import timestamp_millis, to_bytes
from localstack.utils.generic import dict_utils
from localstack.utils.http_utils import add_query_params_to_url

LOG = logging.getLogger(__name__)

AUTH_BASIC = "BASIC"
AUTH_API_KEY = "API_KEY"
AUTH_OAUTH = "AUTH_CLIENT_CREDENTIALS"


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

    elif ":logs:" in target_arn:
        log_group_name = target_arn.split(":")[-1]
        logs_client = connect_to_service("logs", region_name=region)
        log_stream_name = str(uuid.uuid4())
        logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": now_utc(millis=True), "message": json.dumps(event)}],
        )
    else:
        LOG.warning('Unsupported Events rule target ARN: "%s"', target_arn)


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

    LOG.debug('Calling EventBridge API destination (state "%s"): %s %s', state, method, endpoint)
    headers = {
        # default headers AWS sends with every api destination call
        "User-Agent": "Amazon/EventBridge/ApiDestinations",
        "Content-Type": "application/json; charset=utf-8",
        "Range": "bytes=0-1048575",
        "Accept-Encoding": "gzip,deflate",
        "Connection": "close",
    }

    connection_arn = destination.get("ConnectionArn", "")
    connection_name = re.search(r"connection\/([a-zA-Z0-9-_]+)\/", connection_arn).group(1)
    connection = events_client.describe_connection(Name=connection_name)

    add_connection_parameters(connection, headers, event, endpoint)

    # TODO: consider option to disable the actual network call to avoid unintended side effects
    # TODO: InvocationRateLimitPerSecond (needs some form of thread-safety, scoped to the api destination)
    result = requests.request(
        method=method, url=endpoint, data=json.dumps(event or {}), headers=headers
    )
    if result.status_code >= 400:
        LOG.debug("Received code %s forwarding events: %s %s", result.status_code, method, endpoint)
        if result.status_code == 429 or 500 <= result.status_code <= 600:
            pass  # TODO: retry logic (only retry on 429 and 5xx response status)


def add_connection_parameters(connection, headers, data, endpoint):
    auth_type = connection.get("AuthorizationType").upper()
    if auth_type is AUTH_BASIC:
        basic_auth_parameters = connection.get("BasicAuthParamethers", {})
        username = basic_auth_parameters.get("Username")
        headers.update("Authorization", "Basic {}".format(username))

    if auth_type is AUTH_API_KEY:
        api_key_paramethers = connection.get("ApiKeyAuthParameters", {})
        api_key = api_key_paramethers.get("ApiKeyName", "")
        headers.update("X-API-KEY", api_key)

    # TODO: implement auth keys obtention for Oauth connection type
    if auth_type is AUTH_OAUTH:
        pass

    invocation_parameters = connection.get("InvocationHttpParameters")
    if invocation_parameters:
        # TODO: look into what isValueSecret parameter does
        header_parameters = invocation_parameters.get("HeaderParameters", [])
        for header_parameter in header_parameters:
            headers.update(header_parameter.get("Key"), header_parameter.get("Value"))

        query_string_parameters = invocation_parameters.get("QueryStringParameters", [])
        query_object = {}
        for query_paramater in query_string_parameters:
            query_object.update(query_paramater.get(""), query_paramater.get("Value"))
        endpoint = add_query_params_to_url(endpoint, query_object)

        body_parameters = invocation_parameters.get("BodyParameters", [])
        for body_paramater in body_parameters:
            data.update(body_paramater.get("Key"), body_paramater.get("Value"))
