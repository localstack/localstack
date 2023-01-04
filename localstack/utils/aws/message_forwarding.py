import base64
import json
import logging
import re
import uuid
from typing import Dict, Optional

from moto.events.models import events_backends

from localstack.services.apigateway.helpers import extract_query_string_params
from localstack.utils import collections
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    firehose_name,
    get_sqs_queue_url,
)
from localstack.utils.aws.aws_stack import connect_to_service
from localstack.utils.http import add_path_parameters_to_url, add_query_params_to_url
from localstack.utils.http import safe_requests as requests
from localstack.utils.strings import to_bytes, to_str
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)

AUTH_BASIC = "BASIC"
AUTH_API_KEY = "API_KEY"
AUTH_OAUTH = "OAUTH_CLIENT_CREDENTIALS"


def send_event_to_target(
    target_arn: str,
    event: Dict,
    target_attributes: Dict = None,
    asynchronous: bool = True,
    target: Dict = None,
):
    region = extract_region_from_arn(target_arn)
    if target is None:
        target = {}

    if ":lambda:" in target_arn:
        lambda_client = connect_to_service("lambda")
        lambda_client.invoke(
            FunctionName=target_arn,
            Payload=to_bytes(json.dumps(event)),
            InvocationType="Event" if asynchronous else "RequestResponse",
        )

    elif ":sns:" in target_arn:
        sns_client = connect_to_service("sns", region_name=region)
        sns_client.publish(TopicArn=target_arn, Message=json.dumps(event))

    elif ":sqs:" in target_arn:
        sqs_client = connect_to_service("sqs", region_name=region)
        queue_url = get_sqs_queue_url(target_arn)
        msg_group_id = collections.get_safe(target_attributes, "$.SqsParameters.MessageGroupId")
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
            send_event_to_api_destination(target_arn, event, target.get("HttpParameters"))

        else:
            events_client = connect_to_service("events", region_name=region)
            eventbus_name = target_arn.split(":")[-1].split("/")[-1]
            events_client.put_events(
                Entries=[
                    {
                        "EventBusName": eventbus_name,
                        "Source": event.get("source"),
                        "DetailType": event.get("detail-type"),
                        "Detail": json.dumps(event.get("detail", {})),
                        "Resources": event.get("resources", []),
                    }
                ]
            )

    elif ":kinesis:" in target_arn:
        partition_key_path = collections.get_safe(
            target_attributes,
            "$.KinesisParameters.PartitionKeyPath",
            default_value="$.id",
        )

        stream_name = target_arn.split("/")[-1]
        partition_key = collections.get_safe(event, partition_key_path, event["id"])
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


def auth_keys_from_connection(connection: Dict):
    headers = {}

    auth_type = connection.get("AuthorizationType").upper()
    auth_parameters = connection.get("AuthParameters")
    if auth_type == AUTH_BASIC:
        basic_auth_parameters = auth_parameters.get("BasicAuthParameters", {})
        username = basic_auth_parameters.get("Username", "")
        password = basic_auth_parameters.get("Password", "")
        auth = "Basic " + to_str(
            base64.b64encode("{}:{}".format(username, password).encode("ascii"))
        )
        headers.update({"authorization": auth})

    if auth_type == AUTH_API_KEY:
        api_key_parameters = auth_parameters.get("ApiKeyAuthParameters", {})
        api_key_name = api_key_parameters.get("ApiKeyName", "")
        api_key_value = api_key_parameters.get("ApiKeyValue", "")
        headers.update({api_key_name: api_key_value})

    if auth_type == AUTH_OAUTH:
        oauth_parameters = auth_parameters.get("OAuthParameters", {})
        oauth_method = oauth_parameters.get("HttpMethod")

        oauth_http_parameters = oauth_parameters.get("OAuthHttpParameters", {})
        oauth_endpoint = oauth_parameters.get("AuthorizationEndpoint", "")
        query_object = list_of_parameters_to_object(
            oauth_http_parameters.get("QueryStringParameters", [])
        )
        oauth_endpoint = add_query_params_to_url(oauth_endpoint, query_object)

        client_parameters = oauth_parameters.get("ClientParameters", {})
        client_id = client_parameters.get("ClientID", "")
        client_secret = client_parameters.get("ClientSecret", "")

        oauth_body = list_of_parameters_to_object(oauth_http_parameters.get("BodyParameters", []))
        oauth_body.update({"client_id": client_id, "client_secret": client_secret})

        oauth_header = list_of_parameters_to_object(
            oauth_http_parameters.get("HeaderParameters", [])
        )
        oauth_result = requests.request(
            method=oauth_method,
            url=oauth_endpoint,
            data=json.dumps(oauth_body),
            headers=oauth_header,
        )
        oauth_data = json.loads(oauth_result.text)

        token_type = oauth_data.get("token_type", "")
        access_token = oauth_data.get("access_token", "")
        auth_header = "{} {}".format(token_type, access_token)
        headers.update({"authorization": auth_header})

    return headers


def list_of_parameters_to_object(items):
    return {item.get("Key"): item.get("Value") for item in items}


def send_event_to_api_destination(target_arn, event, http_parameters: Optional[Dict] = None):
    """Send an event to an EventBridge API destination
    See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html"""

    # ARN format: ...:api-destination/{name}/{uuid}
    region = extract_region_from_arn(target_arn)
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

    endpoint = add_api_destination_authorization(destination, headers, event)
    if http_parameters:
        endpoint = add_target_http_parameters(http_parameters, endpoint, headers, event)

    result = requests.request(
        method=method, url=endpoint, data=json.dumps(event or {}), headers=headers
    )
    if result.status_code >= 400:
        LOG.debug("Received code %s forwarding events: %s %s", result.status_code, method, endpoint)
        if result.status_code == 429 or 500 <= result.status_code <= 600:
            pass  # TODO: retry logic (only retry on 429 and 5xx response status)


def add_api_destination_authorization(destination, headers, event):
    connection_arn = destination.get("ConnectionArn", "")
    connection_name = re.search(r"connection\/([a-zA-Z0-9-_]+)\/", connection_arn).group(1)

    account_id = extract_account_id_from_arn(connection_arn)
    region = extract_region_from_arn(connection_arn)

    # Using backend directly due to boto hiding passwords, keys and secret values
    event_backend = events_backends[account_id][region]
    connection = event_backend.describe_connection(name=connection_name)

    headers.update(auth_keys_from_connection(connection))

    auth_parameters = connection.get("AuthParameters", {})
    invocation_parameters = auth_parameters.get("InvocationHttpParameters")

    endpoint = destination.get("InvocationEndpoint")
    if invocation_parameters:
        header_parameters = list_of_parameters_to_object(
            invocation_parameters.get("HeaderParameters", [])
        )
        headers.update(header_parameters)

        body_parameters = list_of_parameters_to_object(
            invocation_parameters.get("BodyParameters", [])
        )
        event.update(body_parameters)

        query_parameters = invocation_parameters.get("QueryStringParameters", [])
        query_object = list_of_parameters_to_object(query_parameters)
        endpoint = add_query_params_to_url(endpoint, query_object)

    return endpoint


def add_target_http_parameters(http_parameters: Dict, endpoint: str, headers: Dict, body):
    endpoint = add_path_parameters_to_url(endpoint, http_parameters.get("PathParameterValues", []))

    # The request should prioritze connection header/query parameters over target params if there is an overlap
    query_params = http_parameters.get("QueryStringParameters", {})
    prev_query_params = extract_query_string_params(endpoint)[1]
    query_params.update(prev_query_params)
    endpoint = add_query_params_to_url(endpoint, query_params)

    target_headers = http_parameters.get("HeaderParameters", {})
    for target_header in target_headers.keys():
        if target_header not in headers:
            headers.update({target_header: target_headers.get(target_header)})

    return endpoint
