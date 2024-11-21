import json
import logging
import re
from typing import Dict, Optional

import requests

from localstack.aws.connect import connect_to
from localstack.services.events.models import events_stores
from localstack.utils.aws.arns import extract_account_id_from_arn, extract_region_from_arn
from localstack.utils.aws.message_forwarding import (
    add_target_http_parameters,
    auth_keys_from_connection,
    list_of_parameters_to_object,
)
from localstack.utils.http import add_query_params_to_url

LOG = logging.getLogger(__name__)


def send_event_to_api_destination(target_arn, event, http_parameters: Optional[Dict] = None):
    """Send an event to an EventBridge API destination
    See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html"""

    # ARN format: ...:api-destination/{name}/{uuid}
    account_id = extract_account_id_from_arn(target_arn)
    region = extract_region_from_arn(target_arn)

    api_destination_name = target_arn.split(":")[-1].split("/")[1]
    events_client = connect_to(aws_access_key_id=account_id, region_name=region).events
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

    store = events_stores[account_id][region]
    connection = store.connections.get(connection_name)
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
