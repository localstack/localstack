import sys
from functools import lru_cache
from typing import Callable, Dict, Optional, Tuple, Union
from urllib.parse import urlsplit

from botocore.awsrequest import create_request_object, prepare_request_dict
from botocore.parsers import create_parser
from botocore.serialize import create_serializer
from moto.backends import get_backend as get_moto_backend
from moto.core.utils import BackendDict
from moto.server import RegexConverter
from werkzeug.datastructures import Headers
from werkzeug.routing import Map, Rule

import localstack
from localstack import config
from localstack.aws.api import HttpRequest, RequestContext, ServiceResponse
from localstack.aws.spec import load_service
from localstack.utils.common import to_str

MotoResponse = Tuple[str, dict, Union[str, bytes]]
MotoDispatcher = Callable[[HttpRequest, str, dict], MotoResponse]

user_agent = f"Localstack/{localstack.__version__} Python/{sys.version.split(' ')[0]}"


@lru_cache()
def get_moto_routing_table(service: str) -> Map:
    """Cached version of load_moto_routing_table."""
    return load_moto_routing_table(service)


def load_moto_routing_table(service: str) -> Map:
    """
    Creates from moto service url_paths a werkzeug URL rule map that can be used to locate moto methods to dispatch
    requests to.

    :param service: the service to get the map for.
    :return: a new Map object
    """
    # code from moto.server.create_backend_app
    backend_dict: BackendDict = get_moto_backend(service)
    if "us-east-1" in backend_dict:
        backend = backend_dict["us-east-1"]
    else:
        backend = backend_dict["global"]

    url_map = Map()
    url_map.converters["regex"] = RegexConverter

    for url_path, handler in backend.flask_paths.items():
        # kinda abusing the werkzeug routing internals here. normally endpoint would be a string, but it works
        url_map.add(Rule(url_path, endpoint=handler))

    return url_map


def get_dispatcher(service: str, path: str) -> MotoDispatcher:
    url_map = get_moto_routing_table(service)

    if len(url_map._rules) == 1:
        # in most cases, there will only be one dispatch method in the list of urls, so no need to do matching
        endpoint, _ = next(url_map.iter_rules())
        return endpoint

    matcher = url_map.bind(config.LOCALSTACK_HOSTNAME)
    endpoint, _ = matcher.match(path_info=path)
    return endpoint


def call_moto(context: RequestContext) -> ServiceResponse:
    service = context.service
    operation_model = context.operation
    request = context.request

    # hack to avoid call to request.form (see moto's BaseResponse.dispatch)
    setattr(request, "body", request.data)

    # this is where we skip the HTTP roundtrip between the moto server and the boto client
    dispatch = get_dispatcher(service.service_name, request.path)

    status, headers, content = dispatch(request, request.url, request.headers)
    response_dict = {  # this is what botocore.endpoint.convert_to_response_dict normally does
        "headers": headers,
        "status_code": status,
        "body": content,
        "context": {
            "operation_name": operation_model.name,
        },
    }

    parser = create_parser(service.protocol)
    response = parser.parse(response_dict, operation_model.output_shape)
    # TODO: handle errors (raise exceptions from error messages)
    return response


def create_aws_request_context(
    service_name: str,
    action: str,
    parameters: Dict,
    region: str = config.AWS_REGION_US_EAST_1,
    endpoint_url: Optional[str] = None,
) -> RequestContext:
    """
    This is a stripped-down version of what the botocore client does to create an http request from a client call. A
    client call looks something like this: boto3.client("sqs").create_queue(QueueName="myqueue"), which will be
    serialized into an HTTP request. This method does the same, without performing the actual request, and with a
    more low-level interface. An equivalent call would be

         create_aws_request_context("sqs", "CreateQueue", {"QueueName": "myqueue"})

    :param service_name: the AWS service
    :param action: the action to invoke
    :param parameters: the invocation parameters
    :param region: the region name (default is us-east-1)
    :param endpoint_url: the endpoint to call (defaults to localstack)
    :return: a RequestContext object that describes this request
    """
    if endpoint_url is None:
        endpoint_url = config.get_edge_url()

    service = load_service(service_name)
    operation = service.operation_model(action)
    request_context = {
        "client_region": region,
        "has_streaming_input": operation.has_streaming_input,
        "auth_type": operation.auth_type,
    }

    # serialize the request into an AWS request object and prepare the request
    serializer = create_serializer(service.protocol)
    serialized_request = serializer.serialize_to_request(parameters, operation)
    prepare_request_dict(
        serialized_request,
        endpoint_url=endpoint_url,
        user_agent=user_agent,
        context=request_context,
    )
    aws_request = create_request_object(serialized_request)
    aws_request = aws_request.prepare()

    # create HttpRequest from AWSRequest
    split_url = urlsplit(aws_request.url)
    host = split_url.netloc.split(":")
    if len(host) == 1:
        server = (to_str(host[0]), None)
    elif len(host) == 2:
        server = (to_str(host[0]), int(host[1]))
    else:
        raise ValueError

    # Use our parser to parse the serialized body
    headers = Headers()
    for k, v in aws_request.headers.items():
        headers[k] = v
    request = HttpRequest(
        method=aws_request.method,
        path=split_url.path,
        query_string=split_url.query,
        headers=headers,
        body=aws_request.body,
        server=server,
    )

    context = RequestContext()
    context.service = service
    context.operation = operation
    context.region = region
    context.request = request

    return context
