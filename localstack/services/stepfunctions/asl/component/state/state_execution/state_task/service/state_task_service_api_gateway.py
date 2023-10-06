from __future__ import annotations

import http
import json
import logging
from json import JSONDecodeError
from typing import Final, Optional, TypedDict
from urllib.parse import urlencode, urljoin, urlparse

import requests
from requests import Response

from localstack import config
from localstack.aws.api.stepfunctions import HistoryEventType, TaskFailedEventDetails
from localstack.constants import (
    APPLICATION_JSON,
    HEADER_CONTENT_TYPE,
    LOCALHOST_HOSTNAME,
    PATH_USER_REQUEST,
)
from localstack.services.stepfunctions.asl.component.common.error_name.custom_error_name import (
    CustomErrorName,
)
from localstack.services.stepfunctions.asl.component.common.error_name.failure_event import (
    FailureEvent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    ResourceRuntimePart,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_callback import (
    StateTaskServiceCallback,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.services.stepfunctions.asl.eval.event.event_detail import EventDetails
from localstack.utils.collections import select_from_typed_dict
from localstack.utils.strings import long_uid

LOG = logging.getLogger(__name__)


ApiEndpoint = str
Headers = dict
Stage = str
Path = str
QueryParameters = dict
RequestBody = dict | str
ResponseBody = dict | str
StatusCode = int
StatusText = str
AllowNullValues = bool


class Method(str):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class AuthType(str):
    NO_AUTH = "NO_AUTH"
    IAM_ROLE = "IAM_ROLE"
    RESOURCE_POLICY = "RESOURCE_POLICY"


class TaskParameters(TypedDict):
    ApiEndpoint: ApiEndpoint
    Method: Method
    Headers: Optional[Headers]
    Stage: Optional[Stage]
    Path: Optional[Path]
    QueryParameters: Optional[QueryParameters]
    RequestBody: Optional[RequestBody]
    AllowNullValues: Optional[AllowNullValues]
    AuthType: Optional[AuthType]


class InvokeOutput(TypedDict):
    Headers: Headers
    ResponseBody: ResponseBody
    StatusCode: StatusCode
    StatusText: StatusText


class SupportedApiCalls(str):
    invoke = "invoke"


class SfnGatewayException(Exception):
    parameters: Final[TaskParameters]
    response: Final[Response]

    def __init__(self, parameters: TaskParameters, response: Response):
        self.parameters = parameters
        self.response = response


class StateTaskServiceApiGateway(StateTaskServiceCallback):

    _SUPPORTED_API_PARAM_BINDINGS: Final[dict[str, set[str]]] = {
        SupportedApiCalls.invoke: set(TaskParameters.__required_keys__)  # noqa
    }

    _FORBIDDEN_HTTP_HEADERS_PREFIX: Final[set[str]] = {"X-Forwarded", "X-Amz", "X-Amzn"}
    _FORBIDDEN_HTTP_HEADERS: Final[set[str]] = {
        "Authorization",
        "Connection",
        "Content-md5",
        "Expect",
        "Host",
        "Max-Forwards",
        "Proxy-Authenticate",
        "Server",
        "TE",
        "Transfer-Encoding",
        "Trailer",
        "Upgrade",
        "Via",
        "Www-Authenticate",
    }

    def _get_supported_parameters(self) -> Optional[set[str]]:
        return self._SUPPORTED_API_PARAM_BINDINGS.get(self.resource.api_action.lower())

    @staticmethod
    def _query_parameters_of(parameters: TaskParameters) -> Optional[str]:
        query_str = None
        query_parameters = parameters.get("QueryParameters")
        # TODO: add support for AllowNullValues.
        if query_parameters is not None:
            for key, value in list(query_parameters.items()):
                if value:
                    query_parameters[key] = value[-1]
                else:
                    query_parameters[key] = ""
            query_str = f"?{urlencode(query_parameters)}"
        return query_str

    @staticmethod
    def _headers_of(parameters: TaskParameters) -> Optional[dict]:
        headers = parameters.get("Headers", dict())
        if headers:
            for key in headers.keys():
                # TODO: the following check takes place at parse time.
                if key in StateTaskServiceApiGateway._FORBIDDEN_HTTP_HEADERS:
                    raise ValueError(f"The 'Headers' field contains unsupported values: {key}")
                for forbidden_prefix in StateTaskServiceApiGateway._FORBIDDEN_HTTP_HEADERS_PREFIX:
                    if key.startswith(forbidden_prefix):
                        raise ValueError(f"The 'Headers' field contains unsupported values: {key}")
            if "RequestBody" in parameters:
                headers[HEADER_CONTENT_TYPE] = APPLICATION_JSON
        headers["Accept"] = APPLICATION_JSON
        return headers

    @staticmethod
    def _path_based_url_of(api_endpoint: ApiEndpoint) -> ApiEndpoint:
        # Attempts to convert an url based api endpoint:
        #   <api-id>.execute-api.<-region->.localhost.localstack.cloud
        # To a path based:
        #   http://localhost:4566/restapis/<api-id>
        # TODO: this heavily normalises url based api endpoints to path endpoint.
        #  there's an argument to be made that this may mast implementation mistakes: investigate further.
        url_spec = urlparse(api_endpoint)
        url_path = url_spec.path
        if not url_path.endswith(LOCALHOST_HOSTNAME):
            return api_endpoint
        path_parts = url_path.split(".")
        api_id = path_parts[0]
        path_based_api_endpoint = f"{config.service_url('apigateway')}/restapis/{api_id}"
        return path_based_api_endpoint

    @staticmethod
    def _invoke_url_of(parameters: TaskParameters) -> str:
        given_api_endpoint = parameters["ApiEndpoint"]
        api_endpoint = StateTaskServiceApiGateway._path_based_url_of(given_api_endpoint)
        if given_api_endpoint != api_endpoint:
            LOG.warning(f"ApiEndpoint '{given_api_endpoint}' ignored in favour of {api_endpoint}")

        url_base = api_endpoint + "/"
        # http://localhost:4566/restapis/<api-id>/<stage>/_user_request_/<path>(?<query-parameters>)?
        url_tail = "/".join(
            [
                parameters.get("Stage", ""),
                PATH_USER_REQUEST,
                parameters.get("Path", ""),
                StateTaskServiceApiGateway._query_parameters_of(parameters) or "",
            ]
        )
        invoke_url = urljoin(url_base, url_tail)
        return invoke_url

    @staticmethod
    def _invoke_output_of(response: Response) -> InvokeOutput:
        status_code = response.status_code
        status_text = http.HTTPStatus(status_code).phrase

        headers = dict(response.headers)

        try:
            response_body = response.json()
        except JSONDecodeError:
            response_body = response.text
            if response_body == json.dumps(dict()):
                response_body = dict()

        headers.pop("server", None)
        if "date" in headers:
            headers["Date"] = [headers.pop("date")]
        headers[HEADER_CONTENT_TYPE] = [APPLICATION_JSON]
        headers["Content-Length"] = [headers["Content-Length"]]
        # TODO: add support for the following generated fields.
        headers["Connection"] = ["keep-alive"]
        headers["x-amz-apigw-id"] = [long_uid()]
        headers["X-Amz-Cf-Id"] = [long_uid()]
        headers["X-Amz-Cf-Pop"] = [long_uid()]
        headers["x-amzn-RequestId"] = [long_uid()]
        headers["X-Amzn-Trace-Id"] = [long_uid()]
        headers["X-Cache"] = ["Miss from cloudfront"]
        headers["Via"] = ["UNSUPPORTED"]

        return InvokeOutput(
            Headers=headers,
            ResponseBody=response_body,
            StatusCode=status_code,
            StatusText=status_text,
        )

    def _from_error(self, env: Environment, ex: Exception) -> FailureEvent:
        if isinstance(ex, SfnGatewayException):
            error_name = f"ApiGateway.{ex.response.status_code}"
            cause = ex.response.text
        else:
            ex_name = ex.__class__.__name__
            error_name = f"ApiGateway.{ex_name}"
            cause = str(ex)
        return FailureEvent(
            error_name=CustomErrorName(error_name),
            event_type=HistoryEventType.TaskFailed,
            event_details=EventDetails(
                taskFailedEventDetails=TaskFailedEventDetails(
                    error=error_name,
                    cause=cause,  # TODO: add support for cause decoration.
                    resource=self._get_sfn_resource(),
                    resourceType=self._get_sfn_resource_type(),
                )
            ),
        )

    def _eval_service_task(
        self,
        env: Environment,
        resource_runtime_part: ResourceRuntimePart,
        normalised_parameters: dict,
    ):
        task_parameters: TaskParameters = select_from_typed_dict(
            typed_dict=TaskParameters, obj=normalised_parameters
        )

        method = task_parameters["Method"]
        invoke_url = self._invoke_url_of(task_parameters)
        headers = self._headers_of(task_parameters)
        json_data = task_parameters.get("RequestBody")

        # RequestBody is only supported for PATCH, POST, and PUT
        if json_data is not None and method not in {Method.PATCH, Method.POST, Method.PUT}:
            raise ValueError()  # TODO

        response: Response = getattr(requests, method.lower())(
            invoke_url, headers=headers, json=json_data
        )

        if response.status_code != 200:
            raise SfnGatewayException(parameters=task_parameters, response=response)

        invoke_output = self._invoke_output_of(response)
        env.stack.append(invoke_output)
