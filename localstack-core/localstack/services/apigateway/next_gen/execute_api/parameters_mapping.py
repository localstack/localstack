# > This section explains how to set up data mappings from an API's method request data, including other data
# stored in context, stage, or util variables, to the corresponding integration request parameters and from an
# integration response data, including the other data, to the method response parameters. The method request
# data includes request parameters (path, query string, headers) and the body. The integration response data
# includes response parameters (headers) and the body. For more information about using the stage variables,
# see API Gateway stage variables reference.
#
# https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html
import json
import logging
from typing import TypedDict

from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import to_str

from .context import EndpointResponse, InvocationRequest
from .gateway_response import BadRequestException, InternalFailureException
from .header_utils import build_multi_value_headers
from .variables import ContextVariables

LOG = logging.getLogger(__name__)


class RequestDataMapping(TypedDict):
    # Integration request parameters, in the form of path variables, query strings or headers, can be mapped from any
    # defined method request parameters and the payload.
    header: dict[str, str]
    path: dict[str, str]
    querystring: dict[str, str | list[str]]


class ResponseDataMapping(TypedDict):
    # Method response header parameters can be mapped from any integration response header or integration response body,
    # $context variables, or static values.
    header: dict[str, str]


class ParametersMapper:
    def map_integration_request(
        self,
        request_parameters: dict[str, str],
        invocation_request: InvocationRequest,
        context_variables: ContextVariables,
        stage_variables: dict[str, str],
    ) -> RequestDataMapping:
        request_data_mapping = RequestDataMapping(
            header={},
            path={},
            querystring={},
        )
        # storing the case-sensitive headers once, the mapping is strict
        case_sensitive_headers = build_multi_value_headers(invocation_request["headers"])

        for integration_mapping, request_mapping in request_parameters.items():
            integration_param_location, param_name = integration_mapping.removeprefix(
                "integration.request."
            ).split(".")

            if request_mapping.startswith("method.request."):
                method_req_expr = request_mapping.removeprefix("method.request.")
                value = self._retrieve_parameter_from_invocation_request(
                    method_req_expr, invocation_request, case_sensitive_headers
                )

            else:
                value = self._retrieve_parameter_from_variables_and_static(
                    mapping_value=request_mapping,
                    context_variables=context_variables,
                    stage_variables=stage_variables,
                )

            if value:
                request_data_mapping[integration_param_location][param_name] = value

        return request_data_mapping

    def map_integration_response(
        self,
        response_parameters: dict[str, str],
        integration_response: EndpointResponse,
        context_variables: ContextVariables,
        stage_variables: dict[str, str],
    ) -> ResponseDataMapping:
        response_data_mapping = ResponseDataMapping(header={})

        # storing the case-sensitive headers once, the mapping is strict
        case_sensitive_headers = build_multi_value_headers(integration_response["headers"])

        for response_mapping, integration_mapping in response_parameters.items():
            header_name = response_mapping.removeprefix("method.response.header.")

            if integration_mapping.startswith("integration.response."):
                method_req_expr = integration_mapping.removeprefix("integration.response.")
                value = self._retrieve_parameter_from_integration_response(
                    method_req_expr, integration_response, case_sensitive_headers
                )
            else:
                value = self._retrieve_parameter_from_variables_and_static(
                    mapping_value=integration_mapping,
                    context_variables=context_variables,
                    stage_variables=stage_variables,
                )

            if value:
                response_data_mapping["header"][header_name] = value

        return response_data_mapping

    def _retrieve_parameter_from_variables_and_static(
        self,
        mapping_value: str,
        context_variables: ContextVariables,
        stage_variables: dict[str, str],
    ):
        if mapping_value.startswith("context."):
            context_var_expr = mapping_value.removeprefix("context.")
            return self._retrieve_parameter_from_context_variables(
                context_var_expr, context_variables
            )

        elif mapping_value.startswith("stageVariables."):
            stage_var_name = mapping_value.removeprefix("stageVariables.")
            return self._retrieve_parameter_from_stage_variables(stage_var_name, stage_variables)

        elif mapping_value.startswith("'") and mapping_value.endswith("'"):
            return mapping_value.strip("'")

        else:
            LOG.warning(
                "Unrecognized parameter mapping value: '%s'. Skipping this mapping.",
                mapping_value,
            )
            return None

    def _retrieve_parameter_from_integration_response(
        self,
        expr: str,
        integration_response: EndpointResponse,
        case_sensitive_headers: dict[str, list[str]],
    ) -> str | None:
        """
        See https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html#mapping-response-parameters
        :param expr: mapping expression stripped from `integration.response.`:
                     Can be of the following: `header.<param_name>`, multivalueheader.<param_name>, `body` and
                     `body.<JSONPath_expression>.`
        :param integration_response: the Response to map parameters from
        :return: the value to map in the ResponseDataMapping
        """
        if expr.startswith("body"):
            body = integration_response.get("body") or b"{}"
            body = body.strip()
            try:
                decoded_body = self._json_load(body)
            except ValueError:
                raise InternalFailureException(message="Internal server error")

            if expr == "body":
                return to_str(body)

            elif expr.startswith("body."):
                json_path = expr.removeprefix("body.")
                return self._get_json_path_from_dict(decoded_body, json_path)
            else:
                LOG.warning(
                    "Unrecognized integration.response parameter: '%s'. Skipping the parameter mapping.",
                    expr,
                )
                return None

        param_type, param_name = expr.split(".")

        if param_type == "header":
            if header := case_sensitive_headers.get(param_name):
                return header[-1]

        elif param_type == "multivalueheader":
            if header := case_sensitive_headers.get(param_name):
                return ",".join(header)

        else:
            LOG.warning(
                "Unrecognized integration.response parameter: '%s'. Skipping the parameter mapping.",
                expr,
            )

    def _retrieve_parameter_from_invocation_request(
        self,
        expr: str,
        invocation_request: InvocationRequest,
        case_sensitive_headers: dict[str, list[str]],
    ) -> str | list[str] | None:
        """
        See https://docs.aws.amazon.com/apigateway/latest/developerguide/request-response-data-mappings.html#mapping-response-parameters
        :param expr: mapping expression stripped from `method.request.`:
                     Can be of the following: `path.<param_name>`, `querystring.<param_name>`,
                     `multivaluequerystring.<param_name>`, `header.<param_name>`, `multivalueheader.<param_name>`,
                     `body` and `body.<JSONPath_expression>.`
        :param invocation_request: the InvocationRequest to map parameters from
        :return: the value to map in the RequestDataMapping
        """
        if expr.startswith("body"):
            body = invocation_request["body"] or b"{}"
            body = body.strip()
            try:
                decoded_body = self._json_load(body)
            except ValueError:
                raise BadRequestException(message="Invalid JSON in request body")

            if expr == "body":
                return to_str(body)

            elif expr.startswith("body."):
                json_path = expr.removeprefix("body.")
                return self._get_json_path_from_dict(decoded_body, json_path)
            else:
                LOG.warning(
                    "Unrecognized method.request parameter: '%s'. Skipping the parameter mapping.",
                    expr,
                )
                return None

        param_type, param_name = expr.split(".")
        if param_type == "path":
            return invocation_request["path_parameters"].get(param_name)

        elif param_type == "querystring":
            multi_qs_params = invocation_request["multi_value_query_string_parameters"].get(
                param_name
            )
            if multi_qs_params:
                return multi_qs_params[-1]

        elif param_type == "multivaluequerystring":
            multi_qs_params = invocation_request["multi_value_query_string_parameters"].get(
                param_name
            )
            if len(multi_qs_params) == 1:
                return multi_qs_params[0]
            return multi_qs_params

        elif param_type == "header":
            if header := case_sensitive_headers.get(param_name):
                return header[-1]

        elif param_type == "multivalueheader":
            if header := case_sensitive_headers.get(param_name):
                return ",".join(header)

        else:
            LOG.warning(
                "Unrecognized method.request parameter: '%s'. Skipping the parameter mapping.",
                expr,
            )

    def _retrieve_parameter_from_context_variables(
        self, expr: str, context_variables: ContextVariables
    ) -> str | None:
        # we're using JSON path here because we could access nested properties like `context.identity.sourceIp`
        return self._get_json_path_from_dict(context_variables, expr)

    @staticmethod
    def _retrieve_parameter_from_stage_variables(
        stage_var_name: str, stage_variables: dict[str, str]
    ) -> str | None:
        return stage_variables.get(stage_var_name)

    @staticmethod
    def _get_json_path_from_dict(body: dict, path: str) -> str | None:
        # TODO: verify we don't have special cases
        try:
            return extract_jsonpath(body, f"$.{path}")
        except KeyError:
            return None

    @staticmethod
    def _json_load(body: bytes) -> dict | list:
        """
        AWS only tries to JSON decode the body if it starts with some leading characters ({, [, ", ')
        otherwise, it ignores it
        :param body:
        :return:
        """
        if any(body.startswith(c) for c in (b"{", b"[", b"'", b'"')):
            return json.loads(body)

        return {}
