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

from .context import InvocationRequest
from .gateway_response import Default4xxError
from .variables import ContextVariables

LOG = logging.getLogger(__name__)


class RequestDataMapping(TypedDict):
    # Integration request parameters, in the form of path variables, query strings or headers, can be mapped from any
    # defined method request parameters and the payload.
    header: dict[str, str]
    path: dict[str, str]
    querystring: dict[str, str | list[str]]


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
        # TODO: maybe extract functionality and re-use in `map_integration_response`

        for integration_mapping, request_mapping in request_parameters.items():
            integration_param_location, param_name = integration_mapping.removeprefix(
                "integration.request."
            ).split(".")

            if request_mapping.startswith("method.request."):
                method_req_expr = request_mapping.removeprefix("method.request.")
                value = self._retrieve_parameter_from_invocation_request(
                    method_req_expr, invocation_request
                )

            elif request_mapping.startswith("context."):
                context_var_expr = request_mapping.removeprefix("context.")
                value = self._retrieve_parameter_from_context_variables(
                    context_var_expr, context_variables
                )

            elif request_mapping.startswith("stageVariables."):
                stage_var_name = request_mapping.removeprefix("stageVariables.")
                value = self._retrieve_parameter_from_stage_variables(
                    stage_var_name, stage_variables
                )

            elif request_mapping.startswith("'") and request_mapping.endswith("'"):
                value = request_mapping.strip("'")

            else:
                LOG.warning(
                    "Unrecognized requestParameter value: '%s'. Skipping the parameter mapping.",
                    request_mapping,
                )
                value = None

            if value:
                request_data_mapping[integration_param_location][param_name] = value

        return request_data_mapping

    def map_integration_response(self):
        pass

    def _retrieve_parameter_from_invocation_request(
        self, expr: str, invocation_request: InvocationRequest
    ) -> str | list[str] | None:
        if expr.startswith("body"):
            body = invocation_request["body"] or b"{}"
            body = body.strip()
            try:
                decoded_body = self._json_load(body)
            except ValueError:
                raise Default4xxError(message="Invalid JSON in request body")

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
            multi_headers = invocation_request["multi_value_headers"].get(param_name)
            if multi_headers:
                return multi_headers[-1]

        elif param_type == "multivalueheader":
            multi_headers = invocation_request["multi_value_headers"].get(param_name, [])
            return ",".join(multi_headers)

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
