import abc
import json
from typing import Type

from apispec import APISpec

from localstack.aws.api.apigateway import ListOfModel
from localstack.aws.connect import connect_to
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp

from .helpers import OpenAPIExt

# TODO:
# - handle more extensions
#   see the list in OpenAPIExt
#   currently handled:
#     - x-amazon-apigateway-integration
#


class _BaseOpenApiExporter(abc.ABC):
    VERSION = None

    def __init__(self):
        self.export_formats = {"application/json": "to_dict", "application/yaml": "to_yaml"}

    def _add_models(self, spec: APISpec, models: ListOfModel, base_path: str):
        for model in models:
            model_def = json.loads(model["schema"])
            self._resolve_refs(model_def, base_path)
            spec.components.schema(
                component_id=model["name"],
                component=model_def,
            )

    def _resolve_refs(self, schema: dict, base_path: str):
        if "$ref" in schema:
            schema["$ref"] = f"{base_path}/{schema['$ref'].rsplit('/', maxsplit=1)[-1]}"
        for value in schema.values():
            if isinstance(value, dict):
                self._resolve_refs(value, base_path)

    @staticmethod
    def _get_integration(method_integration: dict) -> dict:
        fields = {
            "type",
            "passthroughBehavior",
            "requestParameters",
            "requestTemplates",
            "httpMethod",
            "uri",
        }
        integration = {k: v for k, v in method_integration.items() if k in fields}
        integration["type"] = integration["type"].lower()
        integration["passthroughBehavior"] = integration["passthroughBehavior"].lower()
        if responses := method_integration.get("integrationResponses"):
            integration["responses"] = {"default": responses.get("200")}
        return integration

    @abc.abstractmethod
    def export(
        self,
        api_id: str,
        stage: str,
        export_format: str,
        with_extension: bool,
        account_id: str,
        region_name: str,
    ) -> str | dict: ...

    @abc.abstractmethod
    def _add_paths(self, spec: APISpec, resources: dict, with_extension: bool):
        """
        This method iterates over the different REST resources and its methods to add the APISpec paths using the
        `apispec` module.
        The path format is different between Swagger (OpenAPI 2.0) and OpenAPI 3.0
        :param spec: an APISpec object representing the exported API Gateway REST API
        :param resources: the API Gateway REST API resources (methods, methods integrations, responses...)
        :param with_extension: flag to add the custom OpenAPI extension `apigateway`, allowing to properly import
        integrations for example, or authorizers. (all the `x-amazon` fields contained in `OpenAPIExt`).
        :return: None
        """
        ...


class _OpenApiSwaggerExporter(_BaseOpenApiExporter):
    VERSION = "2.0"

    def _add_paths(self, spec, resources, with_extension):
        for item in resources.get("items"):
            path = item.get("path")
            for method, method_config in item.get("resourceMethods", {}).items():
                method = method.lower()

                method_integration = method_config.get("methodIntegration", {})
                integration_responses = method_integration.get("integrationResponses", {})
                method_responses = method_config.get("methodResponses")
                responses = {}
                produces = set()
                for status_code, values in method_responses.items():
                    response = {"description": f"{status_code} response"}
                    if response_parameters := values.get("responseParameters"):
                        headers = {}
                        for parameter in response_parameters:
                            in_, name = parameter.removeprefix("method.response.").split(".")
                            # TODO: other type?
                            if in_ == "header":
                                headers[name] = {"type": "string"}

                        if headers:
                            response["headers"] = headers
                    if response_models := values.get("responseModels"):
                        for content_type, model_name in response_models.items():
                            produces.add(content_type)
                            response["schema"] = model_name
                    if integration_response := integration_responses.get(status_code, {}):
                        produces.update(integration_response.get("responseTemplates", {}).keys())

                    responses[status_code] = response

                request_parameters = method_config.get("requestParameters", {})
                parameters = []
                for parameter, required in request_parameters.items():
                    in_, name = parameter.removeprefix("method.request.").split(".")
                    in_ = in_ if in_ != "querystring" else "query"
                    parameters.append(
                        {"name": name, "in": in_, "required": required, "type": "string"}
                    )

                request_models = method_config.get("requestModels", {})
                for model_name in request_models.values():
                    parameter = {
                        "in": "body",
                        "name": model_name,
                        "required": True,
                        "schema": {"$ref": f"#/definitions/{model_name}"},
                    }
                    parameters.append(parameter)

                method_operations = {"responses": responses}
                if parameters:
                    method_operations["parameters"] = parameters
                if produces:
                    method_operations["produces"] = list(produces)
                if content_types := request_models | method_integration.get("requestTemplates", {}):
                    method_operations["consumes"] = list(content_types.keys())
                if operation_name := method_config.get("operationName"):
                    method_operations["operationId"] = operation_name
                if with_extension and method_integration:
                    method_operations[OpenAPIExt.INTEGRATION] = self._get_integration(
                        method_integration
                    )

                spec.path(path=path, operations={method: method_operations})

    def export(
        self,
        api_id: str,
        stage: str,
        export_format: str,
        with_extension: bool,
        account_id: str,
        region_name: str,
    ) -> str:
        """
        https://github.com/OAI/OpenAPI-Specification/blob/main/versions/2.0.md
        """
        apigateway_client = connect_to(
            aws_access_key_id=account_id, region_name=region_name
        ).apigateway

        rest_api = apigateway_client.get_rest_api(restApiId=api_id)
        resources = apigateway_client.get_resources(restApiId=api_id)
        models = apigateway_client.get_models(restApiId=api_id)

        info = {}
        if (description := rest_api.get("description")) is not None:
            info["description"] = description

        spec = APISpec(
            title=rest_api.get("name"),
            version=rest_api.get("version")
            or timestamp(rest_api.get("createdDate"), format=TIMESTAMP_FORMAT_TZ),
            info=info,
            openapi_version=self.VERSION,
            basePath=f"/{stage}",
            schemes=["https"],
        )

        self._add_paths(spec, resources, with_extension)
        self._add_models(spec, models["items"], "#/definitions")

        response = getattr(spec, self.export_formats.get(export_format))()
        if (
            with_extension
            and isinstance(response, dict)
            and (binary_media_types := rest_api.get("binaryMediaTypes")) is not None
        ):
            response[OpenAPIExt.BINARY_MEDIA_TYPES] = binary_media_types

        return response


class _OpenApiOAS30Exporter(_BaseOpenApiExporter):
    VERSION = "3.0.1"

    def _add_paths(self, spec, resources, with_extension):
        for item in resources.get("items"):
            path = item.get("path")
            for method, method_config in item.get("resourceMethods", {}).items():
                method = method.lower()

                method_integration = method_config.get("methodIntegration", {})
                integration_responses = method_integration.get("integrationResponses", {})
                method_responses = method_config.get("methodResponses")
                responses = {}
                produces = set()
                for status_code, values in method_responses.items():
                    response = {"description": f"{status_code} response"}
                    content = {}
                    if response_parameters := values.get("responseParameters"):
                        headers = {}
                        for parameter in response_parameters:
                            in_, name = parameter.removeprefix("method.response.").split(".")
                            # TODO: other type? query?
                            if in_ == "header":
                                headers[name] = {"schema": {"type": "string"}}

                        if headers:
                            response["headers"] = headers
                    if response_models := values.get("responseModels"):
                        for content_type, model_name in response_models.items():
                            content[content_type] = {
                                "schema": {"$ref": f"#/components/schemas/{model_name}"}
                            }
                    if integration_response := integration_responses.get(status_code, {}):
                        produces.update(integration_response.get("responseTemplates", {}).keys())

                    response["content"] = content
                    responses[status_code] = response

                request_parameters = method_config.get("requestParameters", {})
                parameters = []
                for parameter, required in request_parameters.items():
                    in_, name = parameter.removeprefix("method.request.").split(".")
                    in_ = in_ if in_ != "querystring" else "query"
                    parameters.append({"name": name, "in": in_, "schema": {"type": "string"}})

                request_body = {"content": {}}
                request_models = method_config.get("requestModels", {})
                for content_type, model_name in request_models.items():
                    request_body["content"][content_type] = {
                        "schema": {"$ref": f"#/components/schemas/{model_name}"},
                    }
                    request_body["required"] = True

                method_operations = {"responses": responses}
                if parameters:
                    method_operations["parameters"] = parameters
                if request_body["content"]:
                    method_operations["requestBody"] = request_body
                if operation_name := method_config.get("operationName"):
                    method_operations["operationId"] = operation_name
                if with_extension and method_integration:
                    method_operations[OpenAPIExt.INTEGRATION] = self._get_integration(
                        method_integration
                    )

                spec.path(path=path, operations={method: method_operations})

    def export(
        self,
        api_id: str,
        stage: str,
        export_format: str,
        with_extension: bool,
        account_id: str,
        region_name: str,
    ) -> str:
        """
        https://github.com/OAI/OpenAPI-Specification/blob/main/versions/3.1.0.md
        """
        apigateway_client = connect_to(
            aws_access_key_id=account_id, region_name=region_name
        ).apigateway

        rest_api = apigateway_client.get_rest_api(restApiId=api_id)
        resources = apigateway_client.get_resources(restApiId=api_id)
        models = apigateway_client.get_models(restApiId=api_id)

        info = {}

        if (description := rest_api.get("description")) is not None:
            info["description"] = description

        spec = APISpec(
            title=rest_api.get("name"),
            version=rest_api.get("version")
            or timestamp(rest_api.get("createdDate"), format=TIMESTAMP_FORMAT_TZ),
            info=info,
            openapi_version=self.VERSION,
            servers=[{"variables": {"basePath": {"default": stage}}}],
        )

        self._add_paths(spec, resources, with_extension)
        self._add_models(spec, models["items"], "#/components/schemas")

        response = getattr(spec, self.export_formats.get(export_format))()
        if isinstance(response, dict):
            if "components" not in response:
                response["components"] = {}

            if (
                with_extension
                and (binary_media_types := rest_api.get("binaryMediaTypes")) is not None
            ):
                response[OpenAPIExt.BINARY_MEDIA_TYPES] = binary_media_types

        return response


class OpenApiExporter:
    exporters: dict[str, Type[_BaseOpenApiExporter]]

    def __init__(self):
        self.exporters = {"swagger": _OpenApiSwaggerExporter, "oas30": _OpenApiOAS30Exporter}

    def export_api(
        self,
        api_id: str,
        stage: str,
        export_type: str,
        account_id: str,
        region_name: str,
        export_format: str = "application/json",
        with_extension=False,
    ) -> str:
        exporter = self.exporters.get(export_type)()
        return exporter.export(
            api_id, stage, export_format, with_extension, account_id, region_name
        )
