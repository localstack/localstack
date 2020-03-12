import json
import logging
from moto.apigateway import models as apigateway_models
from moto.apigateway import responses as apigateway_responses
from moto.apigateway.exceptions import (
    BadRequestException, CrossAccountNotAllowed, MethodNotFoundException
)
from localstack import config
from localstack.constants import DEFAULT_PORT_APIGATEWAY_BACKEND
from localstack.services.infra import start_moto_server

LOG = logging.getLogger(__name__)


def apply_patches():
    def apigateway_models_resource_get_method(self, method_type):
        method = self.resource_methods.get(method_type)
        if not method:
            raise MethodNotFoundException()
        return method

    def apigateway_models_backend_delete_method(self, function_id, resource_id, method_type):
        resource = self.get_resource(function_id, resource_id)
        method = resource.get_method(method_type)
        if not method:
            raise MethodNotFoundException()

        return resource.resource_methods.pop(method_type)

    def apigateway_models_resource_delete_integration(self, method_type):
        if method_type in self.resource_methods:
            return self.resource_methods[method_type].pop('methodIntegration')
        return {}

    def apigateway_responses_resource_methods(self, request, full_url, headers):
        self.setup_class(request, full_url, headers)
        url_path_parts = self.path.split('/')
        function_id = url_path_parts[2]
        resource_id = url_path_parts[4]
        method_type = url_path_parts[6]

        if self.method == 'GET':
            method = self.backend.get_method(function_id, resource_id, method_type)
            return 200, {}, json.dumps(method)

        elif self.method == 'PUT':
            authorization_type = self._get_param('authorizationType')
            method = self.backend.create_method(
                function_id, resource_id, method_type, authorization_type
            )
            return 200, {}, json.dumps(method)

        elif self.method == 'DELETE':
            self.backend.delete_method(
                function_id, resource_id, method_type
            )

            return 200, {}, ''

        return 200, {}, ''

    def apigateway_responses_integrations(self, request, full_url, headers):
        self.setup_class(request, full_url, headers)
        url_path_parts = self.path.split('/')
        function_id = url_path_parts[2]
        resource_id = url_path_parts[4]
        method_type = url_path_parts[6]

        try:
            integration_response = {}

            if self.method == 'GET':
                integration_response = self.backend.get_integration(
                    function_id, resource_id, method_type
                )
            elif self.method == 'PUT':
                integration_type = self._get_param('type')
                uri = self._get_param('uri')
                credentials = self._get_param('credentials')
                request_templates = self._get_param('requestTemplates')
                method = self.backend.get_method(function_id, resource_id, method_type)

                integration_http_method = method['httpMethod']

                integration_response = self.backend.create_integration(
                    function_id,
                    resource_id,
                    method_type,
                    integration_type,
                    uri,
                    credentials=credentials,
                    integration_method=integration_http_method,
                    request_templates=request_templates,
                )
            elif self.method == 'DELETE':
                integration_response = self.backend.delete_integration(
                    function_id, resource_id, method_type
                )

            return 200, {}, json.dumps(integration_response)

        except BadRequestException as e:
            return self.error(
                'com.amazonaws.dynamodb.v20111205#BadRequestException', e.message
            )
        except CrossAccountNotAllowed as e:
            return self.error(
                'com.amazonaws.dynamodb.v20111205#AccessDeniedException', e.message
            )

    apigateway_models.Resource.get_method = apigateway_models_resource_get_method
    apigateway_models.Resource.delete_integration = apigateway_models_resource_delete_integration
    apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method
    apigateway_responses.APIGatewayResponse.resource_methods = apigateway_responses_resource_methods
    apigateway_responses.APIGatewayResponse.integrations = apigateway_responses_integrations


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY
    backend_port = backend_port or DEFAULT_PORT_APIGATEWAY_BACKEND

    apply_patches()

    return start_moto_server(
        key='apigateway', name='API Gateway', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )
