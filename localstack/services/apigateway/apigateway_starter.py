import logging
from moto.apigateway import models as apigateway_models
from moto.apigateway.exceptions import (
    MethodNotFoundException, NoIntegrationDefined
)
from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.common import short_uid

LOG = logging.getLogger(__name__)


def apply_patches():
    def apigateway_models_backend_delete_method(self, function_id, resource_id, method_type):
        resource = self.get_resource(function_id, resource_id)
        method = resource.get_method(method_type)
        if not method:
            raise MethodNotFoundException()

        return resource.resource_methods.pop(method_type)

    def apigateway_models_resource_get_method(self, method_type):
        method = self.resource_methods.get(method_type)
        if not method:
            raise MethodNotFoundException()

        return method

    def apigateway_models_resource_get_integration(self, method_type):
        resource_method = self.resource_methods.get(method_type, {})
        if 'methodIntegration' not in resource_method:
            raise NoIntegrationDefined()

        return resource_method['methodIntegration']

    def apigateway_models_resource_delete_integration(self, method_type):
        if method_type in self.resource_methods:
            return self.resource_methods[method_type].pop('methodIntegration')

        return {}

    def apigateway_models_Integration_init(
            self, integration_type, uri, http_method,
            request_templates=None, pass_through_behavior='WHEN_NO_MATCH', cache_key_parameters=[]
    ):
        super(apigateway_models.Integration, self).__init__()
        self['type'] = integration_type
        self['uri'] = uri
        self['httpMethod'] = http_method
        self['passthroughBehavior'] = pass_through_behavior
        self['cacheKeyParameters'] = cache_key_parameters
        self['cacheNamespace'] = short_uid()
        self['integrationResponses'] = {'200': apigateway_models.IntegrationResponse(200)}
        if request_templates:
            self['requestTemplates'] = request_templates

    apigateway_models.APIGatewayBackend.delete_method = apigateway_models_backend_delete_method
    apigateway_models.Resource.get_method = apigateway_models_resource_get_method
    apigateway_models.Resource.get_integration = apigateway_models_resource_get_integration
    apigateway_models.Resource.delete_integration = apigateway_models_resource_delete_integration

    apigateway_models.Integration.__init__ = apigateway_models_Integration_init


def start_apigateway(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_APIGATEWAY

    apply_patches()

    return start_moto_server(
        key='apigateway', name='API Gateway', asynchronous=asynchronous,
        port=port, backend_port=backend_port, update_listener=update_listener
    )
