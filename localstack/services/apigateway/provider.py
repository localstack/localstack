import json
import logging

from moto.apigateway.responses import APIGatewayResponse

from localstack.aws.api import RequestContext
from localstack.aws.api.apigateway import (
    ApigatewayApi,
    ApiKeySourceType,
    Boolean,
    EndpointConfiguration,
    ListOfString,
    MapOfStringToString,
    NullableInteger,
    RestApi,
    String,
)

LOG = logging.getLogger(__name__)


class ApigatewayProvider(ApigatewayApi):
    def create_rest_api(
        self,
        context: RequestContext,
        name: String,
        description: String = None,
        version: String = None,
        clone_from: String = None,
        binary_media_types: ListOfString = None,
        minimum_compression_size: NullableInteger = None,
        api_key_source: ApiKeySourceType = None,
        endpoint_configuration: EndpointConfiguration = None,
        policy: String = None,
        tags: MapOfStringToString = None,
        disable_execute_api_endpoint: Boolean = None,
    ) -> RestApi:

        response = APIGatewayResponse()
        status, _, rest_api = response.restapis(
            context.request, context.request.full_path, context.request.headers
        )
        return json.loads(rest_api)
        # return APIGatewayBackend(context.region).create_rest_api(
        #     name=name,
        #     description=description,
        #     api_key_source=api_key_source,
        #     endpoint_configuration=endpoint_configuration,
        #     tags=tags,
        #     policy=policy,
        #     minimum_compression_size=minimum_compression_size,
        # )
