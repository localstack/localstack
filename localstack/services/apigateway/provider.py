import logging

import boto3

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
        # Directly to backend

        # response = APIGatewayResponse()
        # status, _, rest_api = response.restapis(
        #     context.request, context.request.full_path, context.request.headers
        # )
        # return json.loads(rest_api)

        # boto3 patched version
        client = boto3.client("apigateway")
        return client.create_rest_api(
            name=name,
            description=description or "",
            version=version or "",
            cloneFrom=clone_from or "",
            binaryMediaTypes=binary_media_types or [""],
            minimumCompressionSize=minimum_compression_size or 1,
            apiKeySource=api_key_source or "",
            endpointConfiguration=endpoint_configuration or {},
            policy=policy or "",
            tags=tags or {},
            disableExecuteApiEndpoint=disable_execute_api_endpoint or False,
        )
