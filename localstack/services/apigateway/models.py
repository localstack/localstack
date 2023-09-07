from typing import Any, Dict, List

from requests.structures import CaseInsensitiveDict

from localstack.aws.api.apigateway import (
    Authorizer,
    DocumentationPart,
    DocumentationVersion,
    DomainName,
    GatewayResponse,
    GatewayResponseType,
    Model,
    RequestValidator,
    RestApi,
)
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws import arns


class RestApiContainer:
    # contains the RestApi dictionary. We're not making use of it yet, still using moto data.
    rest_api: RestApi
    # maps AuthorizerId -> Authorizer
    authorizers: Dict[str, Authorizer]
    # maps RequestValidatorId -> RequestValidator
    validators: Dict[str, RequestValidator]
    # map DocumentationPartId -> DocumentationPart
    documentation_parts: Dict[str, DocumentationPart]
    # map doc version name -> DocumentationVersion
    documentation_versions: Dict[str, DocumentationVersion]
    # not used yet, still in moto
    gateway_responses: Dict[GatewayResponseType, GatewayResponse]
    # maps Model name -> Model
    models: Dict[str, Model]
    # maps Model name -> resolved dict Model, so we don't need to load the JSON everytime
    resolved_models: Dict[str, dict]
    # maps ResourceId of a Resource to its children ResourceIds
    resource_children: Dict[str, List[str]]

    def __init__(self, rest_api: RestApi):
        self.rest_api = rest_api
        self.authorizers = {}
        self.validators = {}
        self.documentation_parts = {}
        self.documentation_versions = {}
        self.gateway_responses = {}
        self.models = {}
        self.resolved_models = {}
        self.resource_children = {}


class ApiGatewayStore(BaseStore):
    # maps (API id) -> RestApiContainer
    # TODO: remove CaseInsensitiveDict, and lower the value of the ID when getting it from the tags
    rest_apis: Dict[str, RestApiContainer] = LocalAttribute(default=CaseInsensitiveDict)

    # account details
    account: Dict[str, Any] = LocalAttribute(default=dict)

    # maps (domain_name) -> [path_mappings]
    base_path_mappings: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps ID to VPC link details
    vpc_links: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps cert ID to client certificate details
    client_certificates: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps domain name to domain name model
    domain_names: Dict[str, DomainName] = LocalAttribute(default=dict)

    # maps resource ARN to tags
    TAGS: Dict[str, Dict[str, str]] = CrossRegionAttribute(default=dict)

    def __init__(self):
        super().__init__()

        self.account.update(
            {
                "cloudwatchRoleArn": arns.role_arn("api-gw-cw-role"),
                "throttleSettings": {"burstLimit": 1000, "rateLimit": 500},
                "features": ["UsagePlans"],
                "apiKeyVersion": "1",
            }
        )


apigateway_stores = AccountRegionBundle("apigateway", ApiGatewayStore)
