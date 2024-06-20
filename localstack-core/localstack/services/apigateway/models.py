from typing import Any, Dict, List

from moto.apigateway.models import RestAPI as MotoRestAPI
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
from localstack.constants import DEFAULT_AWS_ACCOUNT_ID
from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossAccountAttribute,
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


class RestApiDeployment:
    def __init__(
        self,
        account_id: str,
        region: str,
        localstack_rest_api: RestApiContainer,
        moto_rest_api: MotoRestAPI,
    ):
        self.localstack_rest_api = localstack_rest_api
        self.moto_rest_api = moto_rest_api
        self.account_id = account_id
        self.region = region


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

    # internal deployments, represents a frozen REST API for a deployment, used in our router
    # TODO: make sure API ID are unique across all accounts
    # maps ApiID + deploymentId to a RestApiDeployment, an executable/snapshot of a REST API
    internal_deployments: dict[(str, str), RestApiDeployment] = CrossAccountAttribute(default=dict)

    # active deployments, mapping API ID + Stage to deployment ID
    # TODO: make sure API ID are unique across all accounts
    active_deployments: dict[(str, str), str] = CrossAccountAttribute(dict)

    def __init__(self):
        super().__init__()

        self.account.update(
            {
                "cloudwatchRoleArn": arns.iam_role_arn(
                    "api-gw-cw-role", DEFAULT_AWS_ACCOUNT_ID
                ),  # FIXME: account ID must be of the current store
                "throttleSettings": {"burstLimit": 1000, "rateLimit": 500},
                "features": ["UsagePlans"],
                "apiKeyVersion": "1",
            }
        )


apigateway_stores = AccountRegionBundle("apigateway", ApiGatewayStore)
