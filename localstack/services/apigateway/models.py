from typing import Any, Dict, List

from localstack.services.stores import (
    AccountRegionBundle,
    BaseStore,
    CrossRegionAttribute,
    LocalAttribute,
)
from localstack.utils.aws import arns


class ApiGatewayStore(BaseStore):
    # TODO: introduce a RestAPI class to encapsulate the variables below
    # maps (API id) -> [authorizers]
    authorizers: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps (API id) -> [validators]
    validators: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps (API id) -> [documentation_parts]
    documentation_parts: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps (API id) -> [gateway_responses]
    gateway_responses: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # account details
    account: Dict[str, Any] = LocalAttribute(default=dict)

    # maps (domain_name) -> [path_mappings]
    base_path_mappings: Dict[str, List[Dict]] = LocalAttribute(default=dict)

    # maps ID to VPC link details
    vpc_links: Dict[str, Dict] = LocalAttribute(default=dict)

    # maps cert ID to client certificate details
    client_certificates: Dict[str, Dict] = LocalAttribute(default=dict)

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
