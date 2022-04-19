import logging
from functools import lru_cache
from typing import NamedTuple, Optional

from werkzeug.http import parse_dict_header

from localstack.aws.spec import ServiceCatalog
from localstack.http import Request
from localstack.services.s3.s3_utils import uses_host_addressing

LOG = logging.getLogger(__name__)


class ServiceIndicators(NamedTuple):
    signing_name: Optional[str] = None
    target_prefix: Optional[str] = None
    operation: Optional[str] = None


def get_header_indicators(request: Request) -> ServiceIndicators:
    x_amz_target = request.headers.get("x-amz-target")
    authorization = request.headers.get("authorization")

    signing_name = None
    if authorization:
        auth_type, auth_info = authorization.split(None, 1)
        auth_type = auth_type.lower().strip()

        if auth_type == "aws4-hmac-sha256":
            values = parse_dict_header(auth_info)
            aws_access_key_id, date, region, signing_name, _ = values["Credential"].split("/")

    if x_amz_target:
        target_prefix, target = x_amz_target.split(".", 1)
    else:
        target_prefix, target = None, None

    return ServiceIndicators(signing_name, target_prefix, target)


signing_name_path_prefix_rules = {
    # custom rules based on URI path prefixes that are not easily generalizable
    "apigateway": {
        "/v2": "apigatewayv2",
    },
    "appconfig": {
        "/configuration": "appconfigdata",
    },
    "execute-api": {
        "/@connections": "apigatewaymanagementapi",
        "/participant": "connectparticipant",
        "*": "iot",
    },
    "ses": {
        "/v2": "sesv2",
        "/v1": "pinpoint-email",
    },
    "greengrass": {"/greengrass/v2/": "greengrassv2"},
    "cloudsearch": {"/2013-01-01": "cloudsearchdomain"},
    "s3": {"/v20180820": "s3control"},
    "iot1click": {
        "/projects": "iot1click-projects",
        "/devices": "iot1click-devices",
    },
    "es": {
        "/2015-01-01": "es",
        "/2021-01-01": "opensearch",
    },
}


def custom_signing_name_rules(signing_name: str, request: Request) -> Optional[str]:
    rules = signing_name_path_prefix_rules.get(signing_name)
    if not rules:

        if signing_name == "servicecatalog":
            if request.path == "/" and request.method == "POST":
                return "servicecatalog"
            else:
                return "servicecatalog-appregistry"

        return

    for prefix, name in rules.items():
        if request.path.startswith(prefix):
            return name

    return rules.get("*", signing_name)


def custom_host_addressing_rules(host: str) -> Optional[str]:
    if uses_host_addressing(host):
        return "s3"
    elif ".execute-api." in host:
        return "apigateway"


@lru_cache()
def get_service_catalog() -> ServiceCatalog:
    return ServiceCatalog()


def guess_aws_service_name(request: Request, services: ServiceCatalog = None) -> Optional[str]:
    if services is None:
        services = get_service_catalog()

    signing_name, target_prefix, operation = get_header_indicators(request)

    candidates = set()
    if signing_name:
        by_signing_name = services.by_signing_name(signing_name)

        if len(by_signing_name) == 1:
            # a unique signing-name -> service name mapping is the case for ~75% of service operations
            return by_signing_name[0]

        custom_match = custom_signing_name_rules(signing_name, request)
        if custom_match:
            return custom_match

        candidates.update(by_signing_name)

    if target_prefix and operation:
        target_candidates = services.by_target_prefix(target_prefix)
        if len(target_candidates) == 1:
            return target_candidates[0]

        candidates.update(target_candidates)
        for service_name in list(candidates):
            service = services.get(service_name)
            if operation not in service.operation_names:
                candidates.remove(service_name)

    if len(candidates) == 1:
        return candidates.pop()

    host = request.host
    if host:
        for prefix, services in services.endpoint_prefix_index.items():
            if host.startswith(prefix):
                if len(services) == 1:
                    return services[0]
                candidates.update(services)

        custom_host_match = custom_host_addressing_rules(host)
        if custom_host_match:
            return custom_host_match

    if len(candidates) == 0:
        return None

    LOG.warning("could not uniquely determine service from request, candidates=%s", candidates)

    if signing_name:
        return signing_name

    return candidates.pop()
