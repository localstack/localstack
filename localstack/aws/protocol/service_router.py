import logging
from functools import lru_cache
from typing import NamedTuple, Optional, Set

from werkzeug.http import parse_dict_header

from localstack.aws.spec import ServiceCatalog
from localstack.http import Request

LOG = logging.getLogger(__name__)


class _ServiceIndicators(NamedTuple):
    """Encapsulates the different fields that might indicate which service a request is targeting."""

    # AWS service's "signing name" - Contained in the Authorization header
    # (https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html)
    signing_name: Optional[str] = None
    # Target prefix as defined in the service specs for non-rest protocols - Contained in the X-Amz-Target header
    target_prefix: Optional[str] = None
    # Targeted operation as defined in the service specs for non-rest protocols - Contained in the X-Amz-Target header
    operation: Optional[str] = None
    # Host field of the HTTP request
    host: Optional[str] = None
    # Path of the HTTP request
    path: Optional[str] = None


def _extract_service_indicators(request: Request) -> _ServiceIndicators:
    """Extracts all different fields that might indicate which service a request is targeting."""
    x_amz_target = request.headers.get("x-amz-target")
    authorization = request.headers.get("authorization")

    signing_name = None
    if authorization:
        try:
            auth_type, auth_info = authorization.split(None, 1)
            auth_type = auth_type.lower().strip()
            if auth_type == "aws4-hmac-sha256":
                values = parse_dict_header(auth_info)
                _, _, _, signing_name, _ = values["Credential"].split("/")
        except (ValueError, KeyError):
            LOG.debug("auth header could not be parsed for service routing: %s", authorization)
            pass
    if x_amz_target:
        if "." in x_amz_target:
            target_prefix, operation = x_amz_target.split(".", 1)
        else:
            target_prefix = None
            operation = x_amz_target
    else:
        target_prefix, operation = None, None

    return _ServiceIndicators(
        signing_name, target_prefix, operation, request.host, request.root_path
    )


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
            # servicecatalog uses the protocol json (only uses root path /)
            # servicecatalog-appregistry uses rest-json (only uses non-root path)
            if request.path == "/":
                return "servicecatalog"
            else:
                return "servicecatalog-appregistry"
        return

    for prefix, name in rules.items():
        if request.path.startswith(prefix):
            return name

    return rules.get("*", signing_name)


def custom_host_addressing_rules(host: str) -> Optional[str]:
    if ".execute-api." in host:
        return "apigateway"
    # TODO this has been removed here, since it has been moved to the custom rules in the current implementation
    # if uses_host_addressing(host):
    #     return "s3"


def custom_payload_rules(candidates: Set[str], request: Request) -> Optional[str]:
    """
    This function allows defining rules which need to inspect the payload (and therefore are very expensive to perform).
    Be careful and make sure that there really is no other way to distinguish the requests than inspecting the payload!

    :param candidates: limited amount of services where the matching service needs to be found
    :param request: complete request
    :return: selected service or None
    """
    return None


@lru_cache()
def get_service_catalog() -> ServiceCatalog:
    """Loads the ServiceCatalog (which contains all the service specs)."""
    return ServiceCatalog()


def determine_aws_service_name(
    request: Request, services: ServiceCatalog = get_service_catalog()
) -> Optional[str]:
    """
    Tries to determine the name of the AWS service an incoming request is targeting.
    :param request: to determine the target service name of
    :param services: service catalog (can be handed in for caching purposes)
    :return: service name string (or None if the targeting service could not be determined exactly)
    """
    signing_name, target_prefix, operation, host, path = _extract_service_indicators(request)
    candidates = set()

    # 1. check the signing names
    if signing_name:
        by_signing_name = services.by_signing_name(signing_name)
        if len(by_signing_name) == 1:
            # a unique signing-name -> service name mapping is the case for ~75% of service operations
            return by_signing_name[0]

        # try to find a match with the custom signing name rules
        custom_match = custom_signing_name_rules(signing_name, request)
        if custom_match:
            return custom_match

        # still ambiguous - add the services to the list of candidates
        candidates.update(by_signing_name)

    # 2. check the target prefix
    if target_prefix and operation:
        target_candidates = services.by_target_prefix(target_prefix)
        if len(target_candidates) == 1:
            # a unique target prefix
            return target_candidates[0]

        # still ambiguous - add the services to the list of candidates
        candidates.update(target_candidates)

        # exclude services where the operation is not contained in the service spec
        for service_name in list(candidates):
            service = services.get(service_name)
            if operation not in service.operation_names:
                candidates.remove(service_name)

        if len(candidates) == 1:
            return candidates.pop()
    else:
        # exclude services which have a target prefix (the current request does not have one)
        for service_name in list(candidates):
            service = services.get(service_name)
            if service.metadata.get("targetPrefix") is not None:
                candidates.remove(service_name)
        if len(candidates) == 1:
            return candidates.pop()

    # 3. check the path / endpoint prefix
    if path:
        for prefix, services_per_prefix in services.endpoint_prefix_index.items():
            if path.startswith(prefix):
                if len(services_per_prefix) == 1:
                    return services_per_prefix[0]
                candidates.update(services_per_prefix)

    # 4. check the host (custom host addressing rules)
    if host:
        custom_host_match = custom_host_addressing_rules(host)
        if custom_host_match:
            return custom_host_match

    # 5. finally perform the expensive rules which need to parse the payload
    custom_payload_match = custom_payload_rules(candidates, request)
    if custom_payload_match:
        return custom_payload_match

    LOG.warning("could not uniquely determine service from request, candidates=%s", candidates)

    if signing_name:
        return signing_name
    if candidates:
        return candidates.pop()
    return None
