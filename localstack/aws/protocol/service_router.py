import logging
from functools import lru_cache
from typing import NamedTuple, Optional

from werkzeug.http import parse_dict_header

from localstack.aws.spec import ServiceCatalog
from localstack.http import Request
from localstack.services.sqs.sqs_listener import is_sqs_queue_url

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

    return _ServiceIndicators(signing_name, target_prefix, operation, request.host, request.path)


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


def custom_path_addressing_rules(path: str) -> Optional[str]:
    if is_sqs_queue_url(path):
        return "sqs"


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
        signing_name_candidates = services.by_signing_name(signing_name)
        if len(signing_name_candidates) == 1:
            # a unique signing-name -> service name mapping is the case for ~75% of service operations
            return signing_name_candidates[0]

        # try to find a match with the custom signing name rules
        custom_match = custom_signing_name_rules(signing_name, request)
        if custom_match:
            return custom_match

        # still ambiguous - add the services to the list of candidates
        candidates.update(signing_name_candidates)

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

    # 3. check the path
    if path:
        # iterate over the service spec's endpoint prefix
        for prefix, services_per_prefix in services.endpoint_prefix_index.items():
            if path.startswith(prefix):
                if len(services_per_prefix) == 1:
                    return services_per_prefix[0]
                candidates.update(services_per_prefix)

        # try to find a match with the custom path rules
        custom_path_match = custom_path_addressing_rules(path)
        if custom_path_match:
            return custom_path_match

    # 4. check the host (custom host addressing rules)
    if host:
        custom_host_match = custom_host_addressing_rules(host)
        if custom_host_match:
            return custom_host_match

    # 5. check the query / form-data
    values = request.values
    if "Action" in values and "Version" in values:
        # query / ec2 protocol requests always have an action and a version (the action is more significant)
        query_candidates = services.by_operation(values["Action"])
        if len(query_candidates) == 1:
            return query_candidates[0]

        for service in list(query_candidates):
            service_model = services.get(service)
            if values["Version"] != service_model.api_version:
                # the combination of Version and Action is not unique, add matches to the candidates
                query_candidates.remove(service)

        if len(query_candidates) == 1:
            return query_candidates[0]

        candidates.update(query_candidates)

    LOG.warning("could not uniquely determine service from request, candidates=%s", candidates)

    if signing_name:
        return signing_name
    if candidates:
        return candidates.pop()
    return None
