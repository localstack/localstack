import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib import parse as urlparse

from botocore.utils import InvalidArnException
from jsonpatch import apply_patch
from jsonpointer import JsonPointerException
from moto.apigateway import models as apigateway_models
from moto.apigateway.utils import create_id as create_resource_id
from requests.models import Response

from localstack import config
from localstack.constants import (
    APPLICATION_JSON,
    LOCALHOST_HOSTNAME,
    PATH_USER_REQUEST,
    TEST_AWS_ACCOUNT_ID,
)
from localstack.services.apigateway.context import InvocationPayload
from localstack.services.generic_proxy import RegionBackend
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import requests_error_response_json, requests_response
from localstack.utils.aws.aws_stack import parse_arn
from localstack.utils.common import try_json

LOG = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_MAIN = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+(\?.*)?"
PATH_REGEX_SUB = r"^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*"

# path regex patterns
PATH_REGEX_AUTHORIZERS = r"^/restapis/([A-Za-z0-9_\-]+)/authorizers/?([^?/]+)?(\?.*)?"
PATH_REGEX_VALIDATORS = r"^/restapis/([A-Za-z0-9_\-]+)/requestvalidators/?([^?/]+)?(\?.*)?"
PATH_REGEX_RESPONSES = r"^/restapis/([A-Za-z0-9_\-]+)/gatewayresponses(/[A-Za-z0-9_\-]+)?(\?.*)?"
PATH_REGEX_DOC_PARTS = r"^/restapis/([A-Za-z0-9_\-]+)/documentation/parts/?([^?/]+)?(\?.*)?"
PATH_REGEX_PATH_MAPPINGS = r"/domainnames/([^/]+)/basepathmappings/?(.*)"
PATH_REGEX_CLIENT_CERTS = r"/clientcertificates/?([^/]+)?$"
PATH_REGEX_VPC_LINKS = r"/vpclinks/([^/]+)?(.*)"
PATH_REGEX_TEST_INVOKE_API = r"^\/restapis\/([A-Za-z0-9_\-]+)\/resources\/([A-Za-z0-9_\-]+)\/methods\/([A-Za-z0-9_\-]+)/?(\?.*)?"

# template for SQS inbound data
APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE = (
    "Action=SendMessage&MessageBody=$util.base64Encode($input.json('$'))"
)

# special tag name to allow specifying a custom ID for new REST APIs
TAG_KEY_CUSTOM_ID = "_custom_id_"

# map API IDs to region names
API_REGIONS = {}

# TODO: make the CRUD operations in this file generic for the different model types (authorizes, validators, ...)


class APIGatewayRegion(RegionBackend):
    # TODO: introduce a RestAPI class to encapsulate the variables below
    # maps (API id) -> [authorizers]
    authorizers: Dict[str, List[Dict]]
    # maps (API id) -> [validators]
    validators: Dict[str, List[Dict]]
    # maps (API id) -> [documentation_parts]
    documentation_parts: Dict[str, List[Dict]]
    # maps (API id) -> [gateway_responses]
    gateway_responses: Dict[str, List[Dict]]
    # account details
    account: Dict[str, Any]
    # maps (domain_name) -> [path_mappings]
    base_path_mappings: Dict[str, List[Dict]]
    # maps ID to VPC link details
    vpc_links: Dict[str, Dict]
    # maps cert ID to client certificate details
    client_certificates: Dict[str, Dict]

    def __init__(self):
        self.authorizers = {}
        self.validators = {}
        self.documentation_parts = {}
        self.gateway_responses = {}
        self.account = {
            "cloudwatchRoleArn": aws_stack.role_arn("api-gw-cw-role"),
            "throttleSettings": {"burstLimit": 1000, "rateLimit": 500},
            "features": ["UsagePlans"],
            "apiKeyVersion": "1",
        }
        self.base_path_mappings = {}
        self.vpc_links = {}
        self.client_certificates = {}


def make_json_response(message):
    return requests_response(json.dumps(message), headers={"Content-Type": APPLICATION_JSON})


def make_error_response(message, code=400, error_type=None):
    if code == 404 and not error_type:
        error_type = "NotFoundException"
    error_type = error_type or "InvalidRequest"
    return requests_error_response_json(message, code=code, error_type=error_type)


def make_accepted_response():
    response = Response()
    response.status_code = 202
    return response


def get_api_id_from_path(path):
    match = re.match(PATH_REGEX_SUB, path)
    if match:
        return match.group(1)
    return re.match(PATH_REGEX_MAIN, path).group(1)


# -------------
# ACCOUNT APIs
# -------------


def get_account():
    region_details = APIGatewayRegion.get()
    return to_account_response_json(region_details.account)


def update_account(data):
    region_details = APIGatewayRegion.get()
    apply_json_patch_safe(region_details.account, data["patchOperations"], in_place=True)
    return to_account_response_json(region_details.account)


def handle_accounts(method, path, data, headers):
    if method == "GET":
        return get_account()
    if method == "PATCH":
        return update_account(data)
    return make_error_response("Not implemented for API Gateway accounts: %s" % method, code=404)


# -----------------
# AUTHORIZERS APIs
# -----------------


def get_authorizer_id_from_path(path):
    match = re.match(PATH_REGEX_AUTHORIZERS, path)
    return match.group(2) if match else None


def _find_authorizer(api_id, authorizer_id):
    return find_api_subentity_by_id(api_id, authorizer_id, "authorizers")


def normalize_authorizer(data):
    is_list = isinstance(data, list)
    entries = data if is_list else [data]
    for i in range(len(entries)):
        entry = common.clone(entries[i])
        # terraform sends this as a string in patch, so convert to int
        entry["authorizerResultTtlInSeconds"] = int(entry.get("authorizerResultTtlInSeconds", 300))
        entries[i] = entry
    return entries if is_list else entries[0]


def get_authorizers(path):
    region_details = APIGatewayRegion.get()

    # This function returns either a list or a single authorizer (depending on the path)
    api_id = get_api_id_from_path(path)
    authorizer_id = get_authorizer_id_from_path(path)

    auth_list = region_details.authorizers.get(api_id) or []

    if authorizer_id:
        authorizer = _find_authorizer(api_id, authorizer_id)
        if authorizer is None:
            return make_error_response(
                "Authorizer not found: %s" % authorizer_id,
                code=404,
                error_type="NotFoundException",
            )
        return to_authorizer_response_json(api_id, authorizer)

    result = [to_authorizer_response_json(api_id, a) for a in auth_list]
    result = {"item": result}
    return result


def add_authorizer(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = common.short_uid()[:6]  # length 6 to make TF tests pass
    result = common.clone(data)

    result["id"] = authorizer_id
    result = normalize_authorizer(result)
    region_details.authorizers.setdefault(api_id, []).append(result)

    return make_json_response(to_authorizer_response_json(api_id, result))


def update_authorizer(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = get_authorizer_id_from_path(path)

    authorizer = _find_authorizer(api_id, authorizer_id)
    if authorizer is None:
        return make_error_response("Authorizer not found for API: %s" % api_id, code=404)

    result = apply_json_patch_safe(authorizer, data["patchOperations"])
    result = normalize_authorizer(result)

    auth_list = region_details.authorizers[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]["id"] == authorizer_id:
            auth_list[i] = result

    return make_json_response(to_authorizer_response_json(api_id, result))


def delete_authorizer(path):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = get_authorizer_id_from_path(path)

    auth_list = region_details.authorizers[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]["id"] == authorizer_id:
            del auth_list[i]
            break

    return make_accepted_response()


def handle_authorizers(method, path, data, headers):
    if method == "GET":
        return get_authorizers(path)
    if method == "POST":
        return add_authorizer(path, data)
    if method == "PATCH":
        return update_authorizer(path, data)
    if method == "DELETE":
        return delete_authorizer(path)
    return make_error_response("Not implemented for API Gateway authorizers: %s" % method, code=404)


# -------------------------
# DOCUMENTATION PARTS APIs
# -------------------------


def get_documentation_part_id_from_path(path):
    match = re.match(PATH_REGEX_DOC_PARTS, path)
    return match.group(2) if match else None


def _find_documentation_part(api_id, documentation_part_id):
    return find_api_subentity_by_id(api_id, documentation_part_id, "documentation_parts")


def get_documentation_parts(path):
    region_details = APIGatewayRegion.get()

    # This function returns either a list or a single entity (depending on the path)
    api_id = get_api_id_from_path(path)
    entity_id = get_documentation_part_id_from_path(path)

    auth_list = region_details.documentation_parts.get(api_id) or []

    if entity_id:
        entity = _find_documentation_part(api_id, entity_id)
        if entity is None:
            return make_error_response(
                "Documentation part not found: %s" % entity_id,
                code=404,
                error_type="NotFoundException",
            )
        return to_documentation_part_response_json(api_id, entity)

    result = [to_documentation_part_response_json(api_id, a) for a in auth_list]
    result = {"item": result}
    return result


def add_documentation_part(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    entity_id = common.short_uid()[:6]  # length 6 to make TF tests pass
    result = common.clone(data)

    result["id"] = entity_id
    region_details.documentation_parts.setdefault(api_id, []).append(result)

    return make_json_response(to_documentation_part_response_json(api_id, result))


def update_documentation_part(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    entity_id = get_documentation_part_id_from_path(path)

    entity = _find_documentation_part(api_id, entity_id)
    if entity is None:
        return make_error_response("Documentation part not found for API: %s" % api_id, code=404)

    result = apply_json_patch_safe(entity, data["patchOperations"])

    auth_list = region_details.documentation_parts[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]["id"] == entity_id:
            auth_list[i] = result

    return make_json_response(to_documentation_part_response_json(api_id, result))


def delete_documentation_part(path):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    entity_id = get_documentation_part_id_from_path(path)

    auth_list = region_details.documentation_parts[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]["id"] == entity_id:
            del auth_list[i]
            break

    return make_accepted_response()


def handle_documentation_parts(method, path, data, headers):
    if method == "GET":
        return get_documentation_parts(path)
    if method == "POST":
        return add_documentation_part(path, data)
    if method == "PATCH":
        return update_documentation_part(path, data)
    if method == "DELETE":
        return delete_documentation_part(path)
    return make_error_response(
        "Not implemented for API Gateway documentation parts: %s" % method, code=404
    )


# -----------------------
# BASE PATH MAPPING APIs
# -----------------------


def get_domain_from_path(path):
    matched = re.match(PATH_REGEX_PATH_MAPPINGS, path)
    return matched.group(1) if matched else None


def get_base_path_from_path(path):
    return re.match(PATH_REGEX_PATH_MAPPINGS, path).group(2)


def get_base_path_mapping(path):
    region_details = APIGatewayRegion.get()

    # This function returns either a list or a single mapping (depending on the path)
    domain_name = get_domain_from_path(path)
    base_path = get_base_path_from_path(path)

    mappings_list = region_details.base_path_mappings.get(domain_name) or []

    if base_path:
        mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
        if mapping is None:
            return make_error_response(
                "Base path mapping not found: %s" % base_path,
                code=404,
                error_type="NotFoundException",
            )
        return to_base_mapping_response_json(domain_name, base_path, mapping)

    result = [to_base_mapping_response_json(domain_name, m["basePath"], m) for m in mappings_list]
    result = {"item": result}
    return result


def add_base_path_mapping(path, data):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    # Note: "(none)" is a special value in API GW:
    # https://docs.aws.amazon.com/apigateway/api-reference/link-relation/basepathmapping-by-base-path
    base_path = data["basePath"] = data.get("basePath") or "(none)"
    result = common.clone(data)

    region_details.base_path_mappings.setdefault(domain_name, []).append(result)

    return make_json_response(to_base_mapping_response_json(domain_name, base_path, result))


def update_base_path_mapping(path, data):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    base_path = get_base_path_from_path(path)

    mappings_list = region_details.base_path_mappings.get(domain_name) or []

    mapping = ([m for m in mappings_list if m["basePath"] == base_path] or [None])[0]
    if mapping is None:
        return make_error_response(
            "Not found: mapping for domain name %s, base path %s in list %s"
            % (domain_name, base_path, mappings_list),
            code=404,
        )

    operations = data["patchOperations"]
    operations = operations if isinstance(operations, list) else [operations]
    for operation in operations:
        if operation["path"] == "/restapiId":
            operation["path"] = "/restApiId"
    result = apply_json_patch_safe(mapping, operations)

    for i in range(len(mappings_list)):
        if mappings_list[i]["basePath"] == base_path:
            mappings_list[i] = result

    return make_json_response(to_base_mapping_response_json(domain_name, base_path, result))


def delete_base_path_mapping(path):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    base_path = get_base_path_from_path(path)

    mappings_list = region_details.base_path_mappings.get(domain_name) or []
    for i in range(len(mappings_list)):
        if mappings_list[i]["basePath"] == base_path:
            del mappings_list[i]
            return make_accepted_response()

    return make_error_response(
        "Base path mapping %s for domain %s not found" % (base_path, domain_name),
        code=404,
    )


def handle_base_path_mappings(method, path, data, headers):
    path = urlparse.unquote(path)
    if method == "GET":
        return get_base_path_mapping(path)
    if method == "POST":
        return add_base_path_mapping(path, data)
    if method == "PATCH":
        return update_base_path_mapping(path, data)
    if method == "DELETE":
        return delete_base_path_mapping(path)
    return make_error_response(
        "Not implemented for API Gateway base path mappings: %s" % method, code=404
    )


# ------------------------
# CLIENT CERTIFICATE APIs
# ------------------------


def get_cert_id_from_path(path):
    matched = re.match(PATH_REGEX_CLIENT_CERTS, path)
    return matched.group(1) if matched else None


def get_client_certificate(path):
    region_details = APIGatewayRegion.get()
    cert_id = get_cert_id_from_path(path)
    result = region_details.client_certificates.get(cert_id)
    if result is None:
        return make_error_response('Client certificate ID "%s" not found' % cert_id, code=404)
    return result


def add_client_certificate(path, data):
    region_details = APIGatewayRegion.get()
    result = common.clone(data)
    result["clientCertificateId"] = cert_id = common.short_uid()
    result["createdDate"] = common.now_utc()
    result["expirationDate"] = result["createdDate"] + 60 * 60 * 24 * 30  # assume 30 days validity
    result["pemEncodedCertificate"] = "testcert-123"  # TODO return proper certificate!
    region_details.client_certificates[cert_id] = result
    return make_json_response(to_client_cert_response_json(result))


def update_client_certificate(path, data):
    region_details = APIGatewayRegion.get()
    entity_id = get_cert_id_from_path(path)
    entity = region_details.client_certificates.get(entity_id)
    if entity is None:
        return make_error_response('Client certificate ID "%s" not found' % entity_id, code=404)
    result = apply_json_patch_safe(entity, data["patchOperations"])
    return make_json_response(to_client_cert_response_json(result))


def delete_client_certificate(path):
    region_details = APIGatewayRegion.get()
    entity_id = get_cert_id_from_path(path)
    entity = region_details.client_certificates.pop(entity_id, None)
    if entity is None:
        return make_error_response('VPC link ID "%s" not found for deletion' % entity_id, code=404)
    return make_accepted_response()


def handle_client_certificates(method, path, data, headers):
    if method == "GET":
        return get_client_certificate(path)
    if method == "POST":
        return add_client_certificate(path, data)
    if method == "PATCH":
        return update_client_certificate(path, data)
    if method == "DELETE":
        return delete_client_certificate(path)
    return make_error_response(
        "Not implemented for API Gateway base path mappings: %s" % method, code=404
    )


# --------------
# VCP LINK APIs
# --------------


def get_vpc_links(path):
    region_details = APIGatewayRegion.get()
    vpc_link_id = get_vpc_link_id_from_path(path)
    if vpc_link_id:
        vpc_link = region_details.vpc_links.get(vpc_link_id)
        if vpc_link is None:
            return make_error_response('VPC link ID "%s" not found' % vpc_link_id, code=404)
        return make_json_response(to_vpc_link_response_json(vpc_link))
    result = region_details.vpc_links.values()
    result = [to_vpc_link_response_json(r) for r in result]
    result = {"items": result}
    return result


def add_vpc_link(path, data):
    region_details = APIGatewayRegion.get()
    result = common.clone(data)
    result["id"] = common.short_uid()
    result["status"] = "AVAILABLE"
    region_details.vpc_links[result["id"]] = result
    return make_json_response(to_vpc_link_response_json(result))


def update_vpc_link(path, data):
    region_details = APIGatewayRegion.get()
    vpc_link_id = get_vpc_link_id_from_path(path)
    vpc_link = region_details.vpc_links.get(vpc_link_id)
    if vpc_link is None:
        return make_error_response('VPC link ID "%s" not found' % vpc_link_id, code=404)
    result = apply_json_patch_safe(vpc_link, data["patchOperations"])
    return make_json_response(to_vpc_link_response_json(result))


def delete_vpc_link(path):
    region_details = APIGatewayRegion.get()
    vpc_link_id = get_vpc_link_id_from_path(path)
    vpc_link = region_details.vpc_links.pop(vpc_link_id, None)
    if vpc_link is None:
        return make_error_response(
            'VPC link ID "%s" not found for deletion' % vpc_link_id, code=404
        )
    return make_accepted_response()


def get_vpc_link_id_from_path(path):
    match = re.match(PATH_REGEX_VPC_LINKS, path)
    return match.group(1) if match else None


def handle_vpc_links(method, path, data, headers):
    if method == "GET":
        return get_vpc_links(path)
    if method == "POST":
        return add_vpc_link(path, data)
    if method == "PATCH":
        return update_vpc_link(path, data)
    if method == "DELETE":
        return delete_vpc_link(path)
    return make_error_response("Not implemented for API Gateway VPC links: %s" % method, code=404)


# ----------------
# VALIDATORS APIs
# ----------------


def get_validator_id_from_path(path):
    match = re.match(PATH_REGEX_VALIDATORS, path)
    return match.group(2) if match else None


def _find_validator(api_id, validator_id):
    region_details = APIGatewayRegion.get()
    auth_list = region_details.validators.get(api_id) or []
    return ([a for a in auth_list if a["id"] == validator_id] or [None])[0]


def get_validators(path):
    region_details = APIGatewayRegion.get()

    # This function returns either a list or a single validator (depending on the path)
    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    auth_list = region_details.validators.get(api_id) or []

    if validator_id:
        validator = _find_validator(api_id, validator_id)
        if validator is None:
            return make_error_response(
                "Validator %s for API Gateway %s not found" % (validator_id, api_id),
                code=404,
            )
        return to_validator_response_json(api_id, validator)

    result = [to_validator_response_json(api_id, a) for a in auth_list]
    result = {"item": result}
    return result


def add_validator(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = common.short_uid()[:6]  # length 6 (as in AWS) to make TF tests pass
    result = common.clone(data)
    result["id"] = validator_id

    region_details.validators.setdefault(api_id, []).append(result)

    return result


def update_validator(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    validator = _find_validator(api_id, validator_id)
    if validator is None:
        return make_error_response(
            "Validator %s for API Gateway %s not found" % (validator_id, api_id),
            code=404,
        )

    result = apply_json_patch_safe(validator, data["patchOperations"])

    entry_list = region_details.validators[api_id]
    for i in range(len(entry_list)):
        if entry_list[i]["id"] == validator_id:
            entry_list[i] = result

    return make_json_response(to_validator_response_json(api_id, result))


def delete_validator(path):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    auth_list = region_details.validators[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]["id"] == validator_id:
            del auth_list[i]
            return make_accepted_response()

    return make_error_response(
        "Validator %s for API Gateway %s not found" % (validator_id, api_id), code=404
    )


def handle_validators(method, path, data, headers):
    if method == "GET":
        return get_validators(path)
    if method == "POST":
        return add_validator(path, data)
    if method == "PATCH":
        return update_validator(path, data)
    if method == "DELETE":
        return delete_validator(path)
    return make_error_response("Not implemented for API Gateway validators: %s" % method, code=404)


# -----------------------
# GATEWAY RESPONSES APIs
# -----------------------


# TODO: merge with to_response_json(..) above
def gateway_response_to_response_json(item, api_id):
    base_path = "/restapis/%s/gatewayresponses" % api_id
    item["_links"] = {
        "self": {"href": "%s/%s" % (base_path, item["responseType"])},
        "gatewayresponse:put": {
            "href": "%s/{response_type}" % base_path,
            "templated": True,
        },
        "gatewayresponse:update": {"href": "%s/%s" % (base_path, item["responseType"])},
    }
    item["responseParameters"] = item.get("responseParameters", {})
    item["responseTemplates"] = item.get("responseTemplates", {})
    return item


def get_gateway_responses(api_id):
    region_details = APIGatewayRegion.get()
    result = region_details.gateway_responses.get(api_id, [])

    href = "http://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-gatewayresponse-{rel}.html"
    base_path = "/restapis/%s/gatewayresponses" % api_id

    result = {
        "_links": {
            "curies": {"href": href, "name": "gatewayresponse", "templated": True},
            "self": {"href": base_path},
            "first": {"href": base_path},
            "gatewayresponse:by-type": {
                "href": "%s/{response_type}" % base_path,
                "templated": True,
            },
            "item": [{"href": "%s/%s" % (base_path, r["responseType"])} for r in result],
        },
        "_embedded": {"item": [gateway_response_to_response_json(i, api_id) for i in result]},
        # Note: Looks like the format required by aws CLI ("item" at top level) differs from the docs:
        # https://docs.aws.amazon.com/apigateway/api-reference/resource/gateway-responses/
        "item": [gateway_response_to_response_json(i, api_id) for i in result],
    }
    return result


def get_gateway_response(api_id, response_type):
    region_details = APIGatewayRegion.get()
    responses = region_details.gateway_responses.get(api_id, [])
    result = [r for r in responses if r["responseType"] == response_type]
    if result:
        return result[0]
    return make_error_response(
        "Gateway response %s for API Gateway %s not found" % (response_type, api_id),
        code=404,
    )


def put_gateway_response(api_id, response_type, data):
    region_details = APIGatewayRegion.get()
    responses = region_details.gateway_responses.setdefault(api_id, [])
    existing = ([r for r in responses if r["responseType"] == response_type] or [None])[0]
    if existing:
        existing.update(data)
    else:
        data["responseType"] = response_type
        responses.append(data)
    return data


def delete_gateway_response(api_id, response_type):
    region_details = APIGatewayRegion.get()
    responses = region_details.gateway_responses.get(api_id) or []
    region_details.gateway_responses[api_id] = [
        r for r in responses if r["responseType"] != response_type
    ]
    return make_accepted_response()


def update_gateway_response(api_id, response_type, data):
    region_details = APIGatewayRegion.get()
    responses = region_details.gateway_responses.setdefault(api_id, [])

    existing = ([r for r in responses if r["responseType"] == response_type] or [None])[0]
    if existing is None:
        return make_error_response(
            "Gateway response %s for API Gateway %s not found" % (response_type, api_id),
            code=404,
        )
    result = apply_json_patch_safe(existing, data["patchOperations"])
    return result


def handle_gateway_responses(method, path, data, headers):
    search_match = re.search(PATH_REGEX_RESPONSES, path)
    api_id = search_match.group(1)
    response_type = (search_match.group(2) or "").lstrip("/")
    if method == "GET":
        if response_type:
            return get_gateway_response(api_id, response_type)
        return get_gateway_responses(api_id)
    if method == "PUT":
        return put_gateway_response(api_id, response_type, data)
    if method == "PATCH":
        return update_gateway_response(api_id, response_type, data)
    if method == "DELETE":
        return delete_gateway_response(api_id, response_type)
    return make_error_response(
        "Not implemented for API Gateway gateway responses: %s" % method, code=404
    )


# ---------------
# UTIL FUNCTIONS
# ---------------


def to_authorizer_response_json(api_id, data):
    return to_response_json("authorizer", data, api_id=api_id)


def to_validator_response_json(api_id, data):
    return to_response_json("validator", data, api_id=api_id)


def to_documentation_part_response_json(api_id, data):
    return to_response_json("documentationpart", data, api_id=api_id)


def to_base_mapping_response_json(domain_name, base_path, data):
    self_link = "/domainnames/%s/basepathmappings/%s" % (domain_name, base_path)
    return to_response_json("basepathmapping", data, self_link=self_link)


def to_account_response_json(data):
    return to_response_json("account", data, self_link="/account")


def to_vpc_link_response_json(data):
    return to_response_json("vpclink", data)


def to_client_cert_response_json(data):
    return to_response_json("clientcertificate", data, id_attr="clientCertificateId")


def to_response_json(model_type, data, api_id=None, self_link=None, id_attr=None):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    id_attr = id_attr or "id"
    result = common.clone(data)
    if not self_link:
        self_link = "/%ss/%s" % (model_type, data[id_attr])
        if api_id:
            self_link = "/restapis/%s/%s" % (api_id, self_link)
    if "_links" not in result:
        result["_links"] = {}
    result["_links"]["self"] = {"href": self_link}
    result["_links"]["curies"] = {
        "href": "https://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-authorizer-latest.html",
        "name": model_type,
        "templated": True,
    }
    result["_links"]["%s:delete" % model_type] = {"href": self_link}
    return result


def find_api_subentity_by_id(api_id, entity_id, map_name):
    region_details = APIGatewayRegion.get()
    auth_list = getattr(region_details, map_name).get(api_id) or []
    entity = ([a for a in auth_list if a["id"] == entity_id] or [None])[0]
    return entity


def path_based_url(api_id, stage_name, path):
    """Return URL for inbound API gateway for given API ID, stage name, and path"""
    pattern = "%s/restapis/{api_id}/{stage_name}/%s{path}" % (
        config.service_url("apigateway"),
        PATH_USER_REQUEST,
    )
    return pattern.format(api_id=api_id, stage_name=stage_name, path=path)


def host_based_url(rest_api_id: str, path: str, stage_name: str = None):
    """Return URL for inbound API gateway for given API ID, stage name, and path with custom dns
    format"""
    pattern = "http://{endpoint}{stage}{path}"
    stage = stage_name and f"/{stage_name}" or ""
    return pattern.format(endpoint=get_execute_api_endpoint(rest_api_id), stage=stage, path=path)


def get_execute_api_endpoint(api_id: str, protocol: str = "") -> str:
    port = config.get_edge_port_http()
    return f"{protocol}{api_id}.execute-api.{LOCALHOST_HOSTNAME}:{port}"


def tokenize_path(path):
    return path.lstrip("/").split("/")


def extract_path_params(path: str, extracted_path: str) -> Dict[str, str]:
    tokenized_extracted_path = tokenize_path(extracted_path)
    # Looks for '{' in the tokenized extracted path
    path_params_list = [(i, v) for i, v in enumerate(tokenized_extracted_path) if "{" in v]
    tokenized_path = tokenize_path(path)
    path_params = {}
    for param in path_params_list:
        path_param_name = param[1][1:-1]
        path_param_position = param[0]
        if path_param_name.endswith("+"):
            path_params[path_param_name.rstrip("+")] = "/".join(
                tokenized_path[path_param_position:]
            )
        else:
            path_params[path_param_name] = tokenized_path[path_param_position]
    path_params = common.json_safe(path_params)
    return path_params


def extract_query_string_params(path: str) -> Tuple[str, Dict[str, str]]:
    parsed_path = urlparse.urlparse(path)
    path = parsed_path.path
    parsed_query_string_params = urlparse.parse_qs(parsed_path.query)

    query_string_params = {}
    for query_param_name, query_param_values in parsed_query_string_params.items():
        if len(query_param_values) == 1:
            query_string_params[query_param_name] = query_param_values[0]
        else:
            query_string_params[query_param_name] = query_param_values

    # strip trailing slashes from path to fix downstream lookups
    path = path.rstrip("/") or "/"
    return [path, query_string_params]


def get_cors_response(headers):
    # TODO: for now we simply return "allow-all" CORS headers, but in the future
    # we should implement custom headers for CORS rules, as supported by API Gateway:
    # http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html
    response = Response()
    response.status_code = 200
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH"
    response.headers["Access-Control-Allow-Headers"] = "*"
    response._content = ""
    return response


def get_rest_api_paths(rest_api_id, region_name=None):
    apigateway = aws_stack.connect_to_service(service_name="apigateway", region_name=region_name)
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources["items"]:
        path = resource.get("path")
        # TODO: check if this is still required in the general case (can we rely on "path" being
        #  present?)
        path = path or aws_stack.get_apigateway_path_for_resource(
            rest_api_id, resource["id"], region_name=region_name
        )
        resource_map[path] = resource
    return resource_map


# TODO: Extract this to a set of rules that have precedence and easy to test individually.
#
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-settings
#  -method-request.html
#  https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html
def get_resource_for_path(path: str, path_map: Dict[str, Dict]) -> Optional[Tuple[str, dict]]:
    matches = []
    # creates a regex from the input path if there are parameters, e.g /foo/{bar}/baz -> /foo/[
    # ^\]+/baz, otherwise is a direct match.
    for api_path, details in path_map.items():
        api_path_regex = re.sub(r"{[^+]+\+}", r"[^\?#]+", api_path)
        api_path_regex = re.sub(r"{[^}]+}", r"[^/]+", api_path_regex)
        if re.match(r"^%s$" % api_path_regex, path):
            matches.append((api_path, details))

    # if there are no matches, it's not worth to proceed, bail here!
    if not matches:
        return None

    # so we have matches and perhaps more than one, e.g
    # /{proxy+} and /api/{proxy+} for inputs like /api/foo/bar
    # /foo/{param1}/baz and /foo/{param1}/{param2} for inputs like /for/bar/baz
    if len(matches) > 1:
        # check if we have an exact match (exact matches take precedence)
        for match in matches:
            if match[0] == path:
                return match

        # not an exact match but parameters can fit in
        for match in matches:
            if path_matches_pattern(path, match[0]):
                return match

        # at this stage, we have more than one match but we have an eager example like
        # /{proxy+} or /api/{proxy+}, so we pick the best match by sorting by length
        sorted_matches = sorted(matches, key=lambda x: len(x[0]), reverse=True)
        return sorted_matches[0]
    return matches[0]


def path_matches_pattern(path, api_path):
    api_paths = api_path.split("/")
    paths = path.split("/")
    reg_check = re.compile(r"{(.*)}")
    if len(api_paths) != len(paths):
        return False
    results = [
        part == paths[indx]
        for indx, part in enumerate(api_paths)
        if reg_check.match(part) is None and part
    ]

    return len(results) > 0 and all(results)


def connect_api_gateway_to_sqs(gateway_name, stage_name, queue_arn, path, region_name=None):
    resources = {}
    template = APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE
    resource_path = path.replace("/", "")
    region_name = region_name or aws_stack.get_region()

    try:
        arn = parse_arn(queue_arn)
        queue_name = arn["resource"]
        sqs_region = arn["region"]
    except InvalidArnException:
        queue_name = queue_arn
        sqs_region = region_name

    resources[resource_path] = [
        {
            "httpMethod": "POST",
            "authorizationType": "NONE",
            "integrations": [
                {
                    "type": "AWS",
                    "uri": "arn:aws:apigateway:%s:sqs:path/%s/%s"
                    % (sqs_region, TEST_AWS_ACCOUNT_ID, queue_name),
                    "requestTemplates": {"application/json": template},
                }
            ],
        }
    ]
    return aws_stack.create_api_gateway(
        name=gateway_name,
        resources=resources,
        stage_name=stage_name,
        region_name=region_name,
    )


def apply_json_patch_safe(subject, patch_operations, in_place=True, return_list=False):
    """Apply JSONPatch operations, using some customizations for compatibility with API GW
    resources."""

    results = []
    patch_operations = (
        [patch_operations] if isinstance(patch_operations, dict) else patch_operations
    )
    for operation in patch_operations:
        try:
            # special case: for "replace" operations, assume "" as the default value
            if operation["op"] == "replace" and operation.get("value") is None:
                operation["value"] = ""

            if operation["op"] != "remove" and operation.get("value") is None:
                LOG.info('Missing "value" in JSONPatch operation for %s: %s', subject, operation)
                continue

            if operation["op"] == "add":
                path = operation["path"]
                target = subject.get(path.strip("/"))
                target = target or common.extract_from_jsonpointer_path(subject, path)
                if not isinstance(target, list):
                    # for "add" operations, we should ensure that the path target is a list instance
                    value = [] if target is None else [target]
                    common.assign_to_path(subject, path, value=value, delimiter="/")
                target = common.extract_from_jsonpointer_path(subject, path)
                if isinstance(target, list) and not path.endswith("/-"):
                    # if "path" is an attribute name pointing to an array in "subject", and we're running
                    # an "add" operation, then we should use the standard-compliant notation "/path/-"
                    operation["path"] = "%s/-" % path

            result = apply_patch(subject, [operation], in_place=in_place)
            if not in_place:
                subject = result
            results.append(result)
        except JsonPointerException:
            pass  # path cannot be found - ignore
        except Exception as e:
            if "non-existent object" in str(e):
                if operation["op"] == "replace":
                    # fall back to an ADD operation if the REPLACE fails
                    operation["op"] = "add"
                    result = apply_patch(subject, [operation], in_place=in_place)
                    results.append(result)
                    continue
                if operation["op"] == "remove" and isinstance(subject, dict):
                    result = subject.pop(operation["path"], None)
                    results.append(result)
                    continue
            raise
    if return_list:
        return results
    return (results or [subject])[-1]


def import_api_from_openapi_spec(
    rest_api: apigateway_models.RestAPI, function_id: str, body: Dict, query_params: Dict
) -> apigateway_models.RestAPI:
    """Import an API from an OpenAPI spec document"""

    # Remove default root, then add paths from API spec
    rest_api.resources = {}

    def get_or_create_path(path):
        parts = path.rstrip("/").replace("//", "/").split("/")
        parent_id = ""
        if len(parts) > 1:
            parent_path = "/".join(parts[:-1])
            parent = get_or_create_path(parent_path)
            parent_id = parent.id
        existing = [
            r
            for r in rest_api.resources.values()
            if r.path_part == (parts[-1] or "/") and (r.parent_id or "") == (parent_id or "")
        ]
        if existing:
            return existing[0]
        return add_path(path, parts, parent_id=parent_id)

    def add_path(path, parts, parent_id=""):
        child_id = create_resource_id()
        path = path or "/"
        child = apigateway_models.Resource(
            resource_id=child_id,
            region_name=rest_api.region_name,
            api_id=rest_api.id,
            path_part=parts[-1] or "/",
            parent_id=parent_id,
        )
        for m, payload in body["paths"].get(path, {}).items():
            m = m.upper()
            payload = payload["x-amazon-apigateway-integration"]

            child.add_method(m, None, None)
            integration = apigateway_models.Integration(
                http_method=m,
                uri=payload.get("uri"),
                integration_type=payload["type"],
                pass_through_behavior=payload.get("passthroughBehavior"),
                request_templates=payload.get("requestTemplates") or {},
            )
            integration.create_integration_response(
                status_code=payload.get("responses", {}).get("default", {}).get("statusCode", 200),
                selection_pattern=None,
                response_templates=None,
                content_handling=None,
            )
            child.resource_methods[m]["methodIntegration"] = integration

        rest_api.resources[child_id] = child
        return child

    basepath_mode = (query_params.get("basepath") or ["prepend"])[0]
    base_path = (body.get("basePath") or "") if basepath_mode == "prepend" else ""
    for path in body.get("paths", {}):
        get_or_create_path(base_path + path)

    policy = body.get("x-amazon-apigateway-policy")
    if policy:
        policy = json.dumps(policy) if isinstance(policy, dict) else str(policy)
        rest_api.policy = policy
    minimum_compression_size = body.get("x-amazon-apigateway-minimum-compression-size")
    if minimum_compression_size is not None:
        rest_api.minimum_compression_size = int(minimum_compression_size)
    endpoint_config = body.get("x-amazon-apigateway-endpoint-configuration")
    if endpoint_config:
        if endpoint_config.get("vpcEndpointIds"):
            endpoint_config.setdefault("types", ["PRIVATE"])
        rest_api.endpoint_configuration = endpoint_config

    return rest_api


def apply_template(
    integration: Dict[str, Any],
    req_res_type: str,
    data: InvocationPayload,
    path_params=None,
    query_params=None,
    headers=None,
    context=None,
):
    if path_params is None:
        path_params = {}
    if query_params is None:
        query_params = {}
    if headers is None:
        headers = {}
    if context is None:
        context = {}
    integration_type = integration.get("type") or integration.get("integrationType")
    if integration_type in ["HTTP", "AWS"]:
        # apply custom request template
        content_type = APPLICATION_JSON  # TODO: make configurable!
        template = integration.get("%sTemplates" % req_res_type, {}).get(content_type)
        if template:
            variables = {"context": context or {}}
            input_ctx = {"body": data}
            # little trick to flatten the input context so velocity templates
            # work from the root.
            # orig - { "body": '{"action": "$default","message":"foobar"}'
            # after - {
            #   "body": '{"action": "$default","message":"foobar"}',
            #   "action": "$default",
            #   "message": "foobar"
            # }
            if data:
                dict_pack = try_json(data)
                if isinstance(dict_pack, dict):
                    for k, v in dict_pack.items():
                        input_ctx.update({k: v})

            def _params(name=None):
                # See https://docs.aws.amazon.com/apigateway/latest/developerguide/
                #    api-gateway-mapping-template-reference.html#input-variable-reference
                # Returns "request parameter from the path, query string, or header value (
                # searched in that order)"
                combined = {}
                combined.update(path_params or {})
                combined.update(query_params or {})
                combined.update(headers or {})
                return combined if not name else combined.get(name)

            input_ctx["params"] = _params
            data = aws_stack.render_velocity_template(template, input_ctx, variables=variables)
    return data
