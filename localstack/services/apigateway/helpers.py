import re
import json
import logging
from jsonpatch import apply_patch
from jsonpointer import JsonPointerException
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack import config
from localstack.utils import common
from localstack.constants import TEST_AWS_ACCOUNT_ID, APPLICATION_JSON, PATH_USER_REQUEST
from localstack.utils.aws import aws_stack
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws.aws_responses import requests_response, requests_error_response_json

LOG = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_MAIN = r'^/restapis/([A-Za-z0-9_\-]+)/[a-z]+(\?.*)?'
PATH_REGEX_SUB = r'^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*'
PATH_REGEX_SUB = r'^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*'

# path regex patterns
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers/?([^?/]+)?(\?.*)?'
PATH_REGEX_VALIDATORS = r'^/restapis/([A-Za-z0-9_\-]+)/requestvalidators/?([^?/]+)?(\?.*)?'
PATH_REGEX_RESPONSES = r'^/restapis/([A-Za-z0-9_\-]+)/gatewayresponses(/[A-Za-z0-9_\-]+)?(\?.*)?'
PATH_REGEX_PATH_MAPPINGS = r'/domainnames/([^/]+)/basepathmappings/?(.*)'
PATH_REGEX_CLIENT_CERTS = r'/clientcertificates/?([^/]+)?$'
PATH_REGEX_VPC_LINKS = r'/vpclinks/([^/]+)?(.*)'

# template for SQS inbound data
APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE = "Action=SendMessage&MessageBody=$util.base64Encode($input.json('$'))"

# TODO: make the CRUD operations in this file generic for the different model types (authorizes, validators, ...)


class APIGatewayRegion(RegionBackend):
    def __init__(self):
        # maps (API id) -> [authorizers]
        self.authorizers = {}
        # maps (API id) -> [validators]
        self.validators = {}
        # account details
        self.account = {
            'cloudwatchRoleArn': aws_stack.role_arn('api-gw-cw-role'),
            'throttleSettings': {
                'burstLimit': 1000,
                'rateLimit': 500
            },
            'features': ['UsagePlans'],
            'apiKeyVersion': '1'
        }
        # maps (domain_name) -> [path_mappings]
        self.base_path_mappings = {}
        # maps ID to VPC link details
        self.vpc_links = {}
        # maps cert ID to client certificate details
        self.client_certificates = {}


def make_json_response(message):
    return requests_response(json.dumps(message), headers={'Content-Type': APPLICATION_JSON})


def make_error_response(message, code=400, error_type=None):
    if code == 404 and not error_type:
        error_type = 'NotFoundException'
    error_type = error_type or 'InvalidRequest'
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
    apply_json_patch_safe(region_details.account, data['patchOperations'], in_place=True)
    return to_account_response_json(region_details.account)


def handle_accounts(method, path, data, headers):
    if method == 'GET':
        return get_account()
    if method == 'PATCH':
        return update_account(data)
    return make_error_response('Not implemented for API Gateway accounts: %s' % method, code=404)


# -----------------
# AUTHORIZERS APIs
# -----------------

def get_authorizer_id_from_path(path):
    match = re.match(PATH_REGEX_AUTHORIZERS, path)
    return match.group(2) if match else None


def _find_authorizer(api_id, authorizer_id):
    region_details = APIGatewayRegion.get()
    auth_list = region_details.authorizers.get(api_id) or []
    authorizer = ([a for a in auth_list if a['id'] == authorizer_id] or [None])[0]
    return authorizer


def normalize_authorizer(data):
    is_list = isinstance(data, list)
    entries = data if is_list else [data]
    for i in range(len(entries)):
        entry = common.clone(entries[i])
        # terraform sends this as a string in patch, so convert to int
        entry['authorizerResultTtlInSeconds'] = int(entry.get('authorizerResultTtlInSeconds', 300))
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
            return make_error_response('Authorizer not found: %s' % authorizer_id,
                code=404, error_type='NotFoundException')
        return to_authorizer_response_json(api_id, authorizer)

    result = [to_authorizer_response_json(api_id, a) for a in auth_list]
    result = {'item': result}
    return result


def add_authorizer(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = common.short_uid()[:6]  # length 6 to make TF tests pass
    result = common.clone(data)

    result['id'] = authorizer_id
    result = normalize_authorizer(result)

    region_details.authorizers[api_id] = region_details.authorizers.get(api_id) or []
    region_details.authorizers[api_id].append(result)

    return make_json_response(to_authorizer_response_json(api_id, result))


def update_authorizer(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = get_authorizer_id_from_path(path)

    authorizer = _find_authorizer(api_id, authorizer_id)
    if authorizer is None:
        return make_error_response('Authorizer not found for API: %s' % api_id, code=404)

    result = apply_json_patch_safe(authorizer, data['patchOperations'])
    result = normalize_authorizer(result)

    auth_list = region_details.authorizers[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]['id'] == authorizer_id:
            auth_list[i] = result

    return make_json_response(to_authorizer_response_json(api_id, result))


def delete_authorizer(path):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    authorizer_id = get_authorizer_id_from_path(path)

    auth_list = region_details.authorizers[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]['id'] == authorizer_id:
            del auth_list[i]
            break

    return make_accepted_response()


def handle_authorizers(method, path, data, headers):
    if method == 'GET':
        return get_authorizers(path)
    if method == 'POST':
        return add_authorizer(path, data)
    if method == 'PATCH':
        return update_authorizer(path, data)
    if method == 'DELETE':
        return delete_authorizer(path)
    return make_error_response('Not implemented for API Gateway authorizers: %s' % method, code=404)


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
        mapping = ([m for m in mappings_list if m['basePath'] == base_path] or [None])[0]
        if mapping is None:
            return make_error_response('Base path mapping not found: %s' % base_path, code=404,
                error_type='NotFoundException')
        return to_base_mapping_response_json(domain_name, base_path, mapping)

    result = [to_base_mapping_response_json(domain_name, m['basePath'], m) for m in mappings_list]
    result = {'item': result}
    return result


def add_base_path_mapping(path, data):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    # Note: "(none)" is a special value in API GW:
    # https://docs.aws.amazon.com/apigateway/api-reference/link-relation/basepathmapping-by-base-path
    base_path = data['basePath'] = data.get('basePath') or '(none)'
    result = common.clone(data)

    region_details.base_path_mappings[domain_name] = region_details.base_path_mappings.get(domain_name) or []
    region_details.base_path_mappings[domain_name].append(result)

    return make_json_response(to_base_mapping_response_json(domain_name, base_path, result))


def update_base_path_mapping(path, data):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    base_path = get_base_path_from_path(path)

    mappings_list = region_details.base_path_mappings.get(domain_name) or []

    mapping = ([m for m in mappings_list if m['basePath'] == base_path] or [None])[0]
    if mapping is None:
        return make_error_response('Not found: mapping for domain name %s, base path %s' %
            (domain_name, base_path), code=404)

    operations = data['patchOperations']
    operations = operations if isinstance(operations, list) else [operations]
    for operation in operations:
        if operation['path'] == '/restapiId':
            operation['path'] = '/restApiId'
    result = apply_json_patch_safe(mapping, operations)

    for i in range(len(mappings_list)):
        if mappings_list[i]['basePath'] == base_path:
            mappings_list[i] = result

    return make_json_response(to_base_mapping_response_json(domain_name, base_path, result))


def delete_base_path_mapping(path):
    region_details = APIGatewayRegion.get()

    domain_name = get_domain_from_path(path)
    base_path = get_base_path_from_path(path)

    mappings_list = region_details.base_path_mappings.get(domain_name) or []
    for i in range(len(mappings_list)):
        if mappings_list[i]['basePath'] == base_path:
            del mappings_list[i]
            return make_accepted_response()

    return make_error_response('Base path mapping %s for domain %s not found' % (base_path, domain_name), code=404)


def handle_base_path_mappings(method, path, data, headers):
    if method == 'GET':
        return get_base_path_mapping(path)
    if method == 'POST':
        return add_base_path_mapping(path, data)
    if method == 'PATCH':
        return update_base_path_mapping(path, data)
    if method == 'DELETE':
        return delete_base_path_mapping(path)
    return make_error_response('Not implemented for API Gateway base path mappings: %s' % method, code=404)


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
    result['clientCertificateId'] = cert_id = common.short_uid()
    result['createdDate'] = common.now_utc()
    result['expirationDate'] = result['createdDate'] + 60 * 60 * 24 * 30  # assume 30 days validity
    result['pemEncodedCertificate'] = 'testcert-123'  # TODO return proper certificate!
    region_details.client_certificates[cert_id] = result
    return make_json_response(to_client_cert_response_json(result))


def update_client_certificate(path, data):
    region_details = APIGatewayRegion.get()
    entity_id = get_cert_id_from_path(path)
    entity = region_details.client_certificates.get(entity_id)
    if entity is None:
        return make_error_response('Client certificate ID "%s" not found' % entity_id, code=404)
    result = apply_json_patch_safe(entity, data['patchOperations'])
    return make_json_response(to_client_cert_response_json(result))


def delete_client_certificate(path):
    region_details = APIGatewayRegion.get()
    entity_id = get_cert_id_from_path(path)
    entity = region_details.client_certificates.pop(entity_id, None)
    if entity is None:
        return make_error_response('VPC link ID "%s" not found for deletion' % entity_id, code=404)
    return make_accepted_response()


def handle_client_certificates(method, path, data, headers):
    if method == 'GET':
        return get_client_certificate(path)
    if method == 'POST':
        return add_client_certificate(path, data)
    if method == 'PATCH':
        return update_client_certificate(path, data)
    if method == 'DELETE':
        return delete_client_certificate(path)
    return make_error_response('Not implemented for API Gateway base path mappings: %s' % method, code=404)


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
    result = {'items': result}
    return result


def add_vpc_link(path, data):
    region_details = APIGatewayRegion.get()
    result = common.clone(data)
    result['id'] = common.short_uid()
    result['status'] = 'AVAILABLE'
    region_details.vpc_links[result['id']] = result
    return make_json_response(to_vpc_link_response_json(result))


def update_vpc_link(path, data):
    region_details = APIGatewayRegion.get()
    vpc_link_id = get_vpc_link_id_from_path(path)
    vpc_link = region_details.vpc_links.get(vpc_link_id)
    if vpc_link is None:
        return make_error_response('VPC link ID "%s" not found' % vpc_link_id, code=404)
    result = apply_json_patch_safe(vpc_link, data['patchOperations'])
    return make_json_response(to_vpc_link_response_json(result))


def delete_vpc_link(path):
    region_details = APIGatewayRegion.get()
    vpc_link_id = get_vpc_link_id_from_path(path)
    vpc_link = region_details.vpc_links.pop(vpc_link_id, None)
    if vpc_link is None:
        return make_error_response('VPC link ID "%s" not found for deletion' % vpc_link_id, code=404)
    return make_accepted_response()


def get_vpc_link_id_from_path(path):
    match = re.match(PATH_REGEX_VPC_LINKS, path)
    return match.group(1) if match else None


def handle_vpc_links(method, path, data, headers):
    if method == 'GET':
        return get_vpc_links(path)
    if method == 'POST':
        return add_vpc_link(path, data)
    if method == 'PATCH':
        return update_vpc_link(path, data)
    if method == 'DELETE':
        return delete_vpc_link(path)
    return make_error_response('Not implemented for API Gateway VPC links: %s' % method, code=404)


# ----------------
# VALIDATORS APIs
# ----------------

def get_validator_id_from_path(path):
    match = re.match(PATH_REGEX_VALIDATORS, path)
    return match.group(2) if match else None


def _find_validator(api_id, validator_id):
    region_details = APIGatewayRegion.get()
    auth_list = region_details.validators.get(api_id) or []
    validator = ([a for a in auth_list if a['id'] == validator_id] or [None])[0]
    return validator


def get_validators(path):
    region_details = APIGatewayRegion.get()

    # This function returns either a list or a single validator (depending on the path)
    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    auth_list = region_details.validators.get(api_id) or []

    if validator_id:
        validator = _find_validator(api_id, validator_id)
        if validator is None:
            return make_error_response('Validator %s for API Gateway %s not found' %
                (validator_id, api_id), code=404)
        return to_validator_response_json(api_id, validator)

    result = [to_validator_response_json(api_id, a) for a in auth_list]
    result = {'item': result}
    return result


def add_validator(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = common.short_uid()[:6]  # length 6 (as in AWS) to make TF tests pass
    result = common.clone(data)
    result['id'] = validator_id

    region_details.validators[api_id] = region_details.validators.get(api_id) or []
    region_details.validators[api_id].append(result)

    return result


def update_validator(path, data):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    validator = _find_validator(api_id, validator_id)
    if validator is None:
        return make_error_response('Validator %s for API Gateway %s not found' % (validator_id, api_id), code=404)

    result = apply_json_patch_safe(validator, data['patchOperations'])

    entry_list = region_details.validators[api_id]
    for i in range(len(entry_list)):
        if entry_list[i]['id'] == validator_id:
            entry_list[i] = result

    return make_json_response(to_validator_response_json(api_id, result))


def delete_validator(path):
    region_details = APIGatewayRegion.get()

    api_id = get_api_id_from_path(path)
    validator_id = get_validator_id_from_path(path)

    auth_list = region_details.validators[api_id]
    for i in range(len(auth_list)):
        if auth_list[i]['id'] == validator_id:
            del auth_list[i]
            return make_accepted_response()

    return make_error_response('Validator %s for API Gateway %s not found' % (validator_id, api_id), code=404)


def handle_validators(method, path, data, headers):
    if method == 'GET':
        return get_validators(path)
    if method == 'POST':
        return add_validator(path, data)
    if method == 'PATCH':
        return update_validator(path, data)
    if method == 'DELETE':
        return delete_validator(path)
    return make_error_response('Not implemented for API Gateway validators: %s' % method, code=404)


# ---------------
# UTIL FUNCTIONS
# ---------------

def to_authorizer_response_json(api_id, data):
    return to_response_json('authorizer', data, api_id=api_id)


def to_validator_response_json(api_id, data):
    return to_response_json('validator', data, api_id=api_id)


def to_base_mapping_response_json(domain_name, base_path, data):
    self_link = '/domainnames/%s/basepathmappings/%s' % (domain_name, base_path)
    return to_response_json('basepathmapping', data, self_link=self_link)


def to_account_response_json(data):
    return to_response_json('account', data, self_link='/account')


def to_vpc_link_response_json(data):
    return to_response_json('vpclink', data)


def to_client_cert_response_json(data):
    return to_response_json('clientcertificate', data, id_attr='clientCertificateId')


def to_response_json(model_type, data, api_id=None, self_link=None, id_attr=None):
    if isinstance(data, list) and len(data) == 1:
        data = data[0]
    id_attr = id_attr or 'id'
    result = common.clone(data)
    if not self_link:
        self_link = '/%ss/%s' % (model_type, data[id_attr])
        if api_id:
            self_link = '/restapis/%s/%s' % (api_id, self_link)
    if '_links' not in result:
        result['_links'] = {}
    result['_links']['self'] = {'href': self_link}
    result['_links']['curies'] = {
        'href': 'https://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-authorizer-latest.html',
        'name': model_type,
        'templated': True
    }
    result['_links']['%s:delete' % model_type] = {'href': self_link}
    return result


def gateway_request_url(api_id, stage_name, path):
    """ Return URL for inbound API gateway for given API ID, stage name, and path """
    pattern = '%s/restapis/{api_id}/{stage_name}/%s{path}' % (config.TEST_APIGATEWAY_URL, PATH_USER_REQUEST)
    return pattern.format(api_id=api_id, stage_name=stage_name, path=path)


def tokenize_path(path):
    return path.lstrip('/').split('/')


def extract_path_params(path, extracted_path):
    tokenized_extracted_path = tokenize_path(extracted_path)
    # Looks for '{' in the tokenized extracted path
    path_params_list = [(i, v) for i, v in enumerate(tokenized_extracted_path) if '{' in v]
    tokenized_path = tokenize_path(path)
    path_params = {}
    for param in path_params_list:
        path_param_name = param[1][1:-1].encode('utf-8')
        path_param_position = param[0]
        if path_param_name.endswith(b'+'):
            path_params[path_param_name] = '/'.join(tokenized_path[path_param_position:])
        else:
            path_params[path_param_name] = tokenized_path[path_param_position]
    path_params = common.json_safe(path_params)
    return path_params


def extract_query_string_params(path):
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
    path = path.rstrip('/') or '/'
    return [path, query_string_params]


def get_cors_response(headers):
    # TODO: for now we simply return "allow-all" CORS headers, but in the future
    # we should implement custom headers for CORS rules, as supported by API Gateway:
    # http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html
    response = Response()
    response.status_code = 200
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response._content = ''
    return response


def get_rest_api_paths(rest_api_id, region_name=None):
    apigateway = aws_stack.connect_to_service(service_name='apigateway', region_name=region_name)
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources['items']:
        path = resource.get('path')
        path = path or aws_stack.get_apigateway_path_for_resource(rest_api_id, resource['id'], region_name=region_name)
        resource_map[path] = resource
    return resource_map


def get_resource_for_path(path, path_map):
    matches = []
    for api_path, details in path_map.items():
        api_path_regex = re.sub(r'\{[^\+]+\+\}', r'[^\?#]+', api_path)
        api_path_regex = re.sub(r'\{[^\}]+\}', r'[^/]+', api_path_regex)
        if re.match(r'^%s$' % api_path_regex, path):
            matches.append((api_path, details))
    if not matches:
        return None
    if len(matches) > 1:
        # check if we have an exact match
        for match in matches:
            if match[0] == path:
                return match
            if path_matches_pattern(path, match[0]):
                return match
        raise Exception('Ambiguous API path %s - matches found: %s' % (path, matches))
    return matches[0]


def path_matches_pattern(path, api_path):
    api_paths = api_path.split('/')
    paths = path.split('/')
    reg_check = re.compile(r'\{(.*)\}')
    results = []
    if len(api_paths) != len(paths):
        return False
    for indx, part in enumerate(api_paths):
        if reg_check.match(part) is None and part:
            results.append(part == paths[indx])
    return len(results) > 0 and all(results)


def connect_api_gateway_to_sqs(gateway_name, stage_name, queue_arn, path, region_name=None):
    resources = {}
    template = APIGATEWAY_SQS_DATA_INBOUND_TEMPLATE
    resource_path = path.replace('/', '')
    region_name = region_name or aws_stack.get_region()
    queue_name = aws_stack.sqs_queue_name(queue_arn)
    sqs_region = aws_stack.extract_region_from_arn(queue_arn) or region_name
    resources[resource_path] = [{
        'httpMethod': 'POST',
        'authorizationType': 'NONE',
        'integrations': [{
            'type': 'AWS',
            'uri': 'arn:aws:apigateway:%s:sqs:path/%s/%s' % (
                sqs_region, TEST_AWS_ACCOUNT_ID, queue_name
            ),
            'requestTemplates': {
                'application/json': template
            },
        }]
    }]
    return aws_stack.create_api_gateway(
        name=gateway_name, resources=resources, stage_name=stage_name, region_name=region_name)


def apply_json_patch_safe(subject, patch_operations, in_place=True, return_list=False):
    results = []
    for operation in patch_operations:
        try:
            # special case: for "replace" operations, assume "" as the default value
            if operation['op'] == 'replace' and operation.get('value') is None:
                operation['value'] = ''

            if operation['op'] != 'remove' and operation.get('value') is None:
                LOG.info('Missing "value" in JSONPatch operation for %s: %s' % (subject, operation))
                continue

            # special case: if "path" is an attribute name pointing to an array in "subject", and we're
            # running an "add" operation, then we should use the standard-compliant notation "/path/-"
            if operation['op'] == 'add' and isinstance(subject.get(operation['path'].strip('/')), list):
                operation['path'] = '%s/-' % operation['path']

            result = apply_patch(subject, [operation], in_place=in_place)
            if not in_place:
                subject = result
            results.append(result)
        except JsonPointerException:
            pass  # path cannot be found - ignore
        except Exception as e:
            if 'non-existent object' in str(e):
                if operation['op'] == 'replace':
                    # fall back to an ADD operation if the REPLACE fails
                    operation['op'] = 'add'
                    return apply_patch(subject, [operation], in_place=in_place)
                if operation['op'] == 'remove' and isinstance(subject, dict):
                    subject.pop(operation['path'], None)
            raise
    if return_list:
        return results
    return (results or [subject])[-1]
