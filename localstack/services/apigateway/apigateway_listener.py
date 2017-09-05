import re
import logging
import json
import requests
from requests.models import Response
from localstack.constants import APPLICATION_JSON, PATH_USER_REQUEST
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.services.awslambda import lambda_api
from localstack.services.kinesis import kinesis_listener
from localstack.services.generic_proxy import ProxyListener

# set up logger
LOGGER = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_MAIN = r'^/restapis/([A-Za-z0-9_\-]+)/[a-z]+(\?.*)?'
PATH_REGEX_SUB = r'^/restapis/([A-Za-z0-9_\-]+)/[a-z]+/([A-Za-z0-9_\-]+)/.*'
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers(\?.*)?'

# maps API ids to authorizers
AUTHORIZERS = {}


def make_response(message):
    response = Response()
    response.status_code = 200
    response.headers['Content-Type'] = APPLICATION_JSON
    response._content = json.dumps(message)
    return response


def make_error(message, code=400):
    response = Response()
    response.status_code = code
    response._content = json.dumps({'message': message})
    return response


def get_api_id_from_path(path):
    match = re.match(PATH_REGEX_SUB, path)
    if match:
        return match.group(1)
    return re.match(PATH_REGEX_MAIN, path).group(1)


def get_authorizers(path):
    result = {'item': []}
    api_id = get_api_id_from_path(path)
    for key, value in AUTHORIZERS.items():
        auth_api_id = get_api_id_from_path(value['_links']['self']['href'])
        if auth_api_id == api_id:
            result['item'].append(value)
    return result


def add_authorizer(path, data):
    api_id = get_api_id_from_path(path)
    result = common.clone(data)
    result['id'] = common.short_uid()
    if '_links' not in result:
        result['_links'] = {}
    result['_links']['self'] = {
        'href': '/restapis/%s/authorizers/%s' % (api_id, result['id'])
    }
    AUTHORIZERS[result['id']] = result
    return result


def handle_authorizers(method, path, data, headers):
    result = {}
    if method == 'GET':
        result = get_authorizers(path)
    elif method == 'POST':
        result = add_authorizer(path, data)
    else:
        return make_error('Not implemented for API Gateway authorizers: %s' % method, 404)
    return make_response(result)


def tokenize_path(path):
    return path.lstrip('/').split('/')


def get_rest_api_paths(rest_api_id):
    apigateway = aws_stack.connect_to_service(service_name='apigateway')
    resources = apigateway.get_resources(restApiId=rest_api_id, limit=100)
    resource_map = {}
    for resource in resources['items']:
        path = aws_stack.get_apigateway_path_for_resource(rest_api_id, resource['id'])
        resource_map[path] = resource
    return resource_map


def extract_path_params(path, extracted_path):
    tokenized_extracted_path = tokenize_path(extracted_path)
    # Looks for '{' in the tokenized extracted path
    path_params_list = [(i, v) for i, v in enumerate(tokenized_extracted_path) if '{' in v]
    tokenized_path = tokenize_path(path)
    path_params = {}
    for param in path_params_list:
        path_param_name = param[1][1:-1].encode('utf-8')
        path_param_position = param[0]
        path_params[path_param_name] = tokenized_path[path_param_position]
    path_params = common.json_safe(path_params)
    return path_params


def get_resource_for_path(path, path_map):
    matches = []
    for api_path, details in path_map.items():
        api_path_regex = re.sub(r'\{[^\}]+\}', '[^/]+', api_path)
        if re.match(r'^%s$' % api_path_regex, path):
            matches.append((api_path, details))
    if not matches:
        return None
    if len(matches) > 1:
        # check if we have an exact match
        for match in matches:
            if match[0] == path:
                return match
        raise Exception('Ambiguous API path %s - matches found: %s' % (path, matches))
    return matches[0]


class ProxyListenerApiGateway(ProxyListener):

    def forward_request(self, method, path, data, headers):

        # Paths to match
        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST

        if re.match(regex2, path):
            search_match = re.search(regex2, path)
            api_id = search_match.group(1)
            relative_path = '/%s' % search_match.group(3)
            try:
                integration = aws_stack.get_apigateway_integration(api_id, method, path=relative_path)
                assert integration
            except Exception:
                # if we have no exact match, try to find an API resource that contains path parameters
                path_map = get_rest_api_paths(rest_api_id=api_id)
                extracted_path, resource = get_resource_for_path(path=relative_path, path_map=path_map) or {}
                integrations = resource.get('resourceMethods', {})
                integration = integrations.get(method, {})
                integration = integration.get('methodIntegration')
                if not integration:
                    return make_error('Unable to find integration for path %s' % path, 404)

            uri = integration.get('uri')
            if method == 'POST' and integration['type'] == 'AWS':
                if uri.endswith('kinesis:action/PutRecords'):
                    template = integration['requestTemplates'][APPLICATION_JSON]
                    new_request = aws_stack.render_velocity_template(template, data)

                    # forward records to target kinesis stream
                    headers = aws_stack.mock_aws_request_headers(service='kinesis')
                    headers['X-Amz-Target'] = kinesis_listener.ACTION_PUT_RECORDS
                    result = common.make_http_request(url=TEST_KINESIS_URL,
                        method='POST', data=new_request, headers=headers)
                    return result
                else:
                    msg = 'API Gateway action uri "%s" not yet implemented' % uri
                    LOGGER.warning(msg)
                    return make_error(msg, 404)

            elif integration['type'] == 'AWS_PROXY':
                if uri.startswith('arn:aws:apigateway:') and ':lambda:path' in uri:
                    func_arn = uri.split(':lambda:path')[1].split('functions/')[1].split('/invocations')[0]
                    data_str = json.dumps(data) if isinstance(data, dict) else data

                    try:
                        path_params = extract_path_params(path=relative_path, extracted_path=extracted_path)
                    except:
                        path_params = {}
                    result = lambda_api.process_apigateway_invocation(func_arn, relative_path, data_str,
                        headers, path_params=path_params, method=method, resource_path=path)

                    response = Response()
                    parsed_result = result if isinstance(result, dict) else json.loads(result)
                    parsed_result = common.json_safe(parsed_result)
                    response.status_code = int(parsed_result.get('statusCode', 200))
                    response.headers.update(parsed_result.get('headers', {}))
                    try:
                        response_body = parsed_result['body']
                        response._content = json.dumps(response_body)
                    except:
                        response._content = '{}'
                    return response
                else:
                    msg = 'API Gateway action uri "%s" not yet implemented' % uri
                    LOGGER.warning(msg)
                    return make_error(msg, 404)

            elif integration['type'] == 'HTTP':
                function = getattr(requests, method.lower())
                if isinstance(data, dict):
                    data = json.dumps(data)
                result = function(integration['uri'], data=data, headers=headers)
                return result

            else:
                msg = ('API Gateway integration type "%s" for method "%s" not yet implemented' %
                    (integration['type'], method))
                LOGGER.warning(msg)
                return make_error(msg, 404)

            return 200

        if re.match(PATH_REGEX_AUTHORIZERS, path):
            return handle_authorizers(method, path, data, headers)

        return True


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
