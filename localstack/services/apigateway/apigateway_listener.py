import re
import logging
import json
import requests
import dateutil.parser
from .helpers import get_rest_api_paths, get_resource_for_path
from six.moves.urllib import parse as urlparse
from requests.models import Response
from flask import Response as FlaskResponse
from localstack.constants import APPLICATION_JSON, PATH_USER_REQUEST
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, to_bytes
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


def _create_response_object(content, code, headers):
    response = Response()
    response.status_code = code
    response.headers = headers
    response._content = content
    return response


def make_response(message):
    return _create_response_object(json.dumps(message), code=200, headers={'Content-Type': APPLICATION_JSON})


def flask_to_requests_response(r):
    return _create_response_object(r.data, code=r.status_code, headers=r.headers)


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

    return [path, query_string_params]


def get_cors_response(headers):
    # TODO: for now we simply return "allow-all" CORS headers, but in the future
    # we should implement custom headers for CORS rules, as supported by API Gateway:
    # http://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html
    response = Response()
    response.status_code = 200
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = '*'
    response._content = ''
    return response


class ProxyListenerApiGateway(ProxyListener):

    def forward_request(self, method, path, data, headers):
        data = data and json.loads(to_str(data))

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
                try:
                    integration = aws_stack.get_apigateway_integration(api_id, 'ANY', path=relative_path)
                    assert integration
                except Exception:
                    # if we have no exact match, try to find an API resource that contains path parameters
                    path_map = get_rest_api_paths(rest_api_id=api_id)
                    try:
                        extracted_path, resource = get_resource_for_path(path=relative_path, path_map=path_map)
                    except Exception:
                        return make_error('Unable to find path %s' % path, 404)

                    integrations = resource.get('resourceMethods', {})
                    integration = integrations.get(method, {})
                    if not integration:
                        integration = integrations.get('ANY', {})
                    integration = integration.get('methodIntegration')
                    if not integration:

                        if method == 'OPTIONS' and 'Origin' in headers:
                            # default to returning CORS headers if this is an OPTIONS request
                            return get_cors_response(headers)

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

                    relative_path, query_string_params = extract_query_string_params(path=relative_path)

                    try:
                        path_params = extract_path_params(path=relative_path, extracted_path=extracted_path)
                    except Exception:
                        path_params = {}

                    result = lambda_api.process_apigateway_invocation(func_arn, relative_path, data_str,
                        headers, path_params=path_params, query_string_params=query_string_params,
                        method=method, resource_path=path)

                    if isinstance(result, FlaskResponse):
                        return flask_to_requests_response(result)

                    response = Response()
                    parsed_result = result if isinstance(result, dict) else json.loads(result)
                    parsed_result = common.json_safe(parsed_result)
                    response.status_code = int(parsed_result.get('statusCode', 200))
                    response.headers.update(parsed_result.get('headers', {}))
                    try:
                        if isinstance(parsed_result['body'], dict):
                            response._content = json.dumps(parsed_result['body'])
                        else:
                            response._content = parsed_result['body']
                    except Exception:
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

    def return_response(self, method, path, data, headers, response):
        try:
            response_data = json.loads(response.content)
            # Fix an upstream issue in Moto API Gateway, where it returns `createdDate` as a string
            # instead of as an integer timestamp:
            # see https://github.com/localstack/localstack/issues/511
            if 'createdDate' in response_data and not isinstance(response_data['createdDate'], int):
                response_data['createdDate'] = int(dateutil.parser.parse(response_data['createdDate']).strftime('%s'))
                response._content = to_bytes(json.dumps(response_data))
                response.headers['Content-Length'] = len(response.content)
        except Exception:
            pass


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
