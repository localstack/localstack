import re
import logging
import json
import requests
from requests.models import Response
from localstack.constants import *
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.services.awslambda import lambda_api
from localstack.services.kinesis import kinesis_listener
from localstack.services.generic_proxy import ProxyListener
import pprint
from random import randint

# set up logger
LOGGER = logging.getLogger(__name__)

PATH_REGEX_AUTHORIZER = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers/([A-Za-z0-9_\-]+)/.*'
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers(\?.*)?'

# maps API ids to authorizers
AUTHORIZERS = {}

# request parameters global state
# TODO: Redesign to work with multiple REST API's
REQUEST_PATH_PARAMETERS = {}


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
    match = re.match(PATH_REGEX_AUTHORIZER, path)
    if match:
        return match.group(1)
    return re.match(PATH_REGEX_AUTHORIZERS, path).group(1)


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
    # print(method, path)
    if method == 'GET':
        result = get_authorizers(path)
    elif method == 'POST':
        result = add_authorizer(path, data)
    else:
        return make_error('Not implemented for API Gateway authorizers: %s' % method, 404)
    return make_response(result)


def tokenize_path(path):
    return path[1:].split('/')


def make_path_params(path_params_table, tokenized_relative_path):
    path_params = {}
    for param_index in path_params_table:
        try:
            path_params[path_params_table[param_index]] = tokenized_relative_path[param_index]
        except:
            pass
    return path_params


class ProxyListenerApiGateway(ProxyListener):

    def forward_request(self, method, path, data, headers):

        # TODO: Maybe a better match for this, don't know if this is ever a false positive
        if method == 'PUT' and 'requestParameters' in data:
            tokenized_put_path = tokenize_path(path)
            pprint.pprint(tokenized_put_path)
            rest_api_id = tokenized_put_path[1]
            for key in data['requestParameters']:
                REQUEST_PATH_PARAMETERS[rest_api_id] = {randint(0, 99): key.encode('utf-8')}
            pprint.pprint(REQUEST_PATH_PARAMETERS)
        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST
        if re.match(regex2, path):
            search_match = re.search(regex2, path)
            api_id = search_match.group(1)
            relative_path = '/%s' % search_match.group(3)
            try:
                integration = aws_stack.get_apigateway_integration(api_id, method, path=relative_path)
            except Exception as e:
                try:
                    integration = aws_stack.get_apigateway_integration(api_id, method, path='/')
                except Exception as f:
                    pprint.pprint(f)
                    msg = ('API Gateway endpoint "%s" for method "%s" not found' % (relative_path, method))
                    LOGGER.warning(msg)
                    return make_error(msg, 404)
            uri = integration.get('uri')
            if method == 'POST' and integration['type'] in ['AWS']:
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
                    if relative_path == '/':
                        result = lambda_api.process_apigateway_invocation(
                            func_arn, relative_path, data_str, headers)
                    else:
                        # param_list = relative_path[1:].split('/')
                        # path_params = {}
                        # for i, param in enumerate(param_list):
                        #     try:
                        #         path_params[REQUEST_PATH_PARAMETERS[i]] = param
                        #     except:
                        #         msg = ('API Gateway integration type "%s" for method "%s" not yet implemented' %
                        #             (integration['type'], method))
                        #         LOGGER.warning(msg)
                        #         return make_error(msg, 404)
                        pprint.pprint(path)
                        tokenized_path = tokenize_path(path)
                        rest_api_id = tokenized_path[1] # TODO: Figure out a better variable name
                        pprint.pprint(REQUEST_PATH_PARAMETERS)
                        path_params = make_path_params(REQUEST_PATH_PARAMETERS[rest_api_id], tokenized_path)
                        result = lambda_api.process_apigateway_invocation(
                            func_arn, relative_path, data_str, headers, path_params=path_params)
                    response = Response()
                    parsed_result = json.loads(result)
                    response.status_code = int(parsed_result['statusCode'])
                    response.headers.update(parsed_result.get('headers', {}))
                    response_body = parsed_result['body']
                    if response_body is None or response_body == '':
                        response._content = ''
                    else:
                        response._content = json.dumps(response_body)
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
