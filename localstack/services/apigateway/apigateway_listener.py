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

# set up logger
LOGGER = logging.getLogger(__name__)

PATH_REGEX_AUTHORIZER = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers/([A-Za-z0-9_\-]+)/.*'
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


class ProxyListenerApiGateway(ProxyListener):

    def forward_request(self, method, path, data, headers):

        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST
        if re.match(regex2, path):
            search_match = re.search(regex2, path)
            api_id = search_match.group(1)
            path = '/%s' % search_match.group(3)
            try:
                integration = aws_stack.get_apigateway_integration(api_id, method, path)
            except Exception as e:
                msg = ('API Gateway endpoint "%s" for method "%s" not found' % (path, method))
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
                    result = lambda_api.process_apigateway_invocation(func_arn, path, data_str, headers)
                    response = Response()
                    parsed_result = json.loads(result)
                    response.status_code = int(parsed_result['statusCode'])
                    response.headers.update(parsed_result.get('headers', {}))
                    try:
                        response_body = parsed_result['body']
                        response._content = json.dumps(response_body)
                    except:
                        pass
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
