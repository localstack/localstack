import re
import json
import logging
import requests
from flask import Response as FlaskResponse
from six.moves.urllib_parse import urljoin
from requests.models import Response
from localstack.constants import APPLICATION_JSON, PATH_USER_REQUEST
from localstack.config import TEST_KINESIS_URL, TEST_SQS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, to_bytes
from localstack.utils.analytics import event_publisher
from localstack.services.kinesis import kinesis_listener
from localstack.services.awslambda import lambda_api
from localstack.services.apigateway import helpers
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import flask_to_requests_response, requests_response, LambdaResponse
from localstack.services.apigateway.helpers import (get_resource_for_path,
    handle_authorizers, extract_query_string_params,
    extract_path_params, make_error_response, get_cors_response)

# set up logger
LOGGER = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers(\?.*)?'
PATH_REGEX_RESPONSES = r'^/restapis/([A-Za-z0-9_\-]+)/gatewayresponses(/[A-Za-z0-9_\-]+)?(\?.*)?'
PATH_REGEX_USER_REQUEST = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST

# Maps API IDs to list of gateway responses
GATEWAY_RESPONSES = {}


class AuthorizationError(Exception):
    pass


class ProxyListenerApiGateway(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if re.match(PATH_REGEX_USER_REQUEST, path):
            search_match = re.search(PATH_REGEX_USER_REQUEST, path)
            api_id = search_match.group(1)
            stage = search_match.group(2)
            relative_path_w_query_params = '/%s' % search_match.group(3)
            try:
                return invoke_rest_api(api_id, stage, method, relative_path_w_query_params, data, headers, path=path)
            except AuthorizationError as e:
                return make_error_response('Not authorized to invoke REST API %s: %s' % (api_id, e), 403)

        data = data and json.loads(to_str(data))

        if re.match(PATH_REGEX_AUTHORIZERS, path):
            return handle_authorizers(method, path, data, headers)

        if re.match(PATH_REGEX_RESPONSES, path):
            search_match = re.search(PATH_REGEX_RESPONSES, path)
            api_id = search_match.group(1)
            if method == 'GET':
                return get_gateway_responses(api_id)
            if method == 'PUT':
                response_type = search_match.group(2).lstrip('/')
                return put_gateway_response(api_id, response_type, data)

        return True

    def return_response(self, method, path, data, headers, response):
        # fix backend issue (missing support for API documentation)
        if re.match(r'/restapis/[^/]+/documentation/versions', path):
            if response.status_code == 404:
                return requests_response({'position': '1', 'items': []})

        # publish event
        if method == 'POST' and path == '/restapis':
            content = json.loads(to_str(response.content))
            event_publisher.fire_event(event_publisher.EVENT_APIGW_CREATE_API,
                payload={'a': event_publisher.get_hash(content['id'])})
        api_regex = r'^/restapis/([a-zA-Z0-9\-]+)$'
        if method == 'DELETE' and re.match(api_regex, path):
            api_id = re.sub(api_regex, r'\1', path)
            event_publisher.fire_event(event_publisher.EVENT_APIGW_DELETE_API,
                payload={'a': event_publisher.get_hash(api_id)})


# ------------
# API METHODS
# ------------

def get_gateway_responses(api_id):
    result = GATEWAY_RESPONSES.get(api_id, [])
    base_path = '/restapis/%s/gatewayresponses' % api_id
    href = 'http://docs.aws.amazon.com/apigateway/latest/developerguide/restapi-gatewayresponse-{rel}.html'

    def item(i):
        i['_links'] = {
            'self': {
                'href': '%s/%s' % (base_path, i['responseType'])
            },
            'gatewayresponse:put': {
                'href': '%s/{response_type}' % base_path,
                'templated': True
            },
            'gatewayresponse:update': {
                'href': '%s/%s' % (base_path, i['responseType'])
            }
        }
        i['responseParameters'] = i.get('responseParameters', {})
        i['responseTemplates'] = i.get('responseTemplates', {})
        return i

    result = {
        '_links': {
            'curies': {
                'href': href,
                'name': 'gatewayresponse',
                'templated': True
            },
            'self': {'href': base_path},
            'first': {'href': base_path},
            'gatewayresponse:by-type': {
                'href': '%s/{response_type}' % base_path,
                'templated': True
            },
            'item': [{'href': '%s/%s' % (base_path, r['responseType'])} for r in result]
        },
        '_embedded': {
            'item': [item(i) for i in result]
        },
        # Note: Looks like the format required by aws CLI ("item" at top level) differs from the docs:
        # https://docs.aws.amazon.com/apigateway/api-reference/resource/gateway-responses/
        'item': [item(i) for i in result]
    }
    return result


def put_gateway_response(api_id, response_type, data):
    GATEWAY_RESPONSES[api_id] = GATEWAY_RESPONSES.get(api_id, [])
    data['responseType'] = response_type
    GATEWAY_RESPONSES[api_id].append(data)
    return data


def run_authorizer(api_id, headers, authorizer):
    # TODO implement authorizers
    pass


def authorize_invocation(api_id, headers):
    client = aws_stack.connect_to_service('apigateway')
    authorizers = client.get_authorizers(restApiId=api_id, limit=100).get('items', [])
    for authorizer in authorizers:
        run_authorizer(api_id, headers, authorizer)


def invoke_rest_api(api_id, stage, method, invocation_path, data, headers, path=None):
    path = path or invocation_path
    relative_path, query_string_params = extract_query_string_params(path=invocation_path)

    # run gateway authorizers for this request
    authorize_invocation(api_id, headers)

    path_map = helpers.get_rest_api_paths(rest_api_id=api_id)
    try:
        extracted_path, resource = get_resource_for_path(path=relative_path, path_map=path_map)
    except Exception:
        return make_error_response('Unable to find path %s' % path, 404)

    integrations = resource.get('resourceMethods', {})
    integration = integrations.get(method, {})
    if not integration:
        integration = integrations.get('ANY', {})
    integration = integration.get('methodIntegration')
    if not integration:
        if method == 'OPTIONS' and 'Origin' in headers:
            # default to returning CORS headers if this is an OPTIONS request
            return get_cors_response(headers)
        return make_error_response('Unable to find integration for path %s' % path, 404)

    uri = integration.get('uri')
    if integration['type'] == 'AWS':
        if 'kinesis:action/' in uri:
            if uri.endswith('kinesis:action/PutRecords'):
                target = kinesis_listener.ACTION_PUT_RECORDS
            if uri.endswith('kinesis:action/ListStreams'):
                target = kinesis_listener.ACTION_LIST_STREAMS

            template = integration['requestTemplates'][APPLICATION_JSON]
            new_request = aws_stack.render_velocity_template(template, data)
            # forward records to target kinesis stream
            headers = aws_stack.mock_aws_request_headers(service='kinesis')
            headers['X-Amz-Target'] = target
            result = common.make_http_request(url=TEST_KINESIS_URL,
                method='POST', data=new_request, headers=headers)
            return result

        if method == 'POST':
            if uri.startswith('arn:aws:apigateway:') and ':sqs:path' in uri:
                template = integration['requestTemplates'][APPLICATION_JSON]
                account_id, queue = uri.split('/')[-2:]
                region_name = uri.split(':')[3]

                new_request = aws_stack.render_velocity_template(template, data) + '&QueueName=%s' % queue
                headers = aws_stack.mock_aws_request_headers(service='sqs', region_name=region_name)

                url = urljoin(TEST_SQS_URL, 'queue/%s' % queue)
                result = common.make_http_request(url, method='POST', headers=headers, data=new_request)
                return result

        msg = 'API Gateway AWS integration action URI "%s", method "%s" not yet implemented' % (uri, method)
        LOGGER.warning(msg)
        return make_error_response(msg, 404)

    elif integration['type'] == 'AWS_PROXY':
        if uri.startswith('arn:aws:apigateway:') and ':lambda:path' in uri:
            func_arn = uri.split(':lambda:path')[1].split('functions/')[1].split('/invocations')[0]
            data_str = json.dumps(data) if isinstance(data, (dict, list)) else to_str(data)
            account_id = uri.split(':lambda:path')[1].split(':function:')[0].split(':')[-1]

            source_ip = headers['X-Forwarded-For'].split(',')[-2]

            # Sample request context:
            # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-create-api-as-simple-proxy-for-lambda.html#api-gateway-create-api-as-simple-proxy-for-lambda-test
            request_context = {
                'path': relative_path,
                'accountId': account_id,
                'resourceId': resource.get('id'),
                'stage': stage,
                'identity': {
                    'accountId': account_id,
                    'sourceIp': source_ip,
                    'userAgent': headers['User-Agent'],
                }
            }

            try:
                path_params = extract_path_params(path=relative_path, extracted_path=extracted_path)
            except Exception:
                path_params = {}

            result = lambda_api.process_apigateway_invocation(func_arn, relative_path, data_str,
                headers, path_params=path_params, query_string_params=query_string_params,
                method=method, resource_path=path, request_context=request_context)
            if isinstance(result, FlaskResponse):
                return flask_to_requests_response(result)
            if isinstance(result, Response):
                return result

            response = LambdaResponse()
            parsed_result = result if isinstance(result, dict) else json.loads(str(result))
            parsed_result = common.json_safe(parsed_result)
            parsed_result = {} if parsed_result is None else parsed_result
            response.status_code = int(parsed_result.get('statusCode', 200))
            parsed_headers = parsed_result.get('headers', {})
            if parsed_headers is not None:
                response.headers.update(parsed_headers)
            try:
                if isinstance(parsed_result['body'], dict):
                    response.content = json.dumps(parsed_result['body'])
                else:
                    response.content = to_bytes(parsed_result['body'])
            except Exception:
                response._content = '{}'
            response.headers['Content-Length'] = len(response.content)
            response.multi_value_headers = parsed_result.get('multiValueHeaders') or {}
            return response

        elif uri.startswith('arn:aws:apigateway:') and ':dynamodb:action' in uri:
            # arn:aws:apigateway:us-east-1:dynamodb:action/PutItem&Table=MusicCollection
            table_name = uri.split(':dynamodb:action')[1].split('&Table=')[1]
            action = uri.split(':dynamodb:action')[1].split('&Table=')[0]

            if 'PutItem' in action and method == 'PUT':
                response_template = path_map.get(relative_path, {}).get('resourceMethods', {})\
                    .get(method, {}).get('methodIntegration', {}).\
                    get('integrationResponses', {}).get('200', {}).get('responseTemplates', {})\
                    .get('application/json', None)

                if response_template is None:
                    msg = 'Invalid response template defined in integration response.'
                    return make_error_response(msg, 404)

                response_template = json.loads(response_template)
                if response_template['TableName'] != table_name:
                    msg = 'Invalid table name specified in integration response template.'
                    return make_error_response(msg, 404)

                dynamo_client = aws_stack.connect_to_resource('dynamodb')
                table = dynamo_client.Table(table_name)

                event_data = {}
                data_dict = json.loads(data)
                for key, _ in response_template['Item'].items():
                    event_data[key] = data_dict[key]

                table.put_item(Item=event_data)
                response = requests_response(event_data, headers=aws_stack.mock_aws_request_headers())
                return response
        else:
            msg = 'API Gateway action uri "%s" not yet implemented' % uri
            LOGGER.warning(msg)
            return make_error_response(msg, 404)

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
        return make_error_response(msg, 404)


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
