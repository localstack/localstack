import re
import json
import time
import logging
import requests
import datetime
from flask import Response as FlaskResponse
from six.moves.urllib_parse import urljoin
from requests.models import Response
from localstack.utils import common
from localstack.config import TEST_KINESIS_URL, TEST_SQS_URL
from localstack.constants import APPLICATION_JSON, PATH_USER_REQUEST, TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, to_bytes
from localstack.utils.analytics import event_publisher
from localstack.services.kinesis import kinesis_listener
from localstack.services.awslambda import lambda_api
from localstack.services.apigateway import helpers
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import flask_to_requests_response, requests_response, LambdaResponse
from localstack.services.apigateway.helpers import (get_resource_for_path, handle_authorizers,
    extract_query_string_params, extract_path_params, make_error_response, get_cors_response)

# set up logger
LOGGER = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers(\?.*)?'
PATH_REGEX_RESPONSES = r'^/restapis/([A-Za-z0-9_\-]+)/gatewayresponses(/[A-Za-z0-9_\-]+)?(\?.*)?'
PATH_REGEX_USER_REQUEST = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST
HOST_REGEX_EXECUTE_API = r'(.*://)?([a-zA-Z0-9-]+)\.execute-api\..*'

# Maps API IDs to list of gateway responses
GATEWAY_RESPONSES = {}


class AuthorizationError(Exception):
    pass


class ProxyListenerApiGateway(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if re.match(PATH_REGEX_USER_REQUEST, path):
            return invoke_rest_api_from_request(method, path, data, headers)

        data = data and json.loads(to_str(data))

        if re.match(PATH_REGEX_AUTHORIZERS, path):
            return handle_authorizers(method, path, data, headers)

        if re.match(PATH_REGEX_RESPONSES, path):
            search_match = re.search(PATH_REGEX_RESPONSES, path)
            api_id = search_match.group(1)
            response_type = (search_match.group(2) or '').lstrip('/')
            if method == 'GET':
                if response_type:
                    return get_gateway_response(api_id, response_type)
                return get_gateway_responses(api_id)
            if method == 'PUT':
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


def get_gateway_response(api_id, response_type):
    responses = GATEWAY_RESPONSES.get(api_id, [])
    result = [r for r in responses if r['responseType'] == response_type]
    return result[0] if result else 404


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


def validate_api_key(api_key, stage):

    key = None
    usage_plan_id = None

    client = aws_stack.connect_to_service('apigateway')
    usage_plans = client.get_usage_plans()
    for item in usage_plans.get('items', []):
        api_stages = item.get('apiStages', [])
        for api_stage in api_stages:
            if api_stage.get('stage') == stage:
                usage_plan_id = item.get('id')
    if not usage_plan_id:
        return False

    usage_plan_keys = client.get_usage_plan_keys(usagePlanId=usage_plan_id)
    for item in usage_plan_keys.get('items', []):
        key = item.get('value')

    if key != api_key:
        return False

    return True


def is_api_key_valid(is_api_key_required, headers, stage):
    if not is_api_key_required:
        return True

    api_key = headers.get('X-API-Key')
    if not api_key:
        return False

    return validate_api_key(api_key, stage)


def update_content_length(response):
    if response and response.content:
        response.headers['Content-Length'] = str(len(response.content))


def apply_template(integration, req_res_type, data, path_params={}, query_params={}, headers={}):
    if integration['type'] in ['HTTP', 'AWS']:
        # apply custom request template
        template = integration.get('%sTemplates' % req_res_type, {}).get(APPLICATION_JSON)
        if template:
            context = {}
            context['body'] = data

            def _params(name=None):
                # See https://docs.aws.amazon.com/apigateway/latest/developerguide/
                #    api-gateway-mapping-template-reference.html#input-variable-reference
                # Returns "request parameter from the path, query string, or header value (searched in that order)"
                combined = {}
                combined.update(path_params or {})
                combined.update(query_params or {})
                combined.update(headers or {})
                return combined if not name else combined.get(name)

            context['params'] = _params
            data = aws_stack.render_velocity_template(template, context)
    return data


def get_api_id_stage_invocation_path(path, headers):
    path_match = re.search(PATH_REGEX_USER_REQUEST, path)
    host_header = headers.get('Host', '')
    host_match = re.search(HOST_REGEX_EXECUTE_API, host_header)
    if path_match:
        api_id = path_match.group(1)
        stage = path_match.group(2)
        relative_path_w_query_params = '/%s' % path_match.group(3)
    elif host_match:
        api_id = host_match.group(1)
        stage = path.strip('/').split('/')[0]
        relative_path_w_query_params = '/%s' % path.lstrip('/').partition('/')[2]
    return api_id, stage, relative_path_w_query_params


def invoke_rest_api_from_request(method, path, data, headers, context={}):
    api_id, stage, relative_path_w_query_params = get_api_id_stage_invocation_path(path, headers)
    try:
        return invoke_rest_api(api_id, stage, method, relative_path_w_query_params,
            data, headers, path=path, context=context)
    except AuthorizationError as e:
        return make_error_response('Not authorized to invoke REST API %s: %s' % (api_id, e), 403)


def invoke_rest_api(api_id, stage, method, invocation_path, data, headers, path=None, context={}):
    path = path or invocation_path
    relative_path, query_string_params = extract_query_string_params(path=invocation_path)

    # run gateway authorizers for this request
    authorize_invocation(api_id, headers)
    path_map = helpers.get_rest_api_paths(rest_api_id=api_id)
    try:
        extracted_path, resource = get_resource_for_path(path=relative_path, path_map=path_map)
    except Exception:
        return make_error_response('Unable to find path %s' % path, 404)

    api_key_required = resource.get('resourceMethods', {}).get(method, {}).get('apiKeyRequired')
    if not is_api_key_valid(api_key_required, headers, stage):
        return make_error_response('Access denied - invalid API key', 403)

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

    uri = integration.get('uri') or ''
    integration_type = integration['type'].upper()

    if uri.startswith('arn:aws:apigateway:') and ':lambda:path' in uri:
        if integration_type in ['AWS', 'AWS_PROXY']:
            func_arn = uri.split(':lambda:path')[1].split('functions/')[1].split('/invocations')[0]
            data_str = json.dumps(data) if isinstance(data, (dict, list)) else to_str(data)

            try:
                path_params = extract_path_params(path=relative_path, extracted_path=extracted_path)
            except Exception:
                path_params = {}

            # apply custom request template
            data_str = apply_template(integration, 'request', data_str, path_params=path_params,
                query_params=query_string_params, headers=headers)

            # Sample request context:
            # https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-create-api-as-simple-proxy-for-lambda.html#api-gateway-create-api-as-simple-proxy-for-lambda-test
            request_context = get_lambda_event_request_context(method, path, data, headers,
                integration_uri=uri, resource_id=resource.get('id'))

            result = lambda_api.process_apigateway_invocation(func_arn, relative_path, data_str,
                stage, api_id, headers, path_params=path_params, query_string_params=query_string_params,
                method=method, resource_path=path, request_context=request_context, event_context=context)

            if isinstance(result, FlaskResponse):
                response = flask_to_requests_response(result)
            elif isinstance(result, Response):
                response = result
            else:
                response = LambdaResponse()
                parsed_result = result if isinstance(result, dict) else json.loads(str(result or '{}'))
                parsed_result = common.json_safe(parsed_result)
                parsed_result = {} if parsed_result is None else parsed_result
                response.status_code = int(parsed_result.get('statusCode', 200))
                parsed_headers = parsed_result.get('headers', {})
                if parsed_headers is not None:
                    response.headers.update(parsed_headers)
                try:
                    if isinstance(parsed_result['body'], dict):
                        response._content = json.dumps(parsed_result['body'])
                    else:
                        response._content = to_bytes(parsed_result['body'])
                except Exception:
                    response._content = '{}'
                update_content_length(response)
                response.multi_value_headers = parsed_result.get('multiValueHeaders') or {}

            # apply custom response template
            response._content = apply_template(integration, 'response', response._content)
            response.headers['Content-Length'] = str(len(response.content or ''))

            return response

        msg = 'API Gateway AWS integration action URI "%s", method "%s" not yet implemented' % (uri, method)
        LOGGER.warning(msg)
        return make_error_response(msg, 404)

    elif integration_type == 'AWS':
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
            # TODO apply response template..?
            return result

        elif 'states:action/' in uri:
            if uri.endswith('states:action/StartExecution'):
                action = 'StartExecution'
            decoded_data = data.decode()
            if 'stateMachineArn' in decoded_data and 'input' in decoded_data:
                payload = json.loads(decoded_data)
            elif APPLICATION_JSON in integration.get('requestTemplates', {}):
                template = integration['requestTemplates'][APPLICATION_JSON]
                payload = aws_stack.render_velocity_template(template, data, as_json=True)
            client = aws_stack.connect_to_service('stepfunctions')

            kwargs = {'name': payload['name']} if 'name' in payload else {}
            result = client.start_execution(stateMachineArn=payload['stateMachineArn'],
                            input=payload['input'], **kwargs)
            response = requests_response(
                content={
                    'executionArn': result['executionArn'],
                    'startDate': str(result['startDate'])
                },
                headers=aws_stack.mock_aws_request_headers()
            )
            return response

        if method == 'POST':
            if uri.startswith('arn:aws:apigateway:') and ':sqs:path' in uri:
                template = integration['requestTemplates'][APPLICATION_JSON]
                account_id, queue = uri.split('/')[-2:]
                region_name = uri.split(':')[3]

                new_request = '%s&QueueName=%s' % (aws_stack.render_velocity_template(template, data), queue)
                headers = aws_stack.mock_aws_request_headers(service='sqs', region_name=region_name)

                url = urljoin(TEST_SQS_URL, '%s/%s' % (TEST_AWS_ACCOUNT_ID, queue))
                result = common.make_http_request(url, method='POST', headers=headers, data=new_request)
                return result

        msg = 'API Gateway AWS integration action URI "%s", method "%s" not yet implemented' % (uri, method)
        LOGGER.warning(msg)
        return make_error_response(msg, 404)

    elif integration_type == 'AWS_PROXY':
        if uri.startswith('arn:aws:apigateway:') and ':dynamodb:action' in uri:
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

    elif integration_type in ['HTTP_PROXY', 'HTTP']:
        function = getattr(requests, method.lower())

        # apply custom request template
        data = apply_template(integration, 'request', data)

        if isinstance(data, dict):
            data = json.dumps(data)

        result = function(integration['uri'], data=data, headers=headers)

        # apply custom response template
        data = apply_template(integration, 'response', data)

        return result

    elif integration_type == 'MOCK':
        # TODO: add logic for MOCK responses
        pass

    if method == 'OPTIONS':
        # fall back to returning CORS headers if this is an OPTIONS request
        return get_cors_response(headers)

    msg = ('API Gateway integration type "%s", method "%s", URI "%s" not yet implemented' %
           (integration['type'], method, integration.get('uri')))
    LOGGER.warning(msg)
    return make_error_response(msg, 404)


def get_lambda_event_request_context(method, path, data, headers, integration_uri=None, resource_id=None):
    _, stage, relative_path_w_query_params = get_api_id_stage_invocation_path(path, headers)
    relative_path, query_string_params = extract_query_string_params(path=relative_path_w_query_params)
    source_ip = headers.get('X-Forwarded-For', ',').split(',')[-2].strip()
    integration_uri = integration_uri or ''
    account_id = integration_uri.split(':lambda:path')[-1].split(':function:')[0].split(':')[-1]
    request_context = {
        # adding stage to the request context path.
        # https://github.com/localstack/localstack/issues/2210
        'path': '/' + stage + relative_path,
        'accountId': account_id,
        'resourceId': resource_id,
        'stage': stage,
        'identity': {
            'accountId': account_id,
            'sourceIp': source_ip,
            'userAgent': headers.get('User-Agent'),
        },
        'httpMethod': method,
        'protocol': 'HTTP/1.1',
        'requestTime': datetime.datetime.utcnow(),
        'requestTimeEpoch': int(time.time() * 1000),
    }
    return request_context


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
