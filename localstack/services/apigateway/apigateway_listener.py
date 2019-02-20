import re
import logging
import json
import requests
from requests.models import Response
from flask import Response as FlaskResponse
from localstack.constants import APPLICATION_JSON, PATH_USER_REQUEST
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str
from localstack.services.awslambda import lambda_api
from localstack.services.kinesis import kinesis_listener
from localstack.services.generic_proxy import ProxyListener
from .helpers import (get_rest_api_paths, get_resource_for_path,
                      flask_to_requests_response, handle_authorizers,
                      extract_query_string_params, extract_path_params,
                      make_error, get_cors_response)

# set up logger
LOGGER = logging.getLogger(__name__)

# regex path patterns
PATH_REGEX_AUTHORIZERS = r'^/restapis/([A-Za-z0-9_\-]+)/authorizers(\?.*)?'


class ProxyListenerApiGateway(ProxyListener):

    def forward_request(self, method, path, data, headers):
        data = data and json.loads(to_str(data))

        # Paths to match
        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/(.*)$' % PATH_USER_REQUEST

        if re.match(regex2, path):
            search_match = re.search(regex2, path)
            api_id = search_match.group(1)
            stage = search_match.group(2)
            relative_path_w_query_params = '/%s' % search_match.group(3)

            relative_path, query_string_params = extract_query_string_params(path=relative_path_w_query_params)

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
                    account_id = uri.split(':lambda:path')[1].split(':function:')[0].split(':')[-1]
                    data_str = json.dumps(data) if isinstance(data, dict) else data

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
        # fix backend issue (missing support for API documentation)
        if re.match(r'/restapis/[^/]+/documentation/versions', path):
            if response.status_code == 404:
                response = Response()
                response.status_code = 200
                result = {'position': '1', 'items': []}
                response._content = json.dumps(result)
                return response


# instantiate listener
UPDATE_APIGATEWAY = ProxyListenerApiGateway()
