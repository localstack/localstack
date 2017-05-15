import re
import logging
import json
import requests
from requests.models import Response
from localstack.constants import *
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack

# set up logger
LOGGER = logging.getLogger(__name__)


def make_error(message, code=400):
    response = Response()
    response.status_code = code
    response._content = json.dumps({'message': message})
    return response


def update_apigateway(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:

        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/([^/]*)$' % PATH_USER_REQUEST
        if re.match(regex2, path):
            search_match = re.search(regex2, path)
            api_id = search_match.group(1)
            sub_path = '/%s' % search_match.group(3)
            try:
                integration = aws_stack.get_apigateway_integration(api_id, method, sub_path)
            except Exception as e:
                msg = ('API Gateway endpoint "%s" for method "%s" not found' % (path, method))
                LOGGER.warning(msg)
                return make_error(msg, 404)
            if method == 'POST' and integration['type'] == 'AWS':
                if integration['uri'].endswith('kinesis:action/PutRecords'):
                    template = integration['requestTemplates'][APPLICATION_JSON]
                    new_request = aws_stack.render_velocity_template(template, data)

                    # forward records to target kinesis stream
                    headers = aws_stack.mock_aws_request_headers(service='kinesis')
                    headers['X-Amz-Target'] = KINESIS_ACTION_PUT_RECORDS
                    result = common.make_http_request(url=TEST_KINESIS_URL,
                        method='POST', data=new_request, headers=headers)
                    return result
                else:
                    msg = 'API Gateway action uri "%s" not yet implemented' % integration['uri']
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

        return True
