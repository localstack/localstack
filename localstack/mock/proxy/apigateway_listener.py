import re
from localstack.constants import *
from localstack.config import TEST_KINESIS_URL
from localstack.utils import common
from localstack.utils.aws import aws_stack


def update_apigateway(method, path, data, headers, response=None, return_forward_info=False):
    if return_forward_info:

        regex1 = r'^/restapis/[A-Za-z0-9\-]+/deployments$'
        if method == 'POST' and re.match(regex1, path):
            # this is a request to deploy the API gateway, simply return HTTP code 200
            return 200

        regex2 = r'^/restapis/([A-Za-z0-9_\-]+)/([A-Za-z0-9_\-]+)/%s/([^/]+)$' % PATH_USER_REQUEST
        if method == 'POST' and re.match(regex2, path):
            api_id = re.search(regex2, path).group(1)
            sub_path = '/%s' % re.search(regex2, path).group(3)
            integration = aws_stack.get_apigateway_integration(api_id, method, sub_path)
            template = integration['requestTemplates'][APPLICATION_JSON]
            new_request = aws_stack.render_velocity_template(template, data)

            # forward records to our main kinesis stream
            # TODO check whether the target of this API method is 'kinesis'
            headers = aws_stack.mock_aws_request_headers(service='kinesis')
            headers['X-Amz-Target'] = KINESIS_ACTION_PUT_RECORDS
            result = common.make_http_request(url=TEST_KINESIS_URL,
                method='POST', data=new_request, headers=headers)
            return 200

        return True
