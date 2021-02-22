import re
from requests.models import Request
from localstack.utils.common import to_str
from localstack.constants import APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerCloudWatchLogs(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == 'POST' and path == '/':
            if 'nextToken' in to_str(data or ''):
                data = self._fix_next_token_request(data)
                headers['Content-Length'] = str(len(data))
                return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect response content-type header from cloudwatch logs #1343
        response.headers['content-type'] = APPLICATION_AMZ_JSON_1_1
        str_content = re.sub(
            r'arn:aws:logs:([^:]+):1:',
            r'arn:aws:logs:\1:%s:' % TEST_AWS_ACCOUNT_ID,
            to_str(response.content or '')
        )
        response._content = str.encode(str_content)
        if 'nextToken' in str_content:
            self._fix_next_token_response(response)
            response.headers['Content-Length'] = str(len(response._content))

    @staticmethod
    def _fix_next_token_request(data):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*"([0-9]+)"'
        replacement = r'"nextToken": \1'
        return re.sub(pattern, replacement, to_str(data))

    @staticmethod
    def _fix_next_token_response(response):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*([0-9]+)'
        replacement = r'"nextToken": "\1"'
        response._content = re.sub(pattern, replacement, to_str(response.content))


# instantiate listener
UPDATE_LOGS = ProxyListenerCloudWatchLogs()
