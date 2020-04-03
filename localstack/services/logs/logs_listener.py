import re
from requests.models import Request
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener

AWS_JSON_CONTENT_TYPE = 'application/x-amz-json-1.1'


class ProxyListenerCloudWatchLogs(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == 'POST' and path == '/':
            if 'nextToken' in to_str(data or ''):
                data = self._fix_next_token_request(data)
                headers['content-length'] = str(len(data))
                return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        # Fix Incorrect response content-type header from cloudwatch logs #1343
        response.headers['content-type'] = AWS_JSON_CONTENT_TYPE

        if 'nextToken' in to_str(response.content or ''):
            self._fix_next_token_response(response)
            response.headers['content-length'] = str(len(response._content))

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
