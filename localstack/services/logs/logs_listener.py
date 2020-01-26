import re
from requests.models import Request
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerCloudWatchLogs(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'POST' and path == '/':
            if 'nextToken' in to_str(data or ''):
                data = self._fix_next_token_request(data)
                headers['content-length'] = str(len(data))
                return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        if 'nextToken' in to_str(response.content or ''):
            self._fix_next_token_response(response)
            response.headers['content-length'] = str(len(response._content))

    def _fix_next_token_request(self, data):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*"([0-9]+)"'
        replacement = r'"nextToken": \1'
        return re.sub(pattern, replacement, to_str(data))

    def _fix_next_token_response(self, response):
        # Fix for https://github.com/localstack/localstack/issues/1527
        pattern = r'"nextToken":\s*([0-9]+)'
        replacement = r'"nextToken": "\1"'
        response._content = re.sub(pattern, replacement, to_str(response.content))


# instantiate listener
UPDATE_LOGS = ProxyListenerCloudWatchLogs()
