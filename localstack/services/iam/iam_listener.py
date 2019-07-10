import re
from requests.models import Request
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerIAM(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'POST' and path == '/':
            data = self._reset_account_id(data)
            return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):

        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            self._fix_account_id(response)
            # fix dates returned from this API (fixes an issue with Terraform)
            self._fix_date_format(response)
            # fix content-length header
            response.headers['content-length'] = len(response._content)

    def _fix_date_format(self, response):
        """ Normalize date to format '2019-06-13T18:10:09.1234Z' """
        pattern = r'<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>'
        replacement = r'<CreateDate>\1T\2Z</CreateDate>'
        self._replace(response, pattern, replacement)

    def _fix_account_id(self, response):
        pattern = r'<([^>]*)Arn>\s*arn:aws:iam::([0-9]+):([^<]+)</\1Arn>'
        replacement = r'<\1Arn>arn:aws:iam::%s:\3</\1Arn>' % TEST_AWS_ACCOUNT_ID
        self._replace(response, pattern, replacement)

    def _reset_account_id(self, data):
        """ Fix account ID in request payload. All external-facing responses contain our
            predefined account ID (defaults to 000000000000), whereas the backend endpoint
            from moto expects a different hardcoded account ID (123456789012). """
        return aws_stack.fix_account_id_in_arns(
            data, colon_delimiter='%3A', existing=TEST_AWS_ACCOUNT_ID, replace=MOTO_ACCOUNT_ID)

    def _replace(self, response, pattern, replacement):
        content = to_str(response.content)
        response._content = re.sub(pattern, replacement, content)


# instantiate listener
UPDATE_IAM = ProxyListenerIAM()
