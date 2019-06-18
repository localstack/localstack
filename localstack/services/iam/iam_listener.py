import re
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerIAM(ProxyListener):

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
        pattern = r'<Arn>\s*arn:aws:iam::([0-9]+):([^<]+)</Arn>'
        replacement = r'<Arn>arn:aws:iam::%s:\2</Arn>' % TEST_AWS_ACCOUNT_ID
        self._replace(response, pattern, replacement)

    def _replace(self, response, pattern, replacement):
        content = to_str(response.content)
        response._content = re.sub(pattern, replacement, content)


# instantiate listener
UPDATE_IAM = ProxyListenerIAM()
