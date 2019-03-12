import re
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import to_str
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerIAM(ProxyListener):

    def return_response(self, method, path, data, headers, response):
        # fix hardcoded account ID in ARNs returned from this API
        if response.content:
            content = to_str(response.content)
            pattern = r'<Arn>\s*arn:aws:iam::([0-9]+):([^<]+)</Arn>'
            replacement = r'<Arn>arn:aws:iam::%s:\2</Arn>' % TEST_AWS_ACCOUNT_ID
            response._content = re.sub(pattern, replacement, content)
            response.headers['content-length'] = len(response._content)


# instantiate listener
UPDATE_IAM = ProxyListenerIAM()
