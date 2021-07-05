from requests.models import Request

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import MessageConversion

BOOL_ATTRS = [
    "RequireLowercaseCharacters",
    "RequireUppercaseCharacters",
    "HardExpiry",
    "RequireSymbols",
    "ExpirePasswords",
]


class ProxyListenerIAM(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == "POST" and path == "/":
            data = MessageConversion._reset_account_id(data)
            return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            MessageConversion.fix_account_id(response)
            # fix dates returned from this API (fixes issues with Terraform)
            MessageConversion.fix_date_format(response)
            MessageConversion.fix_error_codes(method, data, response)
            MessageConversion.fix_xml_empty_boolean(response, BOOL_ATTRS)
            # fix content-length header
            response.headers["Content-Length"] = str(len(response._content))


# instantiate listener
UPDATE_IAM = ProxyListenerIAM()
