from requests.models import Request

from localstack.constants import APPLICATION_JSON
from localstack.services.generic_proxy import ProxyListener
from localstack.utils.aws.aws_responses import MessageConversion, is_invalid_html_response
from localstack.utils.http import replace_response_content
from localstack.utils.time import parse_timestamp


class ProxyListenerSTS(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == "POST" and path == "/":
            data = MessageConversion._reset_account_id(data)
            return Request(data=data, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            MessageConversion.fix_account_id(response)
            # fix dates returned from this API (fixes an issue with Terraform)
            MessageConversion.fix_date_format(response)
            # fix returned error codes
            MessageConversion.fix_error_codes(method, data, response)
            # fix content-length header
            response.headers["Content-Length"] = str(len(response._content))
            # fix content-type header
            if is_invalid_html_response(response.headers, response._content):
                response.headers["Content-Type"] = "text/xml"

            if headers.get("Accept") == APPLICATION_JSON:
                # convert "Expiration" to int for JSON response format (tested against AWS)
                # TODO: introduce a proper/generic approach that works across arbitrary date fields in JSON

                def _replace(match):
                    timestamp = parse_timestamp(match.group(1).strip())
                    return f"<Expiration>{int(timestamp.timestamp())}</Expiration>"

                pattern = r"<Expiration>([^<]+)</Expiration>"
                replace_response_content(response, pattern, _replace)


# instantiate listener
UPDATE_STS = ProxyListenerSTS()
