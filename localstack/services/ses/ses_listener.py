import re
import xmltodict
from localstack.utils.common import to_str
from localstack.utils.aws.aws_responses import make_error
from localstack.services.generic_proxy import ProxyListener


class ProxyListenerSES(ProxyListener):
    def forward_request(self, method, path, data, headers):
        return True

    def return_response(self, method, path, data, headers, response):
        has_xmlns = self.response_has_xmlns(to_str(response.content))
        if not has_xmlns and response.status_code >= 400:
            content_dict = xmltodict.parse(to_str(response.content))
            error_description = content_dict['ErrorResponse']['Errors']['Error']
            code = error_description['Code']
            message = error_description['Message']
            new_response = make_error(message=message, code=response.status_code, code_string=code, service='ses')
            response._content = new_response.data

    def response_has_xmlns(self, xml_string):
        if re.match(r'xmlns', xml_string):
            return True
        return False


# instantiate listener
UPDATE_SES = ProxyListenerSES()
