import re

from localstack.services.generic_proxy import ProxyListener
from localstack.utils.common import to_bytes, to_str


class ProxyListenerSES(ProxyListener):
    def return_response(self, method, path, data, headers, response, request_handler=None):
        xml = to_str(response.content)
        has_xmlns = self.response_has_xmlns(xml)
        if xml and xml[0] == "<" and not has_xmlns:
            xmlns = "http://ses.amazonaws.com/doc/2010-01-31/"
            response_type = re.findall(r"<(\w+)\s?>", xml)[0]
            response_xmlns = '%s xmlns="%s"' % (response_type, xmlns)

            new_xml = re.sub(r"<\?xml.+\?>\n\s*", "", xml)
            new_xml = re.sub(r"</?Errors>\n\s*", "", new_xml)
            new_xml = re.sub(response_type, response_xmlns, new_xml, 1)

            response._content = to_bytes(new_xml)
            response.headers.update({"Content-Length": str(len(new_xml))})
        return response

    def response_has_xmlns(self, xml_string):
        return re.search(r'\s+xmlns="\S+"', xml_string)


# instantiate listener
UPDATE_SES = ProxyListenerSES()
