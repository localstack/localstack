import uuid
import logging
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack.utils.common import to_str
from localstack.utils.cloudformation import template_deployer
from localstack.services.generic_proxy import ProxyListener

XMLNS_CLOUDFORMATION = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'
LOGGER = logging.getLogger(__name__)

# maps change set names to change set details
CHANGE_SETS = {}


def error_response(message, code=400, error_type='ValidationError'):
    response = Response()
    response.status_code = code
    response.headers['x-amzn-errortype'] = error_type
    response._content = """<ErrorResponse xmlns="%s">
          <Error>
            <Type>Sender</Type>
            <Code>%s</Code>
            <Message>%s</Message>
          </Error>
          <RequestId>%s</RequestId>
        </ErrorResponse>""" % (XMLNS_CLOUDFORMATION, error_type, message, uuid.uuid4())
    return response


def make_response(operation_name, content='', code=200):
    response = Response()
    response._content = """<{op_name}Response xmlns="{xmlns}">
      <{op_name}Result>
        {content}
      </{op_name}Result>
      <ResponseMetadata><RequestId>{uid}</RequestId></ResponseMetadata>
    </{op_name}Response>""".format(xmlns=XMLNS_CLOUDFORMATION,
        op_name=operation_name, uid=uuid.uuid4(), content=content)
    response.status_code = code
    return response


def validate_template(req_data):
    LOGGER.debug(req_data)
    response_content = """
        <Capabilities></Capabilities>
        <CapabilitiesReason></CapabilitiesReason>
        <DeclaredTransforms></DeclaredTransforms>
        <Description></Description>
        <Parameters>
        </Parameters>
    """
    try:
        template_deployer.template_to_json(req_data.get('TemplateBody')[0])
        response = make_response('ValidateTemplate', response_content)
        return response
    except Exception as err:
        response = error_response('Template Validation Error: %s' % err)
        return response


class ProxyListenerCloudFormation(ProxyListener):

    def forward_request(self, method, path, data, headers):
        req_data = None
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            action = req_data.get('Action')[0]

        if req_data:
            if action == 'ValidateTemplate':
                return validate_template(req_data)

        return True


# instantiate listener
UPDATE_CLOUDFORMATION = ProxyListenerCloudFormation()
