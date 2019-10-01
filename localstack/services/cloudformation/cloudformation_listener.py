import re
import uuid
import logging
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, obj_to_xml
from localstack.utils.analytics import event_publisher
from localstack.utils.cloudformation import template_deployer
from localstack.services.generic_proxy import ProxyListener

XMLNS_CLOUDFORMATION = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'
LOG = logging.getLogger(__name__)


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
    LOG.debug('Validate CloudFormation template: %s' % req_data)
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

            if action == 'CreateStack':
                stack_name = req_data.get('StackName')[0]
                event_publisher.fire_event(event_publisher.EVENT_CLOUDFORMATION_CREATE_STACK,
                    payload={'n': event_publisher.get_hash(stack_name)})

            if action == 'DescribeStackEvents':
                # fix an issue where moto cannot handle ARNs as stack names (or missing names)
                stack_name = req_data.get('StackName')
                run_fix = not stack_name
                if stack_name:
                    stack_name = stack_name[0]
                    if stack_name.startswith('arn:aws:cloudformation'):
                        run_fix = True
                        stack_name = re.sub(r'arn:aws:cloudformation:[^:]+:[^:]+:stack/([^/]+)(/.+)?',
                                            r'\1', stack_name)
                if run_fix:
                    stack_names = [stack_name] if stack_name else self._list_stack_names()
                    client = aws_stack.connect_to_service('cloudformation')
                    events = []
                    for stack_name in stack_names:
                        tmp = client.describe_stack_events(StackName=stack_name)['StackEvents'][:1]
                        events.extend(tmp)
                    events = [{'member': e} for e in events]
                    response_content = '<StackEvents>%s</StackEvents>' % obj_to_xml(events)
                    return make_response('DescribeStackEvents', response_content)

        if req_data:
            if action == 'ValidateTemplate':
                return validate_template(req_data)

        return True

    def return_response(self, method, path, data, headers, response):
        if response.status_code >= 400:
            LOG.debug('Error response from CloudFormation (%s) %s %s: %s' %
                      (response.status_code, method, path, response.content))
        if response._content:
            aws_stack.fix_account_id_in_arns(response)

    def _list_stack_names(self):
        client = aws_stack.connect_to_service('cloudformation')
        stack_names = [s['StackName'] for s in client.list_stacks()['StackSummaries']]
        return stack_names


# instantiate listener
UPDATE_CLOUDFORMATION = ProxyListenerCloudFormation()
