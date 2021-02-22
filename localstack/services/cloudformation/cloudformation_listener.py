# NOTE: This code is deprecated and will be removed in a future iteration!

import re
import uuid
import logging
from requests.models import Request, Response
from six.moves.urllib import parse as urlparse
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, obj_to_xml, timestamp_millis
from localstack.utils.analytics import event_publisher
from localstack.utils.cloudformation import template_deployer, template_preparer
from localstack.services.generic_proxy import ProxyListener

XMLNS_CLOUDFORMATION = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'
LOG = logging.getLogger(__name__)

MOTO_CLOUDFORMATION_ACCOUNT_ID = '123456789'


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
    </{op_name}Response>""".format(
        xmlns=XMLNS_CLOUDFORMATION, op_name=operation_name, uid=uuid.uuid4(), content=content)
    response.status_code = code
    return response


def fix_hardcoded_creation_date(response):
    # TODO: remove once this is fixed upstream
    search = r'<CreationTime>\s*(2011-05-23T15:47:44Z)?\s*</CreationTime>'
    replace = r'<CreationTime>%s</CreationTime>' % timestamp_millis()
    fix_in_response(search, replace, response)


def fix_region_in_arns(response):
    search = r'arn:aws:cloudformation:[^:]+:'
    replace = r'arn:aws:cloudformation:%s:' % aws_stack.get_region()
    fix_in_response(search, replace, response)


def fix_in_response(search, replace, response):
    response._content = re.sub(search, replace, to_str(response._content or ''))
    response.headers['Content-Length'] = str(len(response._content))


class ProxyListenerCloudFormation(ProxyListener):
    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        data = data or ''
        data_orig = data
        data = aws_stack.fix_account_id_in_arns(data, existing='%3A{}%3Astack/'.format(TEST_AWS_ACCOUNT_ID),
            replace='%3A{}%3Astack/'.format(MOTO_CLOUDFORMATION_ACCOUNT_ID), colon_delimiter='')
        data = aws_stack.fix_account_id_in_arns(data, existing='%3A{}%3AchangeSet/'.format(TEST_AWS_ACCOUNT_ID),
            replace='%3A{}%3AchangeSet/'.format(MOTO_CLOUDFORMATION_ACCOUNT_ID), colon_delimiter='')
        data = aws_stack.fix_account_id_in_arns(data, existing=TEST_AWS_ACCOUNT_ID,
            replace=MOTO_ACCOUNT_ID, colon_delimiter='%3A')

        req_data = None
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            req_data = dict([(k, v[0]) for k, v in req_data.items()])
            action = req_data.get('Action')
            stack_name = req_data.get('StackName')

            if action == 'CreateStack':
                event_publisher.fire_event(
                    event_publisher.EVENT_CLOUDFORMATION_CREATE_STACK,
                    payload={'n': event_publisher.get_hash(stack_name)}
                )

            if action == 'DeleteStack':
                client = aws_stack.connect_to_service('cloudformation')
                stack_resources = client.list_stack_resources(StackName=stack_name)['StackResourceSummaries']
                from localstack.utils.cloudformation import template_deployer_old
                template_deployer_old.delete_stack(stack_name, stack_resources)

            if action == 'DescribeStackEvents':
                # fix an issue where moto cannot handle ARNs as stack names (or missing names)
                run_fix = not stack_name
                if stack_name:
                    if stack_name.startswith('arn:aws:cloudformation'):
                        run_fix = True
                        pattern = r'arn:aws:cloudformation:[^:]+:[^:]+:stack/([^/]+)(/.+)?'
                        stack_name = re.sub(pattern, r'\1', stack_name)
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
                return template_preparer.validate_template(req_data)

            if action in ['CreateStack', 'UpdateStack', 'CreateChangeSet']:
                modified = template_deployer.prepare_template_body(req_data)
                if modified:
                    data = urlparse.urlencode(req_data, doseq=True)
                    return Request(data=data, headers=headers, method=method)

            if data != data_orig or action in ['DescribeChangeSet', 'ExecuteChangeSet']:
                return Request(data=urlparse.urlencode(req_data, doseq=True), headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        req_data = urlparse.parse_qs(to_str(data))
        req_data = dict([(k, v[0]) for k, v in req_data.items()])
        action = req_data.get('Action')

        if response.status_code >= 400:
            LOG.debug('Error response for CloudFormation action "%s" (%s) %s %s: %s' %
                      (action, response.status_code, method, path, response.content))

        if response._content:
            aws_stack.fix_account_id_in_arns(response)
            fix_hardcoded_creation_date(response)
            fix_region_in_arns(response)

    @staticmethod
    def _list_stack_names():
        client = aws_stack.connect_to_service('cloudformation')
        stacks = client.list_stacks()['StackSummaries']
        stack_names = []
        for stack in stacks:
            status = stack['StackStatus']
            if 'FAILED' in status or 'DELETE' in status:
                continue
            stack_names.append(stack['StackName'])
        return stack_names


# instantiate listener
UPDATE_CLOUDFORMATION = ProxyListenerCloudFormation()
