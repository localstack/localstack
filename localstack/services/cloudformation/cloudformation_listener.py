import re
import os
import json
import uuid
import boto3
import logging
from requests.models import Request, Response
from six.moves.urllib import parse as urlparse
from samtranslator.translator.transform import transform as transform_sam
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, obj_to_xml, safe_requests
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
    # TODO implement actual validation logic
    response_content = """
        <Capabilities></Capabilities>
        <CapabilitiesReason></CapabilitiesReason>
        <DeclaredTransforms></DeclaredTransforms>
        <Description></Description>
        <Parameters>
        </Parameters>
    """
    try:
        template_body = get_template_body(req_data)
        template_deployer.template_to_json(template_body)
        response = make_response('ValidateTemplate', response_content)
        return response
    except Exception as err:
        response = error_response('Template Validation Error: %s' % err)
        return response


def transform_template(req_data):
    template_body = get_template_body(req_data)
    parsed = template_deployer.parse_template(template_body)

    policy_map = {
        # SAM Transformer expects this map to be non-empty, but apparently the content doesn't matter (?)
        'dummy': 'entry'
        # 'AWSLambdaBasicExecutionRole': 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
    }

    class MockPolicyLoader(object):
        def load(self):
            return policy_map

    if parsed.get('Transform') == 'AWS::Serverless-2016-10-31':
        # Note: we need to fix boto3 region, otherwise AWS SAM transformer fails
        region_before = os.environ.get('AWS_DEFAULT_REGION')
        if boto3.session.Session().region_name is None:
            os.environ['AWS_DEFAULT_REGION'] = aws_stack.get_region()
        try:
            transformed = transform_sam(parsed, {}, MockPolicyLoader())
            return transformed
        finally:
            os.environ.pop('AWS_DEFAULT_REGION', None)
            if region_before is not None:
                os.environ['AWS_DEFAULT_REGION'] = region_before


def get_template_body(req_data):
    body = req_data.get('TemplateBody')
    if body:
        return body
    url = req_data.get('TemplateURL')
    if url:
        response = safe_requests.get(url, verify=False)
        if response.status_code >= 400:
            # check if this is an S3 URL, then get the file directly from there
            if '://localhost' in url or re.match(r'.*s3(\-website)?\.([^\.]+\.)?amazonaws.com.*', url):
                parsed_path = urlparse.urlparse(url).path.lstrip('/')
                parts = parsed_path.partition('/')
                client = aws_stack.connect_to_service('s3')
                result = client.get_object(Bucket=parts[0], Key=parts[2])
                body = to_str(result['Body'].read())
                return body
            raise Exception('Unable to fetch template body (code %s) from URL %s' % (response.status_code, url))
        return response.content
    raise Exception('Unable to get template body from input: %s' % req_data)


class ProxyListenerCloudFormation(ProxyListener):

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        req_data = None
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(to_str(data))
            req_data = dict([(k, v[0]) for k, v in req_data.items()])
            action = req_data.get('Action')

            if action == 'CreateStack':
                stack_name = req_data.get('StackName')
                event_publisher.fire_event(event_publisher.EVENT_CLOUDFORMATION_CREATE_STACK,
                    payload={'n': event_publisher.get_hash(stack_name)})

            if action == 'DescribeStackEvents':
                # fix an issue where moto cannot handle ARNs as stack names (or missing names)
                stack_name = req_data.get('StackName')
                run_fix = not stack_name
                if stack_name:
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
            if action == 'CreateStack':
                modified_request = transform_template(req_data)
                if modified_request:
                    req_data.pop('TemplateURL', None)
                    req_data['TemplateBody'] = json.dumps(modified_request)
                    data = urlparse.urlencode(req_data, doseq=True)
                    return Request(data=data, headers=headers, method=method)

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
