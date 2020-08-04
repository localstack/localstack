import re
import os
import json
import uuid
import boto3
import logging
from requests.models import Request, Response
from six.moves.urllib import parse as urlparse
from samtranslator.translator.transform import transform as transform_sam
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.services.s3 import s3_listener
from localstack.utils.common import to_str, obj_to_xml, safe_requests, run_safe, timestamp_millis
from localstack.utils.analytics import event_publisher
from localstack.utils.cloudformation import template_deployer
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


def validate_template(req_data):
    LOG.debug('Validate CloudFormation template: %s' % req_data)
    # TODO implement actual validation logic
    # Note: if we enable this via moto, ensure that we have cfnlint module available (adds ~58MB in size :/)
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
            return json.dumps(transformed)
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
        response = run_safe(lambda: safe_requests.get(url, verify=False))
        # check error codes, and code 301 - fixes https://github.com/localstack/localstack/issues/1884
        status_code = 0 if response is None else response.status_code
        if response is None or status_code == 301 or status_code >= 400:
            # check if this is an S3 URL, then get the file directly from there
            url = convert_s3_to_local_url(url)
            if is_local_service_url(url):
                parsed_path = urlparse.urlparse(url).path.lstrip('/')
                parts = parsed_path.partition('/')
                client = aws_stack.connect_to_service('s3')
                LOG.debug('Download CloudFormation template content from local S3: %s - %s' % (parts[0], parts[2]))
                result = client.get_object(Bucket=parts[0], Key=parts[2])
                body = to_str(result['Body'].read())
                return body
            raise Exception('Unable to fetch template body (code %s) from URL %s' % (status_code, url))
        return response.content
    raise Exception('Unable to get template body from input: %s' % req_data)


def is_local_service_url(url):
    candidates = ('localhost', config.LOCALSTACK_HOSTNAME, config.HOSTNAME_EXTERNAL, config.HOSTNAME)
    return url and any('://%s:' % host in url for host in candidates)


def is_real_s3_url(url):
    return re.match(r'.*s3(\-website)?\.([^\.]+\.)?amazonaws.com.*', url or '')


def convert_s3_to_local_url(url):
    if not is_real_s3_url(url):
        return url
    url_parsed = urlparse.urlparse(url)
    path = url_parsed.path
    bucket_name, _, key = path.lstrip('/').replace('//', '/').partition('/')
    # note: make sure to normalize the bucket name here!
    bucket_name = s3_listener.normalize_bucket_name(bucket_name)
    local_url = '%s/%s/%s' % (config.TEST_S3_URL, bucket_name, key)
    return local_url


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
                template_deployer.delete_stack(stack_name, stack_resources)

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
                return validate_template(req_data)

            if action in ['CreateStack', 'UpdateStack']:
                do_replace_url = is_real_s3_url(req_data.get('TemplateURL'))
                if do_replace_url:
                    req_data['TemplateURL'] = convert_s3_to_local_url(req_data['TemplateURL'])
                url = req_data.get('TemplateURL', '')
                is_custom_local_endpoint = is_local_service_url(url) and '://localhost:' not in url
                modified_template_body = transform_template(req_data)
                if not modified_template_body and is_custom_local_endpoint:
                    modified_template_body = get_template_body(req_data)
                if modified_template_body:
                    req_data.pop('TemplateURL', None)
                    req_data['TemplateBody'] = modified_template_body
                if modified_template_body or do_replace_url:
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
