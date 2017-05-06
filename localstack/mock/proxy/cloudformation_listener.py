import re
import uuid
from requests.models import Response
from six.moves.urllib import parse as urlparse
from localstack.constants import *
from localstack.config import DEFAULT_REGION
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.utils.cloudformation import template_deployer

XMLNS_CLOUDFORMATION = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'

ERROR_TYPES = {
    400: 'ValidationError',
    404: 'ChangeSetNotFound'
}

# maps change set names to change set details
CHANGE_SETS = {}


def error_response(message, code=400):
    response = Response()
    response.status_code = code
    error_type = ERROR_TYPES.get(code)
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


def make_response(operation_name, message='', code=400):
    response = Response()
    response._content = """<{op_name}Response xmlns="{xmlns}">
      <{op_name}Result>
        {content}
      </{op_name}Result>
      <ResponseMetadata><RequestId>{uid}</RequestId></ResponseMetadata>
    </{op_name}Response>""".format(xmlns=XMLNS_CLOUDFORMATION,
        op_name=operation_name, uid=uuid.uuid4(), content=content)
    response.status_code = 200
    return response


def stack_exists(stack_name):
    cloudformation = aws_stack.connect_to_service('cloudformation')
    stacks = cloudformation.list_stacks()
    for stack in stacks['StackSummaries']:
        if stack['StackName'] == stack_name:
            return True
    return False


def create_change_set(req_data):
    cs_name = req_data.get('ChangeSetName')[0]
    change_set_uuid = uuid.uuid4()
    cs_arn = 'arn:aws:cloudformation:%s:%s:changeSet/%s/%s' % (
        DEFAULT_REGION, TEST_AWS_ACCOUNT_ID, cs_name, change_set_uuid)
    CHANGE_SETS[cs_arn] = dict(req_data)
    response = make_response('CreateChangeSet', '<Id>%s</Id>' % cs_arn)
    return response


def describe_change_set(req_data):
    cs_arn = req_data.get('ChangeSetName')[0]
    cs_details = CHANGE_SETS.get(cs_arn)
    if not cs_details:
        return error_response('Change Set %s does not exist' % cs_arn, 404)
    stack_name = cs_details.get('StackName')[0]
    response_content = """
        <StackName>%s</StackName>
        <ChangeSetId>%s</ChangeSetId>
        <Status>CREATE_COMPLETE</Status>""" % (stack_name, cs_arn)
    response = make_response('DescribeChangeSet', response_content)
    return response


def execute_change_set(req_data):
    cs_arn = req_data.get('ChangeSetName')[0]
    stack_name = req_data.get('StackName')[0]
    cs_details = CHANGE_SETS.get(cs_arn)
    if not cs_details:
        return error_response('Change Set %s does not exist' % cs_arn, 404)

    # convert to JSON (might have been YAML, and update_stack/create_stack seem to only work with JSON)
    template = template_deployer.template_to_json(cs_details.get('TemplateBody')[0])

    # update stack information
    cloudformation_service = aws_stack.connect_to_service('cloudformation')
    if stack_exists(stack_name):
        result = cloudformation_service.update_stack(StackName=stack_name,
            TemplateBody=template)
    else:
        result = cloudformation_service.create_stack(StackName=stack_name,
            TemplateBody=template)

    # now run the actual deployment
    template_deployer.deploy_template(template)

    response = make_response('ExecuteChangeSet')
    return response


def update_cloudformation(method, path, data, headers, response=None, return_forward_info=False):
    req_data = None
    if method == 'POST' and path == '/':
        req_data = urlparse.parse_qs(data)
        action = req_data.get('Action')[0]

    if return_forward_info:
        if req_data:
            if action == 'CreateChangeSet':
                return create_change_set(req_data)
            elif action == 'DescribeChangeSet':
                return describe_change_set(req_data)
            elif action == 'ExecuteChangeSet':
                return execute_change_set(req_data)
        return True

    if req_data:
        if action == 'CreateStack' or action == 'UpdateStack':
            if response.status_code in range(200, 300):
                # run the actual deployment
                template = template_deployer.template_to_json(req_data.get('TemplateBody')[0])
                template_deployer.deploy_template(template)
