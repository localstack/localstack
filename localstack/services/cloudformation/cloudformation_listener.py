import re
import uuid
import logging
import xmltodict
import requests
from requests.models import Response, Request
from six.moves.urllib import parse as urlparse
from localstack.constants import DEFAULT_REGION, TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_stack
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
        return error_response('Change Set %s does not exist' % cs_arn, 404, 'ChangeSetNotFound')
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
        return error_response('Change Set %s does not exist' % cs_arn, 404, 'ChangeSetNotFound')

    # convert to JSON (might have been YAML, and update_stack/create_stack seem to only work with JSON)
    template = template_deployer.template_to_json(cs_details.get('TemplateBody')[0])

    # update stack information
    cloudformation_service = aws_stack.connect_to_service('cloudformation')
    if stack_exists(stack_name):
        cloudformation_service.update_stack(StackName=stack_name,
            TemplateBody=template)
    else:
        cloudformation_service.create_stack(StackName=stack_name,
            TemplateBody=template)

    # now run the actual deployment
    template_deployer.deploy_template(template)

    response = make_response('ExecuteChangeSet')
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
            req_data = urlparse.parse_qs(data)
            action = req_data.get('Action')[0]

        if req_data:
            if action == 'CreateChangeSet':
                return create_change_set(req_data)
            elif action == 'DescribeChangeSet':
                return describe_change_set(req_data)
            elif action == 'ExecuteChangeSet':
                return execute_change_set(req_data)
            elif action == 'UpdateStack' and req_data.get('TemplateURL'):
                # Temporary fix until the moto CF backend can handle TemplateURL (currently fails)
                url = re.sub(r'https?://s3\.amazonaws\.com', aws_stack.get_local_service_url('s3'),
                    req_data.get('TemplateURL')[0])
                req_data['TemplateBody'] = requests.get(url).content
                modified_data = urlparse.urlencode(req_data, doseq=True)
                return Request(data=modified_data, headers=headers, method=method)
            elif action == 'ValidateTemplate':
                return validate_template(req_data)

        return True

    def return_response(self, method, path, data, headers, response):
        req_data = None
        if method == 'POST' and path == '/':
            req_data = urlparse.parse_qs(data)
            action = req_data.get('Action')[0]

        if req_data:
            if action == 'DescribeStackResources':
                if response.status_code < 300:
                    response_dict = xmltodict.parse(response.content)['DescribeStackResourcesResponse']
                    resources = response_dict['DescribeStackResourcesResult']['StackResources']
                    if not resources:
                        # Check if stack exists
                        stack_name = req_data.get('StackName')[0]
                        cloudformation_client = aws_stack.connect_to_service('cloudformation')
                        try:
                            cloudformation_client.describe_stacks(StackName=stack_name)
                        except Exception:
                            return error_response('Stack with id %s does not exist' % stack_name, code=404)
            if action == 'DescribeStackResource':
                if response.status_code >= 500:
                    # fix an error in moto where it fails with 500 if the stack does not exist
                    return error_response('Stack resource does not exist', code=404)
            elif action == 'CreateStack' or action == 'UpdateStack':
                # run the actual deployment
                template = template_deployer.template_to_json(req_data.get('TemplateBody')[0])
                template_deployer.deploy_template(template, req_data.get('StackName')[0])
                if response.status_code >= 400:
                    return make_response(action)


# instantiate listener
UPDATE_CLOUDFORMATION = ProxyListenerCloudFormation()
