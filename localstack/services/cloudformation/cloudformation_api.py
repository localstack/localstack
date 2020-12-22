import requests.models
from flask import Flask, request
from localstack.utils.aws import aws_stack
from localstack.utils.common import parse_request_data, short_uid, clone, select_attributes, timestamp_millis
from localstack.utils.cloudformation import template_deployer
from localstack.utils.aws.aws_responses import (
    requests_response_xml, requests_to_flask_response, flask_error_response_xml)
from localstack.services.cloudformation import cloudformation_listener  # , cloudformation_starter

APP_NAME = 'cloudformation_api'
app = Flask(APP_NAME)

XMLNS_CF = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'


class RegionState(object):
    STATES = {}

    def __init__(self):
        # maps stack ID to stack details
        self.stacks = {}

    @classmethod
    def get(cls):
        region = aws_stack.get_region()
        state = cls.STATES[region] = cls.STATES.get(region) or RegionState()
        return state


class Stack(object):
    def __init__(self, params=None):
        self.params = params or {}
        self.params_original = clone(self.params)
        self.params['StackId'] = self.params.get('StackId') or short_uid()
        self.params['StackStatus'] = 'CREATE_IN_PROGRESS'
        self.params['Parameters'] = self.params.get('Parameters') or []
        self.params['CreationTime'] = self.params.get('CreationTime') or timestamp_millis()
        self.resource_states = {}
        self.events = []
        self.change_sets = []

    def describe_details(self):
        attrs = ['StackId', 'StackName', 'Description', 'Parameters', 'StackStatusReason',
            'StackStatus', 'Capabilities', 'Outputs', 'Tags', 'ParentId', 'RootId', 'RoleARN',
            'CreationTime', 'DeletionTime', 'LastUpdatedTime']
        result = select_attributes(self.params, attrs)
        for attr in ['Parameters', 'Capabilities']:
            result[attr] = {'member': result.get(attr, [])}
        result['Outputs'] = {'member': self.outputs}
        return result

    def set_stack_status(self, status):
        self.params['StackStatus'] = status
        event = {
            'EventId': short_uid(),
            'StackId': self.stack_id,
            'StackName': self.stack_name,
            'LogicalResourceId': self.stack_name,
            'PhysicalResourceId': self.stack_id,
            'ResourceStatus': status,
            'ResourceType': 'AWS::CloudFormation::Stack'
        }
        self.events.append(event)

    def set_resource_status(self, resource_id, status, physical_res_id=None):
        resource = self.resources[resource_id]
        state = self.resource_states[resource_id] = self.resource_states.get(resource_id) or {}
        attr_defaults = (('LogicalResourceId', resource_id), ('PhysicalResourceId', physical_res_id))
        for res in [resource, state]:
            for attr, default in attr_defaults:
                res[attr] = res.get(attr) or default
        state['ResourceStatus'] = status
        state['StackName'] = state.get('StackName') or self.stack_name
        state['StackId'] = state.get('StackId') or self.stack_id
        state['ResourceType'] = state.get('ResourceType') or self.resources[resource_id].get('Type')

    def resource_status(self, resource_id):
        result = self._lookup(self.resource_states, resource_id)
        return result

    @property
    def stack_name(self):
        return self.params['StackName']

    @property
    def stack_id(self):
        return self.params['StackId']

    @property
    def resources(self):
        return self.params['Resources']

    @property
    def outputs(self):
        result = []
        for k, details in self.params.get('Outputs', {}).items():
            value = template_deployer.resolve_refs_recursively(self.stack_name, details['Value'], self.resources)
            export = details.get('Export', {}).get('Name')
            description = details.get('Description')
            entry = {'OutputKey': k, 'OutputValue': value, 'Description': description, 'ExportName': export}
            result.append(entry)
        return result

    def resource(self, resource_id):
        return self._lookup(self.resources, resource_id)

    def _lookup(self, resource_map, resource_id):
        resource = resource_map.get(resource_id)
        if not resource:
            raise Exception('Unable to find details for resource "%s" in stack "%s"' % (resource_id, self.stack_name))
        return resource


class StackChangeSet(Stack):
    def __init__(self, params={}):
        super(StackChangeSet, self).__init__(params)
        self.params['Id'] = self.params.get('Id') or short_uid()
        self.params.pop('StackId', None)

    @property
    def change_set_id(self):
        return self.params['Id']


# --------------
# API ENDPOINTS
# --------------

def create_stack(req_params):
    state = RegionState.get()
    cloudformation_listener.prepare_template_body(req_params)
    stack_details = template_deployer.parse_template(req_params['TemplateBody'])
    stack_details['StackName'] = req_params.get('StackName')
    stack = Stack(stack_details)
    state.stacks[stack.stack_id] = stack
    deployer = template_deployer.TemplateDeployer(stack)
    deployer.run_deploymeny_loop()
    result = {'StackId': stack.stack_id}
    return result


def delete_stack(req_params):
    state = RegionState.get()
    stack_name = req_params.get('StackName')
    stack = find_stack(stack_name)
    stack_resources = list(stack.resources.values())
    template_deployer.delete_stack(stack_name, stack_resources)
    state.stacks.pop(stack.stack_id)
    return {}


def describe_stacks(req_params):
    state = RegionState.get()
    stack_name = req_params.get('StackName')
    stacks = [s.describe_details() for s in state.stacks.values() if stack_name in [None, s.stack_name]]
    result = {'Stacks': {'member': stacks}}
    return result


def describe_stack_resource(req_params):
    stack_name = req_params.get('StackName')
    resource_id = req_params.get('LogicalResourceId')
    stack = find_stack(stack_name)
    if not stack:
        return flask_error_response_xml('Unable to find stack named "%s"' % stack_name,
            code=404, code_string='ResourceNotFoundException')
    details = stack.resource_status(resource_id)
    result = {'StackResourceDetail': details}
    return result


def describe_stack_resources(req_params):
    stack_name = req_params.get('StackName')
    resource_id = req_params.get('LogicalResourceId')
    phys_resource_id = req_params.get('PhysicalResourceId')
    if phys_resource_id and stack_name:
        return flask_error_response_xml('Cannot specify both StackName and PhysicalResourceId')
    # TODO: filter stack by PhysicalResourceId!
    stack = find_stack(stack_name)
    statuses = [stack.resource_status(res_id) for res_id, _ in stack.resource_states.items() if
        resource_id in [res_id, None]]
    return {'StackResources': {'member': statuses}}


def list_stack_resources(req_params):
    result = describe_stack_resources(req_params)
    result = {'StackResourceSummaries': result.pop('StackResources')}
    return result


def create_change_set(req_params):
    stack_name = req_params.get('StackName')
    cloudformation_listener.prepare_template_body(req_params)
    stack_details = template_deployer.parse_template(req_params['TemplateBody'])
    stack_details['StackName'] = stack_name
    change_set = StackChangeSet(stack_details)
    stack = find_stack(stack_name)
    deployer = template_deployer.TemplateDeployer(stack)
    deployer.apply_change_set(change_set)
    return {'StackId': stack.stack_id, 'Id': change_set.change_set_id}


def validate_template(req_params):
    result = cloudformation_listener.validate_template(req_params)
    return result


def describe_stack_events(req_params):
    stack_name = req_params.get('StackName')
    state = RegionState.get()
    events = []
    for stack_id, stack in state.stacks.items():
        if stack_name in [None, stack.stack_name]:
            events.extend(stack.events)
    return {'StackEvents': events}


# -----------------
# MAIN ENTRY POINT
# -----------------

@app.route('/', methods=['POST'])
def handle_request():
    data = request.get_data()
    req_params = parse_request_data(request.method, request.path, data)
    action = req_params.get('Action', '')
    # print('!req_params', req_params, action)

    func = ENDPOINTS.get(action)
    if not func:
        return '', 404
    result = func(req_params)

    result = _response(action, result)
    print('!!result', result.data)
    return result


ENDPOINTS = {
    'CreateStack': create_stack,
    'CreateChangeSet': create_change_set,
    'DeleteStack': delete_stack,
    'DescribeStackEvents': describe_stack_events,
    'DescribeStacks': describe_stacks,
    'DescribeStackResource': describe_stack_resource,
    'DescribeStackResources': describe_stack_resources,
    'ListStackResources': list_stack_resources,
    'ValidateTemplate': validate_template
}


# ---------------
# UTIL FUNCTIONS
# ---------------

def find_stack(stack_name):
    state = RegionState.get()
    return ([s for s in state.stacks.values() if stack_name == s.stack_name] or [None])[0]


def _response(action, result):
    if isinstance(result, (dict, str)):
        result = requests_response_xml(action, result, xmlns=XMLNS_CF)
    if isinstance(result, requests.models.Response):
        result = requests_to_flask_response(result)
    return result


def serve(port, quiet=True):
    from localstack.services import generic_proxy  # moved here to fix circular import errors
    return generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
