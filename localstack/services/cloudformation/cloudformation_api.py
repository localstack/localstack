import json
import logging
import traceback
import xmltodict
from flask import Flask, request
from requests.models import Response
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.common import (
    parse_request_data, short_uid, long_uid, clone, clone_safe, select_attributes,
    timestamp_millis, recurse_object)
from localstack.utils.cloudformation import template_deployer, template_preparer
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.aws.aws_responses import (
    requests_response_xml, requests_to_flask_response, flask_error_response_xml, extract_url_encoded_param_list)

APP_NAME = 'cloudformation_api'
app = Flask(APP_NAME)

LOG = logging.getLogger(__name__)

XMLNS_CF = 'http://cloudformation.amazonaws.com/doc/2010-05-15/'


class CloudFormationRegion(RegionBackend):

    def __init__(self):
        # maps stack ID to stack details
        self.stacks = {}
        # maps stack set ID to stack set details
        self.stack_sets = {}

    @property
    def exports(self):
        exports = []
        output_keys = {}
        for stack_id, stack in self.stacks.items():
            for output in stack.outputs:
                export_name = output.get('ExportName')
                if not export_name:
                    continue
                if export_name in output_keys:
                    # TODO: raise exception on stack creation in case of duplicate exports
                    LOG.warning('Found duplicate export name %s in stacks: %s %s' % (
                        export_name, output_keys[export_name], stack.stack_id))
                entry = {
                    'ExportingStackId': stack.stack_id,
                    'Name': export_name,
                    'Value': output['OutputValue']
                }
                exports.append(entry)
                output_keys[export_name] = stack.stack_id
        return exports


class StackSet(object):
    """ A stack set contains multiple stack instances. """
    def __init__(self, metadata={}):
        self.metadata = metadata
        # list of stack instances
        self.stack_instances = []
        # maps operation ID to stack set operation details
        self.operations = {}

    @property
    def stack_set_name(self):
        return self.metadata.get('StackSetName')


class StackInstance(object):
    """ A stack instance belongs to a stack set and is specific to a region / account ID. """
    def __init__(self, metadata={}):
        self.metadata = metadata
        # reference to the deployed stack belonging to this stack instance
        self.stack = None


class Stack(object):
    def __init__(self, metadata=None, template={}):
        self.metadata = metadata or {}
        self.template = template or {}
        self._template_raw = clone_safe(self.template)
        self.template_original = clone_safe(self.template)
        # initialize resources
        for resource_id, resource in self.template_resources.items():
            resource['LogicalResourceId'] = self.template_original['Resources'][resource_id]['LogicalResourceId'] = (
                resource.get('LogicalResourceId') or resource_id)
        # initialize stack template attributes
        self.template['StackId'] = self.metadata['StackId'] = (self.metadata.get('StackId') or
            aws_stack.cloudformation_stack_arn(self.stack_name, short_uid()))
        self.template['Parameters'] = self.template.get('Parameters') or {}
        self.template['Outputs'] = self.template.get('Outputs') or {}
        # initialize metadata
        self.metadata['Parameters'] = self.metadata.get('Parameters') or []
        self.metadata['StackStatus'] = 'CREATE_IN_PROGRESS'
        self.metadata['CreationTime'] = self.metadata.get('CreationTime') or timestamp_millis()
        # maps resource id to resource state
        self.resource_states = {}
        # maps resource id to moto resource class instance (TODO: remove in the future)
        self.moto_resource_statuses = {}
        # list of stack events
        self.events = []
        # list of stack change sets
        self.change_sets = []
        # initialize parameters
        for i in range(1, 100):
            key = 'Parameters.member.%s.ParameterKey' % i
            value = 'Parameters.member.%s.ParameterValue' % i
            key = self.metadata.get(key)
            value = self.metadata.get(value)
            if not key:
                break
            self.metadata['Parameters'].append({'ParameterKey': key, 'ParameterValue': value})

    def describe_details(self):
        attrs = ['StackId', 'StackName', 'Description', 'StackStatusReason',
            'StackStatus', 'Capabilities', 'ParentId', 'RootId', 'RoleARN',
            'CreationTime', 'DeletionTime', 'LastUpdatedTime', 'ChangeSetId']
        result = select_attributes(self.metadata, attrs)
        result['Tags'] = self.tags
        result['Outputs'] = self.outputs
        result['Parameters'] = self.stack_parameters()
        for attr in ['Capabilities', 'Tags', 'Outputs', 'Parameters']:
            result[attr] = {'member': result.get(attr, [])}
        return result

    def set_stack_status(self, status):
        self.metadata['StackStatus'] = status
        self.metadata['StackStatusReason'] = 'Deployment %s' % ('failed' if 'FAILED' in status else 'succeeded')
        self.add_stack_event(self.stack_name, self.stack_id, status)

    def add_stack_event(self, resource_id, physical_res_id, status):
        event = {
            'EventId': long_uid(),
            'Timestamp': timestamp_millis(),
            'StackId': self.stack_id,
            'StackName': self.stack_name,
            'LogicalResourceId': resource_id,
            'PhysicalResourceId': physical_res_id,
            'ResourceStatus': status,
            'ResourceType': 'AWS::CloudFormation::Stack'
        }
        self.events.insert(0, event)

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
        state['LastUpdatedTimestamp'] = timestamp_millis()
        self.add_stack_event(resource_id, physical_res_id, status)

    def resource_status(self, resource_id):
        result = self._lookup(self.resource_states, resource_id)
        return result

    @property
    def stack_name(self):
        return self.metadata['StackName']

    @property
    def stack_id(self):
        return self.metadata['StackId']

    @property
    def resources(self):
        """ Return dict of resources, parameters, conditions, and other stack metadata. """

        def add_params(defaults=True):
            for param in self.stack_parameters(defaults=defaults):
                if param['ParameterKey'] not in result:
                    props = {'Value': param['ParameterValue']}
                    result[param['ParameterKey']] = {
                        'Type': 'Parameter',
                        'LogicalResourceId': param['ParameterKey'],
                        'Properties': props
                    }

        result = dict(self.template_resources)

        add_params(defaults=False)

        for name, value in self.conditions.items():
            if name not in result:
                result[name] = {'Type': 'Parameter', 'LogicalResourceId': name, 'Properties': {'Value': value}}
        for name, value in self.mappings.items():
            if name not in result:
                result[name] = {'Type': 'Parameter', 'LogicalResourceId': name, 'Properties': {'Value': value}}

        add_params(defaults=True)

        return result

    @property
    def template_resources(self):
        return self.template['Resources']

    @property
    def tags(self):
        return aws_responses.extract_tags(self.metadata)

    @property
    def imports(self):
        def _collect(o, **kwargs):
            if isinstance(o, dict):
                import_val = o.get('Fn::ImportValue')
                if import_val:
                    result.add(import_val)
            return o
        result = set()
        recurse_object(self.resources, _collect)
        return result

    @property
    def outputs(self):
        result = []
        # first, fetch the outputs of nested child stacks
        for stack in self.nested_stacks:
            result.extend(stack.outputs)
        # now, fetch the outputs of this stack
        for k, details in self.template.get('Outputs', {}).items():
            value = None
            try:
                template_deployer.resolve_refs_recursively(self.stack_name, details, self.resources)
                value = details['Value']
            except Exception as e:
                LOG.debug('Unable to resolve references in stack outputs: %s - %s' % (details, e))
            exports = details.get('Export') or {}
            export = exports.get('Name')
            export = template_deployer.resolve_refs_recursively(self.stack_name, export, self.resources)
            description = details.get('Description')
            entry = {'OutputKey': k, 'OutputValue': value, 'Description': description, 'ExportName': export}
            result.append(entry)
        return result

    def stack_parameters(self, defaults=True):
        result = {}
        # add default template parameter values
        if defaults:
            for key, value in self.template_parameters.items():
                result[key] = {'ParameterKey': key, 'ParameterValue': value.get('Default')}
        # add stack parameters
        result.update({p['ParameterKey']: p for p in self.metadata['Parameters']})
        # add parameters of change sets
        for change_set in self.change_sets:
            result.update({p['ParameterKey']: p for p in change_set.metadata['Parameters']})
        result = list(result.values())
        return result

    @property
    def template_parameters(self):
        return self.template['Parameters']

    @property
    def conditions(self):
        return self.template.get('Conditions', {})

    @property
    def mappings(self):
        return self.template.get('Mappings', {})

    @property
    def exports_map(self):
        result = {}
        for export in CloudFormationRegion.get().exports:
            result[export['Name']] = export
        return result

    @property
    def nested_stacks(self):
        """ Return a list of nested stacks that have been deployed by this stack. """
        result = [r for r in self.template_resources.values() if r['Type'] == 'AWS::CloudFormation::Stack']
        result = [find_stack(r['Properties'].get('StackName')) for r in result]
        result = [r for r in result if r]
        return result

    @property
    def status(self):
        return self.metadata['StackStatus']

    @property
    def resource_types(self):
        return [r.get('Type') for r in self.template_resources.values()]

    def resource(self, resource_id):
        return self._lookup(self.resources, resource_id)

    def _lookup(self, resource_map, resource_id):
        resource = resource_map.get(resource_id)
        if not resource:
            raise Exception('Unable to find details for resource "%s" in stack "%s"' % (resource_id, self.stack_name))
        return resource

    def copy(self):
        return Stack(metadata=dict(self.metadata), template=dict(self.template))


class StackChangeSet(Stack):
    def __init__(self, params={}, template={}):
        super(StackChangeSet, self).__init__(params, template)
        name = self.metadata['ChangeSetName']
        if not self.metadata.get('ChangeSetId'):
            self.metadata['ChangeSetId'] = aws_stack.cf_change_set_arn(name, change_set_id=short_uid())

        stack = self.stack = find_stack(self.metadata['StackName'])
        self.metadata['StackId'] = stack.stack_id
        self.metadata['Status'] = 'CREATE_PENDING'

    @property
    def change_set_id(self):
        return self.metadata['ChangeSetId']

    @property
    def change_set_name(self):
        return self.metadata['ChangeSetName']

    @property
    def resources(self):
        result = dict(self.stack.resources)
        result.update(self.resources)
        return result

    @property
    def changes(self):
        result = self.metadata['Changes'] = self.metadata.get('Changes', [])
        return result


# --------------
# API ENDPOINTS
# --------------

def create_stack(req_params):
    state = CloudFormationRegion.get()
    template_deployer.prepare_template_body(req_params)
    template = template_preparer.parse_template(req_params['TemplateBody'])
    stack_name = template['StackName'] = req_params.get('StackName')
    stack = Stack(req_params, template)

    # find existing stack with same name, and remove it if this stack is in DELETED state
    existing = ([s for s in state.stacks.values() if s.stack_name == stack_name] or [None])[0]
    if existing:
        if 'DELETE' not in existing.status:
            return error_response('Stack named "%s" already exists with status "%s"' % (
                stack_name, existing.status), code=400, code_string='ValidationError')
        state.stacks.pop(existing.stack_id)

    state.stacks[stack.stack_id] = stack
    LOG.debug('Creating stack "%s" with %s resources ...' % (stack.stack_name, len(stack.template_resources)))
    deployer = template_deployer.TemplateDeployer(stack)
    try:
        deployer.deploy_stack()
    except Exception as e:
        stack.set_stack_status('CREATE_FAILED')
        msg = 'Unable to create stack "%s": %s' % (stack.stack_name, e)
        LOG.debug('%s %s' % (msg, traceback.format_exc()))
        return error_response(msg, code=400, code_string='ValidationError')
    result = {'StackId': stack.stack_id}
    return result


def create_stack_set(req_params):
    state = CloudFormationRegion.get()
    stack_set = StackSet(req_params)
    stack_set_id = short_uid()
    stack_set.metadata['StackSetId'] = stack_set_id
    state.stack_sets[stack_set_id] = stack_set
    result = {'StackSetId': stack_set_id}
    return result


def create_stack_instances(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not stack_set:
        return not_found_error('Stack set named "%s" does not exist' % set_name)
    stack_set = stack_set[0]
    op_id = req_params.get('OperationId') or short_uid()
    sset_meta = stack_set.metadata
    accounts = extract_url_encoded_param_list(req_params, 'Accounts.member.%s')
    accounts = accounts or extract_url_encoded_param_list(req_params, 'DeploymentTargets.Accounts.member.%s')
    regions = extract_url_encoded_param_list(req_params, 'Regions.member.%s')
    stacks_to_await = []
    for account in accounts:
        for region in regions:
            # deploy new stack
            LOG.debug('Deploying instance for stack set "%s" in region "%s"' % (set_name, region))
            cf_client = aws_stack.connect_to_service('cloudformation', region_name=region)
            kwargs = select_attributes(sset_meta, 'TemplateBody') or select_attributes(sset_meta, 'TemplateURL')
            stack_name = 'sset-%s-%s' % (set_name, account)
            result = cf_client.create_stack(StackName=stack_name, **kwargs)
            stacks_to_await.append((stack_name, region))
            # store stack instance
            instance = {
                'StackSetId': sset_meta['StackSetId'],
                'OperationId': op_id,
                'Account': account,
                'Region': region,
                'StackId': result['StackId'],
                'Status': 'CURRENT',
                'StackInstanceStatus': {'DetailedStatus': 'SUCCEEDED'}
            }
            instance = StackInstance(instance)
            stack_set.stack_instances.append(instance)
    # wait for completion of stack
    for stack in stacks_to_await:
        aws_stack.await_stack_completion(stack[0], region_name=stack[1])
    # record operation
    operation = {
        'OperationId': op_id,
        'StackSetId': stack_set.metadata['StackSetId'],
        'Action': 'CREATE',
        'Status': 'SUCCEEDED'
    }
    stack_set.operations[op_id] = operation
    result = {'OperationId': op_id}
    return result


def delete_stack(req_params):
    stack_name = req_params.get('StackName')
    stack = find_stack(stack_name)
    deployer = template_deployer.TemplateDeployer(stack)
    deployer.delete_stack()
    return {}


def delete_stack_set(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not stack_set:
        return not_found_error('Stack set named "%s" does not exist' % set_name)
    for instance in stack_set[0].stack_instances:
        deployer = template_deployer.TemplateDeployer(instance.stack)
        deployer.delete_stack()
    return {}


def update_stack(req_params):
    stack_name = req_params.get('StackName')
    stack = find_stack(stack_name)
    if not stack:
        return not_found_error('Unable to update non-existing stack "%s"' % stack_name)
    template_preparer.prepare_template_body(req_params)
    template = template_preparer.parse_template(req_params['TemplateBody'])
    new_stack = Stack(req_params, template)
    deployer = template_deployer.TemplateDeployer(stack)
    try:
        deployer.update_stack(new_stack)
    except Exception as e:
        stack.set_stack_status('UPDATE_FAILED')
        msg = 'Unable to update stack "%s": %s' % (stack_name, e)
        LOG.debug('%s %s' % (msg, traceback.format_exc()))
        return error_response(msg, code=400, code_string='ValidationError')
    result = {'StackId': stack.stack_id}
    return result


def update_stack_set(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not stack_set:
        return not_found_error('Stack set named "%s" does not exist' % set_name)
    stack_set = stack_set[0]
    stack_set.metadata.update(req_params)
    op_id = req_params.get('OperationId') or short_uid()
    operation = {
        'OperationId': op_id,
        'StackSetId': stack_set.metadata['StackSetId'],
        'Action': 'UPDATE',
        'Status': 'SUCCEEDED'
    }
    stack_set.operations[op_id] = operation
    return {'OperationId': op_id}


def describe_stacks(req_params):
    state = CloudFormationRegion.get()
    stack_name = req_params.get('StackName')
    stack_list = list(state.stacks.values())
    stacks = [s.describe_details() for s in stack_list if stack_name in [None, s.stack_name, s.stack_id]]
    if stack_name and not stacks:
        return error_response('Stack with id %s does not exist' % stack_name,
            code=400, code_string='ValidationError')
    result = {'Stacks': {'member': stacks}}
    return result


def list_stacks(req_params):
    state = CloudFormationRegion.get()

    stack_status_filters = _get_status_filter_members(req_params)

    stacks = [s.describe_details() for s in state.stacks.values() if
        not stack_status_filters or s.status in stack_status_filters]

    attrs = ['StackId', 'StackName', 'TemplateDescription', 'CreationTime', 'LastUpdatedTime', 'DeletionTime',
             'StackStatus', 'StackStatusReason', 'ParentId', 'RootId', 'DriftInformation']
    stacks = [select_attributes(stack, attrs) for stack in stacks]
    result = {'StackSummaries': {'member': stacks}}
    return result


def describe_stack_resource(req_params):
    stack_name = req_params.get('StackName')
    resource_id = req_params.get('LogicalResourceId')
    stack = find_stack(stack_name)
    if not stack:
        return stack_not_found_error(stack_name)
    details = stack.resource_status(resource_id)
    result = {'StackResourceDetail': details}
    return result


def describe_stack_resources(req_params):
    stack_name = req_params.get('StackName')
    resource_id = req_params.get('LogicalResourceId')
    phys_resource_id = req_params.get('PhysicalResourceId')
    if phys_resource_id and stack_name:
        return error_response('Cannot specify both StackName and PhysicalResourceId', code=400)
    # TODO: filter stack by PhysicalResourceId!
    stack = find_stack(stack_name)
    if not stack:
        return stack_not_found_error(stack_name)
    statuses = [stack.resource_status(res_id) for res_id, _ in stack.resource_states.items() if
        resource_id in [res_id, None]]
    return {'StackResources': {'member': statuses}}


def list_stack_resources(req_params):
    result = describe_stack_resources(req_params)
    if not isinstance(result, dict):
        return result
    result = {'StackResourceSummaries': result.pop('StackResources')}
    return result


def list_stack_instances(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not stack_set:
        return not_found_error('Stack set named "%s" does not exist' % set_name)
    stack_set = stack_set[0]
    result = [inst.metadata for inst in stack_set.stack_instances]
    result = {'Summaries': {'member': result}}
    return result


def create_change_set(req_params):
    stack_name = req_params.get('StackName')
    template_deployer.prepare_template_body(req_params)
    template = template_preparer.parse_template(req_params.pop('TemplateBody'))
    template['StackName'] = stack_name
    template['ChangeSetName'] = req_params.get('ChangeSetName')
    stack = existing = find_stack(stack_name)
    if not existing:
        # automatically create (empty) stack if none exists yet
        state = CloudFormationRegion.get()
        empty_stack_template = dict(template)
        empty_stack_template['Resources'] = {}
        req_params_copy = clone_stack_params(req_params)
        stack = Stack(req_params_copy, empty_stack_template)
        state.stacks[stack.stack_id] = stack
        stack.set_stack_status('CREATE_COMPLETE')
    change_set = StackChangeSet(req_params, template)
    deployer = template_deployer.TemplateDeployer(stack)
    deployer.construct_changes(stack, change_set, change_set_id=change_set.change_set_id, append_to_changeset=True)
    stack.change_sets.append(change_set)
    change_set.metadata['Status'] = 'CREATE_COMPLETE'
    change_set.metadata['ExecutionStatus'] = 'AVAILABLE'
    change_set.metadata['StatusReason'] = 'Changeset created'
    return {'StackId': change_set.stack_id, 'Id': change_set.change_set_id}


def execute_change_set(req_params):
    stack_name = req_params.get('StackName')
    cs_name = req_params.get('ChangeSetName')
    change_set = find_change_set(cs_name, stack_name=stack_name)
    if not change_set:
        return not_found_error('Unable to find change set "%s" for stack "%s"' % (cs_name, stack_name))
    LOG.debug('Executing change set "%s" for stack "%s" with %s resources ...' % (
        cs_name, stack_name, len(change_set.template_resources)))
    deployer = template_deployer.TemplateDeployer(change_set.stack)
    deployer.apply_change_set(change_set)
    change_set.stack.metadata['ChangeSetId'] = change_set.change_set_id
    return {}


def list_change_sets(req_params):
    stack_name = req_params.get('StackName')
    stack = find_stack(stack_name)
    if not stack:
        return not_found_error('Unable to find stack "%s"' % stack_name)
    result = [cs.metadata for cs in stack.change_sets]
    result = {'Summaries': {'member': result}}
    return result


def list_stack_sets(req_params):
    state = CloudFormationRegion.get()
    result = [sset.metadata for sset in state.stack_sets.values()]
    result = {'Summaries': {'member': result}}
    return result


def describe_change_set(req_params):
    stack_name = req_params.get('StackName')
    cs_name = req_params.get('ChangeSetName')
    change_set = find_change_set(cs_name, stack_name=stack_name)
    if not change_set:
        return not_found_error('Unable to find change set "%s" for stack "%s"' % (cs_name, stack_name))
    return change_set.metadata


def describe_stack_set(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    result = [sset.metadata for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not result:
        return not_found_error('Unable to find stack set "%s"' % set_name)
    result = {'StackSet': result[0]}
    return result


def describe_stack_set_operation(req_params):
    state = CloudFormationRegion.get()
    set_name = req_params.get('StackSetName')
    stack_set = [sset for sset in state.stack_sets.values() if sset.stack_set_name == set_name]
    if not stack_set:
        return not_found_error('Unable to find stack set "%s"' % set_name)
    stack_set = stack_set[0]
    op_id = req_params.get('OperationId')
    result = stack_set.operations.get(op_id)
    if not result:
        LOG.debug('Unable to find operation ID "%s" for stack set "%s" in list: %s' % (
            op_id, set_name, list(stack_set.operations.keys())))
        return not_found_error('Unable to find operation ID "%s" for stack set "%s"' % (op_id, set_name))
    result = {'StackSetOperation': result}
    return result


def list_exports(req_params):
    state = CloudFormationRegion.get()
    result = {'Exports': {'member': state.exports}}
    return result


def list_imports(req_params):
    state = CloudFormationRegion.get()
    export_name = req_params.get('ExportName')
    importing_stack_names = []
    for stack in state.stacks.values():
        if export_name in stack.imports:
            importing_stack_names.append(stack.stack_name)
    result = {'Imports': {'member': importing_stack_names}}
    return result


def validate_template(req_params):
    try:
        result = template_preparer.validate_template(req_params)
        result = '<tmp>%s</tmp>' % result
        result = xmltodict.parse(result)['tmp']
        return result
    except Exception as err:
        return error_response('Template Validation Error: %s' % err)


def describe_stack_events(req_params):
    stack_name = req_params.get('StackName')
    state = CloudFormationRegion.get()
    events = []
    for stack_id, stack in state.stacks.items():
        if stack_name in [None, stack.stack_name, stack.stack_id]:
            events.extend(stack.events)
    return {'StackEvents': {'member': events}}


def delete_change_set(req_params):
    stack_name = req_params.get('StackName')
    cs_name = req_params.get('ChangeSetName')
    change_set = find_change_set(cs_name, stack_name=stack_name)
    if not change_set:
        return not_found_error('Unable to find change set "%s" for stack "%s"' % (cs_name, stack_name))
    change_set.stack.change_sets = [cs for cs in change_set.stack.change_sets if cs.change_set_name != cs_name]
    return {}


def get_template(req_params):
    stack_name = req_params.get('StackName')
    cs_name = req_params.get('ChangeSetName')
    stack = find_stack(stack_name)
    if cs_name:
        stack = find_change_set(stack_name, cs_name)
    if not stack:
        return stack_not_found_error(stack_name)
    result = {'TemplateBody': json.dumps(stack._template_raw)}
    return result


def get_template_summary(req_params):
    stack_name = req_params.get('StackName')
    stack = None
    if stack_name:
        stack = find_stack(stack_name)
        if not stack:
            return stack_not_found_error(stack_name)
    else:
        template_deployer.prepare_template_body(req_params)
        template = template_preparer.parse_template(req_params['TemplateBody'])
        req_params['StackName'] = 'tmp-stack'
        stack = Stack(req_params, template)
    result = stack.describe_details()
    id_summaries = {}
    for resource_id, resource in stack.template_resources.items():
        res_type = resource['Type']
        id_summaries[res_type] = id_summaries.get(res_type) or []
        id_summaries[res_type].append(resource_id)
    result['ResourceTypes'] = list(id_summaries.keys())
    result['ResourceIdentifierSummaries'] = [
        {'ResourceType': key, 'LogicalResourceIds': {'member': values}} for key, values in id_summaries.items()]
    return result


# -----------------
# MAIN ENTRY POINT
# -----------------

@app.route('/', methods=['POST'])
def handle_request():
    data = request.get_data()
    req_params = parse_request_data(request.method, request.path, data)
    action = req_params.get('Action', '')

    func = ENDPOINTS.get(action)
    if not func:
        return '', 404
    result = func(req_params)

    result = _response(action, result)
    return result


ENDPOINTS = {
    'CreateChangeSet': create_change_set,
    'CreateStack': create_stack,
    'CreateStackInstances': create_stack_instances,
    'CreateStackSet': create_stack_set,
    'DeleteChangeSet': delete_change_set,
    'DeleteStack': delete_stack,
    'DeleteStackSet': delete_stack_set,
    'DescribeChangeSet': describe_change_set,
    'DescribeStackEvents': describe_stack_events,
    'DescribeStackResource': describe_stack_resource,
    'DescribeStackResources': describe_stack_resources,
    'DescribeStacks': describe_stacks,
    'DescribeStackSet': describe_stack_set,
    'DescribeStackSetOperation': describe_stack_set_operation,
    'ExecuteChangeSet': execute_change_set,
    'GetTemplate': get_template,
    'GetTemplateSummary': get_template_summary,
    'ListChangeSets': list_change_sets,
    'ListExports': list_exports,
    'ListImports': list_imports,
    'ListStackInstances': list_stack_instances,
    'ListStacks': list_stacks,
    'ListStackResources': list_stack_resources,
    'ListStackSets': list_stack_sets,
    'UpdateStack': update_stack,
    'UpdateStackSet': update_stack_set,
    'ValidateTemplate': validate_template
}


# ---------------
# UTIL FUNCTIONS
# ---------------

def error_response(*args, **kwargs):
    kwargs['xmlns'] = kwargs.get('xmlns') or XMLNS_CF
    return flask_error_response_xml(*args, **kwargs)


def not_found_error(message):
    return error_response(message, code=404, code_string='ResourceNotFoundException')


def stack_not_found_error(stack_name):
    return not_found_error('Unable to find stack named "%s"' % stack_name)


def clone_stack_params(stack_params):
    try:
        return clone(stack_params)
    except Exception as e:
        LOG.info('Unable to clone stack parameters: %s' % e)
        return stack_params


def find_stack(stack_name):
    state = CloudFormationRegion.get()
    return ([s for s in state.stacks.values() if stack_name in [s.stack_name, s.stack_id]] or [None])[0]


def find_change_set(cs_name, stack_name=None):
    state = CloudFormationRegion.get()
    stack = find_stack(stack_name)
    stacks = [stack] if stack else state.stacks.values()
    result = [cs for s in stacks for cs in s.change_sets if cs_name in [cs.change_set_id, cs.change_set_name]]
    return (result or [None])[0]


def _response(action, result):
    if isinstance(result, (dict, str)):
        result = requests_response_xml(action, result, xmlns=XMLNS_CF)
    if isinstance(result, Response):
        result = requests_to_flask_response(result)
    return result


def serve(port, quiet=True):
    from localstack.services import generic_proxy  # moved here to fix circular import errors
    return generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)


def _get_status_filter_members(req_params):
    """
    Creates a set of status from the requests parameters

    The API request params specify two parameters of the endpoint:
       - NextToken: Token for next page
       - StackStatusFilter.member.N: Status to use as a filter (it conforms a list)

    StackStatusFilter.member.N abstracts the list of status in the request, and it is sent
    as different parameters, as the N suggests.

    Docs:
         https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ListStacks.html

    Returns:
        set: set of status to filter upon
    """
    return {
        value
        for param, value in req_params.items()
        if param.startswith('StackStatusFilter.member')
    }
