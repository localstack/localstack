import sys
import json
import types
import logging
import traceback
import six
import boto3.session
from moto.s3 import models as s3_models
from moto.iam import models as iam_models
from moto.sqs import models as sqs_models
from moto.sns import models as sns_models
from moto.core import BaseModel
from moto.server import main as moto_main
from moto.kinesis import models as kinesis_models
from moto.dynamodb import models as dynamodb_models
from moto.dynamodb2 import models as dynamodb2_models
from moto.awslambda import models as lambda_models
from moto.apigateway import models as apigw_models
from moto.cloudwatch import models as cw_models
from moto.cloudformation import parsing, responses
from moto.cloudformation import utils as cloudformation_utils
from moto.cloudformation import models as cloudformation_models
from boto.cloudformation.stack import Output
from moto.cloudformation.models import FakeStack, CloudFormationBackend, cloudformation_backends
from moto.cloudformation.exceptions import ValidationError, UnformattedGetAttTemplateException
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack, aws_responses
from localstack.utils.common import (
    FuncThread, short_uid, recurse_object, clone, json_safe, md5, canonical_json,
    get_free_tcp_port, Mock, start_thread, edge_ports_info)
from localstack.stepfunctions import models as sfn_models
from localstack.services.infra import start_proxy_for_service, do_run, canonicalize_api_names
from localstack.utils.bootstrap import setup_logging
from localstack.utils.cloudformation import template_deployer
from localstack.services.cloudformation import service_models

LOG = logging.getLogger(__name__)

MOTO_CFN_ACCOUNT_ID = '123456789'

# Maps (stack_name,resource_logical_id) -> Bool to indicate which resources are currently being updated
CURRENTLY_UPDATING_RESOURCES = {}

# whether to start the API in a separate process
RUN_SERVER_IN_PROCESS = False

# maximum depth of the resource dependency tree
MAX_DEPENDENCY_DEPTH = 40

# map of additional model classes
MODEL_MAP = {
    'AWS::StepFunctions::Activity': service_models.StepFunctionsActivity,
    'AWS::SNS::Subscription': service_models.SNSSubscription,
    'AWS::ApiGateway::GatewayResponse': service_models.GatewayResponse,
    'AWS::ApiGateway::Deployment': apigw_models.Deployment,
    'AWS::ApiGateway::Method': apigw_models.Method,
    'AWS::ApiGateway::Resource': apigw_models.Resource,
    'AWS::ApiGateway::RestApi': apigw_models.RestAPI,
    'AWS::ApiGateway::Stage': apigw_models.Stage,
    'AWS::StepFunctions::StateMachine': sfn_models.StateMachine,
    'AWS::CloudFormation::Stack': service_models.CloudFormationStack,
    'AWS::SSM::Parameter': service_models.SSMParameter,
    'AWS::Logs::LogGroup': service_models.LogsLogGroup,
    'AWS::KinesisFirehose::DeliveryStream': service_models.FirehoseDeliveryStream,
    'AWS::SecretsManager::Secret': service_models.SecretsManagerSecret,
    'AWS::Elasticsearch::Domain': service_models.ElasticsearchDomain,
    'AWS::Events::Rule': service_models.EventsRule,
    'AWS::S3::BucketPolicy': service_models.S3BucketPolicy
}


def start_cloudformation(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_CLOUDFORMATION
    print('Starting mock CloudFormation service on %s ...' % edge_ports_info())
    backend_port = get_free_tcp_port()
    start_proxy_for_service('cloudformation', port, backend_port, update_listener)
    if RUN_SERVER_IN_PROCESS:
        cmd = 'python "%s" cloudformation -p %s -H 0.0.0.0' % (__file__, backend_port)
        env_vars = {'PYTHONPATH': ':'.join(sys.path)}
        return do_run(cmd, asynchronous, env_vars=env_vars)
    else:
        argv = ['cloudformation', '-p', str(backend_port), '-H', '0.0.0.0']
        thread = FuncThread(start_up, argv)
        thread.start()
        return thread


def set_moto_account_ids(resource_json):
    def fix_ids(obj, **kwargs):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, six.string_types):
                    if 'arn' in key.lower() or (':%s:' % TEST_AWS_ACCOUNT_ID) in value:
                        obj[key] = value.replace(TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID)
        return obj

    return recurse_object(resource_json, fix_ids)


def get_entity_id(entity, resource_json=None):
    # check if physical_resource_id is present
    if hasattr(entity, 'physical_resource_id'):
        return entity.physical_resource_id
    # check ID attribute candidates
    types_with_ref_as_id_or_name = (apigw_models.RestAPI, apigw_models.Resource)
    attr_candidates = ['function_arn', 'Arn', 'Ref', 'id', 'Id', 'name', 'Name']
    for attr in attr_candidates:
        if hasattr(entity, attr):
            if attr in ['id', 'name'] and not isinstance(entity, types_with_ref_as_id_or_name):
                LOG.warning('Unable to find ARN, using "%s" instead: %s - %s', attr, resource_json, entity)

            return getattr(entity, attr)
        if hasattr(entity, 'get_cfn_attribute'):
            try:
                result = entity.get_cfn_attribute(attr)
                if result:
                    return result
            except Exception:
                pass
    # fall back to classes that use params as the dict of entity parameters
    if hasattr(entity, 'params'):
        for key, value in (entity.params or {}).items():
            if key.endswith('Name'):
                return value


def convert_objs_to_ids(resource_json):
    def fix_ids(obj, **kwargs):
        if isinstance(obj, dict):
            obj = dict(obj)
            for key, value in obj.items():
                if isinstance(value, BaseModel):
                    entity_id = get_entity_id(value)
                    obj[key] = entity_id or value
        return obj

    return recurse_object(resource_json, fix_ids)


def update_physical_resource_id(resource):
    phys_res_id = getattr(resource, 'physical_resource_id', None)
    if not phys_res_id:
        if isinstance(resource, lambda_models.LambdaFunction):
            func_arn = aws_stack.lambda_function_arn(resource.function_name)
            resource.function_arn = resource.physical_resource_id = func_arn

        elif isinstance(resource, sfn_models.StateMachine):
            sm_arn = aws_stack.state_machine_arn(resource.name)
            resource.physical_resource_id = sm_arn

        elif isinstance(resource, service_models.StepFunctionsActivity):
            act_arn = aws_stack.stepfunctions_activity_arn(resource.params.get('Name'))
            resource.physical_resource_id = act_arn

        elif isinstance(resource, kinesis_models.Stream):
            resource.physical_resource_id = resource.stream_name

        elif isinstance(resource, service_models.LogsLogGroup):
            resource.physical_resource_id = resource.params.get('LogGroupName')

        elif isinstance(resource, service_models.FirehoseDeliveryStream):
            resource.physical_resource_id = resource.params.get('DeliveryStreamName')

        elif isinstance(resource, service_models.SecretsManagerSecret):
            resource.physical_resource_id = resource.params.get('Name')

        elif isinstance(resource, service_models.EventsRule):
            resource.physical_resource_id = resource.params.get('Name')

        elif isinstance(resource, service_models.ElasticsearchDomain):
            resource.physical_resource_id = resource.params.get('DomainName')

        elif isinstance(resource, dynamodb_models.Table):
            resource.physical_resource_id = resource.name

        elif isinstance(resource, dynamodb2_models.Table):
            resource.physical_resource_id = resource.name

        elif isinstance(resource, apigw_models.RestAPI):
            resource.physical_resource_id = resource.id

        else:
            LOG.warning('Unable to determine physical_resource_id for resource %s' % type(resource))


def update_resource_name(resource, resource_json):
    """ Some resources require minor fixes in their CF resource definition
        before we can pass them on to deployment. """
    props = resource_json['Properties'] = resource_json.get('Properties') or {}
    if isinstance(resource, sfn_models.StateMachine) and not props.get('StateMachineName'):
        props['StateMachineName'] = resource.name


def update_dynamodb_index_resource(resource):
    if resource.get('Properties').get('BillingMode') == 'PAY_PER_REQUEST':
        for glob_index in resource.get('Properties', {}).get('GlobalSecondaryIndexes', []):
            if not glob_index.get('ProvisionedThroughput'):
                glob_index['ProvisionedThroughput'] = {'ReadCapacityUnits': 99, 'WriteCapacityUnits': 99}


def add_default_resource_props(resource_props, stack_name, resource_name=None):
    """ Apply some fixes to resource props which otherwise cause deployments to fail """

    res_type = resource_props['Type']
    props = resource_props.get('Properties', {})

    if res_type == 'AWS::Lambda::EventSourceMapping' and not props.get('StartingPosition'):
        props['StartingPosition'] = 'LATEST'

    if res_type == 'AWS::Lambda::Function' and not props.get('FunctionName'):
        props['FunctionName'] = '{}-lambda-{}'.format(stack_name[:45], short_uid())

    if res_type == 'AWS::SNS::Topic' and not props.get('TopicName'):
        props['TopicName'] = 'topic-%s' % short_uid()

    if res_type == 'AWS::SQS::Queue' and not props.get('QueueName'):
        props['QueueName'] = 'queue-%s' % short_uid()

    if res_type == 'AWS::ApiGateway::RestApi' and not props.get('Name'):
        props['Name'] = resource_name

    if res_type == 'AWS::DynamoDB::Table':
        update_dynamodb_index_resource(resource_props)

    if res_type == 'AWS::S3::Bucket':
        props['BucketName'] = props.get('BucketName') or resource_name

    # generate default names for certain resource types
    default_attrs = (('AWS::IAM::Role', 'RoleName'), ('AWS::Events::Rule', 'Name'))
    for entry in default_attrs:
        if res_type == entry[0] and not props.get(entry[1]):
            props_str = canonical_json(json_safe(props))
            props[entry[1]] = 'cf-%s-%s' % (stack_name, md5(props_str))


def apply_patches():
    """ Apply patches to make LocalStack seamlessly interact with the moto backend.
        TODO: Eventually, these patches should be contributed to the upstream repo! """

    # add model mappings to moto
    parsing.MODEL_MAP.update(MODEL_MAP)

    # fix account ID
    parsing.ACCOUNT_ID = TEST_AWS_ACCOUNT_ID

    # Patch clean_json in moto
    def clean_json(resource_json, resources_map):
        try:
            result = clean_json_orig(resource_json, resources_map)
        except RecursionError:
            if isinstance(resource_json, dict) and 'Ref' in resource_json:
                LOG.info('Potential circular dependency detected when resolving Ref "%s"' % resource_json['Ref'])
                return resource_json['Ref']
            raise
        if isinstance(resource_json, dict):
            attr_ref = resource_json.get('Fn::GetAtt')
            if isinstance(attr_ref, list) and result == resource_json:
                # If the attribute cannot be resolved (i.e., result == resource_json), then return
                # an empty value, to avoid returning the original JSON struct (which otherwise
                # results in downstream issues, e.g., when concatenating template values).
                # TODO: Note that this workaround could point towards a general issue with
                # dependency resolution - in fact, this case should never be happening (but it does).
                LOG.debug('Unable to resolve attribute reference %s in resource map keys %s' %
                    (attr_ref, list(resources_map.keys())))
                return None
            if 'Ref' in resource_json and isinstance(result, BaseModel):
                entity_id = get_entity_id(result, resource_json)
                if entity_id:
                    return entity_id
                LOG.warning('Unable to resolve "Ref" attribute for: %s - %s - %s',
                            resource_json, result, type(result))
        return result

    clean_json_orig = parsing.clean_json
    parsing.clean_json = clean_json

    # Patch parse_and_create_resource method in moto to deploy resources in LocalStack
    def parse_and_create_resource(logical_id, resource_json, resources_map, region_name, force_create=False):
        try:
            if hasattr(resources_map, '_deleted'):
                return
            return _parse_and_create_resource(
                logical_id, resource_json, resources_map, region_name, force_create=force_create
            )
        except Exception as e:
            LOG.error('Unable to parse and create resource "%s": %s %s' % (logical_id, e, traceback.format_exc()))
            raise

    def parse_and_update_resource(logical_id, resource_json, resources_map, region_name):
        try:
            return _parse_and_create_resource(logical_id, resource_json, resources_map, region_name, update=True)
        except Exception as e:
            LOG.error('Unable to parse and update resource "%s": %s %s' % (logical_id, e, traceback.format_exc()))
            raise

    def _parse_and_create_resource(logical_id, resource_json, resources_map, region_name,
            update=False, force_create=False):
        stack_name = resources_map.get('AWS::StackName')
        resource_hash_key = (stack_name, logical_id)
        props = resource_json['Properties'] = resource_json.get('Properties') or {}

        # If the current stack is being updated, avoid infinite recursion
        updating = CURRENTLY_UPDATING_RESOURCES.get(resource_hash_key)
        LOG.debug('Currently processing stack resource %s/%s: %s' % (stack_name, logical_id, updating))
        if updating:
            return None
        CURRENTLY_UPDATING_RESOURCES[resource_hash_key] = True

        # parse and get final resource JSON
        resource_tuple = parsing.parse_resource_and_generate_name(logical_id, resource_json, resources_map)
        if not resource_tuple:
            return None
        _, resource_json, resource_name = resource_tuple

        # add some fixes and default props which otherwise cause deployments to fail
        add_default_resource_props(resource_json, stack_name, resource_name=resource_name)
        for resource in resources_map._resource_json_map.values():
            add_default_resource_props(resource, stack_name)

        # check if this resource already exists in the resource map
        resource = resources_map._parsed_resources.get(logical_id)
        if resource and not update and not force_create:
            return resource

        # fix resource ARNs, make sure to convert account IDs 000000000000 to 123456789012
        resource_json_arns_fixed = clone(json_safe(convert_objs_to_ids(resource_json)))
        set_moto_account_ids(resource_json_arns_fixed)
        template_deployer.remove_none_values(resource_json_arns_fixed)

        # create resource definition and store CloudFormation metadata in moto
        moto_create_error = None
        if (resource or update) and not force_create:
            parse_and_update_resource_orig(logical_id, resource_json_arns_fixed, resources_map, region_name)
        elif not resource:
            try:
                resource = parse_and_create_resource_orig(
                    logical_id, resource_json_arns_fixed, resources_map, region_name
                )
                if not resource:
                    # this can happen if the resource has an associated Condition which evaluates to false
                    return resource
                resource.logical_id = logical_id
            except Exception as e:
                moto_create_error = e

        # check whether this resource needs to be deployed
        resource_map_new = dict(resources_map._resource_json_map)
        resource_map_new[logical_id] = resource_json
        should_be_created = template_deployer.should_be_deployed(logical_id, resource_map_new, stack_name)

        # check for moto creation errors and raise an exception if needed
        if moto_create_error:
            if should_be_created:
                raise moto_create_error
            else:
                LOG.info('Error on moto CF resource creation. Ignoring, as should_be_created=%s: %s' %
                         (should_be_created, moto_create_error))

        # Fix for moto which sometimes hard-codes region name as 'us-east-1'
        if hasattr(resource, 'region_name') and resource.region_name != region_name:
            LOG.debug('Updating incorrect region from %s to %s' % (resource.region_name, region_name))
            resource.region_name = region_name

        # check whether this resource needs to be deployed
        is_updateable = False
        if not should_be_created:
            # This resource is either not deployable or already exists. Check if it can be updated
            is_updateable = template_deployer.is_updateable(logical_id, resource_map_new, stack_name)
            if not update or not is_updateable:
                all_satisfied = template_deployer.all_resource_dependencies_satisfied(
                    logical_id, resource_map_new, stack_name
                )
                if not all_satisfied:
                    LOG.info('Resource %s cannot be deployed, found unsatisfied dependencies. %s' % (
                        logical_id, resource_json))
                    details = [logical_id, resource_json, resources_map, region_name]
                    resources_map._unresolved_resources = getattr(resources_map, '_unresolved_resources', {})
                    resources_map._unresolved_resources[logical_id] = details
                else:
                    LOG.debug('Resource %s need not be deployed (is_updateable=%s): %s %s' % (
                        logical_id, is_updateable, resource_json, bool(resource)))
                # Return if this resource already exists and can/need not be updated yet
                # NOTE: We should always return the resource here, to avoid duplicate
                #       creation of resources in moto!
                return resource

        # Apply some fixes/patches to the resource names, then deploy resource in LocalStack
        update_resource_name(resource, resource_json)
        LOG.debug('Deploying CloudFormation resource (update=%s, exists=%s, updateable=%s): %s' %
                  (update, not should_be_created, is_updateable, resource_json))

        try:
            deploy_func = template_deployer.update_resource if update else template_deployer.deploy_resource
            result = deploy_func(logical_id, resource_map_new, stack_name=stack_name)
        finally:
            CURRENTLY_UPDATING_RESOURCES[resource_hash_key] = False

        if not should_be_created:
            # skip the parts below for update requests
            return resource

        def find_id(resource):
            """ Find ID of the given resource. """
            if not resource:
                return
            for id_attr in ('Id', 'id', 'ResourceId', 'RestApiId', 'DeploymentId', 'RoleId'):
                if id_attr in resource:
                    return resource[id_attr]

        # update resource IDs to avoid mismatch between CF moto and LocalStack backend resources
        if hasattr(resource, 'id') or (isinstance(resource, dict) and resource.get('id')):
            existing_id = resource.id if hasattr(resource, 'id') else resource['id']
            new_res_id = find_id(result)
            LOG.debug('Updating resource id: %s - %s, %s - %s' % (existing_id, new_res_id, resource, resource_json))
            if new_res_id:
                LOG.info('Updating resource ID from %s to %s (%s)' % (existing_id, new_res_id, region_name))
                update_resource_id(
                    resource, new_res_id, props, region_name, stack_name, resources_map._resource_json_map,
                    resource_json.get('Properties')
                )
            else:
                LOG.warning('Unable to extract id for resource %s: %s' % (logical_id, result))

        # update physical_resource_id field
        update_physical_resource_id(resource)

        return resource

    def update_resource_id(resource, new_id, props, region_name, stack_name, resource_map, resource_props={}):
        """ Update and fix the ID(s) of the given resource. """

        # NOTE: this is a bit of a hack, which is required because
        # of the order of events when CloudFormation resources are created.
        # When we process a request to create a CF resource that's part of a
        # stack, say, an API Gateway Resource, then we (1) create the object
        # in memory in moto, which generates a random ID for the resource, and
        # then (2) create the actual resource in the backend service using
        # template_deployer.deploy_resource(..) (see above).
        # The resource created in (2) now has a different ID than the resource
        # created in (1), which leads to downstream problems. Hence, we need
        # the logic below to reconcile the ids, i.e., apply IDs from (2) to (1).

        backend = apigw_models.apigateway_backends[region_name]
        if isinstance(resource, apigw_models.RestAPI):
            # We also need to fetch the resources to replace the root resource
            # that moto automatically adds to newly created RestAPI objects
            client = aws_stack.connect_to_service('apigateway')
            resources = client.get_resources(restApiId=new_id, limit=500)['items']
            # repoint ID mappings (make sure this stays BELOW calling get_resources() above)
            api = resource
            backend.apis.pop(api.id, None)
            api.id = new_id
            backend.apis[new_id] = api
            # make sure no resources have been added in addition to the root /
            assert len(api.resources) == 1
            api.resources = {}
            for res in resources:
                res_path_part = res.get('pathPart') or res.get('path')
                res_method_path = resource_props.get('Body', {}).get('paths', {}).get(res_path_part)
                child = api.add_child(res_path_part, res.get('parentId'))

                for key in res_method_path or {}:
                    method_type = key.upper()
                    method = child.resource_methods.get(method_type)
                    if not method:
                        child.add_method(method_type, None, None)

                    path_int = res_method_path[key]['x-amazon-apigateway-integration']
                    child.add_integration(
                        method_type, path_int['type'], path_int.get('uri'),
                        request_templates=path_int.get('requestTemplates'),
                        integration_method=path_int.get('httpMethod'))

                api.resources.pop(child.id)
                child.id = res['id']
                child.api_id = new_id
                api.resources[child.id] = child

        elif isinstance(resource, apigw_models.Resource):
            api_id = props['RestApiId']
            api_id = template_deployer.resolve_refs_recursively(stack_name, api_id, resource_map)
            backend.apis[api_id].resources.pop(resource.id, None)
            backend.apis[api_id].resources[new_id] = resource
            resource.id = new_id

        elif isinstance(resource, apigw_models.Deployment):
            api_id = props['RestApiId']
            api_id = template_deployer.resolve_refs_recursively(stack_name, api_id, resource_map)
            if not api_id:
                api_id = resource_props['RestApiId']

            backend.apis[api_id].deployments.pop(resource['id'], None)
            backend.apis[api_id].deployments[new_id] = resource
            resource['id'] = new_id

        else:
            LOG.warning('Unexpected resource type when updating ID: %s' % type(resource))

    def parse_and_delete_resource(*args, **kwargs):
        try:
            return parse_and_delete_resource_orig(*args, **kwargs)
        except AttributeError:
            # looks like a "delete" method is not yet implemented for a resource type -> ignore
            pass

    parse_and_create_resource_orig = parsing.parse_and_create_resource
    parsing.parse_and_create_resource = parse_and_create_resource
    parse_and_update_resource_orig = parsing.parse_and_update_resource
    parsing.parse_and_update_resource = parse_and_update_resource
    parse_and_delete_resource_orig = parsing.parse_and_delete_resource
    parsing.parse_and_delete_resource = parse_and_delete_resource

    def resource_map_delete(self, *args, **kwargs):
        self._deleted = True
        result = resource_map_delete_orig(self, *args, **kwargs)
        return result

    resource_map_delete_orig = parsing.ResourceMap.delete
    parsing.ResourceMap.delete = resource_map_delete

    # patch CloudFormation parse_output(..) method to fix a bug in moto
    def parse_output(output_logical_id, output_json, resources_map):
        try:
            result = parse_output_orig(output_logical_id, output_json, resources_map)
        except KeyError:
            result = Output()
            result.key = output_logical_id
            result.value = None
            result.description = output_json.get('Description')
        # Make sure output includes export name
        if not hasattr(result, 'export_name'):
            result.export_name = output_json.get('Export', {}).get('Name')
        return result

    parse_output_orig = parsing.parse_output
    parsing.parse_output = parse_output

    # Make sure the export name is returned for stack outputs
    if '<ExportName>' not in responses.DESCRIBE_STACKS_TEMPLATE:
        find = '</OutputValue>'
        replace = """</OutputValue>
        {% if output.export_name %}
        <ExportName>{{ output.export_name }}</ExportName>
        {% endif %}
        """
        responses.DESCRIBE_STACKS_TEMPLATE = responses.DESCRIBE_STACKS_TEMPLATE.replace(find, replace)

    resource_map_diff_orig = parsing.ResourceMap.diff

    def resource_map_diff(self, template, parameters=None):
        resources_diff = resource_map_diff_orig(self, template, parameters)
        if resources_diff['Add'] or resources_diff['Remove'] or resources_diff['Modify']:
            return resources_diff

        raise ValidationError(
            name_or_id='',
            message='No updates are to be performed.'
        )

    parsing.ResourceMap.diff = resource_map_diff

    # Patch CloudFormationBackend.update_stack method in moto
    def make_cf_update_stack(cf_backend):
        cf_update_stack_orig = cf_backend.update_stack

        def cf_update_stack(self, *args, **kwargs):
            stack = cf_update_stack_orig(*args, **kwargs)
            # update stack exports
            self._validate_export_uniqueness(stack)
            for export in stack.exports:
                self.exports[export.name] = export
            return stack
        return types.MethodType(cf_update_stack, cf_backend)

    for region, cf_backend in cloudformation_backends.items():
        cf_backend.update_stack = make_cf_update_stack(cf_backend)

    # Patch DynamoDB get_cfn_attribute(..) method in moto
    def DynamoDB_Table_get_cfn_attribute(self, attribute_name):
        try:
            return ddb_table_get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name == 'Arn':
                return aws_stack.dynamodb_table_arn(table_name=self.name)
            raise

    ddb_table_get_cfn_attribute_orig = dynamodb_models.Table.get_cfn_attribute
    dynamodb_models.Table.get_cfn_attribute = DynamoDB_Table_get_cfn_attribute

    # patch missing ":stream/" in Kinesis ARN

    @property
    def kinesis_arn(self, *args, **kwargs):
        result = self._arn_orig
        if ':stream/' not in result:
            parts = result.split(':')
            result = ':'.join(parts[:-1] + ['stream/%s' % parts[-1]])
        return result

    kinesis_models.Stream._arn_orig = kinesis_models.Stream.arn
    kinesis_models.Stream.arn = kinesis_arn

    # Patch generate_stack_id(..) method in moto
    def generate_stack_id(stack_name, region=None, **kwargs):
        region = region or aws_stack.get_region()
        return generate_stack_id_orig(stack_name, region=region, **kwargs)

    generate_stack_id_orig = cloudformation_utils.generate_stack_id
    cloudformation_utils.generate_stack_id = cloudformation_models.generate_stack_id = generate_stack_id

    # Patch DynamoDB get_cfn_attribute(..) method in moto
    def DynamoDB2_Table_get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return aws_stack.dynamodb_table_arn(table_name=self.name)
        elif attribute_name == 'StreamArn':
            if (self.stream_specification or {}).get('StreamEnabled'):
                return aws_stack.dynamodb_stream_arn(self.name, 'latest')
            return None
        raise UnformattedGetAttTemplateException()

    dynamodb2_models.Table.get_cfn_attribute = DynamoDB2_Table_get_cfn_attribute

    # Patch SQS get_cfn_attribute(..) method in moto
    def SQS_Queue_get_cfn_attribute(self, attribute_name):
        if attribute_name in ['Arn', 'QueueArn']:
            return aws_stack.sqs_queue_arn(queue_name=self.name)
        return SQS_Queue_get_cfn_attribute_orig(self, attribute_name)

    SQS_Queue_get_cfn_attribute_orig = sqs_models.Queue.get_cfn_attribute
    sqs_models.Queue.get_cfn_attribute = SQS_Queue_get_cfn_attribute

    # Patch S3 Bucket get_cfn_attribute(..) method in moto
    def S3_Bucket_get_cfn_attribute(self, attribute_name):
        if attribute_name in ['Arn']:
            return aws_stack.s3_bucket_arn(self.name)
        return S3_Bucket_get_cfn_attribute_orig(self, attribute_name)

    S3_Bucket_get_cfn_attribute_orig = s3_models.FakeBucket.get_cfn_attribute
    s3_models.FakeBucket.get_cfn_attribute = S3_Bucket_get_cfn_attribute

    # Patch SQS physical_resource_id(..) method in moto
    @property
    def SQS_Queue_physical_resource_id(self):
        result = SQS_Queue_physical_resource_id_orig.fget(self)
        if '://' not in result:
            # convert ID to queue URL
            self._physical_resource_id = (getattr(self, '_physical_resource_id', None) or
                aws_stack.get_sqs_queue_url(result))
            return self._physical_resource_id
        return result

    SQS_Queue_physical_resource_id_orig = sqs_models.Queue.physical_resource_id
    sqs_models.Queue.physical_resource_id = SQS_Queue_physical_resource_id

    # Patch LogGroup get_cfn_attribute(..) method in moto
    def LogGroup_get_cfn_attribute(self, attribute_name):
        try:
            return LogGroup_get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name == 'Arn':
                return aws_stack.log_group_arn(self.name)
            raise

    LogGroup_get_cfn_attribute_orig = getattr(cw_models.LogGroup, 'get_cfn_attribute', None)
    cw_models.LogGroup.get_cfn_attribute = LogGroup_get_cfn_attribute

    # Patch Lambda get_cfn_attribute(..) method in moto
    def Lambda_Function_get_cfn_attribute(self, attribute_name):
        try:
            if attribute_name == 'Arn':
                return self.function_arn
            return Lambda_Function_get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name in ('Name', 'FunctionName'):
                return self.function_name
            raise

    Lambda_Function_get_cfn_attribute_orig = lambda_models.LambdaFunction.get_cfn_attribute
    lambda_models.LambdaFunction.get_cfn_attribute = Lambda_Function_get_cfn_attribute

    # Patch DynamoDB get_cfn_attribute(..) method in moto
    def DynamoDB_Table_get_cfn_attribute(self, attribute_name):
        try:
            if attribute_name == 'StreamArn':
                streams = aws_stack.connect_to_service('dynamodbstreams').list_streams(TableName=self.name)['Streams']
                return streams[0]['StreamArn'] if streams else None
            return DynamoDB_Table_get_cfn_attribute_orig(self, attribute_name)
        except Exception as e:
            LOG.warning('Unable to get attribute "%s" from resource %s: %s' % (attribute_name, type(self), e))
            raise

    DynamoDB_Table_get_cfn_attribute_orig = dynamodb_models.Table.get_cfn_attribute
    dynamodb_models.Table.get_cfn_attribute = DynamoDB_Table_get_cfn_attribute

    # Patch IAM get_cfn_attribute(..) method in moto
    def IAM_Role_get_cfn_attribute(self, attribute_name):
        try:
            return IAM_Role_get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name == 'Arn':
                return aws_stack.role_arn(self.name)
            raise

    IAM_Role_get_cfn_attribute_orig = iam_models.Role.get_cfn_attribute
    iam_models.Role.get_cfn_attribute = IAM_Role_get_cfn_attribute

    # Patch IAM Role model
    # https://github.com/localstack/localstack/issues/925
    @property
    def IAM_Role_physical_resource_id(self):
        return self.name

    iam_models.Role.physical_resource_id = IAM_Role_physical_resource_id

    # Patch SNS Topic get_cfn_attribute(..) method in moto
    def SNS_Topic_get_cfn_attribute(self, attribute_name):
        result = SNS_Topic_get_cfn_attribute_orig(self, attribute_name)
        if attribute_name.lower() in ['arn', 'topicarn']:
            result = aws_stack.fix_account_id_in_arns(result)
        return result

    SNS_Topic_get_cfn_attribute_orig = sns_models.Topic.get_cfn_attribute
    sns_models.Topic.get_cfn_attribute = SNS_Topic_get_cfn_attribute

    # Patch create_from_cloudformation_json(..)
    # #2568 Cloudformation create-stack for SNS with yaml causes TypeError

    SNS_Topic_create_from_cloudformation_json_orig = sns_models.Topic.create_from_cloudformation_json

    def SNS_Topic_create_from_cloudformation_json(resource_name, cloudformation_json, region_name):
        properties = cloudformation_json['Properties']
        if properties.get('Subscription'):
            properties['Subscription'] = [subscription for subscription in properties['Subscription'] if subscription]

        return SNS_Topic_create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)

    sns_models.Topic.create_from_cloudformation_json = SNS_Topic_create_from_cloudformation_json

    # Patch ES get_cfn_attribute(..) method
    def ES_get_cfn_attribute(self, attribute_name):
        if attribute_name in ['Arn', 'DomainArn']:
            return aws_stack.es_domain_arn(self.params.get('DomainName'))
        if attribute_name == 'DomainEndpoint':
            if not hasattr(self, '_domain_endpoint'):
                es_details = aws_stack.connect_to_service('es').describe_elasticsearch_domain(
                    DomainName=self.params.get('DomainName'))
                self._domain_endpoint = es_details['DomainStatus']['Endpoint']
            return self._domain_endpoint
        raise UnformattedGetAttTemplateException()

    service_models.ElasticsearchDomain.get_cfn_attribute = ES_get_cfn_attribute

    # Patch Firehose get_cfn_attribute(..) method
    def Firehose_get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return aws_stack.firehose_stream_arn(self.params.get('DeliveryStreamName'))
        raise UnformattedGetAttTemplateException()

    service_models.FirehoseDeliveryStream.get_cfn_attribute = Firehose_get_cfn_attribute

    # Patch LambdaFunction create_from_cloudformation_json(..) method in moto
    @classmethod
    def Lambda_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        resource_name = cloudformation_json.get('Properties', {}).get('FunctionName') or resource_name

        def _from_env(*args, **kwargs):
            result = Mock()
            result.api = Mock()
            result.api.get_adapter = (lambda *args, **kwargs: None)
            return result
        # Temporarily set a mock client, to prevent moto from talking to the Docker daemon
        import docker
        _from_env_orig = docker.from_env
        docker.from_env = _from_env

        try:
            result = Lambda_create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)
        finally:
            docker.from_env = _from_env_orig
        return result

    Lambda_create_from_cloudformation_json_orig = lambda_models.LambdaFunction.create_from_cloudformation_json
    lambda_models.LambdaFunction.create_from_cloudformation_json = Lambda_create_from_cloudformation_json

    # Patch EventSourceMapping create_from_cloudformation_json(..) method in moto
    @classmethod
    def Mapping_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json.get('Properties', {})
        func_name = props.get('FunctionName') or ''
        if ':lambda:' in func_name:
            props['FunctionName'] = aws_stack.lambda_function_name(func_name)
        try:
            return Mapping_create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)
        except Exception:
            LOG.info('Unable to add Lambda event mapping for source ARN "%s" in moto backend (ignoring)' %
                props.get('EventSourceArn'))
            # return an empty dummy instance, to avoid downstream None value issues
            return service_models.BaseModel()

    Mapping_create_from_cloudformation_json_orig = lambda_models.EventSourceMapping.create_from_cloudformation_json
    lambda_models.EventSourceMapping.create_from_cloudformation_json = Mapping_create_from_cloudformation_json

    # Patch LambdaFunction update_from_cloudformation_json(..) method in moto
    @classmethod
    def Lambda_update_from_cloudformation_json(cls,
            original_resource, new_resource_name, cloudformation_json, region_name):
        resource_name = cloudformation_json.get('Properties', {}).get('FunctionName') or new_resource_name
        return Lambda_create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)

    if not hasattr(lambda_models.LambdaFunction, 'update_from_cloudformation_json'):
        lambda_models.LambdaFunction.update_from_cloudformation_json = Lambda_update_from_cloudformation_json

    # Patch Role update_from_cloudformation_json(..) method
    @classmethod
    def Role_update_from_cloudformation_json(cls,
            original_resource, new_resource_name, cloudformation_json, region_name):
        props = cloudformation_json.get('Properties', {})
        original_resource.name = props.get('RoleName') or original_resource.name
        original_resource.assume_role_policy_document = props.get('AssumeRolePolicyDocument')
        return original_resource

    if not hasattr(iam_models.Role, 'update_from_cloudformation_json'):
        iam_models.Role.update_from_cloudformation_json = Role_update_from_cloudformation_json

    # patch ApiGateway Deployment deletion
    @staticmethod
    def depl_delete_from_cloudformation_json(resource_name, resource_json, region_name):
        properties = resource_json['Properties']
        LOG.info('TODO: apigateway.Deployment.delete_from_cloudformation_json %s' % properties)

    if not hasattr(apigw_models.Deployment, 'delete_from_cloudformation_json'):
        apigw_models.Deployment.delete_from_cloudformation_json = depl_delete_from_cloudformation_json

    # patch Lambda Version deletion
    @staticmethod
    def vers_delete_from_cloudformation_json(resource_name, resource_json, region_name):
        properties = resource_json['Properties']
        LOG.info('TODO: apigateway.Deployment.delete_from_cloudformation_json %s' % properties)

    if not hasattr(lambda_models.LambdaVersion, 'delete_from_cloudformation_json'):
        lambda_models.LambdaVersion.delete_from_cloudformation_json = vers_delete_from_cloudformation_json

    # add CloudFormation types
    @classmethod
    def RestAPI_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        name = props.get('Name') or short_uid()
        region_name = props.get('Region') or aws_stack.get_region()
        description = props.get('Description') or ''
        id = props.get('Id') or short_uid()
        return apigw_models.RestAPI(id, region_name, name, description)

    def RestAPI_get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Id':
            return self.id
        if attribute_name == 'Region':
            return self.region_name
        if attribute_name == 'Name':
            return self.name
        if attribute_name == 'Description':
            return self.description
        if attribute_name == 'RootResourceId':
            for id, resource in self.resources.items():
                if resource.parent_id is None:
                    return resource.id
            return None
        raise UnformattedGetAttTemplateException()

    @classmethod
    def Deployment_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        stage_name = props.get('StageName')
        deployment_id = props.get('Id') or short_uid()
        description = props.get('Description') or ''
        return apigw_models.Deployment(deployment_id, stage_name, description)

    @classmethod
    def Resource_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        region_name = props.get('Region') or aws_stack.get_region()
        path_part = props.get('PathPart')
        api_id = props.get('RestApiId')
        parent_id = props.get('ParentId')
        id = props.get('Id') or short_uid()
        return apigw_models.Resource(id, region_name, api_id, path_part, parent_id)

    @classmethod
    def Method_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        method_type = props.get('HttpMethod')
        authorization_type = props.get('AuthorizationType')
        return apigw_models.Method(method_type, authorization_type)

    apigw_models.RestAPI.create_from_cloudformation_json = RestAPI_create_from_cloudformation_json
    apigw_models.RestAPI.get_cfn_attribute = RestAPI_get_cfn_attribute
    apigw_models.Deployment.create_from_cloudformation_json = Deployment_create_from_cloudformation_json
    apigw_models.Resource.create_from_cloudformation_json = Resource_create_from_cloudformation_json
    apigw_models.Method.create_from_cloudformation_json = Method_create_from_cloudformation_json
    # TODO: add support for AWS::ApiGateway::Model, AWS::ApiGateway::RequestValidator, ...

    # fix AttributeError in moto's CloudFormation describe_stack_resource
    def describe_stack_resource(self):
        stack_name = self._get_param('StackName')
        stack = self.cloudformation_backend.get_stack(stack_name)
        logical_resource_id = self._get_param('LogicalResourceId')
        if not stack:
            msg = ('Unable to find CloudFormation stack "%s" in region %s' %
                   (stack_name, aws_stack.get_region()))
            if aws_stack.get_region() != self.region:
                msg = '%s/%s' % (msg, self.region)
            LOG.warning(msg)
            response = aws_responses.flask_error_response_json(msg, code=404, error_type='ResourceNotFoundException')
            return 404, response.headers, response.data

        for stack_resource in stack.stack_resources:
            # Note: Line below has been patched
            # if stack_resource.logical_resource_id == logical_resource_id:
            if stack_resource and stack_resource.logical_resource_id == logical_resource_id:
                resource = stack_resource
                break
        else:
            raise ValidationError(logical_resource_id)

        template = self.response_template(
            responses.DESCRIBE_STACK_RESOURCE_RESPONSE_TEMPLATE)
        return template.render(stack=stack, resource=resource)

    responses.CloudFormationResponse.describe_stack_resource = describe_stack_resource

    # fix moto's describe_stack_events jinja2.exceptions.UndefinedError
    def cf_describe_stack_events(self):
        stack_name = self._get_param('StackName')
        backend = self.cloudformation_backend
        stack = backend.get_stack(stack_name)
        if not stack:
            # Also return stack events for deleted stacks, specified by stack name
            stack = ([stk for id, stk in backend.deleted_stacks.items() if stk.name == stack_name] or [0])[0]
        if not stack:
            raise ValidationError(stack_name,
                message='Unable to find stack "%s" in region %s' % (stack_name, aws_stack.get_region()))
        template = self.response_template(responses.DESCRIBE_STACK_EVENTS_RESPONSE)
        return template.render(stack=stack)

    responses.CloudFormationResponse.describe_stack_events = cf_describe_stack_events

    # fix Lambda regions in moto - see https://github.com/localstack/localstack/issues/1961
    for region in boto3.session.Session().get_available_regions('lambda'):
        if region not in lambda_models.lambda_backends:
            lambda_models.lambda_backends[region] = lambda_models.LambdaBackend(region)

    def set_stack_status(stack, status):
        stack._add_stack_event(status)
        stack.status = status

    # patch FakeStack.initialize_resources
    def run_dependencies_deployment_loop(stack, action):

        def run_loop(*args):
            # NOTE: We're adding this additional loop, as it seems that in some cases moto
            #   does not consider resource dependencies (e.g., if a "DependsOn" resource property
            #   is defined). This loop allows us to incrementally resolve such dependencies.
            resource_map = stack.resource_map
            unresolved = {}
            for i in range(MAX_DEPENDENCY_DEPTH):
                LOG.debug('Running CloudFormation stack deployment loop iteration %s' % (i + 1))
                unresolved = getattr(resource_map, '_unresolved_resources', {})
                if not unresolved:
                    set_stack_status(stack, '%s_COMPLETE' % action)
                    return resource_map
                resource_map._unresolved_resources = {}
                for resource_id, resource_details in unresolved.items():
                    # Re-trigger the resource creation
                    parse_and_create_resource(*resource_details, force_create=True)
                if unresolved.keys() == resource_map._unresolved_resources.keys():
                    # looks like no more resources can be resolved -> bail
                    LOG.warning('Unresolvable dependencies, there may be undeployed stack resources: %s' % unresolved)
                    break
            set_stack_status(stack, '%s_FAILED' % action)
            raise Exception('Unable to resolve all CloudFormation resources after traversing ' +
                'dependency tree (maximum depth %s reached): %s' % (MAX_DEPENDENCY_DEPTH, list(unresolved.keys())))

        # NOTE: We're running the loop in the background, as it might take some time to complete
        FuncThread(run_loop).start()

    def initialize_resources(self):
        self.resource_map._template = self.resource_map._template or self.template_dict
        self.resource_map.load()
        self.resource_map.create(self.template_dict)
        self.output_map.create()
        run_dependencies_deployment_loop(self, 'CREATE')

    def update(self, *args, **kwargs):
        stack_update_orig(self, *args, **kwargs)
        run_dependencies_deployment_loop(self, 'UPDATE')

    FakeStack.initialize_resources = initialize_resources
    stack_update_orig = FakeStack.update
    FakeStack.update = update

    # patch Kinesis Stream get_cfn_attribute(..) method in moto
    def Kinesis_Stream_get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return self.arn

        raise UnformattedGetAttTemplateException()

    kinesis_models.Stream.get_cfn_attribute = Kinesis_Stream_get_cfn_attribute

    # patch cloudformation backend create_change_set(..)
    # #760 cloudformation deploy invalid xml error
    cloudformation_backend_create_change_set_orig = CloudFormationBackend.create_change_set

    def cloudformation_backend_create_change_set(
            self,
            stack_name,
            change_set_name,
            template,
            parameters,
            region_name,
            change_set_type,
            notification_arns=None,
            tags=None,
            role_arn=None):
        change_set_id, _ = cloudformation_backend_create_change_set_orig(
            self,
            stack_name,
            change_set_name,
            template,
            parameters,
            region_name,
            change_set_type,
            notification_arns,
            tags,
            role_arn
        )
        change_set = self.change_sets[change_set_id]
        change_set.status = 'CREATE_COMPLETE'

        return change_set_id, _

    CloudFormationBackend.create_change_set = cloudformation_backend_create_change_set

    # patch cloudformation backend change_set methods
    # #2240 - S3 bucket not created since 0.10.8
    # #2568 - Cloudformation create-stack for SNS with yaml causes TypeError
    cloudformation_backend_describe_change_set_orig = CloudFormationBackend.describe_change_set
    cloudformation_backend_execute_change_set_orig = CloudFormationBackend.execute_change_set

    def cloudformation_backend_describe_change_set(self, change_set_name, stack_name=None):
        change_set_name = change_set_name.replace(TEST_AWS_ACCOUNT_ID, MOTO_CFN_ACCOUNT_ID)
        return cloudformation_backend_describe_change_set_orig(self, change_set_name, stack_name)

    def cloudformation_backend_execute_change_set(self, change_set_name, stack_name=None):
        change_set_name = change_set_name.replace(TEST_AWS_ACCOUNT_ID, MOTO_CFN_ACCOUNT_ID)

        stack = self.change_sets.get(change_set_name)
        if not stack:
            for cs in self.change_sets:
                if self.change_sets[cs].change_set_name == change_set_name:
                    stack = self.change_sets[cs]

        def do_execute(*args):
            try:
                cloudformation_backend_execute_change_set_orig(self, change_set_name, stack_name)
                stack.output_map = stack._create_output_map()
                for export in stack.exports:
                    self.exports[export.name] = export
                set_stack_status(stack, 'CREATE_COMPLETE')
            except Exception:
                set_stack_status(stack, 'CREATE_FAILED')
                raise

        # start execution in background thread, to avoid timeouts/retries from the client
        set_stack_status(stack, 'CREATE_IN_PROGRESS')
        start_thread(do_execute)
        return True

    CloudFormationBackend.describe_change_set = cloudformation_backend_describe_change_set
    CloudFormationBackend.execute_change_set = cloudformation_backend_execute_change_set


def inject_stats_endpoint():
    """ Inject a simple /_stats endpoint into the moto server backend Web app. """
    # TODO: move this utility method to a shared file and enable it for all API endpoints
    from moto import server as moto_server

    def _get_stats():
        from pympler import muppy, summary
        all_objects = muppy.get_objects()
        result = summary.summarize(all_objects)
        result = result[0:20]
        summary = '\n'.join([line for line in summary.format_(result)])
        result = '%s\n\n%s' % (summary, json.dumps(result))
        return result, 200, {'content-type': 'text/plain'}

    def create_backend_app(service):
        backend_app = moto_server.create_backend_app_orig(service)
        backend_app.add_url_rule(
            '/_stats', endpoint='_get_stats', methods=['GET'], view_func=_get_stats, strict_slashes=False)
        return backend_app

    if not hasattr(moto_server, 'create_backend_app_orig'):
        moto_server.create_backend_app_orig = moto_server.create_backend_app
        moto_server.create_backend_app = create_backend_app


def start_up(*args):
    # patch moto implementation
    apply_patches()

    # add memory profiling endpoint
    inject_stats_endpoint()

    return moto_main(*args)


def main():
    setup_logging()

    # make sure all API names and ports are mapped properly
    canonicalize_api_names()

    # start API
    sys.exit(start_up())


if __name__ == '__main__':
    main()
