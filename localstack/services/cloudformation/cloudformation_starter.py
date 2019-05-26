import sys
import logging
from moto.s3 import models as s3_models
from moto.iam import models as iam_models
from moto.sqs import models as sqs_models
from moto.core import BaseModel
from moto.server import main as moto_main
from moto.dynamodb import models as dynamodb_models
from moto.awslambda import models as lambda_models
from moto.apigateway import models as apigw_models
from moto.cloudformation import parsing, responses
from boto.cloudformation.stack import Output
from moto.cloudformation.exceptions import ValidationError, UnformattedGetAttTemplateException
from localstack import config
from localstack.constants import DEFAULT_PORT_CLOUDFORMATION_BACKEND, DEFAULT_REGION
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.stepfunctions import models as sfn_models
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run, setup_logging, canonicalize_api_names)
from localstack.utils.cloudformation import template_deployer
from localstack.services.awslambda.lambda_api import BUCKET_MARKER_LOCAL

LOG = logging.getLogger(__name__)

# Maps (stack_name,resource_logical_id) -> Bool to indicate which resources are currently being updated
CURRENTLY_UPDATING_RESOURCES = {}


def start_cloudformation(port=None, asynchronous=False, update_listener=None):
    port = port or config.PORT_CLOUDFORMATION
    backend_port = DEFAULT_PORT_CLOUDFORMATION_BACKEND
    cmd = 'python "%s" cloudformation -p %s -H 0.0.0.0' % (__file__, backend_port)
    print('Starting mock CloudFormation (%s port %s)...' % (get_service_protocol(), port))
    start_proxy_for_service('dynamodb', port, backend_port, update_listener)
    env_vars = {'PYTHONPATH': ':'.join(sys.path)}
    return do_run(cmd, asynchronous, env_vars=env_vars)


def apply_patches():
    """ Apply patches to make LocalStack seamlessly interact with the moto backend.
        TODO: Eventually, these patches should be contributed to the upstream repo! """

    # Patch S3Backend.get_key method in moto to use S3 API from LocalStack

    def get_key(self, bucket_name, key_name, version_id=None):
        s3_client = aws_stack.connect_to_service('s3')
        value = b''
        if bucket_name != BUCKET_MARKER_LOCAL:
            value = s3_client.get_object(Bucket=bucket_name, Key=key_name)['Body'].read()
        return s3_models.FakeKey(name=key_name, value=value)

    s3_models.S3Backend.get_key = get_key

    # Patch clean_json in moto

    def clean_json(resource_json, resources_map):
        result = clean_json_orig(resource_json, resources_map)
        if isinstance(result, BaseModel):
            if isinstance(resource_json, dict) and 'Ref' in resource_json:
                types_with_ref_as_id_or_name = (apigw_models.RestAPI, apigw_models.Resource)
                attr_candidates = ['function_arn', 'id', 'name']
                for attr in attr_candidates:
                    if hasattr(result, attr):
                        if attr in ['id', 'name'] and not isinstance(result, types_with_ref_as_id_or_name):
                            LOG.warning('Unable to find ARN, using "%s" instead: %s - %s',
                                        attr, resource_json, result)
                        return getattr(result, attr)
                LOG.warning('Unable to resolve "Ref" attribute for: %s - %s - %s',
                            resource_json, result, type(result))
        return result

    clean_json_orig = parsing.clean_json
    parsing.clean_json = clean_json

    # Patch parse_and_create_resource method in moto to deploy resources in LocalStack

    def parse_and_create_resource(logical_id, resource_json, resources_map, region_name):
        try:
            return _parse_and_create_resource(logical_id, resource_json, resources_map, region_name)
        except Exception as e:
            LOG.error('Unable to parse and create resource "%s": %s' % (logical_id, e))
            raise

    def _parse_and_create_resource(logical_id, resource_json, resources_map, region_name):
        stack_name = resources_map.get('AWS::StackName')
        resource_hash_key = (stack_name, logical_id)

        # If the current stack is being updated, avoid infinite recursion
        updating = CURRENTLY_UPDATING_RESOURCES.get(resource_hash_key)
        LOG.debug('Currently updating stack resource %s/%s: %s' % (stack_name, logical_id, updating))
        if updating:
            return None

        # parse and get final resource JSON
        resource_tuple = parsing.parse_resource(logical_id, resource_json, resources_map)
        if not resource_tuple:
            return None
        _, resource_json, _ = resource_tuple

        # add some missing default props which otherwise cause deployments to fail
        props = resource_json['Properties'] = resource_json.get('Properties') or {}
        if resource_json['Type'] == 'AWS::Lambda::EventSourceMapping' and not props.get('StartingPosition'):
            props['StartingPosition'] = 'LATEST'

        # check if this resource already exists in the resource map
        resource = resources_map._parsed_resources.get(logical_id)

        # check whether this resource needs to be deployed
        resource_wrapped = {logical_id: resource_json}
        should_be_created = template_deployer.should_be_deployed(logical_id, resource_wrapped, stack_name)
        if not should_be_created:
            # This resource is either not deployable or already exists. Check if it can be updated
            if not template_deployer.is_updateable(logical_id, resource_wrapped, stack_name):
                LOG.debug('Resource %s need not be deployed: %s' % (logical_id, resource_json))
                if resource:
                    return resource

        if not resource:
            # create resource definition and store CloudFormation metadata in moto
            resource = parse_and_create_resource_orig(logical_id, resource_json, resources_map, region_name)

        # Apply some fixes/patches to the resource names, then deploy resource in LocalStack
        update_resource_name(resource, resource_json)
        LOG.debug('Deploying CloudFormation resource: %s' % resource_json)

        try:
            CURRENTLY_UPDATING_RESOURCES[resource_hash_key] = True
            deploy_func = template_deployer.deploy_resource if should_be_created else template_deployer.update_resource
            result = deploy_func(logical_id, resource_wrapped, stack_name=stack_name)
        finally:
            CURRENTLY_UPDATING_RESOURCES[resource_hash_key] = False

        if not should_be_created:
            # skip the parts below for update requests
            return resource

        def find_id(resource):
            """ Find ID of the given resource. """
            for id_attr in ('Id', 'id', 'ResourceId', 'RestApiId', 'DeploymentId'):
                if id_attr in resource:
                    return resource[id_attr]

        # update resource IDs to avoid mismatch between CF moto and LocalStack backend resources
        if hasattr(resource, 'id') or (isinstance(resource, dict) and resource.get('id')):
            existing_id = resource.id if hasattr(resource, 'id') else resource['id']
            new_res_id = find_id(result)
            LOG.debug('Updating resource id: %s - %s, %s - %s' % (existing_id, new_res_id, resource, resource_json))
            if new_res_id:
                LOG.info('Updating resource ID from %s to %s' % (existing_id, new_res_id))
                update_resource_id(resource, new_res_id, props, region_name)
            else:
                LOG.warning('Unable to extract id for resource %s: %s' % (logical_id, result))

        # update physical_resource_id field
        update_physical_resource_id(resource)

        return resource

    def update_resource_name(resource, resource_json):
        """ Some resources require minor fixes in their CF resource definition
            before we can pass them on to deployment. """
        props = resource_json['Properties'] = resource_json.get('Properties') or {}
        if isinstance(resource, sfn_models.StateMachine) and not props.get('StateMachineName'):
            props['StateMachineName'] = resource.name

    def update_resource_id(resource, new_id, props, region_name):
        """ Update and fix the ID(s) of the given resource. """

        # NOTE: this is a bit of a hack, which is required because
        # of the order of events when CloudFormation resources are created.
        # When we process a request to create a CF resource that's part of a
        # stack, say, an API Gateway Resource, then we (1) create the object
        # in memory in moto, which generates a random ID for the resource, and
        # (2) create the actual resource in the backend service using
        # template_deployer.deploy_resource(..) (see above).
        # The resource created in (2) now has a different ID than the resource
        # created in (1), which leads to downstream problems. Hence, we need
        # the logic below to reconcile the ids, i.e., apply IDs from (2) to (1).

        backend = apigw_models.apigateway_backends[region_name]
        if isinstance(resource, apigw_models.RestAPI):
            backend.apis.pop(resource.id, None)
            backend.apis[new_id] = resource
            # We also need to fetch the resources to replace the root resource
            # that moto automatically adds to newly created RestAPI objects
            client = aws_stack.connect_to_service('apigateway')
            resources = client.get_resources(restApiId=new_id, limit=500)['items']
            # make sure no resources have been added in addition to the root /
            assert len(resource.resources) == 1
            resource.resources = {}
            for res in resources:
                res_path_part = res.get('pathPart') or res.get('path')
                child = resource.add_child(res_path_part, res.get('parentId'))
                resource.resources.pop(child.id)
                child.id = res['id']
                child.api_id = new_id
                resource.resources[child.id] = child
            resource.id = new_id
        elif isinstance(resource, apigw_models.Resource):
            api_id = props['RestApiId']
            backend.apis[api_id].resources.pop(resource.id, None)
            backend.apis[api_id].resources[new_id] = resource
            resource.id = new_id
        elif isinstance(resource, apigw_models.Deployment):
            api_id = props['RestApiId']
            backend.apis[api_id].deployments.pop(resource['id'], None)
            backend.apis[api_id].deployments[new_id] = resource
            resource['id'] = new_id
        else:
            LOG.warning('Unexpected resource type when updating ID: %s' % type(resource))

    def update_physical_resource_id(resource):
        phys_res_id = getattr(resource, 'physical_resource_id') if hasattr(resource, 'physical_resource_id') else None
        if not phys_res_id:
            if isinstance(resource, lambda_models.LambdaFunction):
                func_arn = aws_stack.lambda_function_arn(resource.function_name)
                resource.function_arn = resource.physical_resource_id = func_arn
            elif isinstance(resource, sfn_models.StateMachine):
                sm_arn = aws_stack.state_machine_arn(resource.name)
                resource.physical_resource_id = sm_arn
            else:
                LOG.warning('Unable to determine physical_resource_id for resource %s' % type(resource))

    parse_and_create_resource_orig = parsing.parse_and_create_resource
    parsing.parse_and_create_resource = parse_and_create_resource

    # Patch CloudFormation parse_output(..) method to fix a bug in moto

    def parse_output(output_logical_id, output_json, resources_map):
        try:
            return parse_output_orig(output_logical_id, output_json, resources_map)
        except KeyError:
            output = Output()
            output.key = output_logical_id
            output.value = None
            output.description = output_json.get('Description')
            return output

    parse_output_orig = parsing.parse_output
    parsing.parse_output = parse_output

    # Patch DynamoDB get_cfn_attribute(..) method in moto

    def DynamoDB_Table_get_cfn_attribute(self, attribute_name):
        try:
            return DynamoDB_Table_get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name == 'Arn':
                return aws_stack.dynamodb_table_arn(table_name=self.name)
            raise

    DynamoDB_Table_get_cfn_attribute_orig = dynamodb_models.Table.get_cfn_attribute
    dynamodb_models.Table.get_cfn_attribute = DynamoDB_Table_get_cfn_attribute

    # Patch SQS get_cfn_attribute(..) method in moto

    def SQS_Queue_get_cfn_attribute(self, attribute_name):
        if attribute_name == 'Arn':
            return aws_stack.sqs_queue_arn(queue_name=self.name)
        return SQS_Queue_get_cfn_attribute_orig(self, attribute_name)

    SQS_Queue_get_cfn_attribute_orig = sqs_models.Queue.get_cfn_attribute
    sqs_models.Queue.get_cfn_attribute = SQS_Queue_get_cfn_attribute

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

    # Patch LambdaFunction create_from_cloudformation_json(..) method in moto

    @classmethod
    def Lambda_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        resource_name = cloudformation_json.get('Properties', {}).get('FunctionName') or resource_name
        return Lambda_create_from_cloudformation_json_orig(resource_name, cloudformation_json, region_name)

    Lambda_create_from_cloudformation_json_orig = lambda_models.LambdaFunction.create_from_cloudformation_json
    lambda_models.LambdaFunction.create_from_cloudformation_json = Lambda_create_from_cloudformation_json

    # add CloudWatch types

    parsing.MODEL_MAP['AWS::ApiGateway::Deployment'] = apigw_models.Deployment
    parsing.MODEL_MAP['AWS::ApiGateway::Method'] = apigw_models.Method
    parsing.MODEL_MAP['AWS::ApiGateway::Resource'] = apigw_models.Resource
    parsing.MODEL_MAP['AWS::ApiGateway::RestApi'] = apigw_models.RestAPI
    parsing.MODEL_MAP['AWS::StepFunctions::StateMachine'] = sfn_models.StateMachine

    @classmethod
    def RestAPI_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        name = props['Name']
        region_name = props.get('Region') or DEFAULT_REGION
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
        name = props['StageName']
        deployment_id = props.get('Id') or short_uid()
        description = props.get('Description') or ''
        return apigw_models.Deployment(deployment_id, name, description)

    @classmethod
    def Resource_create_from_cloudformation_json(cls, resource_name, cloudformation_json, region_name):
        props = cloudformation_json['Properties']
        region_name = props.get('Region') or DEFAULT_REGION
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


def inject_stats_endpoint():
    """ Inject a simple /_stats endpoint into the moto server backend Web app. """
    # TODO: move this utility method to a shared file and enable it for all API endpoints
    import json
    from moto import server as moto_server

    def _get_stats():
        from pympler import muppy, summary
        all_objects = muppy.get_objects()
        result = summary.summarize(all_objects)
        result = result[0:20]
        summary = '\n'.join([l for l in summary.format_(result)])
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


def main():
    setup_logging()

    # patch moto implementation
    apply_patches()

    # add memory profiling endpoint
    inject_stats_endpoint()

    # make sure all API names and ports are mapped properly
    canonicalize_api_names()

    # start API
    sys.exit(moto_main())


if __name__ == '__main__':
    main()
