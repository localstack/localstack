import sys
import logging
from moto.s3 import models as s3_models
from moto.core import BaseModel
from moto.server import main as moto_main
from moto.dynamodb import models as dynamodb_models
from moto.apigateway import models as apigw_models
from moto.cloudformation import parsing
from boto.cloudformation.stack import Output
from moto.cloudformation.exceptions import UnformattedGetAttTemplateException
from localstack.config import PORT_CLOUDFORMATION
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid
from localstack.constants import DEFAULT_PORT_CLOUDFORMATION_BACKEND, DEFAULT_REGION
from localstack.stepfunctions import models as sfn_models
from localstack.services.infra import (
    get_service_protocol, start_proxy_for_service, do_run, setup_logging)
from localstack.utils.cloudformation import template_deployer

LOG = logging.getLogger(__name__)


def start_cloudformation(port=PORT_CLOUDFORMATION, asynchronous=False, update_listener=None):
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
        value = s3_client.get_object(Bucket=bucket_name, Key=key_name)['Body'].read()
        return s3_models.FakeKey(name=key_name, value=value)

    s3_models.S3Backend.get_key = get_key

    # Patch clean_json in moto

    def clean_json(resource_json, resources_map):
        result = clean_json_orig(resource_json, resources_map)
        if isinstance(result, BaseModel):
            if isinstance(resource_json, dict) and 'Ref' in resource_json:
                if hasattr(result, 'id'):
                    return result.id
                if hasattr(result, 'name'):
                    # TODO: Check if this is the desired behavior. Better return ARN instead of ID?
                    return result.name
        return result

    clean_json_orig = parsing.clean_json
    parsing.clean_json = clean_json

    # Patch parse_and_create_resource method in moto to deploy resources in LocalStack

    def parse_and_create_resource(logical_id, resource_json, resources_map, region_name):
        # parse and get final resource JSON
        resource_tuple = parsing.parse_resource(logical_id, resource_json, resources_map)
        if not resource_tuple:
            return None
        _, resource_json, _ = resource_tuple

        # create resource definition and store CloudFormation metadata in moto
        resource = parse_and_create_resource_orig(logical_id, resource_json, resources_map, region_name)

        # check whether this resource needs to be deployed
        stack_name = resources_map.get('AWS::StackName')
        resource_wrapped = {logical_id: resource_json}
        should_be_deployed = template_deployer.should_be_deployed(logical_id, resource_wrapped, stack_name)
        if not should_be_deployed:
            LOG.debug('Resource %s need not be deployed: %s' % (logical_id, resource_json))
            return resource

        # deploy resource in LocalStack
        LOG.debug('Deploying CloudFormation resource: %s' % resource_json)
        result = template_deployer.deploy_resource(logical_id, resource_wrapped, stack_name=stack_name)
        props = resource_json.get('Properties') or {}

        # update id in created resource
        def find_id(result):
            for id_attr in ('Id', 'id', 'ResourceId', 'RestApiId', 'DeploymentId'):
                if id_attr in result:
                    return result[id_attr]

        def update_id(resource, new_id):
            # Update the ID of the given resource.
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

        if hasattr(resource, 'id') or (isinstance(resource, dict) and resource.get('id')):
            existing_id = resource.id if hasattr(resource, 'id') else resource['id']
            new_res_id = find_id(result)
            LOG.debug('Updating resource id: %s - %s, %s - %s' % (existing_id, new_res_id, resource, resource_json))
            if new_res_id:
                LOG.info('Updating resource ID from %s to %s' % (existing_id, new_res_id))
                update_id(resource, new_res_id)
            else:
                LOG.warning('Unable to extract id for resource %s: %s' % (logical_id, result))

        return resource

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

    # Patch DynamoDB get_cfn_attribute(..) method to fix a bug in moto

    def get_cfn_attribute(self, attribute_name):
        try:
            return get_cfn_attribute_orig(self, attribute_name)
        except Exception:
            if attribute_name == 'Arn':
                return aws_stack.dynamodb_table_arn(table_name=self.name)
            raise

    get_cfn_attribute_orig = dynamodb_models.Table.get_cfn_attribute
    dynamodb_models.Table.get_cfn_attribute = get_cfn_attribute

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


def main():
    setup_logging()

    # patch moto implementation
    apply_patches()

    # start API
    sys.exit(moto_main())


if __name__ == '__main__':
    main()
