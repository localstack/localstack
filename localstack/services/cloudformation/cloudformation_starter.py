import sys
import logging
from moto.s3 import models as s3_models
from moto.server import main as moto_main
from moto.dynamodb import models as dynamodb_models
from moto.cloudformation import parsing
from boto.cloudformation.stack import Output
from localstack.config import PORT_CLOUDFORMATION
from localstack.constants import DEFAULT_PORT_CLOUDFORMATION_BACKEND
from localstack.services.infra import get_service_protocol, start_proxy_for_service, do_run
from localstack.utils.aws import aws_stack
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

    # Patch parse_and_create_resource method in moto to deploy resources in LocalStack

    def parse_and_create_resource(logical_id, resource_json, resources_map, region_name):
        # parse and get final resource JSON
        resource_tuple = parsing.parse_resource(logical_id, resource_json, resources_map)
        if not resource_tuple:
            return None
        _, resource_json, _ = resource_tuple

        # create resource definition and store CloudFormation metadata in moto
        resource = parse_and_create_resource_orig(logical_id, resource_json, resources_map, region_name)

        # deploy resource in LocalStack
        stack_name = resources_map.get('AWS::StackName')
        resource_wrapped = {logical_id: resource_json}
        if template_deployer.should_be_deployed(logical_id, resource_wrapped, stack_name):
            LOG.debug('Deploying CloudFormation resource: %s' % resource_json)
            template_deployer.deploy_resource(logical_id, resource_wrapped, stack_name=stack_name)
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


def main():
    # patch moto implementation
    apply_patches()

    # start API
    sys.exit(moto_main())


if __name__ == '__main__':
    main()
