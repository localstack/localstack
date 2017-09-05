import json
import yaml
import logging
import traceback
from six import iteritems
from six import string_types
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.constants import DEFAULT_REGION

ACTION_CREATE = 'create'
PLACEHOLDER_RESOURCE_NAME = '__resource_name__'

# flag to indicate whether we are currently in the process of deployment
MARKER_DONT_REDEPLOY_STACK = 'markerToIndicateNotToRedeployStack'

LOGGER = logging.getLogger(__name__)

RESOURCE_TO_FUNCTION = {
    'S3::Bucket': {
        'create': {
            'boto_client': 'resource',
            'function': 'create_bucket',
            'parameters': {
                'Bucket': ['BucketName', PLACEHOLDER_RESOURCE_NAME],
                'ACL': 'AccessControl'
            }
        }
    },
    'SQS::Queue': {
        'create': {
            'boto_client': 'resource',
            'function': 'create_queue',
            'parameters': {
                'QueueName': 'QueueName'
            }
        }
    },
    'Logs::LogGroup': {
        # TODO implement
    },
    'Lambda::Function': {
        'create': {
            'boto_client': 'client',
            'function': 'create_function',
            'parameters': {
                'FunctionName': 'FunctionName',
                'Runtime': 'Runtime',
                'Role': 'Role',
                'Handler': 'Handler',
                'Code': 'Code',
                'Description': 'Description'
                # TODO add missing fields
            },
            'defaults': {
                'Role': 'test_role'
            }
        }
    },
    'Lambda::Version': {},
    'Lambda::Permission': {},
    'Lambda::EventSourceMapping': {
        'create': {
            'boto_client': 'client',
            'function': 'create_event_source_mapping',
            'parameters': {
                'FunctionName': 'FunctionName',
                'EventSourceArn': 'EventSourceArn',
                'StartingPosition': 'StartingPosition',
                'Enabled': 'Enabled',
                'BatchSize': 'BatchSize',
                'StartingPositionTimestamp': 'StartingPositionTimestamp'
            }
        }
    },
    'DynamoDB::Table': {
        'create': {
            'boto_client': 'client',
            'function': 'create_table',
            'parameters': {
                'TableName': 'TableName',
                'AttributeDefinitions': 'AttributeDefinitions',
                'KeySchema': 'KeySchema',
                'ProvisionedThroughput': 'ProvisionedThroughput',
                'LocalSecondaryIndexes': 'LocalSecondaryIndexes',
                'GlobalSecondaryIndexes': 'GlobalSecondaryIndexes',
                'StreamSpecification': 'StreamSpecification'
            },
            'defaults': {
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        }
    },
    'IAM::Role': {
        # TODO implement
    },
    'ApiGateway::RestApi': {
        'create': {
            'boto_client': 'client',
            'function': 'create_rest_api',
            'parameters': {
                'name': 'Name',
                'description': 'Description'
            }
        }
    },
    'ApiGateway::Resource': {
        'create': {
            'boto_client': 'client',
            'function': 'create_resource',
            'parameters': {
                'restApiId': 'RestApiId',
                'pathPart': 'PathPart',
                'parentId': 'ParentId'
            }
        }
    },
    'ApiGateway::Method': {
        'create': {
            'boto_client': 'client',
            'function': 'put_method',
            'parameters': {
                'restApiId': 'RestApiId',
                'resourceId': 'ResourceId',
                'httpMethod': 'HttpMethod',
                'authorizationType': 'AuthorizationType',
                'requestParameters': 'RequestParameters'
            }
        }
    },
    'ApiGateway::Method::Integration': {
    },
    'ApiGateway::Deployment': {
        'create': {
            'boto_client': 'client',
            'function': 'create_deployment',
            'parameters': {
                'restApiId': 'RestApiId',
                'stageName': 'StageName',
                'stageDescription': 'StageDescription',
                'description': 'Description'
            }
        }
    },
    'Kinesis::Stream': {
        'create': {
            'boto_client': 'client',
            'function': 'create_stream',
            'parameters': {
                'StreamName': 'Name',
                'ShardCount': 'ShardCount'
            },
            'defaults': {
                'ShardCount': 1
            }
        }
    }
}


def parse_template(template):
    try:
        return json.loads(template)
    except Exception:
        return yaml.load(template)


def template_to_json(template):
    template = parse_template(template)
    return json.dumps(template)


def get_resource_type(resource):
    return resource['Type'].split('::', 1)[1]


def get_service_name(resource):
    return resource['Type'].split('::')[1].lower()


def get_client(resource):
    resource_type = get_resource_type(resource)
    service = get_service_name(resource)
    resource_config = RESOURCE_TO_FUNCTION.get(resource_type)
    if resource_config is None:
        raise Exception('CloudFormation deployment for resource type %s not yet implemented' % resource_type)
    if ACTION_CREATE not in resource_config:
        # nothing to do for this resource
        return
    try:
        if resource_config[ACTION_CREATE].get('boto_client') == 'resource':
            return aws_stack.connect_to_resource(service)
        return aws_stack.connect_to_service(service)
    except Exception as e:
        LOGGER.warning('Unable to get client for "%s" API, skipping deployment: %s' % (service, e))
        return None


def describe_stack_resources(stack_name, logical_resource_id):
    client = aws_stack.connect_to_service('cloudformation')
    resources = client.describe_stack_resources(StackName=stack_name, LogicalResourceId=logical_resource_id)
    result = []
    for res in resources['StackResources']:
        if res.get('LogicalResourceId') == logical_resource_id:
            result.append(res)
    return result


def retrieve_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources[resource_id]
    resource_id = resource_status.get('PhysicalResourceId') or resource_id
    resource_type = resource_status['ResourceType']
    if not resource:
        resource = {}
    resource_props = resource.get('Properties')
    try:
        if resource_type == 'AWS::Lambda::Function':
            resource_id = resource_props['FunctionName'] if resource else resource_id
            return aws_stack.connect_to_service('lambda').get_function(FunctionName=resource_id)
        if resource_type == 'AWS::Lambda::EventSourceMapping':
            resource_id = resource_props['FunctionName'] if resource else resource_id
            source_arn = resource_props.get('EventSourceArn')
            resource_id = resolve_refs_recursively(stack_name, resource_id, resources)
            source_arn = resolve_refs_recursively(stack_name, source_arn, resources)
            if not resource_id or not source_arn:
                raise Exception('ResourceNotFound')
            mappings = aws_stack.connect_to_service('lambda').list_event_source_mappings(
                FunctionName=resource_id, EventSourceArn=source_arn)
            mapping = list(filter(lambda m:
                m['EventSourceArn'] == source_arn and m['FunctionArn'] == aws_stack.lambda_function_arn(resource_id),
                mappings['EventSourceMappings']))
            if not mapping:
                raise Exception('ResourceNotFound')
            return mapping[0]
        if resource_type == 'AWS::DynamoDB::Table':
            resource_id = resource_props['TableName'] if resource else resource_id
            return aws_stack.connect_to_service('dynamodb').describe_table(TableName=resource_id)
        if resource_type == 'AWS::ApiGateway::RestApi':
            apis = aws_stack.connect_to_service('apigateway').get_rest_apis()['items']
            resource_id = resource_props['Name'] if resource else resource_id
            result = list(filter(lambda api: api['name'] == resource_id, apis))
            return result[0] if result else None
        if resource_type == 'AWS::ApiGateway::Resource':
            api_id = resource_props['RestApiId'] if resource else resource_id
            api_id = resolve_refs_recursively(stack_name, api_id, resources)
            parent_id = resolve_refs_recursively(stack_name, resource_props['ParentId'], resources)
            if not api_id or not parent_id:
                return None
            api_resources = aws_stack.connect_to_service('apigateway').get_resources(restApiId=api_id)['items']
            target_resource = list(filter(lambda res:
                res.get('parentId') == parent_id and res['pathPart'] == resource_props['PathPart'], api_resources))
            if not target_resource:
                return None
            path = aws_stack.get_apigateway_path_for_resource(api_id,
                target_resource[0]['id'], resources=api_resources)
            result = list(filter(lambda res: res['path'] == path, api_resources))
            return result[0] if result else None
        if resource_type == 'AWS::ApiGateway::Deployment':
            api_id = resource_props['RestApiId'] if resource else resource_id
            api_id = resolve_refs_recursively(stack_name, api_id, resources)
            if not api_id:
                return None
            result = aws_stack.connect_to_service('apigateway').get_deployments(restApiId=api_id)['items']
            # TODO possibly filter results by stage name or other criteria
            return result[0] if result else None
        if resource_type == 'AWS::ApiGateway::Method':
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            if not api_id or not res_id:
                return None
            return aws_stack.connect_to_service('apigateway').get_method(restApiId=api_id,
                resourceId=res_id, httpMethod=resource_props['HttpMethod'])
        if resource_type == 'AWS::SQS::Queue':
            queues = aws_stack.connect_to_service('sqs').list_queues()
            result = list(filter(lambda item:
                # TODO possibly find a better way to compare resource_id with queue URLs
                item.endswith('/%s' % resource_id), queues['QueueUrls']))
            return result
        if resource_type == 'AWS::S3::Bucket':
            return aws_stack.connect_to_service('s3').get_bucket_location(Bucket=resource_id)
        if resource_type == 'AWS::Logs::LogGroup':
            # TODO implement
            raise Exception('ResourceNotFound')
        if resource_type == 'AWS::Kinesis::Stream':
            stream_name = resolve_refs_recursively(stack_name, resource_props['Name'], resources)
            result = aws_stack.connect_to_service('kinesis').describe_stream(StreamName=stream_name)
            return result
        if is_deployable_resource(resource):
            LOGGER.warning('Unexpected resource type %s when resolving references' % resource_type)
    except Exception as e:
        # we expect this to be a "not found" exception
        markers = ['NoSuchBucket', 'ResourceNotFound', '404']
        if not list(filter(lambda marker, e=e: marker in str(e), markers)):
            LOGGER.warning('Unexpected error retrieving details for resource %s: %s %s - %s %s' %
                (resource_type, e, traceback.format_exc(), resource, resource_status))
    return None


def extract_resource_attribute(resource_type, resource, attribute):
    LOGGER.debug('Extract resource attribute: %s %s' % (resource_type, attribute))
    # extract resource specific attributes
    if resource_type == 'Lambda::Function':
        actual_attribute = 'FunctionArn' if attribute == 'Arn' else attribute
        return resource['Configuration'][actual_attribute]
    elif resource_type == 'DynamoDB::Table':
        actual_attribute = 'LatestStreamArn' if attribute == 'StreamArn' else attribute
        value = resource['Table'].get(actual_attribute)
        return value
    elif resource_type == 'ApiGateway::RestApi':
        if attribute == 'PhysicalResourceId':
            return resource['id']
        if attribute == 'RootResourceId':
            resources = aws_stack.connect_to_service('apigateway').get_resources(restApiId=resource['id'])['items']
            for res in resources:
                if res['path'] == '/' and not res.get('parentId'):
                    return res['id']
    elif resource_type == 'ApiGateway::Resource':
        if attribute == 'PhysicalResourceId':
            return resource['id']
    return resource.get(attribute)


def resolve_ref(stack_name, ref, resources, attribute):
    LOGGER.debug('Resolving ref %s - %s' % (ref, attribute))
    if ref == 'AWS::Region':
        return DEFAULT_REGION
    resource_status = describe_stack_resources(stack_name, ref)[0]
    attr_value = resource_status.get(attribute)
    if attr_value not in [None, '']:
        return attr_value
    # fetch resource details
    resource = resources.get(ref)
    resource_new = retrieve_resource_details(ref, resource_status, resources, stack_name)
    if not resource_new:
        return
    resource_type = get_resource_type(resource)
    result = extract_resource_attribute(resource_type, resource_new, attribute)
    if not result:
        LOGGER.warning('Unable to extract reference attribute %s from resource: %s' % (attribute, resource_new))
    return result


def resolve_refs_recursively(stack_name, value, resources):
    if isinstance(value, dict):
        if len(value) == 1 and 'Ref' in value:
            return resolve_ref(stack_name, value['Ref'],
                resources, attribute='PhysicalResourceId')
        elif len(value) == 1 and 'Fn::GetAtt' in value:
            return resolve_ref(stack_name, value['Fn::GetAtt'][0],
                resources, attribute=value['Fn::GetAtt'][1])
        else:
            for key, val in iteritems(value):
                value[key] = resolve_refs_recursively(stack_name, val, resources)
        if len(value) == 1 and 'Fn::Join' in value:
            return value['Fn::Join'][0].join(value['Fn::Join'][1])
    if isinstance(value, list):
        for i in range(0, len(value)):
            value[i] = resolve_refs_recursively(stack_name, value[i], resources)
    return value


def set_status_deployed(resource_id, resource, stack_name):
    # TODO
    pass
    # client = aws_stack.connect_to_service('cloudformation')
    # template = {
    #     # TODO update deployment status
    #     MARKER_DONT_REDEPLOY_STACK: {}
    # }
    # TODO: instead of calling update_stack, introduce a backdoor API method to
    # update the deployment status of individual resources. The problem with
    # using the code below is that it sets the status to UPDATE_COMPLETE which may
    # be undesirable (if the stack has just been created we expect CREATE_COMPLETE).
    # client.update_stack(StackName=stack_name, TemplateBody=json.dumps(template), UsePreviousTemplate=True)


def deploy_resource(resource_id, resources, stack_name):
    resource = resources[resource_id]
    client = get_client(resource)
    if not client:
        return False
    resource_type = get_resource_type(resource)
    func_details = RESOURCE_TO_FUNCTION.get(resource_type)
    if not func_details:
        LOGGER.warning('Resource type not yet implemented: %s' % resource['Type'])
        return
    LOGGER.debug('Deploying resource type "%s" id "%s"' % (resource_type, resource_id))
    func_details = func_details[ACTION_CREATE]
    function = getattr(client, func_details['function'])
    params = dict(func_details['parameters'])
    defaults = func_details.get('defaults', {})
    if 'Properties' not in resource:
        resource['Properties'] = {}
    resource_props = resource['Properties']
    for param_key, prop_keys in iteritems(dict(params)):
        params.pop(param_key, None)
        if not isinstance(prop_keys, list):
            prop_keys = [prop_keys]
        for prop_key in prop_keys:
            if prop_key == PLACEHOLDER_RESOURCE_NAME:
                # obtain physical resource name from stack resources
                params[param_key] = resolve_ref(stack_name, resource_id, resources,
                    attribute='PhysicalResourceId')
            else:
                prop_value = resource_props.get(prop_key)
                if prop_value is not None:
                    params[param_key] = prop_value
            tmp_value = params.get(param_key)
            if tmp_value is not None:
                params[param_key] = resolve_refs_recursively(stack_name, tmp_value, resources)
                break
        # hack: convert to boolean
        if params.get(param_key) in ['True', 'False']:
            params[param_key] = params.get(param_key) == 'True'
    # assign default value if empty
    params = common.merge_recursive(defaults, params)
    # invoke function
    try:
        result = function(**params)
    except Exception as e:
        LOGGER.warning('Error calling %s with params: %s for resource: %s' % (function, params, resource))
        raise e
    # some resources have attached/nested resources which we need to create recursively now
    if resource_type == 'ApiGateway::Method':
        integration = resource_props.get('Integration')
        if integration:
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            uri = integration.get('Uri')
            if uri:
                uri = resolve_refs_recursively(stack_name, uri, resources)
                aws_stack.connect_to_service('apigateway').put_integration(restApiId=api_id, resourceId=res_id,
                    httpMethod=resource_props['HttpMethod'], type=integration['Type'],
                    integrationHttpMethod=integration['IntegrationHttpMethod'], uri=uri
                )
    # update status
    set_status_deployed(resource_id, resource, stack_name)
    return result


def deploy_template(template, stack_name):
    if isinstance(template, string_types):
        template = parse_template(template)

    if MARKER_DONT_REDEPLOY_STACK in template:
        # If we are currently deploying, then bail. This can occur if
        # deploy_template(..) method calls boto's update_stack(..) (to update the
        # state of resources) which itself triggers another call to deploy_template(..).
        # We don't want to end up in an infinite/recursive deployment loop.
        return

    resource_map = template.get('Resources')
    if not resource_map:
        LOGGER.warning('CloudFormation template contains no Resources section')
        return

    next = resource_map

    iters = 10
    for i in range(0, iters):

        # get resource details
        for resource_id, resource in iteritems(next):
            stack_resources = describe_stack_resources(stack_name, resource_id)
            resource['__details__'] = stack_resources[0]

        next = resources_to_deploy_next(resource_map, stack_name)
        if not next:
            return

        for resource_id, resource in iteritems(next):
            deploy_resource(resource_id, resource_map, stack_name=stack_name)

    LOGGER.warning('Unable to resolve all dependencies and deploy all resources ' +
        'after %s iterations. Remaining (%s): %s' % (iters, len(next), next))


# --------
# Util methods for analyzing resource dependencies
# --------

def is_deployable_resource(resource):
    resource_type = get_resource_type(resource)
    entry = RESOURCE_TO_FUNCTION.get(resource_type)
    if entry is None:
        LOGGER.warning('Unknown resource type "%s"' % resource_type)
    return entry and entry.get(ACTION_CREATE)


def is_deployed(resource_id, resources, stack_name):
    resource = resources[resource_id]
    resource_status = resource['__details__']
    details = retrieve_resource_details(resource_id, resource_status, resources, stack_name)
    return bool(details)


def all_dependencies_satisfied(resources, stack_name, all_resources, depending_resource=None):
    for resource_id, resource in iteritems(resources):
        if is_deployable_resource(resource):
            if not is_deployed(resource_id, all_resources, stack_name):
                return False
    return True


def resources_to_deploy_next(resources, stack_name):
    result = {}
    for resource_id, resource in iteritems(resources):
        if is_deployable_resource(resource) and not is_deployed(resource_id, resources, stack_name):
            res_deps = get_resource_dependencies(resource_id, resource, resources)
            if all_dependencies_satisfied(res_deps, stack_name, resources, resource_id):
                result[resource_id] = resource
    return result


def get_resource_dependencies(resource_id, resource, resources):
    result = {}
    dumped = json.dumps(common.json_safe(resource))
    for other_id, other in iteritems(resources):
        if resource != other:
            # TODO: traverse dict instead of doing string search
            search1 = '{"Ref": "%s"}' % other_id
            search2 = '{"Fn::GetAtt": ["%s", ' % other_id
            if search1 in dumped or search2 in dumped:
                result[other_id] = other
            if other_id in resource.get('DependsOn', []):
                result[other_id] = other
    return result
