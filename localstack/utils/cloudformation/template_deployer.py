import re
import json
import yaml
import logging
import traceback
from six import iteritems
from six import string_types
from localstack.utils import common
from localstack.utils.aws import aws_stack

ACTION_CREATE = 'create'
PLACEHOLDER_RESOURCE_NAME = '__resource_name__'

LOG = logging.getLogger(__name__)

# list of resource types that can be updated
UPDATEABLE_RESOURCES = ['Lambda::Function', 'ApiGateway::Method']


def str_or_none(o):
    return o if o is None else json.dumps(o) if isinstance(o, (dict, list)) else str(o)


def select_attributes(obj, attrs):
    result = {}
    for attr in attrs:
        if obj.get(attr) is not None:
            result[attr] = str_or_none(obj.get(attr))
    return result


def get_bucket_location_config(**kwargs):
    return {'LocationConstraint': aws_stack.get_region()}


# maps resource types to functions and parameters for creation
RESOURCE_TO_FUNCTION = {
    'S3::Bucket': {
        'create': {
            'function': 'create_bucket',
            'parameters': {
                'Bucket': ['BucketName', PLACEHOLDER_RESOURCE_NAME],
                'ACL': lambda params, **kwargs: convert_acl_cf_to_s3(params.get('AccessControl', 'PublicRead')),
                'CreateBucketConfiguration': lambda params, **kwargs: get_bucket_location_config()
            }
        }
    },
    'SQS::Queue': {
        'create': {
            'function': 'create_queue',
            'parameters': {
                'QueueName': ['QueueName', PLACEHOLDER_RESOURCE_NAME],
                'Attributes': lambda params, **kwargs: select_attributes(params,
                    ['DelaySeconds', 'MaximumMessageSize', 'MessageRetentionPeriod',
                     'VisibilityTimeout', 'RedrivePolicy']
                ),
                'tags': 'Tags'
            }
        }
    },
    'SNS::Topic': {
        'create': {
            'function': 'create_topic',
            'parameters': {
                'Name': 'TopicName',
                'Tags': 'Tags'
            }
        }
    },
    'Logs::LogGroup': {
        # TODO implement
    },
    'Lambda::Function': {
        'create': {
            'function': 'create_function',
            'parameters': {
                'FunctionName': 'FunctionName',
                'Runtime': 'Runtime',
                'Role': 'Role',
                'Handler': 'Handler',
                'Code': 'Code',
                'Description': 'Description',
                'Environment': 'Environment',
                'Timeout': 'Timeout',
                'MemorySize': 'MemorySize',
                # TODO add missing fields
            },
            'defaults': {
                'Role': 'test_role'
            }
        }
    },
    'Lambda::Version': {
        'create': {
            'function': 'publish_version',
            'parameters': {
                # TODO
            }
        }
    },
    'Lambda::Permission': {},
    'Lambda::EventSourceMapping': {
        'create': {
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
            'function': 'create_table',
            'parameters': {
                'TableName': 'TableName',
                'AttributeDefinitions': 'AttributeDefinitions',
                'KeySchema': 'KeySchema',
                'ProvisionedThroughput': 'ProvisionedThroughput',
                'LocalSecondaryIndexes': 'LocalSecondaryIndexes',
                'GlobalSecondaryIndexes': 'GlobalSecondaryIndexes',
                'StreamSpecification': lambda params, **kwargs: (
                    common.merge_dicts(params.get('StreamSpecification'), {'StreamEnabled': True}, default=None))
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
            'function': 'create_rest_api',
            'parameters': {
                'name': 'Name',
                'description': 'Description'
            }
        }
    },
    'ApiGateway::Resource': {
        'create': {
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
            'function': 'create_stream',
            'parameters': {
                'StreamName': 'Name',
                'ShardCount': 'ShardCount'
            },
            'defaults': {
                'ShardCount': 1
            }
        }
    },
    'StepFunctions::StateMachine': {
        'create': {
            'function': 'create_state_machine',
            'parameters': {
                'name': ['StateMachineName', PLACEHOLDER_RESOURCE_NAME],
                'definition': 'DefinitionString',
                'roleArn': lambda params, **kwargs: get_role_arn(params.get('RoleArn'), **kwargs)
            }
        }
    },
    'StepFunctions::Activity': {
        'create': {
            'function': 'create_activity',
            'parameters': {
                'name': ['Name', PLACEHOLDER_RESOURCE_NAME],
                'tags': 'Tags'
            }
        }
    }
}


# ----------------
# UTILITY METHODS
# ----------------

def convert_acl_cf_to_s3(acl):
    """ Convert a CloudFormation ACL string (e.g., 'PublicRead') to an S3 ACL string (e.g., 'public-read') """
    return re.sub('(?<!^)(?=[A-Z])', '-', acl).lower()


def retrieve_topic_arn(topic_name):
    topics = aws_stack.connect_to_service('sns').list_topics()['Topics']
    topic_arns = [t['TopicArn'] for t in topics if t['TopicArn'].endswith(':%s' % topic_name)]
    return topic_arns[0]


def get_role_arn(role_arn, **kwargs):
    role_arn = resolve_refs_recursively(kwargs.get('stack_name'), role_arn, kwargs.get('resources'))
    return aws_stack.role_arn(role_arn)


# ---------------------
# CF TEMPLATE HANDLING
# ---------------------

def parse_template(template):
    try:
        return json.loads(template)
    except Exception:
        return yaml.safe_load(template)


def template_to_json(template):
    template = parse_template(template)
    return json.dumps(template)


def get_resource_type(resource):
    res_type = resource.get('ResourceType') or resource.get('Type') or ''
    parts = res_type.split('::', 1)
    if len(parts) == 1:
        return None
    return parts[1]


def get_service_name(resource):
    res_type = resource.get('Type', '')
    parts = res_type.split('::')
    if len(parts) == 1:
        return None
    if res_type.endswith('Cognito::UserPool'):
        return 'cognito-idp'
    if parts[-2] == 'Cognito':
        # TODO add mappings for "cognito-identity"
        return 'cognito-idp'
    return parts[1].lower()


def get_resource_name(resource):
    res_type = get_resource_type(resource)
    properties = resource.get('Properties') or {}
    name = properties.get('Name')
    if name:
        return name

    # try to extract name from attributes
    if res_type == 'S3::Bucket':
        name = properties.get('BucketName')
    elif res_type == 'SQS::Queue':
        name = properties.get('QueueName')
    elif res_type == 'Cognito::UserPool':
        name = properties.get('PoolName')
    else:
        LOG.warning('Unable to extract name for resource type "%s"' % res_type)

    return name


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
        LOG.warning('Unable to get client for "%s" API, skipping deployment: %s' % (service, e))
        return None


def describe_stack_resource(stack_name, logical_resource_id):
    client = aws_stack.connect_to_service('cloudformation')
    result = client.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_resource_id)
    return result['StackResourceDetail']


def retrieve_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources.get(resource_id)
    resource_id = resource_status.get('PhysicalResourceId') or resource_id
    if not resource:
        resource = {}
    resource_type = get_resource_type(resource)
    resource_props = resource.get('Properties')
    try:
        if resource_type == 'Lambda::Function':
            resource_id = resource_props['FunctionName'] if resource else resource_id
            return aws_stack.connect_to_service('lambda').get_function(FunctionName=resource_id)
        elif resource_type == 'Lambda::Version':
            name = resource_props['FunctionName']
            func_name = aws_stack.lambda_function_name(name)
            func_version = name.split(':')[7] if len(name.split(':')) > 7 else '$LATEST'
            versions = aws_stack.connect_to_service('lambda').list_versions_by_function(FunctionName=func_name)
            return ([v for v in versions['Versions'] if v['Version'] == func_version] or [None])[0]
        elif resource_type == 'Lambda::EventSourceMapping':
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
        elif resource_type == 'DynamoDB::Table':
            resource_id = resource_props['TableName'] if resource else resource_id
            return aws_stack.connect_to_service('dynamodb').describe_table(TableName=resource_id)
        elif resource_type == 'ApiGateway::RestApi':
            apis = aws_stack.connect_to_service('apigateway').get_rest_apis()['items']
            resource_id = resource_props['Name'] if resource else resource_id
            result = list(filter(lambda api: api['name'] == resource_id, apis))
            return result[0] if result else None
        elif resource_type == 'ApiGateway::Resource':
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
        elif resource_type == 'ApiGateway::Deployment':
            api_id = resource_props['RestApiId'] if resource else resource_id
            api_id = resolve_refs_recursively(stack_name, api_id, resources)
            if not api_id:
                return None
            result = aws_stack.connect_to_service('apigateway').get_deployments(restApiId=api_id)['items']
            # TODO possibly filter results by stage name or other criteria
            return result[0] if result else None
        elif resource_type == 'ApiGateway::Method':
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            if not api_id or not res_id:
                return None
            res_obj = aws_stack.connect_to_service('apigateway').get_resource(restApiId=api_id, resourceId=res_id)
            match = [v for (k, v) in res_obj['resourceMethods'].items()
                     if resource_props['HttpMethod'] in (v.get('httpMethod'), k)]
            return match or None
        elif resource_type == 'SQS::Queue':
            sqs_client = aws_stack.connect_to_service('sqs')
            queues = sqs_client.list_queues()
            result = list(filter(lambda item:
                # TODO possibly find a better way to compare resource_id with queue URLs
                item.endswith('/%s' % resource_id), queues.get('QueueUrls', [])))
            if not result:
                return None
            result = sqs_client.get_queue_attributes(QueueUrl=result[0], AttributeNames=['All'])['Attributes']
            result['Arn'] = result['QueueArn']
            return result
        elif resource_type == 'SNS::Topic':
            topics = aws_stack.connect_to_service('sns').list_topics()
            result = list(filter(lambda item: item['TopicArn'] == resource_id, topics.get('Topics', [])))
            return result[0] if result else None
        elif resource_type == 'S3::Bucket':
            bucket_name = resource_props.get('BucketName') or resource_id
            return aws_stack.connect_to_service('s3').get_bucket_location(Bucket=bucket_name)
        elif resource_type == 'Logs::LogGroup':
            # TODO implement
            raise Exception('ResourceNotFound')
        elif resource_type == 'Kinesis::Stream':
            stream_name = resolve_refs_recursively(stack_name, resource_props['Name'], resources)
            result = aws_stack.connect_to_service('kinesis').describe_stream(StreamName=stream_name)
            return result
        elif resource_type == 'StepFunctions::StateMachine':
            sm_name = resource_props.get('StateMachineName') or resource_id
            sm_name = resolve_refs_recursively(stack_name, sm_name, resources)
            sfn_client = aws_stack.connect_to_service('stepfunctions')
            state_machines = sfn_client.list_state_machines()['stateMachines']
            sm_arn = [m['stateMachineArn'] for m in state_machines if m['name'] == sm_name]
            if not sm_arn:
                return None
            result = sfn_client.describe_state_machine(stateMachineArn=sm_arn[0])
            return result
        elif resource_type == 'StepFunctions::Activity':
            act_name = resource_props.get('Name') or resource_id
            act_name = resolve_refs_recursively(stack_name, act_name, resources)
            sfn_client = aws_stack.connect_to_service('stepfunctions')
            activities = sfn_client.list_activities()['activities']
            result = [a['activityArn'] for a in activities if a['name'] == act_name]
            if not result:
                return None
            return result[0]
        if is_deployable_resource(resource):
            LOG.warning('Unexpected resource type %s when resolving references of resource %s: %s' %
                        (resource_type, resource_id, resource))
    except Exception as e:
        check_not_found_exception(e, resource_type, resource, resource_status)
    return None


def check_not_found_exception(e, resource_type, resource, resource_status):
    # we expect this to be a "not found" exception
    markers = ['NoSuchBucket', 'ResourceNotFound', '404']
    if not list(filter(lambda marker, e=e: marker in str(e), markers)):
        LOG.warning('Unexpected error retrieving details for resource %s: %s %s - %s %s' %
            (resource_type, e, traceback.format_exc(), resource, resource_status))


def extract_resource_attribute(resource_type, resource, attribute):
    LOG.debug('Extract resource attribute: %s %s' % (resource_type, attribute))
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
    if ref == 'AWS::Region':
        return aws_stack.get_region()
    resource_status = {}
    if stack_name:
        resource_status = describe_stack_resource(stack_name, ref)
        attr_value = resource_status.get(attribute)
        if attr_value not in [None, '']:
            return attr_value
    elif ref in resources:
        resource_status = resources[ref]['__details__']
    # fetch resource details
    resource = resources.get(ref)
    resource_new = retrieve_resource_details(ref, resource_status, resources, stack_name)
    if not resource_new:
        return
    resource_type = get_resource_type(resource)
    result = extract_resource_attribute(resource_type, resource_new, attribute)
    if not result:
        LOG.warning('Unable to extract reference attribute %s from resource: %s' % (attribute, resource_new))
    return result


def resolve_refs_recursively(stack_name, value, resources):
    if isinstance(value, dict):
        if len(value) == 1 and 'Ref' in value:
            result = resolve_ref(stack_name, value['Ref'],
                resources, attribute='PhysicalResourceId')
            return result
        elif len(value) == 1 and 'Fn::GetAtt' in value:
            return resolve_ref(stack_name, value['Fn::GetAtt'][0],
                resources, attribute=value['Fn::GetAtt'][1])
        else:
            for key, val in iteritems(value):
                value[key] = resolve_refs_recursively(stack_name, val, resources)
        # process special operators
        if len(value) == 1 and 'Fn::Join' in value:
            return value['Fn::Join'][0].join(value['Fn::Join'][1])
        if len(value) == 1 and 'Fn::Sub' in value:
            result = value['Fn::Sub'][0]
            for key, val in value['Fn::Sub'][1].items():
                val = resolve_refs_recursively(stack_name, val, resources)
                result = result.replace('${%s}' % key, val)
            return result
    if isinstance(value, list):
        for i in range(0, len(value)):
            value[i] = resolve_refs_recursively(stack_name, value[i], resources)
    return value


def update_resource(resource_id, resources, stack_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    if resource_type not in UPDATEABLE_RESOURCES:
        LOG.warning('Unable to update resource type "%s", id "%s"' % (resource_type, resource_id))
        return
    props = resource['Properties']
    if resource_type == 'Lambda::Function':
        client = aws_stack.connect_to_service('lambda')
        keys = ('FunctionName', 'Role', 'Handler', 'Description', 'Timeout', 'MemorySize', 'Environment', 'Runtime')
        update_props = dict([(k, props[k]) for k in keys if k in props])
        return client.update_function_configuration(**update_props)
    if resource_type == 'ApiGateway::Method':
        client = aws_stack.connect_to_service('apigateway')
        integration = props.get('Integration')
        # TODO use RESOURCE_TO_FUNCTION mechanism for updates, instead of hardcoding here
        kwargs = {
            'restApiId': props['RestApiId'],
            'resourceId': props['ResourceId'],
            'httpMethod': props['HttpMethod'],
            'requestParameters': props.get('RequestParameters')
        }
        if integration:
            kwargs['type'] = integration['Type']
            kwargs['integrationHttpMethod'] = integration.get('IntegrationHttpMethod')
            kwargs['uri'] = integration.get('Uri')
            return client.put_integration(**kwargs)
        kwargs['authorizationType'] = props.get('AuthorizationType')
        return client.put_method(**kwargs)


def convert_data_types(func_details, params):
    """ Convert data types in the "params" object, with the type defs
        specified in the 'types' attribute of "func_details". """
    types = func_details.get('types') or {}
    attr_names = types.keys() or []

    def cast(_obj, _type):
        if _type == bool:
            return _obj in ['True', 'true', True]
        if _type == str:
            return str(_obj)
        if _type == int:
            return int(_obj)
        return _obj

    def fix_types(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in attr_names:
                    o[k] = cast(v, types[k])
        return o
    result = common.recurse_object(params, fix_types)
    return result


def deploy_resource(resource_id, resources, stack_name):
    resource = resources[resource_id]
    client = get_client(resource)
    if not client:
        return False
    resource_type = get_resource_type(resource)
    func_details = RESOURCE_TO_FUNCTION.get(resource_type)
    if not func_details:
        LOG.warning('Resource type not yet implemented: %s' % resource_type)
        return

    LOG.debug('Deploying resource type "%s" id "%s"' % (resource_type, resource_id))
    func_details = func_details[ACTION_CREATE]
    function = getattr(client, func_details['function'])
    params = func_details['parameters']
    defaults = func_details.get('defaults', {})
    if 'Properties' not in resource:
        resource['Properties'] = {}
    resource_props = resource['Properties']

    if callable(params):
        params = params(resource_props, stack_name=stack_name, resources=resources)
    else:
        params = dict(params)
        for param_key, prop_keys in dict(params).items():
            params.pop(param_key, None)
            if not isinstance(prop_keys, list):
                prop_keys = [prop_keys]
            for prop_key in prop_keys:
                if prop_key == PLACEHOLDER_RESOURCE_NAME:
                    params[param_key] = resource_id
                    resource_name = get_resource_name(resource)
                    if resource_name:
                        params[param_key] = resource_name
                    else:
                        # try to obtain physical resource name from stack resources
                        try:
                            return resolve_ref(stack_name, resource_id, resources,
                                attribute='PhysicalResourceId')
                        except Exception as e:
                            LOG.debug('Unable to extract physical id for resource %s: %s' % (resource_id, e))

                else:
                    if callable(prop_key):
                        prop_value = prop_key(resource_props, stack_name=stack_name, resources=resources)
                    else:
                        prop_value = resource_props.get(prop_key)
                    if prop_value is not None:
                        params[param_key] = prop_value

    # convert refs and boolean strings
    for param_key, prop_keys in dict(params).items():
        tmp_value = params.get(param_key)
        if tmp_value is not None:
            params[param_key] = resolve_refs_recursively(stack_name, tmp_value, resources)
        # Convert to boolean (TODO: do this recursively?)
        if str(tmp_value).lower() in ['true', 'false']:
            params[param_key] = str(tmp_value).lower() == 'true'

    # assign default value if empty
    params = common.merge_recursive(defaults, params)
    # convert data types (e.g., boolean strings to bool)
    params = convert_data_types(func_details, params)

    # invoke function
    try:
        LOG.debug('Request for creating resource type "%s": %s %s' % (
            resource_type, func_details['function'], params))
        result = function(**params)
    except Exception as e:
        LOG.warning('Error calling %s with params: %s for resource: %s' % (function, params, resource))
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
    elif resource_type == 'SNS::Topic':
        subscriptions = resource_props.get('Subscription', [])
        for subscription in subscriptions:
            endpoint = resolve_refs_recursively(stack_name, subscription['Endpoint'], resources)
            topic_arn = retrieve_topic_arn(params['Name'])
            aws_stack.connect_to_service('sns').subscribe(
                TopicArn=topic_arn, Protocol=subscription['Protocol'], Endpoint=endpoint)
    elif resource_type == 'S3::Bucket':
        tags = resource_props.get('Tags')
        if tags:
            aws_stack.connect_to_service('s3').put_bucket_tagging(
                Bucket=params['Bucket'], Tagging={'TagSet': tags})

    return result


def deploy_template(template, stack_name):
    if isinstance(template, string_types):
        template = parse_template(template)

    resource_map = template.get('Resources')
    if not resource_map:
        LOG.warning('CloudFormation template contains no Resources section')
        return

    next = resource_map

    iters = 10
    for i in range(0, iters):

        # get resource details
        for resource_id, resource in next.items():
            stack_resource = describe_stack_resource(stack_name, resource_id)
            resource['__details__'] = stack_resource

        next = resources_to_deploy_next(resource_map, stack_name)
        if not next:
            return

        for resource_id, resource in next.items():
            deploy_resource(resource_id, resource_map, stack_name=stack_name)

    LOG.warning('Unable to resolve all dependencies and deploy all resources ' +
        'after %s iterations. Remaining (%s): %s' % (iters, len(next), next))


# --------
# Util methods for analyzing resource dependencies
# --------

def is_deployable_resource(resource):
    resource_type = get_resource_type(resource)
    entry = RESOURCE_TO_FUNCTION.get(resource_type)
    if entry is None:
        LOG.warning('Unknown resource type "%s": %s' % (resource_type, resource))
    return bool(entry and entry.get(ACTION_CREATE))


def is_deployed(resource_id, resources, stack_name):
    resource = resources[resource_id]
    resource_status = resource.get('__details__') or {}
    details = retrieve_resource_details(resource_id, resource_status, resources, stack_name)
    return bool(details)


def should_be_deployed(resource_id, resources, stack_name):
    """ Return whether the given resource is all of: (1) deployable, (2) not yet deployed,
        and (3) has no unresolved dependencies. """
    resource = resources[resource_id]
    if not is_deployable_resource(resource) or is_deployed(resource_id, resources, stack_name):
        return False
    res_deps = get_resource_dependencies(resource_id, resource, resources)
    return all_dependencies_satisfied(res_deps, stack_name, resources, resource_id)


def is_updateable(resource_id, resources, stack_name):
    """ Return whether the given resource can be updated or not """
    resource = resources[resource_id]
    if not is_deployable_resource(resource) or not is_deployed(resource_id, resources, stack_name):
        return False
    resource_type = get_resource_type(resource)
    return resource_type in UPDATEABLE_RESOURCES


def all_dependencies_satisfied(resources, stack_name, all_resources, depending_resource=None):
    for resource_id, resource in iteritems(resources):
        if is_deployable_resource(resource):
            if not is_deployed(resource_id, all_resources, stack_name):
                return False
    return True


def resources_to_deploy_next(resources, stack_name):
    result = {}
    for resource_id, resource in iteritems(resources):
        if should_be_deployed(resource_id, resources, stack_name):
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
