import re
import os
import json
import yaml
import logging
import traceback
import moto.cloudformation.utils
from urllib.parse import urlparse
from six import iteritems
from moto.cloudformation.models import cloudformation_backends
from moto.cloudformation import parsing
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.constants import AWS_REGION_US_EAST_1
from localstack.services.s3 import s3_listener
from localstack.utils.testutil import create_zip_file
from localstack.services.awslambda.lambda_api import get_handler_file_from_name

ACTION_CREATE = 'create'
ACTION_DELETE = 'delete'
PLACEHOLDER_RESOURCE_NAME = '__resource_name__'
PLACEHOLDER_AWS_NO_VALUE = '__aws_no_value__'

LOG = logging.getLogger(__name__)

# list of resource types that can be updated
UPDATEABLE_RESOURCES = ['Lambda::Function', 'ApiGateway::Method', 'StepFunctions::StateMachine']

# list of static attribute references to be replaced in {'Fn::Sub': '...'} strings
STATIC_REFS = ['AWS::Region', 'AWS::Partition', 'AWS::StackName']

# create safe yaml loader that parses date strings as string, not date objects
NoDatesSafeLoader = yaml.SafeLoader
NoDatesSafeLoader.yaml_implicit_resolvers = {
    k: [r for r in v if r[0] != 'tag:yaml.org,2002:timestamp'] for
    k, v in NoDatesSafeLoader.yaml_implicit_resolvers.items()
}


class DependencyNotYetSatisfied(Exception):
    """ Exception indicating that a resource dependency is not (yet) deployed/available. """
    def __init__(self, resource_ids, message=None):
        message = message or 'Unresolved dependencies: %s' % resource_ids
        super(DependencyNotYetSatisfied, self).__init__(message)
        resource_ids = resource_ids if isinstance(resource_ids, list) else [resource_ids]
        self.resource_ids = resource_ids


def str_or_none(o):
    return o if o is None else json.dumps(o) if isinstance(o, (dict, list)) else str(o)


def params_select_attributes(*attrs):
    def do_select(params, **kwargs):
        result = {}
        for attr in attrs:
            if params.get(attr) is not None:
                result[attr] = str_or_none(params.get(attr))
        return result
    return do_select


def get_bucket_location_config(**kwargs):
    region = aws_stack.get_region()
    if region == AWS_REGION_US_EAST_1:
        return None
    return {'LocationConstraint': region}


def lambda_get_params():
    return lambda params, **kwargs: params


def lambda_keys_to_lower(key=None):
    return lambda params, **kwargs: common.keys_to_lower(params.get(key) if key else params)


def rename_params(func, rename_map):
    def do_rename(params, **kwargs):
        values = func(params, **kwargs) if func else params
        for old_param, new_param in rename_map.items():
            values[new_param] = values.pop(old_param, None)
        return values
    return do_rename


def params_list_to_dict(param_name, key_attr_name='Key', value_attr_name='Value'):
    def do_replace(params, **kwargs):
        result = {}
        for entry in params.get(param_name, []):
            key = entry[key_attr_name]
            value = entry[value_attr_name]
            result[key] = value
        return result
    return do_replace


def params_dict_to_list(param_name, key_attr_name='Key', value_attr_name='Value', wrapper=None):
    def do_replace(params, **kwargs):
        result = []
        for key, value in params.get(param_name, {}).items():
            result.append({key_attr_name: key, value_attr_name: value})
        if wrapper:
            result = {wrapper: result}
        return result
    return do_replace


def get_nested_stack_params(params, **kwargs):
    stack_name = kwargs.get('stack_name', 'stack')
    nested_stack_name = '%s-%s' % (stack_name, common.short_uid())
    stack_params = params.get('Parameters', {})
    stack_params = [{'ParameterKey': k, 'ParameterValue': v} for k, v in stack_params.items()]
    result = {
        'StackName': nested_stack_name,
        'TemplateURL': params.get('TemplateURL'),
        'Parameters': stack_params
    }
    return result


def get_lambda_code_param(params, **kwargs):
    code = params.get('Code', {})
    zip_file = code.get('ZipFile')
    if zip_file and not common.is_base64(zip_file):
        tmp_dir = common.new_tmp_dir()
        handler_file = get_handler_file_from_name(params['Handler'], runtime=params['Runtime'])
        tmp_file = os.path.join(tmp_dir, handler_file)
        common.save_file(tmp_file, zip_file)
        zip_file = create_zip_file(tmp_file, get_content=True)
        code['ZipFile'] = zip_file
        common.rm_rf(tmp_dir)
    return code


def sns_subscription_params(params, **kwargs):
    def attr_val(val):
        return json.dumps(val) if isinstance(val, (dict, list)) else str(val)

    attrs = ['DeliveryPolicy', 'FilterPolicy', 'RawMessageDelivery', 'RedrivePolicy']
    result = dict([(a, attr_val(params[a])) for a in attrs if a in params])
    return result


def events_put_rule_params(params, **kwargs):
    attrs = ['ScheduleExpression', 'EventPattern', 'State', 'Description', 'Name']
    result = select_parameters(*attrs)(params, **kwargs)
    result['Name'] = result.get('Name') or PLACEHOLDER_RESOURCE_NAME

    def wrap_in_lists(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if not isinstance(v, (dict, list)):
                    o[k] = [v]
        return o

    pattern = result.get('EventPattern')
    if isinstance(pattern, dict):
        wrapped = common.recurse_object(pattern, wrap_in_lists)
        result['EventPattern'] = json.dumps(wrapped)
    return result


def es_add_tags_params(params, **kwargs):
    es_arn = aws_stack.es_domain_arn(params.get('DomainName'))
    tags = params.get('Tags', [])
    return {'ARN': es_arn, 'TagList': tags}


def s3_bucket_notification_config(params, **kwargs):
    notif_config = params.get('NotificationConfiguration')
    if not notif_config:
        return None

    lambda_configs = []
    queue_configs = []
    topic_configs = []

    attr_tuples = (
        ('LambdaConfigurations', lambda_configs, 'LambdaFunctionArn', 'Function'),
        ('QueueConfigurations', queue_configs, 'QueueArn', 'Queue'),
        ('TopicConfigurations', topic_configs, 'TopicArn', 'Topic')
    )

    # prepare lambda/queue/topic notification configs
    for attrs in attr_tuples:
        for config in notif_config.get(attrs[0]) or []:
            filter_rules = config.get('Filter', {}).get('S3Key', {}).get('Rules')
            entry = {
                attrs[2]: config[attrs[3]],
                'Events': [config['Event']]
            }
            if filter_rules:
                entry['Filter'] = {'Key': {'FilterRules': filter_rules}}
            attrs[1].append(entry)

    # construct final result
    result = {
        'Bucket': params.get('BucketName') or PLACEHOLDER_RESOURCE_NAME,
        'NotificationConfiguration': {
            'LambdaFunctionConfigurations': lambda_configs,
            'QueueConfigurations': queue_configs,
            'TopicConfigurations': topic_configs
        }
    }
    return result


def select_parameters(*param_names):
    return lambda params, **kwargs: dict([(k, v) for k, v in params.items() if k in param_names])


def merge_parameters(func1, func2):
    return lambda params, **kwargs: common.merge_dicts(func1(params, **kwargs), func2(params, **kwargs))


def dump_json_params(param_func=None, *param_names):
    def replace(params, **kwargs):
        result = param_func(params, **kwargs) if param_func else params
        for name in param_names:
            if isinstance(result.get(name), (dict, list)):
                # Fix for https://github.com/localstack/localstack/issues/2022
                # Convert any date instances to date strings, etc, Version: "2012-10-17"
                param_value = common.json_safe(result[name])
                result[name] = json.dumps(param_value)
        return result
    return replace


def param_defaults(param_func, defaults):
    def replace(params, **kwargs):
        result = param_func(params, **kwargs)
        for key, value in defaults.items():
            if result.get(key) in ['', None]:
                result[key] = value
        return result
    return replace


def iam_create_policy_params(params, **kwargs):
    result = {'PolicyName': params['PolicyName']}
    policy_doc = remove_none_values(params['PolicyDocument'])
    result['PolicyDocument'] = json.dumps(policy_doc)
    return result


def lambda_permission_params(params, **kwargs):
    result = select_parameters('FunctionName', 'Action', 'Principal')(params, **kwargs)
    result['StatementId'] = common.short_uid()
    return result


def get_ddb_provisioned_throughput(params, **kwargs):
    args = params.get('ProvisionedThroughput')
    if args:
        if isinstance(args['ReadCapacityUnits'], str):
            args['ReadCapacityUnits'] = int(args['ReadCapacityUnits'])
        if isinstance(args['WriteCapacityUnits'], str):
            args['WriteCapacityUnits'] = int(args['WriteCapacityUnits'])
    return args


def get_ddb_global_sec_indexes(params, **kwargs):
    args = params.get('GlobalSecondaryIndexes')
    if args:
        for index in args:
            provisoned_throughput = index['ProvisionedThroughput']
            if isinstance(provisoned_throughput['ReadCapacityUnits'], str):
                provisoned_throughput['ReadCapacityUnits'] = int(provisoned_throughput['ReadCapacityUnits'])
            if isinstance(provisoned_throughput['WriteCapacityUnits'], str):
                provisoned_throughput['WriteCapacityUnits'] = int(provisoned_throughput['WriteCapacityUnits'])
    return args


def get_apigw_resource_params(params, **kwargs):
    result = {
        'restApiId': params.get('RestApiId'),
        'pathPart': params.get('PathPart'),
        'parentId': params.get('ParentId')
    }
    if not result.get('parentId'):
        # get root resource id
        apigw = aws_stack.connect_to_service('apigateway')
        resources = apigw.get_resources(restApiId=result['restApiId'])['items']
        root_resource = ([r for r in resources if r['path'] == '/'] or [None])[0]
        if not root_resource:
            raise Exception('Unable to find root resource for REST API %s' % result['restApiId'])
        result['parentId'] = root_resource['id']
    return result


# maps resource types to functions and parameters for creation
RESOURCE_TO_FUNCTION = {
    'S3::Bucket': {
        'create': [{
            'function': 'create_bucket',
            'parameters': {
                'Bucket': ['BucketName', PLACEHOLDER_RESOURCE_NAME],
                'ACL': lambda params, **kwargs: convert_acl_cf_to_s3(params.get('AccessControl', 'PublicRead')),
                'CreateBucketConfiguration': lambda params, **kwargs: get_bucket_location_config()
            }
        }, {
            'function': 'put_bucket_notification_configuration',
            'parameters': s3_bucket_notification_config
        }],
        'delete': [{
            'function': 'delete_bucket_policy',
            'parameters': {
                'Bucket': 'PhysicalResourceId'
            }
        }, {
            'function': 'delete_bucket',
            'parameters': {
                'Bucket': 'PhysicalResourceId'
            }
        }]
    },
    'S3::BucketPolicy': {
        'create': {
            'function': 'put_bucket_policy',
            'parameters': rename_params(dump_json_params(None, 'PolicyDocument'), {'PolicyDocument': 'Policy'})
        }
    },
    'SQS::Queue': {
        'create': {
            'function': 'create_queue',
            'parameters': {
                'QueueName': ['QueueName', PLACEHOLDER_RESOURCE_NAME],
                'Attributes': params_select_attributes(
                    'ContentBasedDeduplication', 'DelaySeconds', 'FifoQueue', 'MaximumMessageSize',
                    'MessageRetentionPeriod', 'VisibilityTimeout', 'RedrivePolicy', 'ReceiveMessageWaitTimeSeconds'
                ),
                'tags': params_list_to_dict('Tags')
            }
        },
        'delete': {
            'function': 'delete_queue',
            'parameters': {
                'QueueUrl': 'PhysicalResourceId'
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
        },
        'delete': {
            'function': 'delete_topic',
            'parameters': {
                'TopicArn': 'PhysicalResourceId'
            }
        }
    },
    'SSM::Parameter': {
        'create': {
            'function': 'put_parameter',
            'parameters': merge_parameters(params_dict_to_list('Tags', wrapper='Tags'), params_select_attributes(
                'Name', 'Type', 'Value', 'Description', 'AllowedPattern', 'Policies', 'Tier'))
        }
    },
    'SecretsManager::Secret': {
        'create': {
            'function': 'create_secret',
            'parameters': select_parameters('Name', 'Description', 'SecretString', 'KmsKeyId', 'Tags')
        },
        'delete': {
            'function': 'delete_secret',
            'parameters': {
                'SecretId': 'PhysicalResourceId'
            }
        }
    },
    'KinesisFirehose::DeliveryStream': {
        'create': {
            'function': 'create_delivery_stream',
            'parameters': select_parameters('DeliveryStreamName', 'DeliveryStreamType',
                'S3DestinationConfiguration', 'ElasticsearchDestinationConfiguration')
        },
        'delete': {
            'function': 'delete_delivery_stream',
            'parameters': {
                'DeliveryStreamName': 'PhysicalResourceId'
            }
        }
    },
    'Elasticsearch::Domain': {
        'create': [{
            'function': 'create_elasticsearch_domain',
            'parameters': select_parameters('AccessPolicies', 'AdvancedOptions', 'CognitoOptions',
                'DomainName', 'EBSOptions', 'ElasticsearchClusterConfig', 'ElasticsearchVersion',
                'EncryptionAtRestOptions', 'LogPublishingOptions', 'NodeToNodeEncryptionOptions',
                'SnapshotOptions', 'VPCOptions')
        }, {
            'function': 'add_tags',
            'parameters': es_add_tags_params
        }],
        'delete': {
            'function': 'delete_elasticsearch_domain',
            'parameters': {
                'DomainName': 'PhysicalResourceId'
            }
        }
    },
    'Logs::LogGroup': {
        'create': {
            'function': 'create_log_group',
            'parameters': {
                'logGroupName': 'LogGroupName'
            }
        },
        'delete': {
            'function': 'delete_log_group',
            'parameters': {
                'logGroupName': 'PhysicalResourceId'
            }
        }
    },
    'Lambda::Function': {
        'create': {
            'function': 'create_function',
            'parameters': {
                'FunctionName': 'FunctionName',
                'Runtime': 'Runtime',
                'Role': 'Role',
                'Handler': 'Handler',
                'Code': get_lambda_code_param,
                'Description': 'Description',
                'Environment': 'Environment',
                'Timeout': 'Timeout',
                'MemorySize': 'MemorySize',
                # TODO add missing fields
            },
            'defaults': {
                'Role': 'test_role'
            }
        },
        'delete': {
            'function': 'delete_function',
            'parameters': {
                'FunctionName': 'PhysicalResourceId'
            }
        }
    },
    'Lambda::Version': {
        'create': {
            'function': 'publish_version',
            'parameters': select_parameters('FunctionName', 'CodeSha256', 'Description')
        }
    },
    'Lambda::Permission': {
        'create': {
            'function': 'add_permission',
            'parameters': lambda_permission_params
        }
    },
    'Lambda::EventSourceMapping': {
        'create': {
            'function': 'create_event_source_mapping',
            'parameters': select_parameters('FunctionName', 'EventSourceArn', 'Enabled',
                'StartingPosition', 'BatchSize', 'StartingPositionTimestamp')
        }
    },
    'DynamoDB::Table': {
        'create': {
            'function': 'create_table',
            'parameters': {
                'TableName': 'TableName',
                'AttributeDefinitions': 'AttributeDefinitions',
                'KeySchema': 'KeySchema',
                'ProvisionedThroughput': get_ddb_provisioned_throughput,
                'LocalSecondaryIndexes': 'LocalSecondaryIndexes',
                'GlobalSecondaryIndexes': get_ddb_global_sec_indexes,
                'StreamSpecification': lambda params, **kwargs: (
                    common.merge_dicts(params.get('StreamSpecification'), {'StreamEnabled': True}, default=None))
            },
            'defaults': {
                'ProvisionedThroughput': {
                    'ReadCapacityUnits': 5,
                    'WriteCapacityUnits': 5
                }
            }
        },
        'delete': {
            'function': 'delete_table',
            'parameters': {
                'TableName': 'PhysicalResourceId'
            }
        }
    },
    'Events::Rule': {
        'create': [{
            'function': 'put_rule',
            'parameters': events_put_rule_params
        }, {
            'function': 'put_targets',
            'parameters': {
                'Rule': PLACEHOLDER_RESOURCE_NAME,
                'EventBusName': 'EventBusName',
                'Targets': 'Targets'
            }
        }],
        'delete': {
            'function': 'delete_rule',
            'parameters': {
                'Name': 'PhysicalResourceId'
            }
        }
    },
    'IAM::Role': {
        'create': {
            'function': 'create_role',
            'parameters':
                param_defaults(
                    dump_json_params(
                        select_parameters('Path', 'RoleName', 'AssumeRolePolicyDocument',
                            'Description', 'MaxSessionDuration', 'PermissionsBoundary', 'Tags'),
                        'AssumeRolePolicyDocument'),
                    {'RoleName': PLACEHOLDER_RESOURCE_NAME})
        },
        'delete': {
            'function': 'delete_role',
            'parameters': {
                'RoleName': 'PhysicalResourceId'
            }
        }
    },
    'IAM::Policy': {
        'create': {
            'function': 'create_policy',
            # TODO: associate policies with users, groups, roles
            'parameters': iam_create_policy_params
        }
        # InlinePolicy in cloudformation will be deleted on deleting Role
    },
    'ApiGateway::RestApi': {
        'create': {
            'function': 'create_rest_api',
            'parameters': {
                'name': 'Name',
                'description': 'Description'
            }
        },
        'delete': {
            'function': 'delete_rest_api',
            'parameters': {
                'restApiId': 'PhysicalResourceId',
            }
        }
    },
    'ApiGateway::Resource': {
        'create': {
            'function': 'create_resource',
            'parameters': get_apigw_resource_params
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
    'ApiGateway::Account': {
    },
    'ApiGateway::Stage': {
        'create': {
            'function': 'create_stage',
            'parameters': lambda_keys_to_lower()
        }
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
    'ApiGateway::GatewayResponse': {
        'create': {
            'function': 'put_gateway_response',
            'parameters': {
                'restApiId': 'RestApiId',
                'responseType': 'ResponseType',
                'statusCode': 'StatusCode',
                'responseParameters': 'ResponseParameters',
                'responseTemplates': 'ResponseTemplates'
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
        },
        'delete': {
            'function': 'delete_stream',
            'parameters': {
                'StreamName': 'PhysicalResourceId'
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
        },
        'update': {
            'function': 'update_state_machine',
            'parameters': {
                'definition': 'DefinitionString'
            }
        },
        'delete': {
            'function': 'delete_state_machine',
            'parameters': {
                'stateMachineArn': 'PhysicalResourceId'
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
    },
    'SNS::Subscription': {
        'create': {
            'function': 'subscribe',
            'parameters': {
                'TopicArn': 'TopicArn',
                'Protocol': 'Protocol',
                'Endpoint': 'Endpoint',
                'Attributes': sns_subscription_params
            }
        }
    },
    'CloudFormation::Stack': {
        'create': {
            'function': 'create_stack',
            'parameters': get_nested_stack_params
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
        yaml.add_multi_constructor('', moto.cloudformation.utils.yaml_tag_constructor, Loader=NoDatesSafeLoader)
        try:
            return yaml.safe_load(template)
        except Exception:
            return yaml.load(template, Loader=NoDatesSafeLoader)


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
    res_type = resource.get('Type', resource.get('ResourceType', ''))
    parts = res_type.split('::')
    if len(parts) == 1:
        return None
    if res_type.endswith('Cognito::UserPool'):
        return 'cognito-idp'
    if parts[-2] == 'Cognito':
        return 'cognito-idp'
    if parts[-2] == 'Elasticsearch':
        return 'es'
    if parts[-2] == 'KinesisFirehose':
        return 'firehose'
    return parts[1].lower()


def get_resource_name(resource):
    res_type = get_resource_type(resource)
    properties = resource.get('Properties') or {}
    name = properties.get('Name')
    if name:
        return name

    # try to extract name from attributes
    if res_type == 'S3::Bucket':
        name = s3_listener.normalize_bucket_name(properties.get('BucketName'))
    elif res_type == 'SQS::Queue':
        name = properties.get('QueueName')
    elif res_type == 'Cognito::UserPool':
        name = properties.get('PoolName')
    elif res_type == 'StepFunctions::StateMachine':
        name = properties.get('StateMachineName')
    elif res_type == 'IAM::Role':
        name = properties.get('RoleName')
    else:
        LOG.warning('Unable to extract name for resource type "%s"' % res_type)

    return name


def get_client(resource, func_config):
    resource_type = get_resource_type(resource)
    service = get_service_name(resource)
    resource_config = RESOURCE_TO_FUNCTION.get(resource_type)
    if resource_config is None:
        raise Exception('CloudFormation deployment for resource type %s not yet implemented' % resource_type)
    try:
        if func_config.get('boto_client') == 'resource':
            return aws_stack.connect_to_resource(service)
        return aws_stack.connect_to_service(service)
    except Exception as e:
        LOG.warning('Unable to get client for "%s" API, skipping deployment: %s' % (service, e))
        return None


def describe_stack_resource(stack_name, logical_resource_id):
    client = aws_stack.connect_to_service('cloudformation')
    try:
        result = client.describe_stack_resource(StackName=stack_name, LogicalResourceId=logical_resource_id)
        return result['StackResourceDetail']
    except Exception as e:
        LOG.warning('Unable to get details for resource "%s" in CloudFormation stack "%s": %s' %
                    (logical_resource_id, stack_name, e))


def retrieve_and_update_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources.get(resource_id) or {}
    resource_props = resource.get('Properties') or {}
    result = retrieve_resource_details(resource_id, resource_status, resources, stack_name)
    if isinstance(result, dict):
        result.pop('ResponseMetadata', None)
        # Note: for now, we're only setting non-existing props (we may set changed props in the future as well)
        update_attrs = {k: v for k, v in result.items() if k not in resource_props}
        resource_props.update(update_attrs)
    return result


def retrieve_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources.get(resource_id)
    resource_id = resource_status.get('PhysicalResourceId') or resource_id
    if not resource:
        resource = {}
    resource_type = get_resource_type(resource)
    resource_props = resource.get('Properties')
    try:
        if resource_type == 'Lambda::Function':
            func_name = resolve_refs_recursively(stack_name, resource_props['FunctionName'], resources)
            resource_id = func_name if resource else resource_id
            return aws_stack.connect_to_service('lambda').get_function(FunctionName=resource_id)

        elif resource_type == 'Lambda::Version':
            name = resolve_refs_recursively(stack_name, resource_props.get('FunctionName'), resources)
            if not name:
                return None
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

        elif resource_type == 'Events::Rule':
            rule_name = resolve_refs_recursively(stack_name, resource_props.get('Name'), resources)
            result = aws_stack.connect_to_service('events').describe_rule(Name=rule_name) or {}
            return result if result.get('Name') else None

        elif resource_type == 'IAM::Role':
            role_name = resolve_refs_recursively(stack_name, resource_props.get('RoleName'), resources)
            return aws_stack.connect_to_service('iam').get_role(RoleName=role_name)['Role']

        elif resource_type == 'SSM::Parameter':
            param_name = resource_props.get('Name') or resource_id
            param_name = resolve_refs_recursively(stack_name, param_name, resources)
            return aws_stack.connect_to_service('ssm').get_parameter(Name=param_name)['Parameter']

        elif resource_type == 'DynamoDB::Table':
            table_name = resource_props.get('TableName') or resource_id
            table_name = resolve_refs_recursively(stack_name, table_name, resources)
            return aws_stack.connect_to_service('dynamodb').describe_table(TableName=table_name)

        elif resource_type == 'ApiGateway::RestApi':
            apis = aws_stack.connect_to_service('apigateway').get_rest_apis()['items']
            api_name = resource_props.get('Name') or resource_id
            api_name = resolve_refs_recursively(stack_name, api_name, resources)
            result = list(filter(lambda api: api['name'] == api_name, apis))
            return result[0] if result else None

        elif resource_type == 'ApiGateway::Resource':
            api_id = resource_props['RestApiId'] if resource else resource_id
            api_id = resolve_refs_recursively(stack_name, api_id, resources)
            parent_id = resolve_refs_recursively(stack_name, resource_props.get('ParentId'), resources)
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

        elif resource_type == 'ApiGateway::Stage':
            api_id = resource_props['RestApiId'] if resource else resource_id
            api_id = resolve_refs_recursively(stack_name, api_id, resources)
            if not api_id:
                return None
            result = aws_stack.connect_to_service('apigateway').get_stage(restApiId=api_id,
                stageName=resource_props['StageName'])
            return result

        elif resource_type == 'ApiGateway::Method':
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            if not api_id or not res_id:
                return None
            res_obj = aws_stack.connect_to_service('apigateway').get_resource(restApiId=api_id, resourceId=res_id)
            match = [v for (k, v) in res_obj.get('resourceMethods', {}).items()
                     if resource_props['HttpMethod'] in (v.get('httpMethod'), k)]
            int_props = resource_props.get('Integration') or {}
            if int_props.get('Type') == 'AWS_PROXY':
                match = [m for m in match if
                    m.get('methodIntegration', {}).get('type') == 'AWS_PROXY' and
                    m.get('methodIntegration', {}).get('httpMethod') == int_props.get('IntegrationHttpMethod')]
            return any(match) or None

        elif resource_type == 'ApiGateway::GatewayResponse':
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            client = aws_stack.connect_to_service('apigateway')
            result = client.get_gateway_response(restApiId=api_id, responseType=resource_props['ResponseType'])
            return result if 'responseType' in result else None

        elif resource_type == 'SQS::Queue':
            queue_name = resolve_refs_recursively(stack_name, resource_props['QueueName'], resources)
            sqs_client = aws_stack.connect_to_service('sqs')
            queues = sqs_client.list_queues()
            result = list(filter(lambda item:
                # TODO possibly find a better way to compare resource_id with queue URLs
                item.endswith('/%s' % queue_name), queues.get('QueueUrls', [])))
            if not result:
                return None
            result = sqs_client.get_queue_attributes(QueueUrl=result[0], AttributeNames=['All'])['Attributes']
            result['Arn'] = result['QueueArn']
            return result

        elif resource_type == 'SNS::Topic':
            topic_name = resolve_refs_recursively(stack_name, resource_props['TopicName'], resources)
            topics = aws_stack.connect_to_service('sns').list_topics()
            result = list(filter(lambda item: item['TopicArn'].split(':')[-1] == topic_name, topics.get('Topics', [])))
            return result[0] if result else None

        elif resource_type == 'SNS::Subscription':
            topic_arn = resource_props.get('TopicArn')
            topic_arn = resolve_refs_recursively(stack_name, topic_arn, resources)
            subs = aws_stack.connect_to_service('sns').list_subscriptions_by_topic(TopicArn=topic_arn)
            result = [sub for sub in subs['Subscriptions'] if
                resource_props.get('Protocol') == sub['Protocol'] and
                resource_props.get('Endpoint') == sub['Endpoint']]
            # TODO: use get_subscription_attributes to compare FilterPolicy
            return result[0] if result else None

        elif resource_type == 'S3::Bucket':
            bucket_name = resource_props.get('BucketName') or resource_id
            bucket_name = resolve_refs_recursively(stack_name, bucket_name, resources)
            bucket_name = s3_listener.normalize_bucket_name(bucket_name)
            s3_client = aws_stack.connect_to_service('s3')
            response = s3_client.get_bucket_location(Bucket=bucket_name)
            notifs = resource_props.get('NotificationConfiguration')
            if not response or not notifs:
                return response
            configs = s3_client.get_bucket_notification_configuration(Bucket=bucket_name)
            has_notifs = (configs.get('TopicConfigurations') or configs.get('QueueConfigurations') or
                configs.get('LambdaFunctionConfigurations'))
            if notifs and not has_notifs:
                return None
            return response

        elif resource_type == 'S3::BucketPolicy':
            bucket_name = resource_props.get('Bucket') or resource_id
            bucket_name = resolve_refs_recursively(stack_name, bucket_name, resources)
            return aws_stack.connect_to_service('s3').get_bucket_policy(Bucket=bucket_name)

        elif resource_type == 'Logs::LogGroup':
            group_name = resource_props.get('LogGroupName')
            group_name = resolve_refs_recursively(stack_name, group_name, resources)
            logs = aws_stack.connect_to_service('logs')
            groups = logs.describe_log_groups(logGroupNamePrefix=group_name)['logGroups']
            return ([g for g in groups if g['logGroupName'] == group_name] or [None])[0]

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

        elif resource_type == 'SecretsManager::Secret':
            secret_name = resource_props.get('Name') or resource_id
            secret_name = resolve_refs_recursively(stack_name, secret_name, resources)
            return aws_stack.connect_to_service('secretsmanager').describe_secret(SecretId=secret_name)

        elif resource_type == 'Elasticsearch::Domain':
            domain_name = resource_props.get('DomainName') or resource_id
            domain_name = resolve_refs_recursively(stack_name, domain_name, resources)
            return aws_stack.connect_to_service('es').describe_elasticsearch_domain(DomainName=domain_name)

        elif resource_type == 'KinesisFirehose::DeliveryStream':
            stream_name = resource_props.get('DeliveryStreamName') or resource_id
            stream_name = resolve_refs_recursively(stack_name, stream_name, resources)
            return aws_stack.connect_to_service('firehose').describe_delivery_stream(DeliveryStreamName=stream_name)

        elif resource_type == 'IAM::Policy':
            client = aws_stack.connect_to_service('iam')
            policy_name = resource_props.get('PolicyName') or resource_id

            # The policy in cloudformation is InlinePolicy, so we must specify at least one of [Roles, Users, Groups]
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
            roles = resource['Properties'].get('Roles', [])
            if roles:
                if isinstance(roles[0], str):
                    role_name = roles[0]
                else:
                    role_name = resources[roles[0]['Ref']]['Properties']['RoleName']

                role_policy = client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                return role_policy

            # TODO The InlinePolicy can be embedded in specified User, or Group

        if is_deployable_resource(resource):
            LOG.warning('Unexpected resource type %s when resolving references of resource %s: %s' %
                        (resource_type, resource_id, resource))

    except DependencyNotYetSatisfied:
        return
    except Exception as e:
        check_not_found_exception(e, resource_type, resource, resource_status)

    return None


def check_not_found_exception(e, resource_type, resource, resource_status):
    # we expect this to be a "not found" exception
    markers = ['NoSuchBucket', 'ResourceNotFound', 'NotFoundException', '404', 'not found']
    if not list(filter(lambda marker, e=e: marker in str(e), markers)):
        LOG.warning('Unexpected error retrieving details for resource %s: %s %s - %s %s' %
            (resource_type, e, traceback.format_exc(), resource, resource_status))


def extract_resource_attribute(resource_type, resource_json, attribute, resource_id=None,
        resource=None, resources=None, stack_name=None):
    LOG.debug('Extract resource attribute: %s %s' % (resource_type, attribute))
    is_ref_attribute = attribute in ['PhysicalResourceId', 'Ref']
    # extract resource specific attributes
    if resource_type == 'Lambda::Function':
        func_configs = resource_json.get('Configuration')
        if is_ref_attribute or attribute == 'Arn':
            if isinstance(resource, dict):
                func_configs = resource.get('Properties', {})
            func_arn = func_configs.get('FunctionArn')
            if func_arn:
                return resolve_refs_recursively(stack_name, func_arn, resources)
            func_name = resolve_refs_recursively(stack_name, func_configs.get('FunctionName'), resources)
            return aws_stack.lambda_function_arn(func_name)
        return func_configs.get(attribute)
    elif resource_type == 'DynamoDB::Table':
        actual_attribute = 'LatestStreamArn' if attribute == 'StreamArn' else attribute
        value = resource_json['Table'].get(actual_attribute)
        return value
    elif resource_type == 'ApiGateway::RestApi':
        if is_ref_attribute:
            return resource_json['id']
        if attribute == 'RootResourceId':
            resources = aws_stack.connect_to_service('apigateway').get_resources(restApiId=resource_json['id'])['items']
            for res in resources:
                if res['path'] == '/' and not res.get('parentId'):
                    return res['id']
    elif resource_type == 'ApiGateway::Resource':
        if is_ref_attribute:
            return resource_json['id']
    elif resource_type == 'S3::Bucket':
        if is_ref_attribute and isinstance(resource, dict):
            bucket_name = resource.get('Properties', {}).get('BucketName')
            return resolve_refs_recursively(stack_name, bucket_name, resources)
    elif resource_type == 'SNS::Topic':
        if is_ref_attribute and resource_json.get('TopicArn'):
            topic_arn = resource_json.get('TopicArn')
            return resolve_refs_recursively(stack_name, topic_arn, resources)
    attribute_lower = common.first_char_to_lower(attribute)
    result = resource_json.get(attribute) or resource_json.get(attribute_lower)
    if result is None and isinstance(resource, dict):
        res_json1 = resource.get('Properties', {})
        result = res_json1.get(attribute) or res_json1.get(attribute_lower)
        if result is None:
            result = get_attr_from_model_instance(resource, attribute,
                resource_type=resource_type, resource_id=resource_id)
    if result is None and is_ref_attribute:
        result = resource_json.get('Id')
    return result


def get_attr_from_model_instance(resource, attribute, resource_type, resource_id=None):
    if not resource_type.startswith('AWS::'):
        resource_type = 'AWS::%s' % resource_type
    model_clazz = parsing.MODEL_MAP.get(resource_type)
    if not model_clazz:
        LOG.info('Unable to find model class for resource type "%s"' % resource_type)
        return
    try:
        inst = model_clazz(resource_name=resource_id, resource_json=resource)
        return inst.get_cfn_attribute(attribute)
    except Exception:
        pass


def resolve_ref(stack_name, ref, resources, attribute):
    if ref == 'AWS::Region':
        return aws_stack.get_region()
    if ref == 'AWS::Partition':
        return 'aws'
    if ref == 'AWS::StackName':
        return stack_name
    if ref == 'AWS::NoValue':
        return PLACEHOLDER_AWS_NO_VALUE

    # first, check stack parameters
    stack_param = get_stack_parameter(stack_name, ref)
    if stack_param is not None:
        return stack_param

    # second, resolve resource references
    resource_status = {}

    if not resource_status and resources.get(ref):
        resource_status = resources[ref].get('__details__', {})
    if not resource_status and resources.get(ref):
        if isinstance(resources[ref].get(attribute), (str, int, float, bool, dict)):
            return resources[ref][attribute]
    # fetch resource details
    resource_new = retrieve_resource_details(ref, resource_status, resources, stack_name)
    if not resource_new:
        return
    resource = resources.get(ref)
    resource_type = get_resource_type(resource)
    result = extract_resource_attribute(resource_type, resource_new, attribute,
        resource_id=ref, resource=resource, resources=resources, stack_name=stack_name)
    if not result:
        LOG.warning('Unable to extract reference attribute %s from resource: %s %s' %
            (attribute, resource_new, resource))
    return result


def resolve_refs_recursively(stack_name, value, resources):
    if isinstance(value, dict):
        keys_list = list(value.keys())
        stripped_fn_lower = keys_list[0].lower().split('::')[-1] if len(keys_list) == 1 else None

        # process special operators
        if keys_list == ['Ref']:
            return resolve_ref(stack_name, value['Ref'], resources, attribute='PhysicalResourceId')

        if stripped_fn_lower == 'getatt':
            return resolve_ref(stack_name, value[keys_list[0]][0], resources, attribute=value[keys_list[0]][1])

        if stripped_fn_lower == 'join':
            join_values = value[keys_list[0]][1]
            join_values = [resolve_refs_recursively(stack_name, v, resources) for v in join_values]
            none_values = [v for v in join_values if v is None]
            if none_values:
                raise Exception('Cannot resolve CF fn::Join %s due to null values: %s' % (value, join_values))
            return value[keys_list[0]][0].join(join_values)

        if stripped_fn_lower == 'sub':
            item_to_sub = value[keys_list[0]]

            if not isinstance(item_to_sub, list):
                attr_refs = dict([(r, {'Ref': r}) for r in STATIC_REFS])
                item_to_sub = [item_to_sub, attr_refs]
            result = item_to_sub[0]

            for key, val in item_to_sub[1].items():
                val = resolve_refs_recursively(stack_name, val, resources)
                result = result.replace('${%s}' % key, val)

            # resolve placeholders
            result = resolve_placeholders_in_string(result, stack_name=stack_name, resources=resources)
            return result

        if stripped_fn_lower == 'findinmap':
            result = resolve_ref(stack_name, value[keys_list[0]][0], resources, attribute=value[keys_list[0]][1])
            if not result:
                raise Exception('Cannot resolve fn::FindInMap: %s %s' % (value[keys_list[0]], list(resources.keys())))

            result = result.get(value[keys_list[0]][2])
            return result

        if stripped_fn_lower == 'importvalue':
            exports = cloudformation_backends[aws_stack.get_region()].exports
            import_value_key = resolve_refs_recursively(stack_name, value[keys_list[0]], resources)
            export = exports[import_value_key]
            return export.value

        for key, val in iteritems(value):
            value[key] = resolve_refs_recursively(stack_name, val, resources)

    if isinstance(value, list):
        for i in range(0, len(value)):
            value[i] = resolve_refs_recursively(stack_name, value[i], resources)

    return value


def resolve_placeholders_in_string(result, stack_name=None, resources=None):
    def _replace(match):
        parts = match.group(1).split('.')
        if len(parts) == 2:
            resolved = resolve_ref(stack_name, parts[0].strip(), resources, attribute=parts[1].strip())
            if resolved is None:
                raise DependencyNotYetSatisfied(resource_ids=parts[0],
                    message='Unable to resolve attribute ref %s' % match.group(1))
            return resolved
        if len(parts) == 1 and parts[0] in resources:
            resource_json = resources[parts[0]]
            result = extract_resource_attribute(resource_json.get('Type'), resource_json, 'Ref',
                resources=resources, resource_id=parts[0])
            return result
        # TODO raise exception here?
        return match.group(0)
    regex = r'\$\{([^\}]+)\}'
    result = re.sub(regex, _replace, result)
    return result


def get_stack_parameter(stack_name, parameter):
    try:
        client = aws_stack.connect_to_service('cloudformation')
        stack = client.describe_stacks(StackName=stack_name)['Stacks']
    except Exception:
        return None
    stack = stack and stack[0]
    if not stack:
        return None
    result = [p['ParameterValue'] for p in stack['Parameters'] if p['ParameterKey'] == parameter]
    return (result or [None])[0]


def update_resource(resource_id, resources, stack_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    if resource_type not in UPDATEABLE_RESOURCES:
        LOG.warning('Unable to update resource type "%s", id "%s"' % (resource_type, resource_id))
        return
    LOG.info('Updating resource %s of type %s' % (resource_id, resource_type))
    props = resource['Properties']

    if resource_type == 'Lambda::Function':
        client = aws_stack.connect_to_service('lambda')
        keys = ('FunctionName', 'Role', 'Handler', 'Description', 'Timeout', 'MemorySize', 'Environment', 'Runtime')
        update_props = dict([(k, props[k]) for k in keys if k in props])
        update_props = resolve_refs_recursively(stack_name, update_props, resources)
        if 'Code' in props:
            client.update_function_code(FunctionName=props['FunctionName'], **props['Code'])
        if 'Environment' in update_props:
            environment_variables = update_props['Environment'].get('Variables', {})
            update_props['Environment']['Variables'] = {k: str(v) for k, v in environment_variables.items()}

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

    if resource_type == 'StepFunctions::StateMachine':
        client = aws_stack.connect_to_service('stepfunctions')
        kwargs = {
            'stateMachineArn': props['stateMachineArn'],
            'definition': props['DefinitionString'],
        }

        return client.update_state_machine(**kwargs)


def fix_account_id_in_arns(params):
    def fix_ids(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if common.is_string(v, exclude_binary=True):
                    o[k] = aws_stack.fix_account_id_in_arns(v)
        elif common.is_string(o, exclude_binary=True):
            o = aws_stack.fix_account_id_in_arns(o)
        return o
    result = common.recurse_object(params, fix_ids)
    return result


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


def remove_none_values(params):
    """ Remove None values recursively in the given object. """
    def remove_nones(o, **kwargs):
        if isinstance(o, dict):
            for k, v in dict(o).items():
                if v is None:
                    o.pop(k)
        if isinstance(o, list):
            common.run_safe(o.remove, None)
            common.run_safe(o.remove, PLACEHOLDER_AWS_NO_VALUE)
        return o
    result = common.recurse_object(params, remove_nones)
    return result


def deploy_resource(resource_id, resources, stack_name):
    return execute_resource_action(resource_id, resources, stack_name, ACTION_CREATE)


def delete_resource(resource_id, resources, stack_name):
    res = resources[resource_id]
    if res['ResourceType'] == 'AWS::S3::Bucket':
        s3_listener.remove_bucket_notification(res['PhysicalResourceId'])

    if res['ResourceType'] == 'AWS::IAM::Role':
        role_name = res['PhysicalResourceId']

        iam_client = aws_stack.connect_to_service('iam')
        rs = iam_client.list_role_policies(
            RoleName=role_name
        )
        for policy in rs['PolicyNames']:
            iam_client.delete_role_policy(
                RoleName=role_name,
                PolicyName=policy
            )

    return execute_resource_action(resource_id, resources, stack_name, ACTION_DELETE)


def execute_resource_action(resource_id, resources, stack_name, action_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    func_details = RESOURCE_TO_FUNCTION.get(resource_type)
    if not func_details or action_name not in func_details:
        LOG.warning('Action "%s" for resource type %s not yet implemented' % (action_name, resource_type))
        return

    LOG.debug('Running action "%s" for resource type "%s" id "%s"' % (action_name, resource_type, resource_id))
    func_details = func_details[action_name]
    func_details = func_details if isinstance(func_details, list) else [func_details]
    results = []
    for func in func_details:
        if callable(func['function']):
            result = func['function'](resource_id, resources, resource_type, func, stack_name)
            results.append(result)
            continue
        client = get_client(resource, func)
        if client:
            result = configure_resource_via_sdk(resource_id, resources, resource_type, func, stack_name)
            results.append(result)
    return (results or [None])[0]


def fix_resource_props_for_sdk_deployment(resource_type, resource_props):
    if resource_type == 'Lambda::Function':
        # Properties will be validated by botocore before sending request to AWS
        # botocore/data/lambda/2015-03-31/service-2.json:1161 (EnvironmentVariableValue)
        # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-lambda-function-environment.html
        if 'Environment' in resource_props:
            environment_variables = resource_props['Environment'].get('Variables', {})
            resource_props['Environment']['Variables'] = {k: str(v) for k, v in environment_variables.items()}

    if resource_type == 'SQS::Queue':
        # https://github.com/localstack/localstack/issues/3004
        if 'ReceiveMessageWaitTimeSeconds' in resource_props:
            resource_props['ReceiveMessageWaitTimeSeconds'] = int(resource_props['ReceiveMessageWaitTimeSeconds'])


def configure_resource_via_sdk(resource_id, resources, resource_type, func_details, stack_name):
    resource = resources[resource_id]
    client = get_client(resource, func_details)
    function = getattr(client, func_details['function'])
    params = func_details.get('parameters') or lambda_get_params()
    defaults = func_details.get('defaults', {})
    if 'Properties' not in resource:
        resource['Properties'] = {}
    resource_props = resource['Properties']

    # Validate props for each resource type
    fix_resource_props_for_sdk_deployment(resource_type, resource_props)

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
                    params[param_key] = PLACEHOLDER_RESOURCE_NAME
                else:
                    if callable(prop_key):
                        prop_value = prop_key(resource_props, stack_name=stack_name,
                            resources=resources, resource_id=resource_id)
                    else:
                        prop_value = resource_props.get(prop_key)
                    if prop_value is not None:
                        params[param_key] = prop_value
                        break

    # replace PLACEHOLDER_RESOURCE_NAME in params
    resource_name_holder = {}

    def fix_placeholders(o, **kwargs):
        if isinstance(o, dict):
            for k, v in o.items():
                if v == PLACEHOLDER_RESOURCE_NAME:
                    if 'value' not in resource_name_holder:
                        resource_name_holder['value'] = get_resource_name(resource) or resource_id
                    o[k] = resource_name_holder['value']
        return o
    common.recurse_object(params, fix_placeholders)

    # assign default values if empty
    params = common.merge_recursive(defaults, params)

    # this is an indicator that we should skip this resource deployment, and return
    if params is None:
        return

    # convert refs and boolean strings
    for param_key, param_value in dict(params).items():
        if param_value is not None:
            param_value = params[param_key] = resolve_refs_recursively(stack_name, param_value, resources)
        # Convert to boolean (TODO: do this recursively?)
        if str(param_value).lower() in ['true', 'false']:
            params[param_key] = str(param_value).lower() == 'true'

    # convert any moto account IDs (123456789012) in ARNs to our format (000000000000)
    params = fix_account_id_in_arns(params)
    # convert data types (e.g., boolean strings to bool)
    params = convert_data_types(func_details, params)
    # remove None values, as they usually raise boto3 errors
    params = remove_none_values(params)

    # invoke function
    try:
        LOG.debug('Request for resource type "%s" in region %s: %s %s' % (
            resource_type, aws_stack.get_region(), func_details['function'], params))
        result = function(**params)
    except Exception as e:
        LOG.warning('Error calling %s with params: %s for resource: %s' % (function, params, resource))
        raise e

    # some resources have attached/nested resources which we need to create recursively now
    if resource_type == 'ApiGateway::Method':
        integration = resource_props.get('Integration')
        apigateway = aws_stack.connect_to_service('apigateway')
        if integration:
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            kwargs = {}
            if integration.get('Uri'):
                uri = resolve_refs_recursively(stack_name, integration.get('Uri'), resources)

                # Moto has a validate method on Uri for integration_type "HTTP" | "HTTP_PROXY" that does not accept
                # Uri value without path, we need to add path ("/") if not exists
                if integration.get('Type') in ['HTTP', 'HTTP_PROXY']:
                    rs = urlparse(uri)
                    if not rs.path:
                        uri = '{}/'.format(uri)

                kwargs['uri'] = uri

            if integration.get('IntegrationHttpMethod'):
                kwargs['integrationHttpMethod'] = integration['IntegrationHttpMethod']

            apigateway.put_integration(
                restApiId=api_id,
                resourceId=res_id,
                httpMethod=resource_props['HttpMethod'],
                type=integration['Type'],
                **kwargs
            )

        responses = resource_props.get('MethodResponses') or []
        for response in responses:
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            res_id = resolve_refs_recursively(stack_name, resource_props['ResourceId'], resources)
            apigateway.put_method_response(restApiId=api_id, resourceId=res_id,
                httpMethod=resource_props['HttpMethod'], statusCode=str(response['StatusCode']),
                responseParameters=response.get('ResponseParameters', {}))

    elif resource_type == 'ApiGateway::RestApi':
        body = resource_props.get('Body')
        if body:
            body = json.dumps(body) if isinstance(body, dict) else body
            client.put_rest_api(restApiId=result['id'], body=common.to_bytes(body))

    elif resource_type == 'SNS::Topic':
        subscriptions = resource_props.get('Subscription', [])
        for subscription in subscriptions:
            if not subscription:
                continue

            endpoint = resolve_refs_recursively(stack_name, subscription['Endpoint'], resources)
            topic_arn = retrieve_topic_arn(params['Name'])
            aws_stack.connect_to_service('sns').subscribe(
                TopicArn=topic_arn, Protocol=subscription['Protocol'], Endpoint=endpoint
            )
    elif resource_type == 'S3::Bucket':
        tags = resource_props.get('Tags')
        if tags:
            aws_stack.connect_to_service('s3').put_bucket_tagging(
                Bucket=params['Bucket'], Tagging={'TagSet': tags})

    return result


def delete_stack(stack_name, stack_resources):
    resources = dict([(r['LogicalResourceId'], common.clone_safe(r)) for r in stack_resources])
    for key, resource in resources.items():
        resources[key]['Properties'] = common.clone_safe(resource)
    for resource_id in resources.keys():
        delete_resource(resource_id, resources, stack_name)


# --------
# Util methods for analyzing resource dependencies
# --------

def is_deployable_resource(resource):
    resource_type = get_resource_type(resource)
    entry = RESOURCE_TO_FUNCTION.get(resource_type)
    if entry is None:
        LOG.warning('Unknown resource type "%s" in resource deployment map: %s' % (resource_type, resource))
    return bool(entry and entry.get(ACTION_CREATE))


def get_deployment_state(resource_id, resources, stack_name):
    res_details = resources[resource_id]
    resource_status = res_details.get('__details__') or {}
    details = retrieve_and_update_resource_details(resource_id, resource_status, resources, stack_name)
    return details


def is_deployed(resource_id, resources, stack_name):
    details = get_deployment_state(resource_id, resources, stack_name)
    return bool(details)


def should_be_deployed(resource_id, resources, stack_name, deploy_state=None):
    """ Return whether the given resource is all of: (1) deployable, (2) not yet deployed,
        and (3) has no unresolved dependencies. """
    res_details = resources[resource_id]
    if not is_deployable_resource(res_details):
        return False
    if deploy_state is None:
        deploy_state = is_deployed(resource_id, resources, stack_name)
    if deploy_state:
        return False
    return all_resource_dependencies_satisfied(resource_id, resources, stack_name)


def is_updateable(resource_id, resources, stack_name):
    """ Return whether the given resource can be updated or not """
    resource = resources[resource_id]
    if not is_deployable_resource(resource) or not is_deployed(resource_id, resources, stack_name):
        return False
    resource_type = get_resource_type(resource)
    return resource_type in UPDATEABLE_RESOURCES


def all_resource_dependencies_satisfied(resource_id, resources, stack_name):
    unsatisfied = get_unsatisfied_dependencies(resource_id, resources, stack_name)
    return not unsatisfied


def get_unsatisfied_dependencies(resource_id, resources, stack_name):
    resource = resources[resource_id]
    res_deps = get_resource_dependencies(resource_id, resource, resources)
    return get_unsatisfied_dependencies_for_resources(res_deps, stack_name, resources, resource_id)


def get_unsatisfied_dependencies_for_resources(
        resources, stack_name, all_resources, depending_resource=None, return_first=True):
    result = {}
    for resource_id, resource in iteritems(resources):
        if is_deployable_resource(resource):
            if not is_deployed(resource_id, all_resources, stack_name):
                LOG.debug('Dependency for resource %s not yet deployed: %s %s' %
                    (depending_resource, resource_id, resource))
                result[resource_id] = resource
                if return_first:
                    break
    return result


# TODO: check if still needed
def resources_to_deploy_next(resources, stack_name):
    result = {}
    for resource_id, resource in resources.items():
        if should_be_deployed(resource_id, resources, stack_name):
            result[resource_id] = resource
    return result


def get_resource_dependencies(resource_id, resource, resources):
    result = {}
    dumped = json.dumps(common.json_safe(resource))
    dependencies = resource.get('DependsOn', [])
    dependencies = dependencies if isinstance(dependencies, list) else [dependencies]
    for other_id, other in resources.items():
        if resource != other:
            # TODO: traverse dict instead of doing string search
            search1 = '{"Ref": "%s"}' % other_id
            search2 = '{"Fn::GetAtt": ["%s", ' % other_id
            if search1 in dumped or search2 in dumped:
                result[other_id] = other
            if other_id in dependencies:
                result[other_id] = other

    return result
