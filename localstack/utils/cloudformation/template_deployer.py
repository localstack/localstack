import re
import os
import json
import yaml
import logging
import traceback
import moto.cloudformation.utils
from urllib.parse import urlparse
from six import iteritems
from moto.core import CloudFormationModel as MotoCloudFormationModel
from moto.cloudformation import parsing
from moto.cloudformation.models import cloudformation_backends
from localstack.utils import common
from localstack.utils.aws import aws_stack
from localstack.constants import AWS_REGION_US_EAST_1, TEST_AWS_ACCOUNT_ID
from localstack.services.s3 import s3_listener
from localstack.utils.common import json_safe, md5, canonical_json, short_uid
from localstack.utils.testutil import create_zip_file, delete_all_s3_objects
from localstack.services.awslambda.lambda_api import get_handler_file_from_name, POLICY_NAME_PATTERN

ACTION_CREATE = 'create'
ACTION_DELETE = 'delete'
PLACEHOLDER_RESOURCE_NAME = '__resource_name__'
PLACEHOLDER_AWS_NO_VALUE = '__aws_no_value__'
AWS_URL_SUFFIX = 'localhost'  # value is "amazonaws.com" in real AWS
IAM_POLICY_VERSION = '2012-10-17'

LOG = logging.getLogger(__name__)

# list of resource types that can be updated
UPDATEABLE_RESOURCES = ['Lambda::Function', 'ApiGateway::Method', 'StepFunctions::StateMachine']

# list of static attribute references to be replaced in {'Fn::Sub': '...'} strings
STATIC_REFS = ['AWS::Region', 'AWS::Partition', 'AWS::StackName', 'AWS::AccountId']

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


class NoStackUpdates(Exception):
    """ Exception indicating that no actions are to be performed in a stack update (which is not allowed) """
    pass


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
            'function': 'delete_bucket',
            'parameters': {
                'Bucket': 'BucketName'
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
                'SecretId': 'Name'
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
                'DeliveryStreamName': 'DeliveryStreamName'
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
                'DomainName': 'DomainName'
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
                'logGroupName': 'LogGroupName'
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
                'TableName': 'TableName'
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
                'RoleName': 'RoleName'
            }
        }
    },
    'IAM::Policy': {
        'create': {
            'function': 'create_policy',
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
                'StreamName': 'Name'
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

def get_secret_arn(secret_name, account_id=None):
    # TODO: create logic to create static without lookup table!
    from localstack.services.secretsmanager import secretsmanager_starter
    storage = secretsmanager_starter.SECRET_ARN_STORAGE
    key = '%s_%s' % (aws_stack.get_region(), secret_name)
    return storage.get(key) or storage.get(secret_name)


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


def find_stack(stack_name):
    from localstack.services.cloudformation.cloudformation_api import find_stack as api_find_stack
    return api_find_stack(stack_name)


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
        return parts[0]
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


def retrieve_resource_details(resource_id, resource_status, resources, stack_name):
    resource = resources.get(resource_id)
    resource_id = resource_status.get('PhysicalResourceId') or resource_id
    if not resource:
        resource = {}
    resource_type = get_resource_type(resource)
    resource_props = resource.get('Properties')
    if resource_props is None:
        raise Exception('Unable to find properties for resource "%s": %s %s' % (resource_id, resource, resources))
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

        elif resource_type == 'Lambda::Permission':
            iam = aws_stack.connect_to_service('iam')
            policy_name = POLICY_NAME_PATTERN % resource_props.get('FunctionName')
            policy_arn = aws_stack.policy_arn(policy_name)
            policy = iam.get_policy(PolicyArn=policy_arn)['Policy']
            version = policy.get('DefaultVersionId')
            policy = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)['PolicyVersion']
            statements = policy['Document']['Statement']
            statements = statements if isinstance(statements, list) else [statements]
            func_arn = aws_stack.lambda_function_arn(resource_props['FunctionName'])
            principal = resource_props.get('Principal')
            existing = [s for s in statements if s['Action'] == resource_props['Action'] and
                s['Resource'] == func_arn and
                (not principal or s['Principal'] in [{'Service': principal}, {'Service': [principal]}])]
            return existing[0] if existing else None

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
            return match[0] if match else None

        elif resource_type == 'ApiGateway::GatewayResponse':
            api_id = resolve_refs_recursively(stack_name, resource_props['RestApiId'], resources)
            if not api_id:
                return
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
            if topic_arn is None:
                return
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
            def _filter(pols):
                return [p for p in pols['AttachedPolicies'] if p['PolicyName'] == policy_name]
            iam = aws_stack.connect_to_service('iam')
            policy_name = resource_props['PolicyName']
            # The policy in cloudformation is InlinePolicy, which can be attached to either of [Roles, Users, Groups]
            # https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html
            result = {}
            roles = resource['Properties'].get('Roles', [])
            users = resource['Properties'].get('Users', [])
            groups = resource['Properties'].get('Groups', [])
            for role in roles:
                role = resolve_refs_recursively(stack_name, role, resources)
                result['role:%s' % role] = _filter(iam.list_attached_role_policies(RoleName=role))
            for user in users:
                user = resolve_refs_recursively(stack_name, user, resources)
                result['user:%s' % user] = _filter(iam.list_attached_user_policies(UserName=user))
            for group in groups:
                group = resolve_refs_recursively(stack_name, group, resources)
                result['group:%s' % group] = _filter(iam.list_attached_group_policies(GroupName=group))
            return {k: v for k, v in result.items() if v}

        elif resource_type == 'CloudFormation::Stack':
            client = aws_stack.connect_to_service('cloudformation')
            child_stack_name = resource_props.get('StackName') or resource_id
            child_stack_name = resolve_refs_recursively(stack_name, child_stack_name, resources)
            result = client.describe_stacks(StackName=child_stack_name)
            return (result.get('Stacks') or [None])[0]

        elif resource_type == 'Parameter':
            return resource_props

        # fallback: try accessing stack.moto_resource_statuses
        stack = find_stack(stack_name)
        moto_resource = stack.moto_resource_statuses.get(resource_id)
        if moto_resource:
            return moto_resource

        # if is_deployable_resource(resource):
        LOG.warning('Unexpected resource type %s when resolving references of resource %s: %s' %
                    (resource_type, resource_id, resource))

    except DependencyNotYetSatisfied:
        return
    except Exception as e:
        check_not_found_exception(e, resource_type, resource, resource_status)

    return None


def check_not_found_exception(e, resource_type, resource, resource_status):
    # we expect this to be a "not found" exception
    markers = ['NoSuchBucket', 'ResourceNotFound', 'NoSuchEntity', 'NotFoundException', '404', 'not found']
    if not list(filter(lambda marker, e=e: marker in str(e), markers)):
        LOG.warning('Unexpected error retrieving details for resource %s: %s %s - %s %s' %
            (resource_type, e, ''.join(traceback.format_stack()), resource, resource_status))


def extract_resource_attribute(resource_type, resource_json, attribute, resource_id=None,
        resource=None, resources=None, stack_name=None):
    LOG.debug('Extract resource attribute: %s %s' % (resource_type, attribute))
    is_ref_attribute = attribute in ['PhysicalResourceId', 'Ref']
    is_ref_attr_or_arn = is_ref_attribute or attribute == 'Arn'
    resource = resource or {}

    if not resource:
        resource = retrieve_resource_details(resource_id, {}, resources, stack_name)
        if not resource:
            return
    if isinstance(resource, MotoCloudFormationModel):
        if is_ref_attribute:
            return getattr(resource, 'physical_resource_id', None)
        if hasattr(resource, 'get_cfn_attribute'):
            return resource.get_cfn_attribute(attribute)
        raise Exception('Unable to extract attribute "%s" from model class %s' % (attribute, type(resource)))

    resource_props = resource.get('Properties', {})
    # extract resource specific attributes
    if resource_type == 'Parameter':
        result = None
        param_value = resource_props.get('Value', resource_json.get('Value',
            resource_json.get('Properties', {}).get('Value')))
        if is_ref_attr_or_arn:
            result = param_value
        elif isinstance(param_value, dict):
            result = param_value.get(attribute)
        if result is not None:
            return result
    elif resource_type == 'Lambda::Function':
        func_configs = resource_json.get('Configuration') or resource.get('Configuration') or {}
        if is_ref_attr_or_arn:
            func_arn = func_configs.get('FunctionArn')
            if func_arn:
                return resolve_refs_recursively(stack_name, func_arn, resources)
            func_name = resolve_refs_recursively(stack_name, func_configs.get('FunctionName'), resources)
            return aws_stack.lambda_function_arn(func_name)
        else:
            return func_configs.get(attribute)
    elif resource_type == 'DynamoDB::Table':
        actual_attribute = 'LatestStreamArn' if attribute == 'StreamArn' else attribute
        value = resource_json.get('Table', {}).get(actual_attribute)
        if value:
            return value
    elif resource_type == 'ApiGateway::RestApi':
        if is_ref_attribute:
            result = resource_json.get('id')
            if result:
                return result
        if attribute == 'RootResourceId':
            resources = aws_stack.connect_to_service('apigateway').get_resources(restApiId=resource_json['id'])['items']
            for res in resources:
                if res['path'] == '/' and not res.get('parentId'):
                    return res['id']
    elif resource_type == 'ApiGateway::Resource':
        if is_ref_attribute:
            return resource.get('id')
    elif resource_type == 'ApiGateway::Deployment':
        if is_ref_attribute:
            return resource.get('id')
    elif resource_type == 'S3::Bucket':
        if is_ref_attr_or_arn:
            bucket_name = resource_props.get('BucketName')
            bucket_name = resolve_refs_recursively(stack_name, bucket_name, resources)
            if attribute == 'Arn':
                return aws_stack.s3_bucket_arn(bucket_name)
            return bucket_name
    elif resource_type == 'Elasticsearch::Domain':
        if attribute == 'DomainEndpoint':
            domain_status = resource_props.get('DomainStatus') or resource_json.get('DomainStatus', {})
            result = domain_status.get('Endpoint')
            if result:
                return result
        if attribute in ['Arn', 'DomainArn']:
            domain_name = resource_props.get('DomainName') or resource_json.get('DomainName')
            return aws_stack.es_domain_arn(domain_name)
    elif resource_type == 'SNS::Topic':
        if is_ref_attribute and resource_json.get('TopicArn'):
            topic_arn = resource_json.get('TopicArn')
            return resolve_refs_recursively(stack_name, topic_arn, resources)
    elif resource_type == 'SQS::Queue':
        if is_ref_attr_or_arn:
            if attribute == 'Arn' and resource_json.get('QueueArn'):
                return resolve_refs_recursively(stack_name, resource_json.get('QueueArn'), resources)
            return aws_stack.get_sqs_queue_url(resource_props.get('QueueName'))
    attribute_lower = common.first_char_to_lower(attribute)
    result = resource_json.get(attribute) or resource_json.get(attribute_lower)
    if result is None and isinstance(resource, dict):
        result = resource_props.get(attribute) or resource_props.get(attribute_lower)
        if result is None:
            result = get_attr_from_model_instance(resource, attribute,
                resource_type=resource_type, resource_id=resource_id)
    if is_ref_attribute:
        for attr in ['Id', 'PhysicalResourceId', 'Ref']:
            if result is None:
                for obj in [resource_json, resource]:
                    result = result or obj.get(attr)
    return result


def canonical_resource_type(resource_type):
    if '::' in resource_type and not resource_type.startswith('AWS::'):
        resource_type = 'AWS::%s' % resource_type
    return resource_type


def get_attr_from_model_instance(resource, attribute, resource_type, resource_id=None):
    resource_type = canonical_resource_type(resource_type)
    model_clazz = parsing.MODEL_MAP.get(resource_type)
    if not model_clazz:
        if resource_type != 'AWS::Parameter':
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
    if ref == 'AWS::StackId':
        # TODO return proper stack id!
        return stack_name
    if ref == 'AWS::AccountId':
        return TEST_AWS_ACCOUNT_ID
    if ref == 'AWS::NoValue':
        return PLACEHOLDER_AWS_NO_VALUE
    if ref == 'AWS::NotificationARNs':
        # TODO!
        return {}
    if ref == 'AWS::URLSuffix':
        return AWS_URL_SUFFIX

    # second, resolve resource references
    resource_status = {}

    is_ref_attribute = attribute in ['Ref', 'PhysicalResourceId', 'Arn']
    if is_ref_attribute:
        resolve_refs_recursively(stack_name, resources[ref], resources)
        return determine_resource_physical_id(resource_id=ref,
            resources=resources, attribute=attribute, stack_name=stack_name)

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
        LOG.warning('Unable to extract reference attribute "%s" from resource: %s %s' %
            (attribute, resource_new, resource))
    return result


def resolve_refs_recursively(stack_name, value, resources):
    if isinstance(value, dict):
        keys_list = list(value.keys())
        stripped_fn_lower = keys_list[0].lower().split('::')[-1] if len(keys_list) == 1 else None

        # process special operators
        if keys_list == ['Ref']:
            ref = resolve_ref(stack_name, value['Ref'], resources, attribute='Ref')
            if ref is None:
                msg = 'Unable to resolve Ref for resource %s' % value['Ref']
                LOG.info('%s - existing: %s %s' % (msg, set(resources.keys()), resources.get(value['Ref'])))
                raise DependencyNotYetSatisfied(resource_ids=value['Ref'], message=msg)
            ref = resolve_refs_recursively(stack_name, ref, resources)
            return ref

        if stripped_fn_lower == 'getatt':
            return resolve_ref(stack_name, value[keys_list[0]][0], resources, attribute=value[keys_list[0]][1])

        if stripped_fn_lower == 'join':
            join_values = value[keys_list[0]][1]
            join_values = [resolve_refs_recursively(stack_name, v, resources) for v in join_values]
            none_values = [v for v in join_values if v is None]
            if none_values:
                raise Exception('Cannot resolve CF fn::Join %s due to null values: %s' % (value, join_values))
            return value[keys_list[0]][0].join([str(v) for v in join_values])

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
            attr = resolve_refs_recursively(stack_name, value[keys_list[0]][1], resources)
            result = resolve_ref(stack_name, value[keys_list[0]][0], resources, attribute=attr)
            if not result:
                raise Exception('Cannot resolve fn::FindInMap: %s %s' % (value[keys_list[0]], list(resources.keys())))

            result = result.get(value[keys_list[0]][2])
            return result

        if stripped_fn_lower == 'importvalue':
            exports = cloudformation_backends[aws_stack.get_region()].exports
            import_value_key = resolve_refs_recursively(stack_name, value[keys_list[0]], resources)
            export = exports[import_value_key]
            return export.value

        if stripped_fn_lower == 'if':
            condition, option1, option2 = value[keys_list[0]]
            condition = evaluate_condition(stack_name, condition, resources)
            return resolve_refs_recursively(stack_name, option1 if condition else option2, resources)

        if stripped_fn_lower == 'not':
            condition = value[keys_list[0]][0]
            condition = resolve_refs_recursively(stack_name, condition, resources)
            return not condition

        if stripped_fn_lower == 'equals':
            operand1, operand2 = value[keys_list[0]]
            operand1 = resolve_refs_recursively(stack_name, operand1, resources)
            operand2 = resolve_refs_recursively(stack_name, operand2, resources)
            return str(operand1) == str(operand2)

        for key, val in value.items():
            value[key] = resolve_refs_recursively(stack_name, val, resources)

    if isinstance(value, list):
        for i in range(len(value)):
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
                resources=resources, resource_id=parts[0], stack_name=stack_name)
            if result is None:
                raise DependencyNotYetSatisfied(resource_ids=parts[0],
                    message='Unable to resolve attribute ref %s' % match.group(1))
            return result
        # TODO raise exception here?
        return match.group(0)
    regex = r'\$\{([^\}]+)\}'
    result = re.sub(regex, _replace, result)
    return result


def evaluate_condition(stack_name, condition, resources):
    condition = resolve_refs_recursively(stack_name, condition, resources)
    condition = resolve_ref(stack_name, condition, resources, attribute='Ref')
    condition = resolve_refs_recursively(stack_name, condition, resources)
    return condition


def evaluate_resource_condition(resource, stack_name, resources):
    condition = resource.get('Condition')
    if condition:
        condition = evaluate_condition(stack_name, condition, resources)
        if is_none_or_empty_value(condition):
            return False
    return True


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
        role_name = res.get('PhysicalResourceId') or res.get('Properties', {}).get('RoleName')
        try:
            iam_client = aws_stack.connect_to_service('iam')
            rs = iam_client.list_role_policies(RoleName=role_name)
            for policy in rs['PolicyNames']:
                iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy)
        except Exception as e:
            if 'NoSuchEntity' not in str(e):
                raise

    return execute_resource_action(resource_id, resources, stack_name, ACTION_DELETE)


def execute_resource_action_fallback(action_name, resource_id, resources, stack_name, resource, resource_type):
    # using moto as fallback for now - TODO remove in the future!
    msg = 'Action "%s" for resource type %s not yet implemented' % (action_name, resource_type)
    long_type = canonical_resource_type(resource_type)
    clazz = parsing.MODEL_MAP.get(long_type)
    if not clazz:
        LOG.warning(msg)
        return
    LOG.info('%s - using fallback mechanism' % msg)
    if action_name == ACTION_CREATE:
        resource_name = get_resource_name(resource) or resource_id
        result = clazz.create_from_cloudformation_json(resource_name, resource, aws_stack.get_region())
        return result


def execute_resource_action(resource_id, resources, stack_name, action_name):
    resource = resources[resource_id]
    resource_type = get_resource_type(resource)
    func_details = RESOURCE_TO_FUNCTION.get(resource_type)

    if not func_details or action_name not in func_details:
        if resource_type in ['Parameter']:
            return
        return execute_resource_action_fallback(action_name,
            resource_id, resources, stack_name, resource, resource_type)

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
            result = configure_resource_via_sdk(resource_id, resources, resource_type, func, stack_name, action_name)
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


def configure_resource_via_sdk(resource_id, resources, resource_type, func_details, stack_name, action_name):
    resource = resources[resource_id]
    client = get_client(resource, func_details)
    function = getattr(client, func_details['function'])
    params = func_details.get('parameters') or lambda_get_params()
    defaults = func_details.get('defaults', {})
    resource_props = resource['Properties'] = resource.get('Properties', {})
    resource_props = dict(resource_props)

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
                        prop_value = resource_props.get(prop_key, resource.get(prop_key))
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

    # run pre-actions
    run_pre_create_actions(action_name, resource_id, resources, resource_type, stack_name, params)

    # invoke function
    try:
        LOG.debug('Request for resource type "%s" in region %s: %s %s' % (
            resource_type, aws_stack.get_region(), func_details['function'], params))
        result = function(**params)
    except Exception as e:
        LOG.warning('Error calling %s with params: %s for resource: %s' % (function, params, resource))
        raise e

    # run post-actions
    run_post_create_actions(action_name, resource_id, resources, resource_type, stack_name, result)

    return result


# TODO: move as individual functions to RESOURCE_TO_FUNCTION
def run_pre_create_actions(action_name, resource_id, resources, resource_type, stack_name, resource_params):
    resource = resources[resource_id]
    resource_props = resource['Properties'] = resource.get('Properties', {})
    if resource_type == 'IAM::Role' and action_name == ACTION_DELETE:
        iam = aws_stack.connect_to_service('iam')
        role_name = resource_props['RoleName']
        for policy in iam.list_attached_role_policies(RoleName=role_name).get('AttachedPolicies', []):
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy['PolicyArn'])
    if resource_type == 'S3::Bucket' and action_name == ACTION_DELETE:
        s3 = aws_stack.connect_to_service('s3')
        bucket_name = resource_props.get('BucketName')
        try:
            s3.delete_bucket_policy(Bucket=bucket_name)
        except Exception:
            pass
        # TODO: verify whether AWS CF automatically deletes all bucket objects, or fails if bucket is non-empty
        try:
            delete_all_s3_objects(bucket_name)
        except Exception as e:
            if 'NoSuchBucket' not in str(e):
                raise
        # hack: make sure the bucket actually exists, to prevent delete_bucket operation later on from failing
        s3.create_bucket(Bucket=bucket_name)


# TODO: move as individual functions to RESOURCE_TO_FUNCTION
def run_post_create_actions(action_name, resource_id, resources, resource_type, stack_name, result):
    if action_name == ACTION_DELETE:
        return result

    resource = resources[resource_id]
    resource_props = resource['Properties'] = resource.get('Properties', {})

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
            client = aws_stack.connect_to_service('apigateway')
            body = json.dumps(body) if isinstance(body, dict) else body
            client.put_rest_api(restApiId=result['id'], body=common.to_bytes(body))

    elif resource_type == 'SNS::Topic':
        subscriptions = resource_props.get('Subscription', [])
        for subscription in subscriptions:
            if is_none_or_empty_value(subscription):
                continue
            endpoint = resolve_refs_recursively(stack_name, subscription['Endpoint'], resources)
            topic_arn = retrieve_topic_arn(resource_props['TopicName'])
            aws_stack.connect_to_service('sns').subscribe(
                TopicArn=topic_arn, Protocol=subscription['Protocol'], Endpoint=endpoint
            )

    elif resource_type == 'S3::Bucket':
        tags = resource_props.get('Tags')
        if tags:
            aws_stack.connect_to_service('s3').put_bucket_tagging(
                Bucket=resource_props['BucketName'], Tagging={'TagSet': tags})

    elif resource_type == 'IAM::Role':
        policies = resource_props.get('Policies', [])
        for policy in policies:
            iam = aws_stack.connect_to_service('iam')
            pol_name = policy['PolicyName']
            doc = dict(policy['PolicyDocument'])
            doc['Version'] = doc.get('Version') or IAM_POLICY_VERSION
            doc = json.dumps(doc)
            iam.put_role_policy(RoleName=resource_props['RoleName'], PolicyName=pol_name, PolicyDocument=doc)

    elif resource_type == 'IAM::Policy':
        # associate policies with users, groups, roles
        groups = resource_props.get('Groups', [])
        roles = resource_props.get('Roles', [])
        users = resource_props.get('Users', [])
        policy_arn = aws_stack.policy_arn(resource_props.get('PolicyName'))
        iam = aws_stack.connect_to_service('iam')
        for group in groups:
            iam.attach_group_policy(GroupName=group, PolicyArn=policy_arn)
        for role in roles:
            iam.attach_role_policy(RoleName=role, PolicyArn=policy_arn)
        for user in users:
            iam.attach_user_policy(UserName=user, PolicyArn=policy_arn)


def is_none_or_empty_value(value):
    return not value or value == PLACEHOLDER_AWS_NO_VALUE


def determine_resource_physical_id(resource_id, resources=None, stack=None, attribute=None, stack_name=None):
    resources = resources or stack.resources
    stack_name = stack_name or stack.stack_name
    resource = resources.get(resource_id, {})
    if not resource:
        return
    resource_type = resource.get('Type') or ''
    resource_type = re.sub('^AWS::', '', resource_type)
    resource_props = resource.get('Properties', {})

    # TODO: put logic into resource-specific model classes
    if resource_type == 'SQS::Queue':
        try:
            return aws_stack.get_sqs_queue_url(resource_props.get('QueueName'))
        except Exception as e:
            if 'NonExistentQueue' in str(e):
                raise DependencyNotYetSatisfied(resource_ids=resource_id, message='Unable to get queue: %s' % e)
    elif resource_type == 'SNS::Topic':
        return aws_stack.sns_topic_arn(resource_props.get('TopicName'))
    elif resource_type == 'ApiGateway::RestApi':
        result = resource_props.get('id')
        if result:
            return result
    elif resource_type == 'ApiGateway::Stage':
        return resource_props.get('StageName')
    elif resource_type == 'Kinesis::Stream':
        return aws_stack.kinesis_stream_arn(resource_props.get('Name'))
    elif resource_type == 'KinesisFirehose::DeliveryStream':
        return aws_stack.firehose_stream_arn(resource_props.get('DeliveryStreamName'))
    elif resource_type == 'Events::Rule':
        return resource_props.get('Name')
    elif resource_type == 'Lambda::Function':
        if attribute == 'Arn':
            return aws_stack.lambda_function_arn(resource_props.get('FunctionName'))
        return resource_props.get('FunctionName')
    elif resource_type == 'StepFunctions::StateMachine':
        return aws_stack.state_machine_arn(resource_props.get('StateMachineName'))  # returns ARN in AWS
    elif resource_type == 'S3::Bucket':
        if attribute == 'Arn':
            return aws_stack.s3_bucket_arn(resource_props.get('BucketName'))
        return resource_props.get('BucketName')  # Note: "Ref" returns bucket name in AWS
    elif resource_type == 'IAM::Role':
        if attribute == 'Arn':
            return aws_stack.role_arn(resource_props.get('RoleName'))
        return resource_props.get('RoleName')
    elif resource_type == 'SecretsManager::Secret':
        arn = get_secret_arn(resource_props.get('Name')) or ''
        if attribute == 'Arn':
            return arn
        return arn.split(':')[-1]
    elif resource_type == 'IAM::Policy':
        if attribute == 'Arn':
            return aws_stack.policy_arn(resource_props.get('PolicyName'))
        return resource_props.get('PolicyName')
    elif resource_type == 'DynamoDB::Table':
        if attribute == 'Ref':
            return resource_props.get('TableName')  # Note: "Ref" returns table name in AWS
        return aws_stack.dynamodb_table_arn(resource_props.get('TableName'))

    res_id = resource.get('PhysicalResourceId')
    if res_id:
        return res_id
    result = extract_resource_attribute(resource_type, resource_props, attribute or 'PhysicalResourceId',
        stack_name=stack_name, resource_id=resource_id, resources=resources)
    if result is not None:
        # note that value could be an empty string here (in case of Parameter values)
        return result
    LOG.info('Unable to determine PhysicalResourceId for "%s" resource, ID "%s"' % (resource_type, resource_id))


def update_resource_details(stack, resource_id, details):
    resource = stack.resources.get(resource_id, {})
    if not resource:
        return
    resource_type = resource.get('Type') or ''
    resource_type = re.sub('^AWS::', '', resource_type)
    resource_props = resource.get('Properties', {})
    if resource_type == 'ApiGateway::RestApi':
        resource_props['id'] = details['id']
    if isinstance(details, MotoCloudFormationModel):
        # fallback: keep track of moto resource status
        stack.moto_resource_statuses[resource_id] = details


def add_default_resource_props(resource_props, stack_name, resource_name=None,
        resource_id=None, update=False, existing_resources=None):
    """ Apply some fixes to resource props which otherwise cause deployments to fail """

    res_type = resource_props['Type']
    props = resource_props['Properties'] = resource_props.get('Properties', {})
    existing_resources = existing_resources or {}

    def _generate_res_name():
        return '%s-%s-%s' % (stack_name, resource_name or resource_id, short_uid())

    if res_type == 'AWS::Lambda::EventSourceMapping' and not props.get('StartingPosition'):
        props['StartingPosition'] = 'LATEST'

    elif res_type == 'AWS::Logs::LogGroup' and not props.get('LogGroupName') and resource_name:
        props['LogGroupName'] = resource_name

    elif res_type == 'AWS::Lambda::Function' and not props.get('FunctionName'):
        props['FunctionName'] = '{}-lambda-{}'.format(stack_name[:45], short_uid())

    elif res_type == 'AWS::SNS::Topic' and not props.get('TopicName'):
        props['TopicName'] = 'topic-%s' % short_uid()

    elif res_type == 'AWS::SQS::Queue' and not props.get('QueueName'):
        props['QueueName'] = 'queue-%s' % short_uid()

    elif res_type == 'AWS::ApiGateway::RestApi' and not props.get('Name'):
        props['Name'] = _generate_res_name()

    elif res_type == 'AWS::DynamoDB::Table':
        update_dynamodb_index_resource(resource_props)

    elif res_type == 'AWS::S3::Bucket' and not props.get('BucketName'):
        existing_bucket = existing_resources.get(resource_id) or {}
        bucket_name = existing_bucket.get('Properties', {}).get('BucketName') or _generate_res_name()
        props['BucketName'] = s3_listener.normalize_bucket_name(bucket_name)

    elif res_type == 'AWS::StepFunctions::StateMachine' and not props.get('StateMachineName'):
        props['StateMachineName'] = _generate_res_name()

    # generate default names for certain resource types
    default_attrs = (('AWS::IAM::Role', 'RoleName'), ('AWS::Events::Rule', 'Name'))
    for entry in default_attrs:
        if res_type == entry[0] and not props.get(entry[1]):
            if not resource_id:
                resource_id = canonical_json(json_safe(props))
                resource_id = md5(resource_id)
            props[entry[1]] = 'cf-%s-%s' % (stack_name, resource_id)


def update_dynamodb_index_resource(resource):
    if resource.get('Properties').get('BillingMode') == 'PAY_PER_REQUEST':
        for glob_index in resource.get('Properties', {}).get('GlobalSecondaryIndexes', []):
            if not glob_index.get('ProvisionedThroughput'):
                glob_index['ProvisionedThroughput'] = {'ReadCapacityUnits': 99, 'WriteCapacityUnits': 99}


# -----------------------
# MAIN TEMPLATE DEPLOYER
# -----------------------

class TemplateDeployer(object):
    def __init__(self, stack):
        self.stack = stack

    @property
    def resources(self):
        return self.stack.resources

    @property
    def stack_name(self):
        return self.stack.stack_name

    # ------------------
    # MAIN ENTRY POINTS
    # ------------------

    def deploy_stack(self):
        self.stack.set_stack_status('CREATE_IN_PROGRESS')
        # create new copy of stack
        new_stack = self.stack.copy()
        # apply changes
        self.apply_changes(self.stack, new_stack, stack_name=self.stack.stack_name, initialize=True)
        # update status
        self.stack.set_stack_status('CREATE_COMPLETE')

    def apply_change_set(self, change_set):
        change_set.stack.set_stack_status('UPDATE_IN_PROGRESS')
        # apply changes
        change_set.changes = self.apply_changes(change_set.stack, change_set, stack_name=change_set.stack_name)
        # update status
        change_set.metadata['Status'] = 'CREATE_COMPLETE'
        change_set.stack.set_stack_status('CREATE_COMPLETE')

    def update_stack(self, new_stack):
        self.stack.set_stack_status('UPDATE_IN_PROGRESS')
        # apply changes
        self.apply_changes(self.stack, new_stack, stack_name=self.stack.stack_name)
        # update status
        self.stack.set_stack_status('UPDATE_COMPLETE')

    def delete_stack(self):
        self.stack.set_stack_status('DELETE_IN_PROGRESS')
        stack_resources = list(self.stack.resources.values())
        stack_name = self.stack.stack_name
        resources = dict([(r['LogicalResourceId'], common.clone_safe(r)) for r in stack_resources])
        for key, resource in resources.items():
            resource['Properties'] = resource.get('Properties', common.clone_safe(resource))
            resource['ResourceType'] = resource.get('ResourceType') or resource.get('Type')
        for resource_id, resource in resources.items():
            # TODO: cache condition value in resource details on deployment and use cached value here
            if evaluate_resource_condition(resource, stack_name, resources):
                delete_resource(resource_id, resources, stack_name)
        # update status
        self.stack.set_stack_status('DELETE_COMPLETE')

    # ----------------------------
    # DEPENDENCY RESOLUTION UTILS
    # ----------------------------

    def is_deployable_resource(self, resource):
        resource_type = get_resource_type(resource)
        entry = RESOURCE_TO_FUNCTION.get(resource_type)
        if entry is None and resource_type not in ['Parameter', None]:
            # fall back to moto resource creation (TODO: remove in the future)
            long_res_type = canonical_resource_type(resource_type)
            if long_res_type in parsing.MODEL_MAP:
                return True
            LOG.warning('Unable to deploy resource type "%s": %s' % (resource_type, resource))
        return bool(entry and entry.get(ACTION_CREATE))

    def is_deployed(self, resource):
        resource_status = {}
        resource_id = resource['LogicalResourceId']
        details = retrieve_resource_details(resource_id, resource_status, self.resources, self.stack_name)
        return bool(details)

    def is_updateable(self, resource):
        """ Return whether the given resource can be updated or not. """
        if not self.is_deployable_resource(resource) or not self.is_deployed(resource):
            return False
        resource_type = get_resource_type(resource)
        return resource_type in UPDATEABLE_RESOURCES

    def all_resource_dependencies_satisfied(self, resource):
        unsatisfied = self.get_unsatisfied_dependencies(resource)
        return not unsatisfied

    def get_unsatisfied_dependencies(self, resource):
        res_deps = self.get_resource_dependencies(resource)
        return self.get_unsatisfied_dependencies_for_resources(res_deps, resource)

    def get_unsatisfied_dependencies_for_resources(self, resources, depending_resource=None, return_first=True):
        result = {}
        for resource_id, resource in iteritems(resources):
            if self.is_deployable_resource(resource):
                if not self.is_deployed(resource):
                    LOG.debug('Dependency for resource %s not yet deployed: %s %s' %
                        (depending_resource, resource_id, resource))
                    result[resource_id] = resource
                    if return_first:
                        break
        return result

    def get_resource_dependencies(self, resource):
        result = {}
        # Note: using the original, unmodified template here to preserve Ref's ...
        raw_resources = self.stack.template_original['Resources']
        raw_resource = raw_resources[resource['LogicalResourceId']]
        dumped = json.dumps(common.json_safe(raw_resource))
        for other_id, other in raw_resources.items():
            if resource != other:
                # TODO: traverse dict instead of doing string search!
                search1 = '{"Ref": "%s"}' % other_id
                search2 = '{"Fn::GetAtt": ["%s", ' % other_id
                if search1 in dumped or search2 in dumped:
                    result[other_id] = other
                if other_id in resource.get('DependsOn', []):
                    result[other_id] = other
        return result

    # -----------------
    # DEPLOYMENT UTILS
    # -----------------

    def add_default_resource_props(self, resources=None):
        resources = resources or self.resources
        for resource_id, resource in resources.items():
            add_default_resource_props(resource, self.stack_name, resource_id=resource_id)

    def init_resource_status(self, resources=None, stack=None, action='CREATE'):
        resources = resources or self.resources
        stack = stack or self.stack
        for resource_id, resource in resources.items():
            stack.set_resource_status(resource_id, '%s_IN_PROGRESS' % action)

    def update_resource_details(self, resource_id, result, stack=None, action='CREATE'):
        stack = stack or self.stack
        # update resource state
        update_resource_details(stack, resource_id, result)
        # update physical resource id
        resource = stack.resources[resource_id]
        physical_id = resource.get('PhysicalResourceId')
        physical_id = physical_id or determine_resource_physical_id(resource_id, stack=stack)
        if not resource.get('PhysicalResourceId') or action == 'UPDATE':
            resource['PhysicalResourceId'] = physical_id
        # set resource status
        stack.set_resource_status(resource_id, '%s_COMPLETE' % action, physical_res_id=physical_id)
        return physical_id

    def get_change_config(self, action, resource, change_set_id=None):
        return {
            'Type': 'Resource',
            'ResourceChange': {
                'Action': action,
                'LogicalResourceId': resource.get('LogicalResourceId'),
                'PhysicalResourceId': resource.get('PhysicalResourceId'),
                'ResourceType': resource.get('Type'),
                'Replacement': 'False',
                'ChangeSetId': change_set_id
            }
        }

    def resource_config_differs(self, resource_new):
        """ Return whether the given resource properties differ from the existing config (for stack updates). """
        resource_old = self.resources[resource_new['LogicalResourceId']]
        props_old = resource_old['Properties']
        props_new = resource_new['Properties']
        ignored_keys = ['LogicalResourceId', 'PhysicalResourceId']
        old_keys = set(props_old.keys()) - set(ignored_keys)
        new_keys = set(props_new.keys()) - set(ignored_keys)
        if old_keys != new_keys:
            return True
        for key in old_keys:
            if props_old[key] != props_new[key]:
                return True

    def merge_properties(self, resource_id, old_stack, new_stack):
        old_resources = old_stack.template['Resources']
        new_resources = new_stack.template['Resources']
        new_resource = new_resources[resource_id]
        old_resource = old_resources[resource_id] = old_resources.get(resource_id) or {}
        for key, value in new_resource.items():
            if key == 'Properties':
                continue
            old_resource[key] = old_resource.get(key, value)
        old_res_props = old_resource['Properties'] = old_resource.get('Properties', {})
        for key, value in new_resource['Properties'].items():
            old_res_props[key] = old_res_props.get(key, value)
        # overwrite original template entirely
        old_stack.template_original['Resources'][resource_id] = new_stack.template_original['Resources'][resource_id]

    def apply_changes(self, old_stack, new_stack, stack_name, change_set_id=None, initialize=False):
        old_resources = old_stack.template['Resources']
        new_resources = new_stack.template['Resources']
        self.init_resource_status(old_resources, action='UPDATE')
        deletes = [val for key, val in old_resources.items() if key not in new_resources]
        adds = [val for key, val in new_resources.items() if initialize or key not in old_resources]
        modifies = [val for key, val in new_resources.items() if key in old_resources]

        # construct changes
        changes = []
        for action, items in (('Remove', deletes), ('Add', adds), ('Modify', modifies)):
            for item in items:
                item['Properties'] = item.get('Properties', {})
                if action != 'Modify' or self.resource_config_differs(item):
                    change = self.get_change_config(action, item, change_set_id=change_set_id)
                    changes.append(change)
                if action in ['Modify', 'Add']:
                    self.merge_properties(item['LogicalResourceId'], old_stack, new_stack)
        if not changes:
            raise NoStackUpdates('No updates are to be performed.')

        # start deployment loop
        return self.apply_changes_in_loop(changes, old_stack, stack_name)

    def apply_changes_in_loop(self, changes, stack, stack_name):
        # apply changes in a retry loop, to resolve resource dependencies and converge to the target state
        changes_done = []
        max_iters = 30
        new_resources = stack.resources
        for i in range(max_iters):
            j = 0
            updated = False
            while j < len(changes):
                change = changes[j]
                action = change['ResourceChange']['Action']
                is_add_or_modify = action in ['Add', 'Modify']
                resource_id = change['ResourceChange']['LogicalResourceId']
                try:
                    if is_add_or_modify:
                        resource = new_resources[resource_id]
                        should_deploy = self.prepare_should_deploy_change(
                            resource_id, action, stack, new_resources)
                        if not should_deploy:
                            del changes[j]
                            continue
                        if not self.all_resource_dependencies_satisfied(resource):
                            j += 1
                            continue
                    self.apply_change(change, stack, new_resources, stack_name=stack_name)
                    changes_done.append(change)
                    del changes[j]
                    updated = True
                except DependencyNotYetSatisfied as e:
                    LOG.debug('Dependencies for "%s" not yet satisfied, retrying in next loop: %s' % (resource_id, e))
                    j += 1
            if not changes:
                break
            if not updated:
                raise Exception('Resource deployment loop completed, pending resource changes: %s' % changes)

        return changes_done

    def prepare_should_deploy_change(self, resource_id, action, stack, new_resources):
        resource = new_resources[resource_id]

        # resolve refs in resource details
        add_default_resource_props(resource, stack.stack_name, resource_id=resource_id,
            existing_resources=stack.resources)
        resolve_refs_recursively(stack.stack_name, resource, new_resources)

        if action == 'Add':
            if not self.is_deployable_resource(resource) or self.is_deployed(resource):
                return False
        if action == 'Modify' and not self.is_updateable(resource):
            return False
        return True

    def apply_change(self, change, old_stack, new_resources, stack_name):
        change_details = change['ResourceChange']
        action = change_details['Action']
        resource_id = change_details['LogicalResourceId']
        resource = new_resources[resource_id]
        if not evaluate_resource_condition(resource, stack_name, new_resources):
            return
        # execute resource action
        if action == 'Add':
            result = deploy_resource(resource_id, new_resources, stack_name)
        elif action == 'Remove':
            old_stack.template['Resources'].pop(resource_id, None)
            result = delete_resource(resource_id, old_stack.resources, stack_name)
        elif action == 'Modify':
            result = update_resource(resource_id, new_resources, stack_name)
        # update resource status and physical resource id
        self.update_resource_details(resource_id, result, stack=old_stack, action='UPDATE')
        return result
