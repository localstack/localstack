import json
import yaml
from six import iteritems
from six import string_types
from localstack.utils.aws import aws_stack

ACTION_CREATE = 'create'

RESOURCE_TO_FUNCTION = {
    'S3::Bucket': {
        'create': {
            'boto_client': 'resource',
            'function': 'create_bucket',
            'parameters': {
                'Bucket': 'BucketName',
                'ACL': 'AccessControl'
            },
        }
    },
    'SQS::Queue': {
        'create': {
            'boto_client': 'resource',
            'function': 'create_queue',
            'parameters': {
                'QueueName': 'QueueName'
            },
        }
    }
}


def parse_template(template):
    try:
        return json.loads(template)
    except Exception as e:
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
    if RESOURCE_TO_FUNCTION[resource_type][ACTION_CREATE].get('boto_client') == 'resource':
        return aws_stack.connect_to_resource(service)
    return aws_stack.connect_to_service(service)


def deploy_resource(resource):
    client = get_client(resource)
    resource_type = get_resource_type(resource)
    func_details = RESOURCE_TO_FUNCTION.get(resource_type)
    if not func_details:
        LOGGER.warning('Resource type not yet implemented: %s' % resource['Type'])
        return
    func_details = func_details[ACTION_CREATE]
    function = getattr(client, func_details['function'])
    params = dict(func_details['parameters'])
    for param_key, prop_key in iteritems(params):
        params[param_key] = resource['Properties'].get(prop_key)
    # invoke function
    return function(**params)


def deploy_template(template):
    if isinstance(template, string_types):
        template = parse_template(template)

    for key, resource in iteritems(template['Resources']):
        deploy_resource(resource)
