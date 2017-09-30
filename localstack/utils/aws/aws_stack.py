import os
import re
import boto3
import json
import base64
import logging
from six import iteritems
from localstack import config
from localstack.constants import (REGION_LOCAL, DEFAULT_REGION,
    ENV_DEV, APPLICATION_AMZ_JSON_1_1, APPLICATION_AMZ_JSON_1_0)
from localstack.utils.common import run_safe, to_str, is_string, make_http_request, timestamp
from localstack.utils.aws.aws_models import KinesisStream

# AWS environment variable names
ENV_ACCESS_KEY = 'AWS_ACCESS_KEY_ID'
ENV_SECRET_KEY = 'AWS_SECRET_ACCESS_KEY'
ENV_SESSION_TOKEN = 'AWS_SESSION_TOKEN'

# set up logger
LOGGER = logging.getLogger(__name__)

# Use this field if you want to provide a custom boto3 session.
# This field takes priority over CREATE_NEW_SESSION_PER_BOTO3_CONNECTION
CUSTOM_BOTO3_SESSION = None
# Use this flag to enable creation of a new session for each boto3 connection.
# This flag will be ignored if CUSTOM_BOTO3_SESSION is specified
CREATE_NEW_SESSION_PER_BOTO3_CONNECTION = False

# Used in AWS assume role function
INITIAL_BOTO3_SESSION = None

# Assume role loop seconds
DEFAULT_TIMER_LOOP_SECONDS = 60 * 50


class Environment(object):
    def __init__(self, region=None, prefix=None):
        # target is the runtime environment to use, e.g.,
        # 'local' for local mode
        self.region = region or DEFAULT_REGION
        # prefix can be 'prod', 'stg', 'uat-1', etc.
        self.prefix = prefix

    def apply_json(self, j):
        if isinstance(j, str):
            j = json.loads(j)
        self.__dict__.update(j)

    @staticmethod
    def from_string(s):
        parts = s.split(':')
        if len(parts) == 1:
            if s in PREDEFINED_ENVIRONMENTS:
                return PREDEFINED_ENVIRONMENTS[s]
            parts = [DEFAULT_REGION, s]
        if len(parts) > 2:
            raise Exception('Invalid environment string "%s"' % s)
        region = parts[0]
        prefix = parts[1]
        return Environment(region=region, prefix=prefix)

    @staticmethod
    def from_json(j):
        if not isinstance(j, dict):
            j = j.to_dict()
        result = Environment()
        result.apply_json(j)
        return result

    def __str__(self):
        return '%s:%s' % (self.region, self.prefix)


PREDEFINED_ENVIRONMENTS = {
    ENV_DEV: Environment(region=REGION_LOCAL, prefix=ENV_DEV)
}


def get_environment(env=None, region_name=None):
    """
    Return an Environment object based on the input arguments.

    Parameter `env` can be either of:
        * None (or empty), in which case the rules below are applied to (env = os.environ['ENV'] or ENV_DEV)
        * an Environment object (then this object is returned)
        * a string '<region>:<name>', which corresponds to Environment(region='<region>', prefix='<prefix>')
        * the predefined string 'dev' (ENV_DEV), which implies Environment(region='local', prefix='dev')
        * a string '<name>', which implies Environment(region=DEFAULT_REGION, prefix='<name>')

    Additionally, parameter `region_name` can be used to override DEFAULT_REGION.
    """
    if not env:
        if 'ENV' in os.environ:
            env = os.environ['ENV']
        else:
            env = ENV_DEV
    elif not is_string(env) and not isinstance(env, Environment):
        raise Exception('Invalid environment: %s' % env)

    if is_string(env):
        env = Environment.from_string(env)
    if region_name:
        env.region = region_name
    if not env.region:
        raise Exception('Invalid region in environment: "%s"' % env)
    return env


def connect_to_resource(service_name, env=None, region_name=None, endpoint_url=None):
    """
    Generic method to obtain an AWS service resource using boto3, based on environment, region, or custom endpoint_url.
    """
    return connect_to_service(service_name, client=False, env=env, region_name=region_name, endpoint_url=endpoint_url)


def get_boto3_credentials():
    if CUSTOM_BOTO3_SESSION:
        return CUSTOM_BOTO3_SESSION.get_credentials()
    return boto3.session.Session().get_credentials()


def get_boto3_session():
    if CUSTOM_BOTO3_SESSION:
        return CUSTOM_BOTO3_SESSION
    if CREATE_NEW_SESSION_PER_BOTO3_CONNECTION:
        return boto3.session.Session()
    # return default session
    return boto3


def get_local_service_url(service_name):
    if service_name == 's3api':
        service_name = 's3'
    return os.environ['TEST_%s_URL' % (service_name.upper().replace('-', '_'))]


def connect_to_service(service_name, client=True, env=None, region_name=None, endpoint_url=None):
    """
    Generic method to obtain an AWS service client using boto3, based on environment, region, or custom endpoint_url.
    """
    env = get_environment(env, region_name=region_name)
    my_session = get_boto3_session()
    method = my_session.client if client else my_session.resource
    verify = True
    if not endpoint_url:
        if env.region == REGION_LOCAL:
            endpoint_url = get_local_service_url(service_name)
            verify = False
    region = env.region if env.region != REGION_LOCAL else DEFAULT_REGION
    return method(service_name, region_name=region, endpoint_url=endpoint_url, verify=verify)


class VelocityInput:
    """Simple class to mimick the behavior of variable '$input' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""
    def __init__(self, value):
        self.value = value

    def path(self, path):
        from jsonpath_rw import parse
        value = self.value if isinstance(self.value, dict) else json.loads(self.value)
        jsonpath_expr = parse(path)
        result = [match.value for match in jsonpath_expr.find(value)]
        result = result[0] if len(result) == 1 else result
        return result

    def json(self, path):
        return json.dumps(self.path(path))


class VelocityUtil:
    """Simple class to mimick the behavior of variable '$util' in AWS API Gateway integration velocity templates.
    See: http://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-mapping-template-reference.html"""
    def base64Encode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        encoded_str = s.encode(config.DEFAULT_ENCODING)
        encoded_b64_str = base64.b64encode(encoded_str)
        return encoded_b64_str.decode(config.DEFAULT_ENCODING)

    def base64Decode(self, s):
        if not isinstance(s, str):
            s = json.dumps(s)
        return base64.b64decode(s)


def render_velocity_template(template, context, as_json=False):
    import airspeed
    t = airspeed.Template(template)
    variables = {
        'input': VelocityInput(context),
        'util': VelocityUtil()
    }
    replaced = t.merge(variables)
    if as_json:
        replaced = json.loads(replaced)
    return replaced


def get_s3_client():
    return boto3.resource('s3',
        endpoint_url=config.TEST_S3_URL,
        config=boto3.session.Config(
            s3={'addressing_style': 'path'}),
        verify=False)


def get_account_id(account_id=None, env=None):
    if account_id:
        return account_id
    env = get_environment(env)
    if env.region == REGION_LOCAL:
        return os.environ['TEST_AWS_ACCOUNT_ID']
    raise Exception('Unable to determine AWS account ID')


def role_arn(role_name, account_id=None, env=None):
    env = get_environment(env)
    account_id = get_account_id(account_id, env=env)
    return 'arn:aws:iam::%s:role/%s' % (account_id, role_name)


def iam_resource_arn(resource, role=None, env=None):
    env = get_environment(env)
    if not role:
        role = get_iam_role(resource, env=env)
    return role_arn(role_name=role, account_id=get_account_id())


def get_iam_role(resource, env=None):
    env = get_environment(env)
    return 'role-%s' % resource


def dynamodb_table_arn(table_name, account_id=None):
    account_id = get_account_id(account_id)
    return 'arn:aws:dynamodb:%s:%s:table/%s' % (DEFAULT_REGION, account_id, table_name)


def dynamodb_stream_arn(table_name, account_id=None):
    account_id = get_account_id(account_id)
    return ('arn:aws:dynamodb:%s:%s:table/%s/stream/%s' %
        (DEFAULT_REGION, account_id, table_name, timestamp()))


def lambda_function_arn(function_name, account_id=None):
    pattern = 'arn:aws:lambda:.*:.*:function:.*'
    if re.match(pattern, function_name):
        return function_name
    if ':' in function_name:
        raise Exception('Lambda function name should not contain a colon ":"')
    account_id = get_account_id(account_id)
    return pattern.replace('.*', '%s') % (DEFAULT_REGION, account_id, function_name)


def cognito_user_pool_arn(user_pool_id, account_id=None):
    account_id = get_account_id(account_id)
    return 'arn:aws:cognito-idp:%s:%s:userpool/%s' % (DEFAULT_REGION, account_id, user_pool_id)


def kinesis_stream_arn(stream_name, account_id=None):
    account_id = get_account_id(account_id)
    return 'arn:aws:kinesis:%s:%s:stream/%s' % (DEFAULT_REGION, account_id, stream_name)


def firehose_stream_arn(stream_name, account_id=None):
    account_id = get_account_id(account_id)
    return ('arn:aws:firehose:%s:%s:deliverystream/%s' % (DEFAULT_REGION, account_id, stream_name))


def s3_bucket_arn(bucket_name, account_id=None):
    return 'arn:aws:s3:::%s' % (bucket_name)


def sqs_queue_arn(queue_name, account_id=None):
    account_id = get_account_id(account_id)
    return ('arn:aws:sqs:%s:%s:%s' % (DEFAULT_REGION, account_id, queue_name))


def sns_topic_arn(topic_name, account_id=None):
    account_id = get_account_id(account_id)
    return ('arn:aws:sns:%s:%s:%s' % (DEFAULT_REGION, account_id, topic_name))


def get_sqs_queue_url(queue_name):
    client = connect_to_service('sqs')
    response = client.get_queue_url(QueueName=queue_name)
    return response['QueueUrl']


def dynamodb_get_item_raw(request):
    headers = mock_aws_request_headers()
    headers['X-Amz-Target'] = 'DynamoDB_20120810.GetItem'
    new_item = make_http_request(url=config.TEST_DYNAMODB_URL,
        method='POST', data=json.dumps(request), headers=headers)
    new_item = json.loads(new_item.text)
    return new_item


def mock_aws_request_headers(service='dynamodb'):
    ctype = APPLICATION_AMZ_JSON_1_0
    if service == 'kinesis':
        ctype = APPLICATION_AMZ_JSON_1_1
    access_key = get_boto3_credentials().access_key
    headers = {
        'Content-Type': ctype,
        'Accept-Encoding': 'identity',
        'X-Amz-Date': '20160623T103251Z',
        'Authorization': ('AWS4-HMAC-SHA256 ' +
            'Credential=%s/20160623/us-east-1/%s/aws4_request, ' +
            'SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234') % (access_key, service)
    }
    return headers


def get_apigateway_integration(api_id, method, path, env=None):
    apigateway = connect_to_service(service_name='apigateway', client=True, env=env)

    resources = apigateway.get_resources(restApiId=api_id, limit=100)
    resource_id = None
    for r in resources['items']:
        if r['path'] == path:
            resource_id = r['id']
    if not resource_id:
        raise Exception('Unable to find apigateway integration for path "%s"' % path)

    integration = apigateway.get_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=method
    )
    return integration


def get_apigateway_resource_for_path(api_id, path, parent=None, resources=None):
    if resources is None:
        apigateway = connect_to_service(service_name='apigateway')
        resources = apigateway.get_resources(restApiId=api_id, limit=100)
    if not isinstance(path, list):
        path = path.split('/')
    if not path:
        return parent
    for resource in resources:
        if resource['pathPart'] == path[0] and (not parent or parent['id'] == resource['parentId']):
            return get_apigateway_resource_for_path(api_id, path[1:], parent=resource, resources=resources)
    return None


def get_apigateway_path_for_resource(api_id, resource_id, path_suffix='', resources=None):
    if resources is None:
        apigateway = connect_to_service(service_name='apigateway')
        resources = apigateway.get_resources(restApiId=api_id, limit=100)['items']
    target_resource = list(filter(lambda res: res['id'] == resource_id, resources))[0]
    path_part = target_resource.get('pathPart', '')
    if path_suffix:
        if path_part:
            path_suffix = '%s/%s' % (path_part, path_suffix)
    else:
        path_suffix = path_part
    parent_id = target_resource.get('parentId')
    if not parent_id:
        return '/%s' % path_suffix
    return get_apigateway_path_for_resource(api_id, parent_id, path_suffix=path_suffix, resources=resources)


def create_api_gateway(name, description=None, resources=None, stage_name=None,
        enabled_api_keys=[], env=None, usage_plan_name=None):
    client = connect_to_service('apigateway', env=env)
    if not resources:
        resources = []
    if not stage_name:
        stage_name = 'testing'
    if not usage_plan_name:
        usage_plan_name = 'Basic Usage'
    if not description:
        description = 'Test description for API "%s"' % name

    LOGGER.info('Creating API resources under API Gateway "%s".' % name)
    api = client.create_rest_api(name=name, description=description)
    # list resources
    api_id = api['id']
    resources_list = client.get_resources(restApiId=api_id)
    root_res_id = resources_list['items'][0]['id']
    # add API resources and methods
    for path, methods in iteritems(resources):
        # create resources recursively
        parent_id = root_res_id
        for path_part in path.split('/'):
            api_resource = client.create_resource(restApiId=api_id, parentId=parent_id, pathPart=path_part)
            parent_id = api_resource['id']
        # add methods to the API resource
        for method in methods:
            client.put_method(
                restApiId=api_id,
                resourceId=api_resource['id'],
                httpMethod=method['httpMethod'],
                authorizationType=method.get('authorizationType') or 'NONE',
                apiKeyRequired=method.get('apiKeyRequired') or False
            )
            # create integrations for this API resource/method
            integrations = method['integrations']
            create_api_gateway_integrations(api_id, api_resource['id'], method, integrations, env=env)
    # deploy the API gateway
    client.create_deployment(restApiId=api_id, stageName=stage_name)
    return api


def create_api_gateway_integrations(api_id, resource_id, method, integrations=[], env=None):
    client = connect_to_service('apigateway', env=env)
    for integration in integrations:
        req_templates = integration.get('requestTemplates') or {}
        res_templates = integration.get('responseTemplates') or {}
        success_code = integration.get('successCode') or '200'
        client_error_code = integration.get('clientErrorCode') or '400'
        server_error_code = integration.get('serverErrorCode') or '500'
        # create integration
        client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method['httpMethod'],
            integrationHttpMethod=method.get('integrationHttpMethod') or method['httpMethod'],
            type=integration['type'],
            uri=integration['uri'],
            requestTemplates=req_templates
        )
        response_configs = [
            {'pattern': '^2.*', 'code': success_code, 'res_templates': res_templates},
            {'pattern': '^4.*', 'code': client_error_code, 'res_templates': {}},
            {'pattern': '^5.*', 'code': server_error_code, 'res_templates': {}}
        ]
        # create response configs
        for response_config in response_configs:
            # create integration response
            client.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method['httpMethod'],
                statusCode=response_config['code'],
                responseTemplates=response_config['res_templates'],
                selectionPattern=response_config['pattern']
            )
            # create method response
            client.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method['httpMethod'],
                statusCode=response_config['code']
            )


def get_elasticsearch_endpoint(domain=None, region_name=None):
    env = get_environment(region_name=region_name)
    if env.region == REGION_LOCAL:
        return os.environ['TEST_ELASTICSEARCH_URL']
    # get endpoint from API
    es_client = connect_to_service(service_name='es', region_name=env.region)
    info = es_client.describe_elasticsearch_domain(DomainName=domain)
    endpoint = 'https://%s' % info['DomainStatus']['Endpoint']
    return endpoint


def connect_elasticsearch(endpoint=None, domain=None, region_name=None, env=None):
    from elasticsearch import Elasticsearch, RequestsHttpConnection
    from requests_aws4auth import AWS4Auth

    env = get_environment(env, region_name=region_name)
    verify_certs = False
    use_ssl = False
    if not endpoint and env.region == REGION_LOCAL:
        endpoint = os.environ['TEST_ELASTICSEARCH_URL']
    if not endpoint and env.region != REGION_LOCAL and domain:
        endpoint = get_elasticsearch_endpoint(domain=domain, region_name=env.region)
    # use ssl?
    if 'https://' in endpoint:
        use_ssl = True
        if env.region != REGION_LOCAL:
            verify_certs = True

    if CUSTOM_BOTO3_SESSION or (ENV_ACCESS_KEY in os.environ and ENV_SECRET_KEY in os.environ):
        access_key = os.environ.get(ENV_ACCESS_KEY)
        secret_key = os.environ.get(ENV_SECRET_KEY)
        session_token = os.environ.get(ENV_SESSION_TOKEN)
        if CUSTOM_BOTO3_SESSION:
            credentials = CUSTOM_BOTO3_SESSION.get_credentials()
            access_key = credentials.access_key
            secret_key = credentials.secret_key
            session_token = credentials.token
        awsauth = AWS4Auth(access_key, secret_key, env.region, 'es', session_token=session_token)
        connection_class = RequestsHttpConnection
        return Elasticsearch(hosts=[endpoint], verify_certs=verify_certs, use_ssl=use_ssl,
                             connection_class=connection_class, http_auth=awsauth)
    return Elasticsearch(hosts=[endpoint], verify_certs=verify_certs, use_ssl=use_ssl)


def create_kinesis_stream(stream_name, shards=1, env=None, delete=False):
    env = get_environment(env)
    # stream
    stream = KinesisStream(id=stream_name, num_shards=shards)
    conn = connect_to_service('kinesis', env=env)
    stream.connect(conn)
    if delete:
        run_safe(lambda: stream.destroy(), print_error=False)
    stream.create()
    stream.wait_for()
    return stream


def kinesis_get_latest_records(stream_name, shard_id, count=10, env=None):
    kinesis = connect_to_service('kinesis', env=env)
    result = []
    response = kinesis.get_shard_iterator(StreamName=stream_name, ShardId=shard_id,
        ShardIteratorType='TRIM_HORIZON')
    shard_iterator = response['ShardIterator']
    while shard_iterator:
        records_response = kinesis.get_records(ShardIterator=shard_iterator)
        records = records_response['Records']
        for record in records:
            try:
                record['Data'] = to_str(record['Data'])
            except Exception:
                pass
        result.extend(records)
        shard_iterator = records_response['NextShardIterator'] if records else False
        while len(result) > count:
            result.pop(0)
    return result
