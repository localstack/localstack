import os
import boto3
import requests
import json
import base64
import logging
import re
from elasticsearch import Elasticsearch, RequestsHttpConnection
from localstack.constants import *
from localstack.utils.common import *
from localstack.utils.aws.aws_models import *
from requests_aws4auth import AWS4Auth

# file to override environment information (used mainly for testing Lambdas locally)
ENVIRONMENT_FILE = '.env.properties'

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
        if not isinstance(obj, dict):
            j = j.to_dict()
        result = Environment()
        result.apply_json(j)
        return result

    def __str__(self):
        return '%s:%s' % (self.region, self.prefix)


PREDEFINED_ENVIRONMENTS = {
    ENV_DEV: Environment(region=REGION_LOCAL, prefix=ENV_DEV)
}


def create_environment_file(env, fallback_to_environ=True):
    try:
        save_file(ENVIRONMENT_FILE, env)
    except Exception, e:
        # LOGGER.warning('Unable to create file "%s" in CWD "%s" (setting $ENV instead: %s): %s' %
        #    (ENVIRONMENT_FILE, os.getcwd(), fallback_to_environ, e))
        # in Lambda environments on AWS we cannot create files, hence simply set $ENV here
        if fallback_to_environ:
            os.environ['ENV'] = env


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
    if os.path.isfile(ENVIRONMENT_FILE):
        try:
            env = load_file(ENVIRONMENT_FILE)
            env = env.strip() if env else env
        except Exception, e:
            # We can safely swallow this exception. In some rare cases, os.environ['ENV'] may
            # be changed by a parallel thread executing a Lambda code. This can only happen when
            # running in the local dev/test environment, hence is not critical for prod usage.
            # If reading the file was unsuccessful, we fall back to ENV_DEV and continue below.
            pass

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


def get_boto3_session():
    my_session = None
    if CUSTOM_BOTO3_SESSION:
        return CUSTOM_BOTO3_SESSION
    if CREATE_NEW_SESSION_PER_BOTO3_CONNECTION:
        return boto3.session.Session()
    # return default session
    return boto3


def connect_to_service(service_name, client=True, env=None, region_name=None, endpoint_url=None):
    """
    Generic method to obtain an AWS service client using boto3, based on environment, region, or custom endpoint_url.
    """
    env = get_environment(env, region_name=region_name)
    my_session = get_boto3_session()
    method = my_session.client if client else my_session.resource
    if not endpoint_url:
        if env.region == REGION_LOCAL:
            endpoint_url = os.environ['TEST_%s_URL' % (service_name.upper())]
    return method(service_name, region_name=env.region, endpoint_url=endpoint_url)


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
        return base64.b64encode(s)

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


def dynamodb_table_arn(table_name, account_id=None):
    if not account_id:
        account_id = TEST_AWS_ACCOUNT_ID
    return "arn:aws:dynamodb:%s:%s:table/%s" % (DEFAULT_REGION, account_id, table_name)


def dynamodb_stream_arn(table_name, account_id=None):
    if not account_id:
        account_id = TEST_AWS_ACCOUNT_ID
    return ("arn:aws:dynamodb:%s:%s:table/%s/stream/%s" %
        (DEFAULT_REGION, account_id, table_name, timestamp()))


def lambda_function_arn(function_name, account_id=None):
    if not account_id:
        account_id = TEST_AWS_ACCOUNT_ID
    return "arn:aws:lambda:%s:%s:function:%s" % (DEFAULT_REGION, account_id, function_name)


def kinesis_stream_arn(stream_name, account_id=None):
    if not account_id:
        account_id = TEST_AWS_ACCOUNT_ID
    return "arn:aws:kinesis:%s:%s:stream/%s" % (DEFAULT_REGION, account_id, stream_name)


def firehose_stream_arn(stream_name, account_id=None):
    if not account_id:
        account_id = TEST_AWS_ACCOUNT_ID
    return ("arn:aws:firehose:%s:%s:deliverystream/%s" % (DEFAULT_REGION, account_id, stream_name))


def s3_bucket_arn(bucket_name, account_id=None):
    return "arn:aws:s3:::%s" % (bucket_name)


def dynamodb_get_item_raw(dynamodb_url, request):
    headers = mock_aws_request_headers()
    headers['X-Amz-Target'] = 'DynamoDB_20120810.GetItem'
    new_item = make_http_request(url=dynamodb_url,
        method='POST', data=json.dumps(request), headers=headers)
    new_item = json.loads(new_item.text)
    return new_item


def mock_aws_request_headers(service='dynamodb'):
    ctype = APPLICATION_AMZ_JSON_1_0
    if service == 'kinesis':
        ctype = APPLICATION_AMZ_JSON_1_1
    headers = {
        'Content-Type': ctype,
        'Accept-Encoding': 'identity',
        'X-Amz-Date': '20160623T103251Z',
        'Authorization': ('AWS4-HMAC-SHA256 ' +
            'Credential=ABC/20160623/us-east-1/%s/aws4_request, ' +
            'SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234') % service
    }
    return headers


def get_apigateway_integration(api_id, method, path, env=None):
    apigateway = connect_to_service(service_name='apigateway', client=True, env=env)

    resources = apigateway.get_resources(
        restApiId=api_id,
        limit=100
    )
    resource_id = None
    for r in resources['items']:
        if r['path'] == path:
            resource_id = r['id']
    if not resource_id:
        raise Exception('Unable to find apigateway integration for path "%s"' % path)

    integration = apigateway.get_integration(
        restApiId=api_id,
        resourceId=resource_id,
        httpMethod=method
    )
    return integration


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


def elasticsearch_get_indices(endpoint=None, domain=None, env=None):
    es = connect_elasticsearch(endpoint=endpoint, env=env, domain=domain)
    indices = es.cat.indices()
    result = []
    for s in re.split(r'\s+', indices):
        if s:
            result.append(s)
    return result


def elasticsearch_delete_index(index, endpoint=None, env=None, ignore_codes=[400, 404]):
    es = connect_elasticsearch(endpoint=endpoint, env=env)
    return es.indices.delete(index=index, ignore=ignore_codes)


def delete_all_elasticsearch_indices(endpoint=None, env=None, domain=None):
    """
    This function drops ALL indexes in Elasticsearch. Use with caution!
    """
    env = get_environment(env)
    if env.region != REGION_LOCAL:
        raise Exception('Refusing to delete ALL Elasticsearch indices outside of local dev environment.')
    indices = elasticsearch_get_indices(endpoint=endpoint, env=env, domain=domain)
    for index in indices:
        elasticsearch_delete_index(index, endpoint=endpoint, env=env)


def delete_all_elasticsearch_data():
    """
    This function drops ALL data in the local Elasticsearch data folder. Use with caution!
    """
    data_dir = os.path.join(LOCALSTACK_ROOT_FOLDER, 'infra', 'elasticsearch', 'data', 'elasticsearch', 'nodes')
    run('rm -rf "%s"' % data_dir)


def create_kinesis_stream(stream_name, shards=1, env=None):
    env = get_environment(env)
    # stream
    stream = KinesisStream(id=stream_name, num_shards=shards)
    # producer
    conn = connect_to_service('kinesis', env=env)
    stream.connect(conn)
    stream.create()
    stream.wait_for()
    return stream
