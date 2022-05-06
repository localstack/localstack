import json
import logging
import os
import re
import socket
import sys
import threading
import time
from functools import lru_cache
from typing import Dict, Optional, Union
from urllib.parse import urlparse

if sys.version_info >= (3, 8):
    from typing import TypedDict
else:
    from typing_extensions import TypedDict

import boto3
import botocore
import botocore.config
from botocore.utils import ArnParser, InvalidArnException

from localstack import config, constants
from localstack.constants import (
    APPLICATION_AMZ_JSON_1_0,
    APPLICATION_AMZ_JSON_1_1,
    APPLICATION_X_WWW_FORM_URLENCODED,
    AWS_REGION_US_EAST_1,
    ENV_DEV,
    INTERNAL_AWS_ACCESS_KEY_ID,
    LOCALHOST,
    MAX_POOL_CONNECTIONS,
    MOTO_ACCOUNT_ID,
    REGION_LOCAL,
    S3_VIRTUAL_HOSTNAME,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_ACCOUNT_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.utils.aws.aws_models import KinesisStream
from localstack.utils.collections import pick_attributes
from localstack.utils.functions import run_safe
from localstack.utils.http import make_http_request
from localstack.utils.strings import is_string, is_string_or_bytes, to_str
from localstack.utils.sync import retry

# AWS environment variable names
ENV_ACCESS_KEY = "AWS_ACCESS_KEY_ID"
ENV_SECRET_KEY = "AWS_SECRET_ACCESS_KEY"
ENV_SESSION_TOKEN = "AWS_SESSION_TOKEN"

# set up logger
LOG = logging.getLogger(__name__)

# cache local region
LOCAL_REGION = None

# Use this flag to enable creation of a new session for each boto3 connection.
CREATE_NEW_SESSION_PER_BOTO3_CONNECTION = False

# Used in AWS assume role function
INITIAL_BOTO3_SESSION = None

# Boto clients cache
BOTO_CLIENTS_CACHE = {}

# Assume role loop seconds
DEFAULT_TIMER_LOOP_SECONDS = 60 * 50

# maps SQS queue ARNs to queue URLs
SQS_ARN_TO_URL_CACHE = {}

# List of parameters with additional event target parameters
EVENT_TARGET_PARAMETERS = ["$.SqsParameters", "$.KinesisParameters"]

# cached value used to determine the DNS status of the S3 hostname (whether it can be resolved properly)
CACHE_S3_HOSTNAME_DNS_STATUS = None

# mutex used when creating boto clients (which isn't thread safe: https://github.com/boto/boto3/issues/801)
BOTO_CLIENT_CREATE_LOCK = threading.RLock()


@lru_cache()
def get_valid_regions():
    valid_regions = set()
    for partition in set(boto3.Session().get_available_partitions()):
        for region in boto3.Session().get_available_regions("sns", partition):
            valid_regions.add(region)
    return valid_regions


def get_valid_regions_for_service(service_name):
    regions = list(boto3.Session().get_available_regions(service_name))
    regions.extend(boto3.Session().get_available_regions("cloudwatch", partition_name="aws-us-gov"))
    regions.extend(boto3.Session().get_available_regions("cloudwatch", partition_name="aws-cn"))
    return regions


class Environment:
    def __init__(self, region=None, prefix=None):
        # target is the runtime environment to use, e.g.,
        # 'local' for local mode
        self.region = region or get_local_region()
        # prefix can be 'prod', 'stg', 'uat-1', etc.
        self.prefix = prefix

    def apply_json(self, j):
        if isinstance(j, str):
            j = json.loads(j)
        self.__dict__.update(j)

    @staticmethod
    def from_string(s):
        parts = s.split(":")
        if len(parts) == 1:
            if s in PREDEFINED_ENVIRONMENTS:
                return PREDEFINED_ENVIRONMENTS[s]
            parts = [get_local_region(), s]
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
        return "%s:%s" % (self.region, self.prefix)


PREDEFINED_ENVIRONMENTS = {ENV_DEV: Environment(region=REGION_LOCAL, prefix=ENV_DEV)}


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
        if "ENV" in os.environ:
            env = os.environ["ENV"]
        else:
            env = ENV_DEV
    elif not is_string(env) and not isinstance(env, Environment):
        raise Exception("Invalid environment: %s" % env)

    if is_string(env):
        env = Environment.from_string(env)
    if region_name:
        env.region = region_name
    if not env.region:
        raise Exception('Invalid region in environment: "%s"' % env)
    return env


def is_local_env(env):
    return not env or env.region == REGION_LOCAL or env.prefix == ENV_DEV


class Boto3Session(boto3.session.Session):
    """Custom boto3 session that points to local endpoint URLs."""

    def resource(self, service, *args, **kwargs):
        self._fix_endpoint(kwargs)
        return connect_to_resource(service, *args, **kwargs)

    def client(self, service, *args, **kwargs):
        self._fix_endpoint(kwargs)
        return connect_to_service(service, *args, **kwargs)

    def _fix_endpoint(self, kwargs):
        if "amazonaws.com" in kwargs.get("endpoint_url", ""):
            kwargs.pop("endpoint_url")


def get_boto3_session(cache=True):
    if not cache or CREATE_NEW_SESSION_PER_BOTO3_CONNECTION:
        return boto3.session.Session()
    # return default session
    return boto3


def get_region():
    # Note: leave import here to avoid import errors (e.g., "flask") for CLI commands
    from localstack.utils.aws.request_context import get_region_from_request_context

    region = get_region_from_request_context()
    if region:
        return region
    # fall back to returning static pre-defined region
    return get_local_region()


def get_partition(region_name: str = None):
    region_name = region_name or get_region()
    return boto3.session.Session().get_partition_for_region(region_name)


def get_local_region():
    global LOCAL_REGION
    if LOCAL_REGION is None:
        session = boto3.session.Session()
        LOCAL_REGION = session.region_name or ""
    return config.DEFAULT_REGION or LOCAL_REGION


def is_internal_call_context(headers):
    """Return whether we are executing in the context of an internal API call, i.e.,
    the case where one API uses a boto3 client to call another API internally."""
    auth_header = headers.get("Authorization") or ""
    return get_internal_credential() in auth_header


def get_internal_credential():
    return "Credential=%s/" % INTERNAL_AWS_ACCESS_KEY_ID


def set_internal_auth(headers):
    authorization = headers.get("Authorization") or ""
    if authorization.startswith("AWS "):
        # Cover Non HMAC Authentication
        authorization = re.sub(
            r"AWS [^/]+",
            "AWS %s" % get_internal_credential(),
            authorization,
        )
    else:
        authorization = re.sub(
            r"Credential=[^/]+/",
            get_internal_credential(),
            authorization,
        )
    headers["Authorization"] = authorization
    return headers


def get_local_service_url(service_name_or_port: Union[str, int]) -> str:
    """Return the local service URL for the given service name or port."""
    if isinstance(service_name_or_port, int):
        return f"{config.get_protocol()}://{LOCALHOST}:{service_name_or_port}"
    service_name = service_name_or_port
    if service_name == "s3api":
        service_name = "s3"
    elif service_name == "runtime.sagemaker":
        service_name = "sagemaker-runtime"
    return config.service_url(service_name)


def connect_to_resource(
    service_name, env=None, region_name=None, endpoint_url=None, *args, **kwargs
):
    """
    Generic method to obtain an AWS service resource using boto3, based on environment, region, or custom endpoint_url.
    """
    return connect_to_service(
        service_name,
        client=False,
        env=env,
        region_name=region_name,
        endpoint_url=endpoint_url,
    )


def connect_to_resource_external(
    service_name,
    env=None,
    region_name=None,
    endpoint_url=None,
    config: botocore.config.Config = None,
    **kwargs,
):
    """
    Generic method to obtain an AWS service resource using boto3, based on environment, region, or custom endpoint_url.
    """
    return create_external_boto_client(
        service_name,
        client=False,
        env=env,
        region_name=region_name,
        endpoint_url=endpoint_url,
        config=config,
    )


def connect_to_service(
    service_name,
    client=True,
    env=None,
    region_name=None,
    endpoint_url=None,
    config: botocore.config.Config = None,
    verify=False,
    cache=True,
    *args,
    **kwargs,
):
    """
    Generic method to obtain an AWS service client using boto3, based on environment, region, or custom endpoint_url.
    """
    # determine context and create cache key
    region_name = region_name or get_region()
    env = get_environment(env, region_name=region_name)
    region = env.region if env.region != REGION_LOCAL else region_name
    key_elements = [service_name, client, env, region, endpoint_url, config, kwargs]
    cache_key = "/".join([str(k) for k in key_elements])

    # check cache first (most calls will be served from cache)
    if cache and cache_key in BOTO_CLIENTS_CACHE:
        return BOTO_CLIENTS_CACHE[cache_key]

    with BOTO_CLIENT_CREATE_LOCK:
        # check cache again within lock context to avoid race conditions
        if cache and cache_key in BOTO_CLIENTS_CACHE:
            return BOTO_CLIENTS_CACHE[cache_key]

        # determine endpoint_url if it is not set explicitly
        if not endpoint_url:
            if is_local_env(env):
                endpoint_url = get_local_service_url(service_name)
                verify = False
            backend_env_name = "%s_BACKEND" % service_name.upper()
            backend_url = os.environ.get(backend_env_name, "").strip()
            if backend_url:
                endpoint_url = backend_url

        # configure S3 path/host style addressing
        if service_name == "s3":
            if re.match(r"https?://localhost(:[0-9]+)?", endpoint_url):
                endpoint_url = endpoint_url.replace("://localhost", "://%s" % get_s3_hostname())

        # create boto client or resource from potentially cached session
        boto_session = get_boto3_session(cache=cache)
        boto_config = config or botocore.client.Config()
        boto_factory = boto_session.client if client else boto_session.resource

        # To, prevent error "Connection pool is full, discarding connection ...",
        # set the environment variable MAX_POOL_CONNECTIONS. Default is 150.
        boto_config.max_pool_connections = MAX_POOL_CONNECTIONS

        new_client = boto_factory(
            service_name,
            region_name=region,
            endpoint_url=endpoint_url,
            verify=verify,
            config=boto_config,
            **kwargs,
        )

        if cache:
            BOTO_CLIENTS_CACHE[cache_key] = new_client

        return new_client


def create_external_boto_client(
    service_name,
    client=True,
    env=None,
    region_name=None,
    endpoint_url=None,
    config: botocore.config.Config = None,
    verify=False,
    cache=True,
    *args,
    **kwargs,
):
    return connect_to_service(
        service_name,
        client,
        env,
        region_name,
        endpoint_url,
        config,
        verify,
        cache,
        aws_access_key_id="__test_call__",
        aws_secret_access_key="__test_key__",
        *args,
        **kwargs,
    )


def get_s3_hostname():
    global CACHE_S3_HOSTNAME_DNS_STATUS
    if CACHE_S3_HOSTNAME_DNS_STATUS is None:
        try:
            assert socket.gethostbyname(S3_VIRTUAL_HOSTNAME)
            CACHE_S3_HOSTNAME_DNS_STATUS = True
        except socket.error:
            CACHE_S3_HOSTNAME_DNS_STATUS = False
    if CACHE_S3_HOSTNAME_DNS_STATUS:
        return S3_VIRTUAL_HOSTNAME
    return LOCALHOST


def generate_presigned_url(*args, **kwargs):
    endpoint_url = kwargs.pop("endpoint_url", None)
    s3_client = connect_to_service(
        "s3",
        endpoint_url=endpoint_url,
        cache=False,
        # Note: presigned URL needs to be created with (external) test credentials
        aws_access_key_id=TEST_AWS_ACCESS_KEY_ID,
        aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
    )
    return s3_client.generate_presigned_url(*args, **kwargs)


def check_valid_region(headers):
    """Check whether a valid region is provided, and if not then raise an Exception."""
    auth_header = headers.get("Authorization")
    if not auth_header:
        raise Exception('Unable to find "Authorization" header in request')
    replaced = re.sub(r".*Credential=([^,]+),.*", r"\1", auth_header)
    if auth_header == replaced:
        raise Exception('Unable to find "Credential" section in "Authorization" header')
    # Format is: <your-access-key-id>/<date>/<aws-region>/<aws-service>/aws4_request
    # See https://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
    parts = replaced.split("/")
    region = parts[2]
    if region not in get_valid_regions():
        raise Exception(f'Invalid region specified in "Authorization" header: "{region}"')


def set_default_region_in_headers(headers, service=None, region=None):
    # this should now be a no-op, as we support arbitrary regions and don't use a "default" region
    # TODO: remove this function once the legacy USE_SINGLE_REGION config is removed
    if not config.USE_SINGLE_REGION:
        return

    auth_header = headers.get("Authorization")
    region = region or get_region()
    if not auth_header:
        if service:
            headers["Authorization"] = mock_aws_request_headers(service, region_name=region)[
                "Authorization"
            ]
        return
    replaced = re.sub(r"(.*Credential=[^/]+/[^/]+/)([^/])+/", r"\1%s/" % region, auth_header)
    headers["Authorization"] = replaced


def fix_account_id_in_arns(response, colon_delimiter=":", existing=None, replace=None):
    """Fix the account ID in the ARNs returned in the given Flask response or string"""
    existing = existing or ["123456789", "1234567890", "123456789012", MOTO_ACCOUNT_ID]
    existing = existing if isinstance(existing, list) else [existing]
    replace = replace or TEST_AWS_ACCOUNT_ID
    is_str_obj = is_string_or_bytes(response)
    content = to_str(response if is_str_obj else response._content)

    replace = r"arn{col}aws{col}\1{col}\2{col}{acc}{col}".format(col=colon_delimiter, acc=replace)
    for acc_id in existing:
        regex = r"arn{col}aws{col}([^:%]+){col}([^:%]*){col}{acc}{col}".format(
            col=colon_delimiter, acc=acc_id
        )
        content = re.sub(regex, replace, content)

    if not is_str_obj:
        response._content = content
        response.headers["Content-Length"] = len(response._content)
        return response
    return content


def inject_test_credentials_into_env(env):
    if ENV_ACCESS_KEY not in env and ENV_SECRET_KEY not in env:
        env[ENV_ACCESS_KEY] = "test"
        env[ENV_SECRET_KEY] = "test"


def inject_region_into_env(env, region):
    env["AWS_REGION"] = region


def dynamodb_table_exists(table_name, client=None):
    client = client or connect_to_service("dynamodb")
    paginator = client.get_paginator("list_tables")
    pages = paginator.paginate(PaginationConfig={"PageSize": 100})
    for page in pages:
        table_names = page["TableNames"]
        if to_str(table_name) in table_names:
            return True
    return False


def sqs_queue_url_for_arn(queue_arn):
    if "://" in queue_arn:
        return queue_arn
    if queue_arn in SQS_ARN_TO_URL_CACHE:
        return SQS_ARN_TO_URL_CACHE[queue_arn]

    try:
        arn = parse_arn(queue_arn)
        region_name = arn["region"]
        queue_name = arn["resource"]
    except InvalidArnException:
        region_name = None
        queue_name = queue_arn

    sqs_client = connect_to_service("sqs", region_name=region_name)
    result = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    SQS_ARN_TO_URL_CACHE[queue_arn] = result
    return result


# TODO: remove and merge with sqs_queue_url_for_arn(..) above!!
def get_sqs_queue_url(queue_arn: str) -> str:
    return sqs_queue_url_for_arn(queue_arn)


def extract_region_from_auth_header(headers: Dict[str, str], use_default=True) -> str:
    auth = headers.get("Authorization") or ""
    region = re.sub(r".*Credential=[^/]+/[^/]+/([^/]+)/.*", r"\1", auth)
    if region == auth:
        region = None
    if use_default:
        region = region or get_region()
    return region


def extract_access_key_id_from_auth_header(headers: Dict[str, str]) -> str:
    auth = headers.get("Authorization") or ""
    access_id = re.sub(r".*Credential=([^/]+)/[^/]+/[^/]+/.*", r"\1", auth)
    if access_id == auth:
        access_id = None
    return access_id


# TODO: extract ARN utils into separate file!

_arn_parser = ArnParser()


class ArnData(TypedDict):
    partition: str
    service: str
    region: str
    account: str
    resource: str


def parse_arn(arn: str) -> ArnData:
    """
    Uses a botocore ArnParser to parse an arn.

    :param arn: the arn string to parse
    :returns: a dictionary containing the ARN components
    :raises InvalidArnException: if the arn is invalid
    """
    return _arn_parser.parse_arn(arn)


def extract_region_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("region")
    except InvalidArnException:
        return None


def extract_service_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("service")
    except InvalidArnException:
        return None


def extract_resource_from_arn(arn: str) -> Optional[str]:
    try:
        return parse_arn(arn).get("resource")
    except InvalidArnException:
        return None


def get_account_id(account_id=None, env=None):
    if account_id:
        return account_id
    env = get_environment(env)
    if is_local_env(env):
        return os.environ["TEST_AWS_ACCOUNT_ID"]
    raise Exception("Unable to determine AWS account ID (%s, %s)" % (account_id, env))


def role_arn(role_name, account_id=None, env=None):
    if not role_name:
        return role_name
    if role_name.startswith("arn:aws:iam::"):
        return role_name
    env = get_environment(env)
    account_id = get_account_id(account_id, env=env)
    return "arn:aws:iam::%s:role/%s" % (account_id, role_name)


def policy_arn(policy_name, account_id=None):
    if ":policy/" in policy_name:
        return policy_name
    account_id = account_id or TEST_AWS_ACCOUNT_ID
    return "arn:aws:iam::{}:policy/{}".format(account_id, policy_name)


def iam_resource_arn(resource, role=None, env=None):
    env = get_environment(env)
    if not role:
        role = get_iam_role(resource, env=env)
    return role_arn(role_name=role, account_id=get_account_id())


def get_iam_role(resource, env=None):
    env = get_environment(env)
    return "role-%s" % resource


def secretsmanager_secret_arn(secret_id, account_id=None, region_name=None, random_suffix=None):
    if ":" in (secret_id or ""):
        return secret_id
    pattern = "arn:aws:secretsmanager:%s:%s:secret:%s"
    arn = _resource_arn(secret_id, pattern, account_id=account_id, region_name=region_name)
    if random_suffix:
        arn += f"-{random_suffix}"
    return arn


def cloudformation_stack_arn(stack_name, stack_id=None, account_id=None, region_name=None):
    stack_id = stack_id or "id-123"
    pattern = "arn:aws:cloudformation:%s:%s:stack/%s/{stack_id}".format(stack_id=stack_id)
    return _resource_arn(stack_name, pattern, account_id=account_id, region_name=region_name)


def cf_change_set_arn(change_set_name, change_set_id=None, account_id=None, region_name=None):
    change_set_id = change_set_id or "id-456"
    pattern = "arn:aws:cloudformation:%s:%s:changeSet/%s/{cs_id}".format(cs_id=change_set_id)
    return _resource_arn(change_set_name, pattern, account_id=account_id, region_name=region_name)


def dynamodb_table_arn(table_name, account_id=None, region_name=None):
    table_name = table_name.split(":table/")[-1]
    pattern = "arn:aws:dynamodb:%s:%s:table/%s"
    return _resource_arn(table_name, pattern, account_id=account_id, region_name=region_name)


def dynamodb_stream_arn(table_name, latest_stream_label, account_id=None):
    account_id = get_account_id(account_id)
    return "arn:aws:dynamodb:%s:%s:table/%s/stream/%s" % (
        get_region(),
        account_id,
        table_name,
        latest_stream_label,
    )


def cloudwatch_alarm_arn(alarm_name, account_id=None, region_name=None):
    pattern = "arn:aws:cloudwatch:%s:%s:alarm:%s"
    return _resource_arn(alarm_name, pattern, account_id=account_id, region_name=region_name)


def log_group_arn(group_name, account_id=None, region_name=None):
    pattern = "arn:aws:logs:%s:%s:log-group:%s"
    return _resource_arn(group_name, pattern, account_id=account_id, region_name=region_name)


def events_rule_arn(rule_name, account_id=None, region_name=None):
    pattern = "arn:aws:events:%s:%s:rule/%s"
    return _resource_arn(rule_name, pattern, account_id=account_id, region_name=region_name)


def lambda_function_arn(function_name, account_id=None, region_name=None):
    return lambda_function_or_layer_arn(
        "function", function_name, account_id=account_id, region_name=region_name
    )


def lambda_layer_arn(layer_name, version=None, account_id=None):
    return lambda_function_or_layer_arn("layer", layer_name, version=None, account_id=account_id)


def lambda_function_or_layer_arn(
    type, entity_name, version=None, account_id=None, region_name=None
):
    pattern = "arn:aws:lambda:.*:.*:(function|layer):.*"
    if re.match(pattern, entity_name):
        return entity_name
    if ":" in entity_name:
        client = connect_to_service("lambda")
        entity_name, _, alias = entity_name.rpartition(":")
        try:
            alias_response = client.get_alias(FunctionName=entity_name, Name=alias)
            version = alias_response["FunctionVersion"]

        except Exception as e:
            msg = "Alias %s of %s not found" % (alias, entity_name)
            LOG.info(f"{msg}: {e}")
            raise Exception(msg)

    account_id = get_account_id(account_id)
    region_name = region_name or get_region()
    pattern = re.sub(r"\([^\|]+\|.+\)", type, pattern)
    result = pattern.replace(".*", "%s") % (region_name, account_id, entity_name)
    if version:
        result = "%s:%s" % (result, version)
    return result


def lambda_function_name(name_or_arn):
    if ":" in name_or_arn:
        arn = parse_arn(name_or_arn)
        if arn["service"] != "lambda":
            raise ValueError("arn is not a lambda arn %s" % name_or_arn)

        return parse_arn(name_or_arn)["resource"].split(":")[1]
    else:
        return name_or_arn


def state_machine_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:states:%s:%s:stateMachine:%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)


def stepfunctions_activity_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:states:%s:%s:activity:%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)


def fix_arn(arn):
    """Function that attempts to "canonicalize" the given ARN. This includes converting
    resource names to ARNs, replacing incorrect regions, account IDs, etc."""
    if arn.startswith("arn:aws:lambda"):
        parts = arn.split(":")
        region = parts[3] if parts[3] in get_valid_regions() else get_region()
        return lambda_function_arn(lambda_function_name(arn), region_name=region)
    LOG.warning("Unable to fix/canonicalize ARN: %s", arn)
    return arn


def cognito_user_pool_arn(user_pool_id, account_id=None, region_name=None):
    pattern = "arn:aws:cognito-idp:%s:%s:userpool/%s"
    return _resource_arn(user_pool_id, pattern, account_id=account_id, region_name=region_name)


def kinesis_stream_arn(stream_name, account_id=None, region_name=None):
    pattern = "arn:aws:kinesis:%s:%s:stream/%s"
    return _resource_arn(stream_name, pattern, account_id=account_id, region_name=region_name)


def elasticsearch_domain_arn(domain_name, account_id=None, region_name=None):
    pattern = "arn:aws:es:%s:%s:domain/%s"
    return _resource_arn(domain_name, pattern, account_id=account_id, region_name=region_name)


def firehose_stream_arn(stream_name, account_id=None, region_name=None):
    pattern = "arn:aws:firehose:%s:%s:deliverystream/%s"
    return _resource_arn(stream_name, pattern, account_id=account_id, region_name=region_name)


def es_domain_arn(domain_name, account_id=None, region_name=None):
    pattern = "arn:aws:es:%s:%s:domain/%s"
    return _resource_arn(domain_name, pattern, account_id=account_id, region_name=region_name)


def kms_key_arn(key_id: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:kms:%s:%s:key/%s"
    return _resource_arn(key_id, pattern, account_id=account_id, region_name=region_name)


def code_signing_arn(code_signing_id: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:lambda:%s:%s:code-signing-config:%s"
    return _resource_arn(code_signing_id, pattern, account_id=account_id, region_name=region_name)


def ssm_parameter_arn(param_name: str, account_id: str = None, region_name: str = None) -> str:
    pattern = "arn:aws:ssm:%s:%s:parameter/%s"
    param_name = param_name.lstrip("/")
    return _resource_arn(param_name, pattern, account_id=account_id, region_name=region_name)


def s3_bucket_arn(bucket_name_or_arn: str, account_id=None):
    bucket_name = s3_bucket_name(bucket_name_or_arn)
    return "arn:aws:s3:::%s" % bucket_name


def s3_bucket_name(bucket_name_or_arn: str) -> str:
    return bucket_name_or_arn.split(":::")[-1]


def _resource_arn(name: str, pattern: str, account_id: str = None, region_name: str = None) -> str:
    if ":" in name:
        return name
    account_id = get_account_id(account_id)
    region_name = region_name or get_region()
    if len(pattern.split("%s")) == 3:
        return pattern % (account_id, name)
    return pattern % (region_name, account_id, name)


def get_events_target_attributes(target):
    return pick_attributes(target, EVENT_TARGET_PARAMETERS)


def get_or_create_bucket(bucket_name: str, s3_client=None):
    s3_client = s3_client or connect_to_service("s3")
    try:
        return s3_client.head_bucket(Bucket=bucket_name)
    except Exception:
        return create_s3_bucket(bucket_name, s3_client=s3_client)


def create_s3_bucket(bucket_name: str, s3_client=None):
    """Creates a bucket in the region that is associated with the current request
    context, or with the given boto3 S3 client, if specified."""
    s3_client = s3_client or connect_to_service("s3")
    region = s3_client.meta.region_name
    kwargs = {}
    if region != AWS_REGION_US_EAST_1:
        kwargs = {"CreateBucketConfiguration": {"LocationConstraint": region}}
    return s3_client.create_bucket(Bucket=bucket_name, **kwargs)


def create_sqs_queue(queue_name, env=None):
    env = get_environment(env)
    # queue
    conn = connect_to_service("sqs", env=env)
    return conn.create_queue(QueueName=queue_name)


def sqs_queue_arn(queue_name, account_id=None, region_name=None):
    account_id = get_account_id(account_id)
    region_name = region_name or get_region()
    queue_name = queue_name.split("/")[-1]
    return "arn:aws:sqs:%s:%s:%s" % (region_name, account_id, queue_name)


def apigateway_restapi_arn(api_id, account_id=None, region_name=None):
    account_id = get_account_id(account_id)
    region_name = region_name or get_region()
    return "arn:aws:apigateway:%s:%s:/restapis/%s" % (region_name, account_id, api_id)


def sqs_queue_name(queue_arn):
    if ":" in queue_arn:
        return parse_arn(queue_arn)["resource"]
    else:
        return queue_arn


def sns_topic_arn(topic_name, account_id=None):
    account_id = get_account_id(account_id)
    return "arn:aws:sns:%s:%s:%s" % (get_region(), account_id, topic_name)


def sqs_receive_message(queue_arn):
    region_name = extract_region_from_arn(queue_arn)
    client = connect_to_service("sqs", region_name=region_name)
    queue_url = get_sqs_queue_url(queue_arn)
    response = client.receive_message(QueueUrl=queue_url)
    return response


def firehose_name(firehose_arn):
    return firehose_arn.split("/")[-1]


def kinesis_stream_name(kinesis_arn):
    return kinesis_arn.split(":stream/")[-1]


def mock_aws_request_headers(service="dynamodb", region_name=None, access_key=None):
    ctype = APPLICATION_AMZ_JSON_1_0
    if service == "kinesis":
        ctype = APPLICATION_AMZ_JSON_1_1
    elif service in ["sns", "sqs"]:
        ctype = APPLICATION_X_WWW_FORM_URLENCODED

    # TODO: consider adding an internal=False flag, to use INTERNAL_AWS_ACCESS_KEY_ID for internal calls here
    access_key = access_key or constants.TEST_AWS_ACCESS_KEY_ID
    region_name = region_name or get_region()
    headers = {
        "Content-Type": ctype,
        "Accept-Encoding": "identity",
        "X-Amz-Date": "20160623T103251Z",
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            + f"Credential={access_key}/20160623/{region_name}/{service}/aws4_request, "
            + "SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234"
        ),
    }
    return headers


def inject_region_into_auth_headers(region, headers):
    auth_header = headers.get("Authorization")
    if auth_header:
        regex = r"Credential=([^/]+)/([^/]+)/([^/]+)/"
        auth_header = re.sub(regex, r"Credential=\1/\2/%s/" % region, auth_header)
        headers["Authorization"] = auth_header


def dynamodb_get_item_raw(request):
    headers = mock_aws_request_headers()
    headers["X-Amz-Target"] = "DynamoDB_20120810.GetItem"
    new_item = make_http_request(
        url=config.service_url("dynamodb"),
        method="POST",
        data=json.dumps(request),
        headers=headers,
    )
    new_item = new_item.text
    new_item = new_item and json.loads(new_item)
    return new_item


def create_dynamodb_table(
    table_name,
    partition_key,
    env=None,
    stream_view_type=None,
    region_name=None,
    client=None,
    sleep_after=2,
):
    """Utility method to create a DynamoDB table"""

    dynamodb = client or connect_to_service(
        "dynamodb", env=env, client=True, region_name=region_name
    )
    stream_spec = {"StreamEnabled": False}
    key_schema = [{"AttributeName": partition_key, "KeyType": "HASH"}]
    attr_defs = [{"AttributeName": partition_key, "AttributeType": "S"}]
    if stream_view_type is not None:
        stream_spec = {"StreamEnabled": True, "StreamViewType": stream_view_type}
    table = None
    try:
        table = dynamodb.create_table(
            TableName=table_name,
            KeySchema=key_schema,
            AttributeDefinitions=attr_defs,
            ProvisionedThroughput={"ReadCapacityUnits": 10, "WriteCapacityUnits": 10},
            StreamSpecification=stream_spec,
        )
    except Exception as e:
        if "ResourceInUseException" in str(e):
            # Table already exists -> return table reference
            return connect_to_resource("dynamodb", env=env, region_name=region_name).Table(
                table_name
            )
        if "AccessDeniedException" in str(e):
            raise

    if sleep_after:
        # TODO: do we need this?
        time.sleep(sleep_after)

    return table


def get_apigateway_integration(api_id, method, path, env=None):
    apigateway = connect_to_service(service_name="apigateway", client=True, env=env)

    resources = apigateway.get_resources(restApiId=api_id, limit=100)
    resource_id = None
    for r in resources["items"]:
        if r["path"] == path:
            resource_id = r["id"]
    if not resource_id:
        raise Exception('Unable to find apigateway integration for path "%s"' % path)

    integration = apigateway.get_integration(
        restApiId=api_id, resourceId=resource_id, httpMethod=method
    )
    return integration


def get_apigateway_resource_for_path(api_id, path, parent=None, resources=None):
    if resources is None:
        apigateway = connect_to_service(service_name="apigateway")
        resources = apigateway.get_resources(restApiId=api_id, limit=100)
    if not isinstance(path, list):
        path = path.split("/")
    if not path:
        return parent
    for resource in resources:
        if resource["pathPart"] == path[0] and (not parent or parent["id"] == resource["parentId"]):
            return get_apigateway_resource_for_path(
                api_id, path[1:], parent=resource, resources=resources
            )
    return None


def get_apigateway_path_for_resource(
    api_id, resource_id, path_suffix="", resources=None, region_name=None
):
    if resources is None:
        apigateway = connect_to_service(service_name="apigateway", region_name=region_name)
        resources = apigateway.get_resources(restApiId=api_id, limit=100)["items"]
    target_resource = list(filter(lambda res: res["id"] == resource_id, resources))[0]
    path_part = target_resource.get("pathPart", "")
    if path_suffix:
        if path_part:
            path_suffix = "%s/%s" % (path_part, path_suffix)
    else:
        path_suffix = path_part
    parent_id = target_resource.get("parentId")
    if not parent_id:
        return "/%s" % path_suffix
    return get_apigateway_path_for_resource(
        api_id,
        parent_id,
        path_suffix=path_suffix,
        resources=resources,
        region_name=region_name,
    )


def create_api_gateway(
    name,
    description=None,
    resources=None,
    stage_name=None,
    enabled_api_keys=None,
    env=None,
    usage_plan_name=None,
    region_name=None,
    auth_creator_func=None,  # function that receives an api_id and returns an authorizer_id
    client=None,
):
    if enabled_api_keys is None:
        enabled_api_keys = []
    if not client:
        client = connect_to_service("apigateway", env=env, region_name=region_name)
    resources = resources or []
    stage_name = stage_name or "testing"
    usage_plan_name = usage_plan_name or "Basic Usage"
    description = description or 'Test description for API "%s"' % name

    LOG.info('Creating API resources under API Gateway "%s".', name)
    api = client.create_rest_api(name=name, description=description)
    api_id = api["id"]

    auth_id = None
    if auth_creator_func:
        auth_id = auth_creator_func(api_id)

    resources_list = client.get_resources(restApiId=api_id)
    root_res_id = resources_list["items"][0]["id"]
    # add API resources and methods
    for path, methods in resources.items():
        # create resources recursively
        parent_id = root_res_id
        for path_part in path.split("/"):
            api_resource = client.create_resource(
                restApiId=api_id, parentId=parent_id, pathPart=path_part
            )
            parent_id = api_resource["id"]
        # add methods to the API resource
        for method in methods:
            kwargs = {"authorizerId": auth_id} if auth_id else {}
            client.put_method(
                restApiId=api_id,
                resourceId=api_resource["id"],
                httpMethod=method["httpMethod"],
                authorizationType=method.get("authorizationType") or "NONE",
                apiKeyRequired=method.get("apiKeyRequired") or False,
                requestParameters=method.get("requestParameters") or {},
                requestModels=method.get("requestModels") or {},
                **kwargs,
            )
            # create integrations for this API resource/method
            integrations = method["integrations"]
            create_api_gateway_integrations(
                api_id,
                api_resource["id"],
                method,
                integrations,
                env=env,
                region_name=region_name,
                client=client,
            )
    # deploy the API gateway
    client.create_deployment(restApiId=api_id, stageName=stage_name)
    return api


def create_api_gateway_integrations(
    api_id, resource_id, method, integrations=None, env=None, region_name=None, client=None
):
    if integrations is None:
        integrations = []
    if not client:
        client = connect_to_service("apigateway", env=env, region_name=region_name)
    for integration in integrations:
        req_templates = integration.get("requestTemplates") or {}
        res_templates = integration.get("responseTemplates") or {}
        success_code = integration.get("successCode") or "200"
        client_error_code = integration.get("clientErrorCode") or "400"
        server_error_code = integration.get("serverErrorCode") or "500"
        request_parameters = integration.get("requestParameters") or {}
        # create integration
        client.put_integration(
            restApiId=api_id,
            resourceId=resource_id,
            httpMethod=method["httpMethod"],
            integrationHttpMethod=method.get("integrationHttpMethod") or method["httpMethod"],
            type=integration["type"],
            uri=integration["uri"],
            requestTemplates=req_templates,
            requestParameters=request_parameters,
        )
        response_configs = [
            {"pattern": "^2.*", "code": success_code, "res_templates": res_templates},
            {"pattern": "^4.*", "code": client_error_code, "res_templates": {}},
            {"pattern": "^5.*", "code": server_error_code, "res_templates": {}},
        ]
        # create response configs
        for response_config in response_configs:
            # create integration response
            client.put_integration_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method["httpMethod"],
                statusCode=response_config["code"],
                responseTemplates=response_config["res_templates"],
                selectionPattern=response_config["pattern"],
            )
            # create method response
            client.put_method_response(
                restApiId=api_id,
                resourceId=resource_id,
                httpMethod=method["httpMethod"],
                statusCode=response_config["code"],
            )


def apigateway_invocations_arn(lambda_uri, region_name: str = None):
    return "arn:aws:apigateway:%s:lambda:path/2015-03-31/functions/%s/invocations" % (
        region_name or get_region(),
        lambda_uri,
    )


def get_opensearch_endpoint(domain_arn: str) -> str:
    """
    Get an OpenSearch cluster endpoint by describing the cluster associated with the domain_arn
    :param domain_arn: ARN of the cluster.
    :returns: cluster endpoint
    :raises: ValueError if the domain_arn is malformed
    """
    region_name = extract_region_from_arn(domain_arn)
    if region_name is None:
        raise ValueError("unable to parse region from opensearch domain ARN")
    opensearch_client = connect_to_service(service_name="opensearch", region_name=region_name)
    domain_name = domain_arn.rpartition("/")[2]
    info = opensearch_client.describe_domain(DomainName=domain_name)
    base_domain = info["DomainStatus"]["Endpoint"]
    endpoint = base_domain if base_domain.startswith("http") else f"https://{base_domain}"
    return endpoint


def get_search_db_connection(endpoint: str, region_name: str):
    """
    Get a connection to an ElasticSearch or OpenSearch DB
    :param endpoint: cluster endpoint
    :param region_name: cluster region e.g. us-east-1
    """
    from opensearchpy import OpenSearch, RequestsHttpConnection
    from requests_aws4auth import AWS4Auth

    verify_certs = False
    use_ssl = False
    # use ssl?
    if "https://" in endpoint:
        use_ssl = True
        # TODO remove this condition once ssl certs are available for .es.localhost.localstack.cloud domains
        endpoint_netloc = urlparse(endpoint).netloc
        if not re.match(r"^.*(localhost(\.localstack\.cloud)?)(:\d+)?$", endpoint_netloc):
            verify_certs = True

    LOG.debug("Creating ES client with endpoint %s", endpoint)
    if ENV_ACCESS_KEY in os.environ and ENV_SECRET_KEY in os.environ:
        access_key = os.environ.get(ENV_ACCESS_KEY)
        secret_key = os.environ.get(ENV_SECRET_KEY)
        session_token = os.environ.get(ENV_SESSION_TOKEN)
        awsauth = AWS4Auth(access_key, secret_key, region_name, "es", session_token=session_token)
        connection_class = RequestsHttpConnection
        return OpenSearch(
            hosts=[endpoint],
            verify_certs=verify_certs,
            use_ssl=use_ssl,
            connection_class=connection_class,
            http_auth=awsauth,
        )
    return OpenSearch(hosts=[endpoint], verify_certs=verify_certs, use_ssl=use_ssl)


def create_kinesis_stream(stream_name, shards=1, env=None, delete=False):
    env = get_environment(env)
    stream = KinesisStream(id=stream_name, num_shards=shards)
    conn = connect_to_service("kinesis", env=env)
    stream.connect(conn)
    if delete:
        run_safe(lambda: stream.destroy(), print_error=False)
    stream.create()
    # Note: Returning the stream without awaiting its creation (via wait_for()) to avoid API call timeouts/retries.
    return stream


def kinesis_get_latest_records(stream_name, shard_id, count=10, env=None):
    kinesis = connect_to_service("kinesis", env=env)
    result = []
    response = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=shard_id, ShardIteratorType="TRIM_HORIZON"
    )
    shard_iterator = response["ShardIterator"]
    while shard_iterator:
        records_response = kinesis.get_records(ShardIterator=shard_iterator)
        records = records_response["Records"]
        for record in records:
            try:
                record["Data"] = to_str(record["Data"])
            except Exception:
                pass
        result.extend(records)
        shard_iterator = records_response["NextShardIterator"] if records else False
        while len(result) > count:
            result.pop(0)
    return result


def get_stack_details(stack_name, region_name=None):
    cloudformation = connect_to_service("cloudformation", region_name=region_name)
    stacks = cloudformation.describe_stacks(StackName=stack_name)
    for stack in stacks["Stacks"]:
        if stack["StackName"] == stack_name:
            return stack


def deploy_cf_stack(stack_name, template_body):
    cfn = connect_to_service("cloudformation")
    cfn.create_stack(StackName=stack_name, TemplateBody=template_body)
    # wait for deployment to finish
    return await_stack_completion(stack_name)


def await_stack_status(stack_name, expected_statuses, retries=20, sleep=2, region_name=None):
    def check_stack():
        stack = get_stack_details(stack_name, region_name=region_name)
        if stack["StackStatus"] not in expected_statuses:
            raise Exception(
                'Status "%s" for stack "%s" not in expected list: %s'
                % (stack["StackStatus"], stack_name, expected_statuses)
            )
        return stack

    expected_statuses = (
        expected_statuses if isinstance(expected_statuses, list) else [expected_statuses]
    )
    return retry(check_stack, retries, sleep)


def await_stack_completion(stack_name, retries=20, sleep=2, statuses=None, region_name=None):
    statuses = statuses or ["CREATE_COMPLETE", "UPDATE_COMPLETE", "DELETE_COMPLETE"]
    return await_stack_status(
        stack_name, statuses, retries=retries, sleep=sleep, region_name=region_name
    )


def get_ecr_repository_arn(name, account_id=None, region_name=None):
    pattern = "arn:aws:ecr:%s:%s:repository/%s"
    return _resource_arn(name, pattern, account_id=account_id, region_name=region_name)
