import functools
import json
import logging
import os
import re
import socket
import threading
from functools import lru_cache
from typing import Dict, Optional, Union

import boto3
import botocore
import botocore.config

from localstack import config
from localstack.aws.accounts import get_aws_access_key_id, get_aws_account_id
from localstack.constants import (
    APPLICATION_AMZ_JSON_1_0,
    APPLICATION_AMZ_JSON_1_1,
    APPLICATION_X_WWW_FORM_URLENCODED,
    ENV_DEV,
    HEADER_LOCALSTACK_ACCOUNT_ID,
    LOCALHOST,
    MAX_POOL_CONNECTIONS,
    REGION_LOCAL,
    S3_VIRTUAL_HOSTNAME,
    TEST_AWS_ACCESS_KEY_ID,
    TEST_AWS_SECRET_ACCESS_KEY,
)
from localstack.utils.strings import is_string, is_string_or_bytes, to_str

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
        LOCAL_REGION = get_boto3_region() or ""
    return config.DEFAULT_REGION or LOCAL_REGION


def get_boto3_region() -> str:
    """Return the region name, as determined from the environment when creating a new boto3 session"""
    return boto3.session.Session().region_name


def is_internal_call_context(headers):
    """Return whether we are executing in the context of an internal API call, i.e.,
    the case where one API uses a boto3 client to call another API internally."""
    return HEADER_LOCALSTACK_ACCOUNT_ID in headers.keys()


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
        *args,
        **kwargs,
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
    internal=True,
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
    key_elements = [service_name, client, env, region, endpoint_url, config, internal, kwargs]
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

        # We set a custom header in all internal calls which help LocalStack
        # identify requests as such
        if client and internal:

            def _add_internal_header(account_id: str, request, **kwargs):
                request.headers.add_header(HEADER_LOCALSTACK_ACCOUNT_ID, account_id)

            # The handler invocation happens in boto context leading to loss of account ID
            # Hence we build a partial here with the account ID baked-in.
            _handler = functools.partial(
                _add_internal_header, kwargs.get("aws_access_key_id", get_aws_account_id())
            )

            event_system = new_client.meta.events
            event_system.register_first("before-sign.*.*", _handler)

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
    aws_access_key_id=None,
    aws_secret_access_key=None,
    *args,
    **kwargs,
):
    # Currently we use the Access Key ID field to specify the AWS account ID; this will change when IAM matures.
    # It is important that the correct Account ID is included in the request as that will determine access to namespaced resources.
    if aws_access_key_id is None:
        aws_access_key_id = get_aws_account_id()

    if aws_secret_access_key is None:
        aws_secret_access_key = TEST_AWS_SECRET_ACCESS_KEY

    return connect_to_service(
        service_name,
        client,
        env,
        region_name,
        endpoint_url,
        config,
        verify,
        cache,
        internal=False,
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
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
    existing = existing or ["123456789", "1234567890", "123456789012", get_aws_account_id()]
    existing = existing if isinstance(existing, list) else [existing]
    replace = replace or get_aws_account_id()
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
    if "AWS_ACCESS_KEY_ID" not in env and "AWS_SECRET_ACCESS_KEY" not in env:
        env["AWS_ACCESS_KEY_ID"] = "test"
        env["AWS_SECRET_ACCESS_KEY"] = "test"


# TODO: remove
def inject_region_into_env(env, region):
    env["AWS_REGION"] = region


def extract_region_from_auth_header(headers: Dict[str, str], use_default=True) -> str:
    auth = headers.get("Authorization") or ""
    region = re.sub(r".*Credential=[^/]+/[^/]+/([^/]+)/.*", r"\1", auth)
    if region == auth:
        region = None
    if use_default:
        region = region or get_region()
    return region


def extract_access_key_id_from_auth_header(headers: Dict[str, str]) -> Optional[str]:
    auth = headers.get("Authorization") or ""

    if auth.startswith("AWS4-"):
        # For Signature Version 4
        access_id = re.findall(r".*Credential=([^/]+)/[^/]+/[^/]+/.*", auth)
        if len(access_id):
            return access_id[0]

    elif auth.startswith("AWS "):
        # For Signature Version 2
        access_id = auth.removeprefix("AWS ").split(":")
        if len(access_id):
            return access_id[0]


def mock_aws_request_headers(
    service="dynamodb", region_name=None, access_key=None, internal=False
) -> Dict[str, str]:
    ctype = APPLICATION_AMZ_JSON_1_0
    if service == "kinesis":
        ctype = APPLICATION_AMZ_JSON_1_1
    elif service in ["sns", "sqs", "sts", "cloudformation"]:
        ctype = APPLICATION_X_WWW_FORM_URLENCODED

    # For S3 presigned URLs, we require that the client and server use the same
    # access key ID to sign requests. So try to use the access key ID for the
    # current request if available
    access_key = access_key or get_aws_access_key_id()
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
    if internal:
        headers[HEADER_LOCALSTACK_ACCOUNT_ID] = get_aws_account_id()
    return headers
