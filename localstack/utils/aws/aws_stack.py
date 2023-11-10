import json
import logging
import os
import re
import socket
from functools import lru_cache
from typing import Dict, Optional, Union

import boto3

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.config import S3_VIRTUAL_HOSTNAME
from localstack.constants import (
    APPLICATION_AMZ_JSON_1_0,
    APPLICATION_AMZ_JSON_1_1,
    APPLICATION_X_WWW_FORM_URLENCODED,
    AWS_REGION_US_EAST_1,
    ENV_DEV,
    HEADER_LOCALSTACK_ACCOUNT_ID,
    INTERNAL_AWS_ACCESS_KEY_ID,
    LOCALHOST,
    REGION_LOCAL,
)
from localstack.utils.strings import is_string, is_string_or_bytes, to_str

# set up logger
LOG = logging.getLogger(__name__)

# cache local region
LOCAL_REGION = None

# Used in AWS assume role function
INITIAL_BOTO3_SESSION = None

# cached value used to determine the DNS status of the S3 hostname (whether it can be resolved properly)
CACHE_S3_HOSTNAME_DNS_STATUS = None


@lru_cache()
def get_valid_regions():
    valid_regions = set()
    for partition in set(boto3.Session().get_available_partitions()):
        for region in boto3.Session().get_available_regions("sns", partition):
            valid_regions.add(region)
    return valid_regions


# FIXME: AWS recommends use of SSM parameter store to determine per region availability
# https://github.com/aws/aws-sdk/issues/206#issuecomment-1471354853
def get_valid_regions_for_service(service_name):
    regions = list(boto3.Session().get_available_regions(service_name))
    regions.extend(boto3.Session().get_available_regions("cloudwatch", partition_name="aws-us-gov"))
    regions.extend(boto3.Session().get_available_regions("cloudwatch", partition_name="aws-cn"))
    return regions


# TODO: Remove, this is super legacy functionality
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


# TODO: Remove
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


# NOTE: This method should not be used as it is not guaranteed to return the correct region
# In the near future it will be deprecated and removed
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


# TODO: Deprecate and remove this
def get_local_region():
    global LOCAL_REGION
    if LOCAL_REGION is None:
        LOCAL_REGION = get_boto3_region() or ""
    return AWS_REGION_US_EAST_1 or LOCAL_REGION


def get_boto3_region() -> str:
    """Return the region name, as determined from the environment when creating a new boto3 session"""
    return boto3.session.Session().region_name


# TODO: remove this and use the `is_internal_call` property of RequestContext
def is_internal_call_context(headers) -> bool:
    """Return whether we are executing in the context of an internal API call, i.e.,
    the case where one API uses a boto3 client to call another API internally."""
    if HEADER_LOCALSTACK_ACCOUNT_ID in headers.keys():
        # TODO: Used by the old client, marked for removal
        return True

    if INTERNAL_AWS_ACCESS_KEY_ID in headers.get("Authorization", ""):
        return True

    return False


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


# TODO remove the `internal` arg
def mock_aws_request_headers(
    service: str, aws_access_key_id: str, region_name: str, internal: bool = False
) -> Dict[str, str]:
    """
    Returns a mock set of headers that resemble SigV4 signing method.
    """
    ctype = APPLICATION_AMZ_JSON_1_0
    if service == "kinesis":
        ctype = APPLICATION_AMZ_JSON_1_1
    elif service in ["sns", "sqs", "sts", "cloudformation"]:
        ctype = APPLICATION_X_WWW_FORM_URLENCODED

    # For S3 presigned URLs, we require that the client and server use the same
    # access key ID to sign requests. So try to use the access key ID for the
    # current request if available
    headers = {
        "Content-Type": ctype,
        "Accept-Encoding": "identity",
        "X-Amz-Date": "20160623T103251Z",  # TODO: Use current date
        "Authorization": (
            "AWS4-HMAC-SHA256 "
            + f"Credential={aws_access_key_id}/20160623/{region_name}/{service}/aws4_request, "
            + "SignedHeaders=content-type;host;x-amz-date;x-amz-target, Signature=1234"
        ),
    }
    if internal:
        # TODO: This method of detecting internal calls is no longer valid
        # We now use the `INTERNAL_REQUEST_PARAMS_HEADER` header which is set to the DTO
        headers[HEADER_LOCALSTACK_ACCOUNT_ID] = get_aws_account_id()
    return headers
