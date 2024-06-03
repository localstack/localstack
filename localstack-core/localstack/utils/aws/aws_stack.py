import logging
import re
import socket
from functools import lru_cache
from typing import List, Union

import boto3

from localstack import config
from localstack.config import S3_VIRTUAL_HOSTNAME
from localstack.constants import (
    LOCALHOST,
)
from localstack.utils.strings import is_string_or_bytes, to_str

# set up logger
LOG = logging.getLogger(__name__)

# cached value used to determine the DNS status of the S3 hostname (whether it can be resolved properly)
CACHE_S3_HOSTNAME_DNS_STATUS = None


@lru_cache()
def get_valid_regions():
    session = boto3.Session()
    valid_regions = set()
    for partition in set(session.get_available_partitions()):
        for region in session.get_available_regions("sns", partition):
            valid_regions.add(region)
    return valid_regions


# FIXME: AWS recommends use of SSM parameter store to determine per region availability
# https://github.com/aws/aws-sdk/issues/206#issuecomment-1471354853
@lru_cache()
def get_valid_regions_for_service(service_name):
    session = boto3.Session()
    regions = list(session.get_available_regions(service_name))
    regions.extend(session.get_available_regions("cloudwatch", partition_name="aws-us-gov"))
    regions.extend(session.get_available_regions("cloudwatch", partition_name="aws-cn"))
    return regions


def get_boto3_region() -> str:
    """Return the region name, as determined from the environment when creating a new boto3 session"""
    return boto3.session.Session().region_name


def get_local_service_url(service_name_or_port: Union[str, int]) -> str:
    """Return the local service URL for the given service name or port."""
    # TODO(srw): we don't need to differentiate on service name any more, so remove the argument
    if isinstance(service_name_or_port, int):
        return f"{config.get_protocol()}://{LOCALHOST}:{service_name_or_port}"
    return config.internal_service_url()


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


def fix_account_id_in_arns(
    response, replacement: str, colon_delimiter: str = ":", existing: Union[str, List[str]] = None
):
    """Fix the account ID in the ARNs returned in the given Flask response or string"""
    from moto.core import DEFAULT_ACCOUNT_ID

    existing = existing or ["123456789", "1234567890", DEFAULT_ACCOUNT_ID]
    existing = existing if isinstance(existing, list) else [existing]
    is_str_obj = is_string_or_bytes(response)
    content = to_str(response if is_str_obj else response._content)

    replacement = r"arn{col}aws{col}\1{col}\2{col}{acc}{col}".format(
        col=colon_delimiter, acc=replacement
    )
    for acc_id in existing:
        regex = r"arn{col}aws{col}([^:%]+){col}([^:%]*){col}{acc}{col}".format(
            col=colon_delimiter, acc=acc_id
        )
        content = re.sub(regex, replacement, content)

    if not is_str_obj:
        response._content = content
        response.headers["Content-Length"] = len(response._content)
        return response
    return content


def inject_test_credentials_into_env(env):
    if "AWS_ACCESS_KEY_ID" not in env and "AWS_SECRET_ACCESS_KEY" not in env:
        env["AWS_ACCESS_KEY_ID"] = "test"
        env["AWS_SECRET_ACCESS_KEY"] = "test"
