import json
import logging
import re
from dataclasses import dataclass
from typing import Any

from botocore.exceptions import ClientError

from localstack.aws.connect import connect_to

LOG = logging.getLogger(__name__)

REGEX_DYNAMIC_REF = re.compile(r"{{resolve:([^:]+):(.+)}}")


@dataclass
class DynamicReference:
    service_name: str
    reference_key: str


def extract_dynamic_reference(value: Any) -> DynamicReference | None:
    if isinstance(value, str):
        if dynamic_ref_match := REGEX_DYNAMIC_REF.match(value):
            return DynamicReference(dynamic_ref_match[1], dynamic_ref_match[2])
    return None


def perform_dynamic_reference_lookup(
    reference: DynamicReference, account_id: str, region_name: str
) -> str | None:
    # basic dynamic reference support
    # see: https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html
    # technically there are more restrictions for each of these services but checking each of these
    # isn't really necessary for the current level of emulation

    # only these 3 services are supported for dynamic references right now
    if reference.service_name == "ssm":
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        try:
            return ssm_client.get_parameter(Name=reference.reference_key)["Parameter"]["Value"]
        except ClientError as e:
            LOG.error("client error accessing SSM parameter '%s': %s", reference.reference_key, e)
            raise
    elif reference.service_name == "ssm-secure":
        ssm_client = connect_to(aws_access_key_id=account_id, region_name=region_name).ssm
        try:
            return ssm_client.get_parameter(Name=reference.reference_key, WithDecryption=True)[
                "Parameter"
            ]["Value"]
        except ClientError as e:
            LOG.error("client error accessing SSM parameter '%s': %s", reference.reference_key, e)
            raise
    elif reference.service_name == "secretsmanager":
        # reference key needs to be parsed further
        # because {{resolve:secretsmanager:secret-id:secret-string:json-key:version-stage:version-id}}
        # we match for "secret-id:secret-string:json-key:version-stage:version-id"
        # where
        #   secret-id can either be the secret name or the full ARN of the secret
        #   secret-string *must* be SecretString
        #   all other values are optional
        secret_id = reference.reference_key
        [json_key, version_stage, version_id] = [None, None, None]
        if "SecretString" in reference.reference_key:
            parts = reference.reference_key.split(":SecretString:")
            secret_id = parts[0]
            # json-key, version-stage and version-id are optional.
            [json_key, version_stage, version_id] = f"{parts[1]}::".split(":")[:3]

        kwargs = {}  # optional args for get_secret_value
        if version_id:
            kwargs["VersionId"] = version_id
        if version_stage:
            kwargs["VersionStage"] = version_stage

        secretsmanager_client = connect_to(
            aws_access_key_id=account_id, region_name=region_name
        ).secretsmanager
        try:
            secret_value = secretsmanager_client.get_secret_value(SecretId=secret_id, **kwargs)[
                "SecretString"
            ]
        except ClientError:
            LOG.error("client error while trying to access key '%s': %s", secret_id)
            raise

        if json_key:
            json_secret = json.loads(secret_value)
            if json_key not in json_secret:
                raise RuntimeError(
                    f"JSON value for {reference.service_name}.{reference.reference_key} not present"
                )
            return json_secret[json_key]
        else:
            return secret_value

    LOG.warning(
        "Unsupported service for dynamic parameter: service_name=%s", reference.service_name
    )
    return None
