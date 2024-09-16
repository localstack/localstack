import json
from datetime import datetime, timezone

import botocore
from botocore.client import BaseClient

from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn
from localstack.utils.json import BytesEncoder


def get_internal_client(
    arn: str,
    client_config: botocore.config.Config = None,
    role_arn: str = None,
    service_principal: str = None,
    source_arn: str = None,
    service: str = None,
    session_name: str = None,
) -> BaseClient:
    """Return a botocore client for a given arn. Supports:
    * assume role if `role_arn` is provided
    * request metadata if `source_arn` is provided
    """
    parsed_arn = parse_arn(arn)
    parsed_arn["service"] = get_standardized_service_name(parsed_arn["service"])
    service = service or parsed_arn["service"]
    if role_arn:
        client = connect_to.with_assumed_role(
            role_arn=role_arn,
            service_principal=service_principal,
            session_name=session_name,
            region_name=parsed_arn["region"],
            config=client_config,
        ).get_client(service)
    else:
        client = connect_to(
            aws_access_key_id=parsed_arn["account"],
            region_name=parsed_arn["region"],
            config=client_config,
        ).get_client(service)

    if source_arn:
        client = client.request_metadata(source_arn=source_arn, service_principal=service_principal)

    return client


def get_standardized_service_name(service_name: str) -> str:
    """Convert ARN service namespace to standardized service name used for boto clients."""
    if service_name == "states":
        return "stepfunctions"
    elif service_name == "dynamodb":
        return "dynamodbstreams"
    else:
        return service_name


def get_current_time() -> datetime:
    return datetime.now(tz=timezone.utc)


def get_datetime_from_timestamp(timestamp: float) -> datetime:
    return datetime.utcfromtimestamp(timestamp)
    # TODO: fixed deprecated API (timestamp snapshots fail with the below)
    # return datetime.fromtimestamp(timestamp, tz=timezone.utc)


def to_json_str(obj: any) -> str:
    """Custom JSON encoding for events with potentially unserializable fields (e.g., byte string).
    JSON encoders in LocalStack:
    * localstack.utils.json.CustomEncoder
    * localstack.utils.json.BytesEncoder
    * localstack.services.events.utils.EventJSONEncoder
    * localstack.services.stepfunctions.asl.utils.encoding._DateTimeEncoder
    """
    return json.dumps(obj, cls=BytesEncoder)
