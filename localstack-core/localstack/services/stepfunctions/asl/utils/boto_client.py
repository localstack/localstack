from typing import Optional

from botocore.client import BaseClient
from botocore.config import Config

from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import TimeoutSeconds
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    ComputedCredentials,
    Credentials,
)
from localstack.utils.aws.client_types import ServicePrincipal

_BOTO_CLIENT_CONFIG = config = Config(
    parameter_validation=False,
    retries={"max_attempts": 0, "total_max_attempts": 1},
    connect_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
    read_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
)


def boto_client_for(
    region: str, account: str, service: str, credentials: Optional[ComputedCredentials] = None
) -> BaseClient:
    if credentials:
        assume_role_arn: Optional[str] = Credentials.get_role_arn_from(
            computed_credentials=credentials
        )
        if assume_role_arn is not None:
            client_factory = connect_to.with_assumed_role(
                role_arn=assume_role_arn,
                service_principal=ServicePrincipal.states,
                region_name=region,
                config=_BOTO_CLIENT_CONFIG,
            )
            return client_factory.get_client(service=service)
    return connect_to.get_client(
        aws_access_key_id=account,
        region_name=region,
        service_name=service,
        config=_BOTO_CLIENT_CONFIG,
    )
