from botocore.client import BaseClient
from botocore.config import Config

from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import TimeoutSeconds
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.credentials import (
    StateCredentials,
)
from localstack.utils.aws.client_types import ServicePrincipal

_BOTO_CLIENT_CONFIG = config = Config(
    parameter_validation=False,
    # Temporary workaround—should be reverted once underlying potential Lambda limitation is resolved.
    # Increased total boto client retry attempts from 1 to 5 to mitigate transient service issues.
    # This helps reduce unnecessary state machine retries on non-service-level errors.
    retries={"total_max_attempts": 5},
    connect_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
    read_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
    tcp_keepalive=True,
)


def boto_client_for(service: str, region: str, state_credentials: StateCredentials) -> BaseClient:
    client_factory = connect_to.with_assumed_role(
        role_arn=state_credentials.role_arn,
        service_principal=ServicePrincipal.states,
        region_name=region,
        config=_BOTO_CLIENT_CONFIG,
    )
    return client_factory.get_client(service=service)
