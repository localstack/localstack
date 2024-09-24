from botocore.client import BaseClient
from botocore.config import Config

from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.component.common.timeouts.timeout import TimeoutSeconds


def boto_client_for(region: str, account: str, service: str) -> BaseClient:
    return connect_to.get_client(
        aws_access_key_id=account,
        region_name=region,
        service_name=service,
        config=Config(
            parameter_validation=False,
            retries={"max_attempts": 0, "total_max_attempts": 1},
            connect_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
            read_timeout=TimeoutSeconds.DEFAULT_TIMEOUT_SECONDS,
        ),
    )
