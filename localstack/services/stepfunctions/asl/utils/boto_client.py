from botocore.client import BaseClient
from botocore.config import Config

from localstack.aws.connect import connect_to


def boto_client_for(region: str, account: str, service: str) -> BaseClient:
    return connect_to.get_client(
        aws_access_key_id=account,
        region_name=region,
        service_name=service,
        config=Config(parameter_validation=False),
    )
