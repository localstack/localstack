from botocore.config import Config

from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.eval.environment import Environment


def get_boto_client(env: Environment, service: str):
    return connect_to.get_client(
        aws_access_key_id=env.account_id,
        region_name=env.region_name,
        service_name=service,
        config=Config(parameter_validation=False),
    )
