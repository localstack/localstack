from botocore.config import Config

from localstack.aws.connect import connect_to
from localstack.services.stepfunctions.asl.eval.environment import Environment


def get_boto_client(env: Environment, service: str):
    execution = env.context_object_manager.context_object["Execution"]
    return connect_to.get_client(
        aws_access_key_id=execution["AccountId"],
        region_name=execution["RegionName"],
        service_name=service,
        config=Config(parameter_validation=False),
    )
