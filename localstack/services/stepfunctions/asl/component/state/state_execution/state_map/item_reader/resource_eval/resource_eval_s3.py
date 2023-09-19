from botocore.config import Config

from localstack.aws.connect import connect_externally_to
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.item_reader.resource_eval.resource_eval import (
    ResourceEval,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.strings import camel_to_snake_case, to_str


class ResourceEvalS3(ResourceEval):
    def eval_resource(self, env: Environment) -> None:
        parameters = env.stack.pop()
        api_action = camel_to_snake_case(self.resource.api_action)
        s3_client = connect_externally_to(config=Config(parameter_validation=False)).s3
        response = getattr(s3_client, api_action)(**parameters)
        # TODO: check behaviour for error cases.
        # TODO: not only body, set custom behavour per supported api call.
        content = to_str(response["Body"].read())
        env.stack.append(content)
