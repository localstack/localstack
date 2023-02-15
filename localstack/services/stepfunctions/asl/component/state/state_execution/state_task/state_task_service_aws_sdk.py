from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.aws import aws_stack
from localstack.utils.common import camel_to_snake_case


class StateTaskServiceAwsSdk(StateTaskService):
    def _eval_execution(self, env: Environment) -> None:
        api_name = self.resource.api_name
        api_action = self.resource.resource_arn.split(":")[-1]  # TODO: always valid assumption?
        api_action = camel_to_snake_case(api_action)

        args = {}
        if self.parameters:
            self.parameters.eval(env=env)
            parameters = env.stack.pop()
            args.update(parameters)

        api_client = aws_stack.create_external_boto_client(service_name=api_name)
        response = getattr(api_client, api_action)(**args)
        response.pop("ResponseMetadata", None)

        env.stack.append(response)
