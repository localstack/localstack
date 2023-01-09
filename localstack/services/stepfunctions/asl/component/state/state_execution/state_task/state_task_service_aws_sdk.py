import json

import requests

from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_service import (
    StateTaskService,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment
from localstack.utils.aws import aws_stack


class StateTaskServiceAwsSdk(StateTaskService):
    def _eval_execution(self, env: Environment) -> None:
        api_name = self.resource.api_name
        api_action = self.resource.resource_arn.split(":")[-1]  # TODO: always valid assumption?

        url: str = aws_stack.get_local_service_url(api_name)
        headers = aws_stack.mock_aws_request_headers(api_name)
        headers["X-Amz-Target"] = f"{api_name}.{api_action}"

        data = None
        if self.parameters:
            self.parameters.eval(env=env)
            parameters = env.stack.pop()
            data = json.dumps(parameters)

        response: requests.Response = requests.post(url, headers=headers, data=data)
        response_json = response.json()

        env.stack.append(response_json)
