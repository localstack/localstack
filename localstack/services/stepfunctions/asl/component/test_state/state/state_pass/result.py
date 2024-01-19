from localstack.services.stepfunctions.asl.component.state.state_pass.result import Result
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class TestStateResult(Result):
    def _eval_body(self, env: TestStateEnvironment) -> None:
        super()._eval_body(env=env)
        state_out = env.stack[-1]
        env.inspection_data["result"] = to_json_str(state_out)
