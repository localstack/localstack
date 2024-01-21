from localstack.services.stepfunctions.asl.component.common.parameters import Parameters
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class TestStateParameters(Parameters):
    def _eval_body(self, env: TestStateEnvironment) -> None:
        super()._eval_body(env=env)
        state_out = env.stack[-1]
        state_out_str = to_json_str(state_out)
        env.inspection_data["afterParameters"] = state_out_str
