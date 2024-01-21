from localstack.services.stepfunctions.asl.component.common.result_selector import ResultSelector
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class TestStateResultSelector(ResultSelector):
    def _eval_body(self, env: TestStateEnvironment) -> None:
        super()._eval_body(env=env)
        state_out = env.stack[-1]
        state_out_str = to_json_str(state_out)
        env.inspection_data["afterResultSelector"] = state_out_str
