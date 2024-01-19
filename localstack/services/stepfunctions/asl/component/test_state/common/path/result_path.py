import copy

from localstack.services.stepfunctions.asl.component.common.path.result_path import ResultPath
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment
from localstack.services.stepfunctions.asl.utils.encoding import to_json_str


class TestStateResultPath(ResultPath):
    def _eval_body(self, env: TestStateEnvironment) -> None:
        super()._eval_body(env=env)
        state_out = copy.deepcopy(env.stack[-1])

        # Propagate the state to all the following inspection data points.
        # AWS chooses to log even absent field. This also includes unsupported fields
        # such as ResultSelector declarations in Pass states.
        # If any, later modifiers will overwrite these values.
        state_out_str = to_json_str(state_out)
        for inspection_entry in ["afterResultPath", "afterOutputPath"]:
            env.inspection_data[inspection_entry] = state_out_str  # noqa
