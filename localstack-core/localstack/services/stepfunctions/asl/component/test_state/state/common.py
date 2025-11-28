from localstack.services.stepfunctions.asl.component.state.state import CommonStateField
from localstack.services.stepfunctions.asl.component.state.state_choice.state_choice import (
    StateChoice,
)
from localstack.services.stepfunctions.asl.component.state.state_continue_with import (
    ContinueWithEnd,
)
from localstack.services.stepfunctions.asl.component.state.state_fail.state_fail import StateFail
from localstack.services.stepfunctions.asl.component.state.state_pass.state_pass import StatePass
from localstack.services.stepfunctions.asl.component.state.state_succeed.state_succeed import (
    StateSucceed,
)
from localstack.services.stepfunctions.asl.component.test_state.state.base_mock import (
    MockedBaseState,
)
from localstack.services.stepfunctions.asl.eval.test_state.environment import TestStateEnvironment


class MockedCommonState(MockedBaseState[CommonStateField]):
    def add_inspection_data(self, env: TestStateEnvironment):
        state = self._wrapped

        if not isinstance(state, StatePass):
            if not self.is_single_state:
                return

            if "afterInputPath" not in env.inspection_data:
                env.inspection_data["afterInputPath"] = env.states.get_input()
            return

        # If not a terminal state, only populate inspection data from pre-processor.
        if not isinstance(self._wrapped.continue_with, ContinueWithEnd):
            return

        if state.result:
            # TODO: investigate interactions between these inspectionData field types.
            # i.e parity tests shows that if "Result" is defined, 'afterInputPath' and 'afterParameters'
            # cannot be present in the inspection data.
            env.inspection_data.pop("afterInputPath", None)
            env.inspection_data.pop("afterParameters", None)

            if "afterResultSelector" not in env.inspection_data:
                env.inspection_data["afterResultSelector"] = state.result.result_obj

            if "afterResultPath" not in env.inspection_data:
                env.inspection_data["afterResultPath"] = env.inspection_data.get(
                    "afterResultSelector", env.states.get_input()
                )
            return

        if "afterInputPath" not in env.inspection_data:
            env.inspection_data["afterInputPath"] = env.states.get_input()

        if "afterParameters" not in env.inspection_data:
            env.inspection_data["afterParameters"] = env.inspection_data.get(
                "afterInputPath", env.states.get_input()
            )

        if "afterResultSelector" not in env.inspection_data:
            env.inspection_data["afterResultSelector"] = env.inspection_data["afterParameters"]

        if "afterResultPath" not in env.inspection_data:
            env.inspection_data["afterResultPath"] = env.inspection_data.get(
                "afterResultSelector", env.states.get_input()
            )

    def _apply_patches(self):
        if not isinstance(self._wrapped, (StatePass, StateFail, StateChoice, StateSucceed)):
            raise ValueError("Needs to be a Pass, Fail, Choice, or Succeed state.")

        original_eval_body = self.wrap_with_mock(self._wrapped._eval_body)

        def mock_eval_execution(env: TestStateEnvironment):
            original_eval_body(env)
            env.set_choice_selected(env.next_state_name)

        mock_eval_execution = self.wrap_with_post_return(
            method=mock_eval_execution,
            post_return_fn=self.add_inspection_data,
        )

        self._wrapped._eval_body = mock_eval_execution
