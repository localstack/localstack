import copy
from typing import Any

from localstack.services.stepfunctions.asl.component.intrinsic.argument.argument import (
    ArgumentList,
)
from localstack.services.stepfunctions.asl.component.intrinsic.function.statesfunction.states_function import (
    StatesFunction,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.state_function_name_types import (
    StatesFunctionNameType,
)
from localstack.services.stepfunctions.asl.component.intrinsic.functionname.states_function_name import (
    StatesFunctionName,
)
from localstack.services.stepfunctions.asl.eval.environment import Environment


class JsonMerge(StatesFunction):
    # Merges two JSON objects into a single object
    #
    # For example:
    # With input
    # {
    #    "json1": { "a": {"a1": 1, "a2": 2}, "b": 2, },
    #    "json2": { "a": {"a3": 1, "a4": 2}, "c": 3 }
    # }
    #
    # Call
    # "output.$": "States.JsonMerge($.json1, $.json2, false)"
    #
    # Returns
    # {
    #    "output": {
    #       "a": {"a3": 1, "a4": 2},
    #       "b": 2,
    #       "c": 3
    #    }
    # }

    def __init__(self, argument_list: ArgumentList):
        super().__init__(
            states_name=StatesFunctionName(function_type=StatesFunctionNameType.JsonMerge),
            argument_list=argument_list,
        )
        if argument_list.size != 3:
            raise ValueError(
                f"Expected 3 arguments for function type '{type(self)}', but got: '{argument_list}'."
            )

    @staticmethod
    def _validate_is_deep_merge_argument(is_deep_merge: Any) -> None:
        if not isinstance(is_deep_merge, bool):
            raise TypeError(
                f"Expected boolean value for deep merge mode, but got: '{is_deep_merge}'."
            )
        if is_deep_merge:
            # This is AWS's limitation, not LocalStack's.
            raise NotImplementedError(
                "Currently, Step Functions only supports the shallow merging mode; "
                "therefore, you must specify the boolean value as false."
            )

    @staticmethod
    def _validate_merge_argument(argument: Any, num: int) -> None:
        if not isinstance(argument, dict):
            raise TypeError(f"Expected a JSON object the argument {num}, but got: '{argument}'.")

    def _eval_body(self, env: Environment) -> None:
        self.argument_list.eval(env=env)
        args = env.stack.pop()

        is_deep_merge = args.pop()
        self._validate_is_deep_merge_argument(is_deep_merge)

        snd = args.pop()
        self._validate_merge_argument(snd, 2)

        fst = args.pop()
        self._validate_merge_argument(snd, 2)

        # Currently, Step Functions only supports the shallow merging mode; therefore, you must specify the boolean
        # value as false. In the shallow mode, if the same key exists in both JSON objects, the latter object's key
        # overrides the same key in the first object. Additionally, objects nested within a JSON object aren't merged
        # when you use shallow merging.
        merged = copy.deepcopy(fst)
        merged.update(snd)

        env.stack.append(merged)
