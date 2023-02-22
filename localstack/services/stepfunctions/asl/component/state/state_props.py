from typing import Any

from localstack.services.stepfunctions.asl.component.common.flow.end import End
from localstack.services.stepfunctions.asl.component.common.flow.next import Next
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.resource import (
    Resource,
)
from localstack.services.stepfunctions.asl.component.state.state_wait.wait_function.wait_function import (
    WaitFunction,
)
from localstack.services.stepfunctions.asl.parse.typed_props import TypedProps


class StateProps(TypedProps):
    name: str

    def add(self, instance: Any) -> None:
        # End-Next conflicts:
        if isinstance(instance, End) and Next in self._instance_by_type:
            raise ValueError(
                f"'{End}' redefines '{Next}', from '{self.get(Next)}' to '{instance}'."
            )
        if isinstance(instance, Next) and End in self._instance_by_type:
            raise ValueError(f"'{Next}' redefines '{End}', from '{self.get(End)}' to '{instance}'.")

        # Resource.
        if issubclass(type(instance), Resource):
            super()._add(Resource, instance)

        # Wait functions.
        if issubclass(type(instance), WaitFunction):
            super()._add(WaitFunction, instance)

        # Base and delegate to preprocessor.
        else:
            super().add(instance)
