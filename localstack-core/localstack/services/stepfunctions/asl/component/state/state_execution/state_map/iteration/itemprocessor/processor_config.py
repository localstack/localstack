from __future__ import annotations

from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.execution_type import (
    ExecutionType,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)


class ProcessorConfig(Component):
    DEFAULT_MODE: Final[Mode] = Mode.Inline
    DEFAULT_EXECUTION_TYPE: Final[ExecutionType] = ExecutionType.Standard

    mode: Final[Mode]
    execution_type: Final[ExecutionType]

    def __init__(
        self, mode: Mode = DEFAULT_MODE, execution_type: ExecutionType = DEFAULT_EXECUTION_TYPE
    ):
        super().__init__()
        self.mode = mode
        self.execution_type = execution_type
