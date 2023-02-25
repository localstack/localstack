from __future__ import annotations

from typing import Final

from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)


class ProcessorConfig(Component):
    DEFAULT_MODE: Final[Mode] = Mode.Inline

    def __init__(self, mode: Mode = DEFAULT_MODE):
        super().__init__()
        self.mode: Final[Mode] = mode
