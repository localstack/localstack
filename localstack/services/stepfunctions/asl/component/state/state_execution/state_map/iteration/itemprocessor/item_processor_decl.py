from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_declaration import (
    IterationDecl,
)
from localstack.services.stepfunctions.asl.component.states import States


class ItemProcessorDecl(IterationDecl):
    processor_config: Final[ProcessorConfig]

    def __init__(
        self,
        comment: Optional[Comment],
        start_at: StartAt,
        states: States,
        processor_config: ProcessorConfig,
    ):
        super().__init__(start_at=start_at, comment=comment, states=states)
        self.processor_config = processor_config
