from typing import Final, Optional

from localstack.services.stepfunctions.asl.component.common.comment import Comment
from localstack.services.stepfunctions.asl.component.common.flow.start_at import StartAt
from localstack.services.stepfunctions.asl.component.common.query_language import QueryLanguage
from localstack.services.stepfunctions.asl.component.component import Component
from localstack.services.stepfunctions.asl.component.program.states import States
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.processor_config import (
    ProcessorConfig,
)


class IterationDecl(Component):
    comment: Final[Optional[Comment]]
    query_language: Final[QueryLanguage]
    start_at: Final[StartAt]
    states: Final[States]
    processor_config: Final[ProcessorConfig]

    def __init__(
        self,
        comment: Optional[Comment],
        query_language: QueryLanguage,
        start_at: StartAt,
        states: States,
        processor_config: ProcessorConfig,
    ):
        self.comment = comment
        self.query_language = query_language
        self.start_at = start_at
        self.states = states
        self.processor_config = processor_config
