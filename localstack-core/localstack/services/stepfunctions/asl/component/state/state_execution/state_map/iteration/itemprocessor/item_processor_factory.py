from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.distributed_item_processor import (
    DistributedItemProcessor,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.inline_item_processor import (
    InlineItemProcessor,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.itemprocessor.item_processor_decl import (
    ItemProcessorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)


def from_item_processor_decl(item_processor_decl: ItemProcessorDecl) -> IterationComponent:
    match item_processor_decl.processor_config.mode:
        case Mode.Inline:
            return InlineItemProcessor(
                query_language=item_processor_decl.query_language,
                start_at=item_processor_decl.start_at,
                states=item_processor_decl.states,
                comment=item_processor_decl.comment,
                processor_config=item_processor_decl.processor_config,
            )
        case Mode.Distributed:
            return DistributedItemProcessor(
                query_language=item_processor_decl.query_language,
                start_at=item_processor_decl.start_at,
                states=item_processor_decl.states,
                comment=item_processor_decl.comment,
                processor_config=item_processor_decl.processor_config,
            )
        case unknown:
            raise ValueError(f"Unknown Map state processing mode: '{unknown}'.")
