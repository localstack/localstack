from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iteration_component import (
    IterationComponent,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.distributed_iterator import (
    DistributedIterator,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.inline_iterator import (
    InlineIterator,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.iteration.iterator.iterator_decl import (
    IteratorDecl,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_map.mode import (
    Mode,
)


def from_iterator_decl(iterator_decl: IteratorDecl) -> IterationComponent:
    match iterator_decl.processor_config.mode:
        case Mode.Inline:
            return InlineIterator(
                query_language=iterator_decl.query_language,
                start_at=iterator_decl.start_at,
                states=iterator_decl.states,
                comment=iterator_decl.comment,
                processor_config=iterator_decl.processor_config,
            )
        case Mode.Distributed:
            return DistributedIterator(
                query_language=iterator_decl.query_language,
                start_at=iterator_decl.start_at,
                states=iterator_decl.states,
                comment=iterator_decl.comment,
                processor_config=iterator_decl.processor_config,
            )
        case unknown:
            raise ValueError(f"Unknown Map state processing mode: '{unknown}'.")
