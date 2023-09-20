from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.resource import (
    LambdaResource,
    Resource,
    ServiceResource,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.service.state_task_service_factory import (
    state_task_service_for,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task import (
    StateTask,
)
from localstack.services.stepfunctions.asl.component.state.state_execution.state_task.state_task_lambda import (
    StateTaskLambda,
)


def state_task_for(resource: Resource) -> StateTask:
    if not resource:
        raise ValueError("No Resource declaration in State Task.")
    if isinstance(resource, LambdaResource):
        state = StateTaskLambda()
    elif isinstance(resource, ServiceResource):
        state = state_task_service_for(service_name=resource.service_name)
    else:
        raise NotImplementedError(
            f"Resource of type '{type(resource)}' are not supported: '{resource}'."
        )
    return state
