import threading

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.stepfunctions import (
    CreateStateMachineInput,
    CreateStateMachineOutput,
    DeleteStateMachineInput,
    DeleteStateMachineOutput,
    LoggingConfiguration,
    LogLevel,
    StepfunctionsApi,
)
from localstack.aws.forwarder import get_request_forwarder_http
from localstack.constants import LOCALHOST
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.stepfunctions.stepfunctions_starter import (
    start_stepfunctions,
    wait_for_stepfunctions,
)

# lock to avoid concurrency issues when creating state machines in parallel (required for StepFunctions-Local)
CREATION_LOCK = threading.RLock()


class StepFunctionsProvider(StepfunctionsApi, ServiceLifecycleHook):
    def __init__(self):
        self.forward_request = get_request_forwarder_http(self.get_forward_url)

    def get_forward_url(self) -> str:
        """Return the URL of the backend StepFunctions server to forward requests to"""
        return f"http://{LOCALHOST}:{config.LOCAL_PORT_STEPFUNCTIONS}"

    def on_before_start(self):
        start_stepfunctions()
        wait_for_stepfunctions()

    def create_state_machine(
        self, context: RequestContext, request: CreateStateMachineInput
    ) -> CreateStateMachineOutput:
        # set default logging configuration
        if not request.get("loggingConfiguration"):
            request["loggingConfiguration"] = LoggingConfiguration(
                level=LogLevel.OFF, includeExecutionData=False
            )
        with CREATION_LOCK:
            return self.forward_request(context, request)

    @handler("DeleteStateMachine", expand=False)
    def delete_state_machine(
        self, context: RequestContext, request: DeleteStateMachineInput
    ) -> DeleteStateMachineOutput:
        result = self.forward_request(context, request)
        return result
