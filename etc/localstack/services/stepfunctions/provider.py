from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.stepfunctions import (
    CreateStateMachineInput,
    CreateStateMachineOutput,
    DeleteStateMachineInput,
    DeleteStateMachineOutput,
    StepfunctionsApi,
)
from localstack.aws.forwarder import HttpFallbackDispatcher, get_request_forwarder_http
from localstack.aws.proxy import AwsApiListener
from localstack.constants import LOCALHOST
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.stepfunctions.stepfunctions_starter import (
    start_stepfunctions,
    wait_for_stepfunctions,
)
from localstack.utils.analytics import event_publisher


class StepFunctionsApiListener(AwsApiListener):
    def __init__(self, provider=None):
        provider = provider or StepFunctionsProvider()
        self.provider = provider
        super().__init__(
            "stepfunctions", HttpFallbackDispatcher(provider, provider.get_forward_url)
        )


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
        result = self.forward_request(context, request)
        event_publisher.fire_event(
            event_publisher.EVENT_STEPFUNCTIONS_CREATE_SM,
            payload={"m": event_publisher.get_hash(request["name"])},
        )
        return result

    @handler("DeleteStateMachine", expand=False)
    def delete_state_machine(
        self, context: RequestContext, request: DeleteStateMachineInput
    ) -> DeleteStateMachineOutput:
        result = self.forward_request(context, request)
        name = request["stateMachineArn"].split(":")[-1]
        event_publisher.fire_event(
            event_publisher.EVENT_STEPFUNCTIONS_DELETE_SM,
            payload={"m": event_publisher.get_hash(name)},
        )
        return result
