import logging
import os
import threading

from localstack import config
from localstack.aws.accounts import get_aws_account_id
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
from localstack.services.stepfunctions.stepfunctions_starter import StepFunctionsServerManager
from localstack.state import AssetDirectory, StateVisitor
from localstack.utils.aws import aws_stack

# lock to avoid concurrency issues when creating state machines in parallel (required for StepFunctions-Local)
CREATION_LOCK = threading.RLock()

LOG = logging.getLogger(__name__)


class StepFunctionsProvider(StepfunctionsApi, ServiceLifecycleHook):
    server_manager = StepFunctionsServerManager()

    def __init__(self):
        self.forward_request = get_request_forwarder_http(self.get_forward_url)

    def on_after_init(self):
        LOG.warning(
            "The 'v1' StepFunctions provider (current default) will be deprecated with the next major release (3.0). "
            "Set 'PROVIDER_OVERRIDE_STEPFUNCTIONS=v2' to opt-in to the new StepFunctions 'v2' provider."
        )

    def get_forward_url(self) -> str:
        """Return the URL of the backend StepFunctions server to forward requests to"""
        account_id = get_aws_account_id()
        region_name = aws_stack.get_region()
        server = self.server_manager.get_server_for_account_region(account_id, region_name)
        return f"http://{LOCALHOST}:{server.port}"

    def accept_state_visitor(self, visitor: StateVisitor):
        visitor.visit(AssetDirectory(self.service, os.path.join(config.dirs.data, self.service)))

    def on_before_state_load(self):
        self.server_manager.shutdown_all()

    def on_before_state_reset(self):
        self.server_manager.shutdown_all()

    def on_before_stop(self):
        self.server_manager.shutdown_all()

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
