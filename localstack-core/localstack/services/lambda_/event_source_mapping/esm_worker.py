import logging
import threading

from localstack_ext.services.pipes.pollers.poller import Poller
from localstack_ext.services.pipes.senders.sender import Sender

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
    FunctionVersion,
    ResourceNotFoundException,
)
from localstack.services.lambda_ import api_utils
from localstack.services.lambda_.api_utils import function_locators_from_arn
from localstack.services.lambda_.invocation.models import lambda_stores
from localstack.utils.threads import FuncThread

LOG = logging.getLogger(__name__)


class EsmState(str):
    # https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html#lambda-CreateEventSourceMapping-response-State
    CREATING = "Creating"
    ENABLING = "Enabling"
    ENABLED = "Enabled"
    DISABLING = "Disabling"
    DISABLED = "Disabled"
    UPDATING = "Updating"
    DELETING = "Deleting"


class EsmStateReason(str):
    USER_INITIATED = "USER_INITIATED"
    NO_RECORDS_PROCESSED = "No records processed"
    # TODO: add others


class EsmWorker:
    esm_config: EventSourceMappingConfiguration
    enabled: bool
    current_state: str
    state_transition_reason: str
    last_processing_result: str

    poller: Poller
    sender: Sender

    _state_lock: threading.RLock
    _shutdown_event: threading.Event
    _poller_thread: FuncThread | None

    def __init__(
        self,
        event_source_mapping_config: EventSourceMappingConfiguration,
        poller: Poller,
        sender: Sender,
        enabled: bool = True,
    ):
        self.esm_config = event_source_mapping_config
        self.current_state = EsmState.CREATING

        self.poller = poller
        self.sender = sender
        self.enabled = enabled

        # TODO: implement lifecycle locking
        self._state_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._poller_thread = None

    @property
    def uuid(self) -> str:
        return self.esm_config["UUID"]

    def create(self):
        if self.enabled:
            self.start_event_source_listener()
        else:
            # TODO: test creating a disabled ESM
            pass

    def start_event_source_listener(self):
        # TODO: implement state lifecycle
        self._poller_thread = FuncThread(
            self.poller_loop,
            name=f"event-source-listener-poller-{self.uuid}",
        )
        self._poller_thread.start()

    def poller_loop(self, *args, **kwargs):
        try:
            LOG.debug("Updating state ...")
            # HACK to work around state update race condition
            # time.sleep(2)
            with self._state_lock:
                # TODO: should we only track state in store object? => requires proper different locking!
                # Update self state (currently unused)
                self.current_state = EsmState.ENABLED
                # Update store state
                function_version = get_function_version_from_arn(self.esm_config["FunctionArn"])
                state = lambda_stores[function_version.id.account][function_version.id.region]
                esm_update = {"State": EsmState.ENABLED}
                state.event_source_mappings[self.esm_config["UUID"]].update(esm_update)
            LOG.debug("Updated state")
            # TODO: implement poller loop
        except Exception as e:
            LOG.error(
                "Error while polling messages for event source mapping %s: %s",
                self.uuid,
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )


# TODO: consolidate these hacky duplicates copied from the Lambda provider (guess they are there because of the store access)
def get_function_version_from_arn(function_arn: str) -> FunctionVersion:
    function_name, qualifier, account_id, region = function_locators_from_arn(function_arn)
    fn = lambda_stores[account_id][region].functions.get(function_name)
    if fn is None:
        if qualifier is None:
            raise ResourceNotFoundException(
                f"Function not found: {api_utils.unqualified_lambda_arn(function_name, account_id, region)}",
                Type="User",
            )
        else:
            raise ResourceNotFoundException(
                f"Function not found: {api_utils.qualified_lambda_arn(function_name, qualifier, account_id, region)}",
                Type="User",
            )
    alias_name = None
    if qualifier and api_utils.qualifier_is_alias(qualifier):
        if qualifier not in fn.aliases:
            alias_arn = api_utils.qualified_lambda_arn(function_name, qualifier, account_id, region)
            raise ResourceNotFoundException(f"Function not found: {alias_arn}", Type="User")
        alias_name = qualifier
        qualifier = fn.aliases[alias_name].function_version

    version = get_function_version(
        function_name=function_name,
        qualifier=qualifier,
        account_id=account_id,
        region=region,
    )
    return version


def get_function_version(
    function_name: str, qualifier: str | None, account_id: str, region: str
) -> FunctionVersion:
    state = lambda_stores[account_id][region]
    function = state.functions.get(function_name)
    qualifier_or_latest = qualifier or "$LATEST"
    version = function and function.versions.get(qualifier_or_latest)
    if not function or not version:
        arn = api_utils.lambda_arn(
            function_name=function_name,
            qualifier=qualifier,
            account=account_id,
            region=region,
        )
        raise ResourceNotFoundException(
            f"Function not found: {arn}",
            Type="User",
        )
    # TODO what if version is missing?
    return version
