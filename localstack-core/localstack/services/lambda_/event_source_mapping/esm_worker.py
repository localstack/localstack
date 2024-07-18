import logging
import threading

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import Poller
from localstack.utils.threads import FuncThread

POLL_INTERVAL_SEC: float = 1

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

    _state_lock: threading.RLock
    _shutdown_event: threading.Event
    _poller_thread: FuncThread | None

    def __init__(
        self,
        esm_config: EventSourceMappingConfiguration,
        poller: Poller,
        enabled: bool = True,
    ):
        self.esm_config = esm_config
        self.current_state = EsmState.CREATING

        self.poller = poller
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
            self.start_event_source_mapping()
        else:
            # TODO: test creating a disabled ESM
            pass

    def start_event_source_mapping(self):
        # TODO: implement state lifecycle
        self._poller_thread = FuncThread(
            self.poller_loop,
            name=f"event-source-mapping-poller-{self.uuid}",
        )
        self._poller_thread.start()

    def poller_loop(self, *args, **kwargs):
        with self._state_lock:
            # TODO: should we only track state in store object? => requires proper different locking!
            self.current_state = EsmState.ENABLED
            # Update store state !?
            # function_version = LambdaProvider._get_function_version_from_arn(self.esm_config["FunctionArn"])
            # state = lambda_stores[function_version.id.account][function_version.id.region]
            # esm_update = {"State": EsmState.ENABLED}
            # state.event_source_mappings[self.esm_config["UUID"]].update(esm_update)
        while not self._shutdown_event.is_set():
            try:
                self.poller.poll_events()
                # Wait for next short-polling interval
                # MAYBE: read the poller interval from self.poller if we need the flexibility
                self._shutdown_event.wait(POLL_INTERVAL_SEC)
            except Exception as e:
                LOG.error(
                    "Error while polling messages for event source %s: %s",
                    self.esm_config["EventSourceArn"],
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                # TODO: implement some backoff here and stop poller upon continuous errors
                # Wait some time between retries to avoid running into the problem right again
                self._shutdown_event.wait(2)
        # TODO: Delete ESM if needed (?!) => check how deleting works with state updates
