import logging
import threading
from enum import StrEnum

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import Poller
from localstack.utils.threads import FuncThread

POLL_INTERVAL_SEC: float = 1

LOG = logging.getLogger(__name__)


class EsmState(StrEnum):
    # https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html#lambda-CreateEventSourceMapping-response-State
    CREATING = "Creating"
    ENABLING = "Enabling"
    ENABLED = "Enabled"
    DISABLING = "Disabling"
    DISABLED = "Disabled"
    UPDATING = "Updating"
    DELETING = "Deleting"


class EsmStateReason(StrEnum):
    # Used for Kinesis and DynamoDB
    USER_ACTION = "User action"
    # Used for SQS
    USER_INITIATED = "USER_INITIATED"
    NO_RECORDS_PROCESSED = "No records processed"
    # TODO: add others?


class EsmWorker:
    esm_config: EventSourceMappingConfiguration
    enabled: bool
    current_state: EsmState
    state_transition_reason: EsmStateReason
    # Either USER_ACTION or USER_INITIATED (SQS) depending on the event source
    user_state_reason: EsmStateReason
    # TODO: test
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
        user_state_reason: EsmStateReason = EsmStateReason.USER_ACTION,
    ):
        self.esm_config = esm_config
        self.enabled = enabled
        self.current_state = EsmState.CREATING
        self.user_state_reason = user_state_reason
        self.state_transition_reason = self.user_state_reason

        self.poller = poller

        # TODO: implement lifecycle locking
        self._state_lock = threading.RLock()
        self._shutdown_event = threading.Event()
        self._poller_thread = None

    @property
    def uuid(self) -> str:
        return self.esm_config["UUID"]

    def create(self):
        if self.enabled:
            with self._state_lock:
                self.current_state = EsmState.CREATING
                self.state_transition_reason = self.user_state_reason
            self.start()
        else:
            # TODO: validate with tests
            with self._state_lock:
                self.current_state = EsmState.DISABLED
                self.state_transition_reason = self.user_state_reason

    def start(self):
        with self._state_lock:
            # CREATING state takes precedence over ENABLING
            if self.current_state != EsmState.CREATING:
                self.current_state = EsmState.ENABLING
                self.state_transition_reason = self.user_state_reason
        self._poller_thread = FuncThread(
            self.poller_loop,
            name=f"event-source-mapping-poller-{self.uuid}",
        )
        self._poller_thread.start()

    def stop(self):
        with self._state_lock:
            self.current_state = EsmState.DISABLING
            self.state_transition_reason = self.user_state_reason
        self._shutdown_event.set()

    def delete(self):
        with self._state_lock:
            self.current_state = EsmState.DELETING
            self.state_transition_reason = self.user_state_reason
        self._shutdown_event.set()

    def poller_loop(self, *args, **kwargs):
        with self._state_lock:
            self.current_state = EsmState.ENABLED
            self.state_transition_reason = self.user_state_reason
            # TODO: idea to not update store state but query state from esm_worker upon querying, but async deletion needs to modify store?!
            # Update store state !?
            # function_version = LambdaProvider._get_function_version_from_arn(self.esm_config["FunctionArn"])
            # state = lambda_stores[function_version.id.account][function_version.id.region]
            # esm_update = {"State": EsmState.ENABLED}
            # state.event_source_mappings[self.esm_config["UUID"]].update(esm_update)
        while not self._shutdown_event.is_set():
            try:
                self.poller.poll_events()
                # TODO: update state transition reason?
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
        # TODO: Delete ESM if needed once everything shut down properly (?!) => check how deleting works with state updates
