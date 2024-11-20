import logging
import threading
from enum import StrEnum

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import Poller
from localstack.services.lambda_.invocation.models import LambdaStore, lambda_stores
from localstack.services.lambda_.provider_utils import get_function_version_from_arn
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

    _state: LambdaStore
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

        function_version = get_function_version_from_arn(self.esm_config["FunctionArn"])
        self._state = lambda_stores[function_version.id.account][function_version.id.region]

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
            self.update_esm_state_in_store(EsmState.DISABLED)

    def start(self):
        with self._state_lock:
            self.enabled = True
            # CREATING state takes precedence over ENABLING
            if self.current_state != EsmState.CREATING:
                self.current_state = EsmState.ENABLING
                self.state_transition_reason = self.user_state_reason
        # Reset the shutdown event such that we don't stop immediately after a restart
        self._shutdown_event.clear()
        self._poller_thread = FuncThread(
            self.poller_loop,
            name=f"event-source-mapping-poller-{self.uuid}",
        )
        self._poller_thread.start()

    def stop(self):
        with self._state_lock:
            self.enabled = False
            self.current_state = EsmState.DISABLING
            self.update_esm_state_in_store(EsmState.DISABLING)
            self.state_transition_reason = self.user_state_reason
        self._shutdown_event.set()

    def delete(self):
        with self._state_lock:
            self.current_state = EsmState.DELETING
            self.update_esm_state_in_store(EsmState.DELETING)
            self.state_transition_reason = self.user_state_reason
        self._shutdown_event.set()

    def poller_loop(self, *args, **kwargs):
        with self._state_lock:
            self.current_state = EsmState.ENABLED
            self.update_esm_state_in_store(EsmState.ENABLED)
            self.state_transition_reason = self.user_state_reason

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
                    self.esm_config.get("EventSourceArn")
                    or self.esm_config.get("SelfManagedEventSource"),
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                # TODO: implement some backoff here and stop poller upon continuous errors
                # Wait some time between retries to avoid running into the problem right again
                self._shutdown_event.wait(2)

        # Optionally closes internal components of Poller. This is a no-op for unimplemented pollers.
        self.poller.close()

        try:
            # Update state in store after async stop or delete
            if self.enabled and self.current_state == EsmState.DELETING:
                # TODO: we also need to remove the ESM worker reference from the Lambda provider to esm_worker
                # TODO: proper locking for store updates
                self.delete_esm_in_store()
            elif not self.enabled and self.current_state == EsmState.DISABLING:
                with self._state_lock:
                    self.current_state = EsmState.DISABLED
                    self.state_transition_reason = self.user_state_reason
                self.update_esm_state_in_store(EsmState.DISABLED)
            else:
                LOG.warning(
                    "Invalid state %s for event source mapping %s.",
                    self.current_state,
                    self.esm_config["UUID"],
                )
        except Exception as e:
            LOG.warning(
                "Failed to update state %s for event source mapping %s. Exception: %s ",
                self.current_state,
                self.esm_config["UUID"],
                e,
                exc_info=LOG.isEnabledFor(logging.DEBUG),
            )

    def delete_esm_in_store(self):
        self._state.event_source_mappings.pop(self.esm_config["UUID"], None)

    # TODO: how can we handle async state updates better? Async deletion or disabling needs to update the model state.
    def update_esm_state_in_store(self, new_state: EsmState):
        esm_update = {"State": new_state}
        # TODO: add proper locking for store updates
        self._state.event_source_mappings[self.esm_config["UUID"]].update(esm_update)
