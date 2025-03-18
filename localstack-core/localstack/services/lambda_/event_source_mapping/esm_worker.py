import logging
import threading
from enum import StrEnum

from localstack.aws.api.lambda_ import (
    EventSourceMappingConfiguration,
)
from localstack.services.lambda_.event_source_mapping.pollers.poller import (
    EmptyPollResultsException,
    Poller,
)
from localstack.services.lambda_.invocation.models import LambdaStore, lambda_stores
from localstack.services.lambda_.provider_utils import get_function_version_from_arn
from localstack.utils.backoff import ExponentialBackoff
from localstack.utils.threads import FuncThread

POLL_INTERVAL_SEC: float = 1
MAX_BACKOFF_POLL_EMPTY_SEC: float = 10
MAX_BACKOFF_POLL_ERROR_SEC: float = 60


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

        # HACK: Flag used to check if a graceful shutdown was triggered.
        self._graceful_shutdown_triggered = False

    @property
    def uuid(self) -> str:
        return self.esm_config["UUID"]

    def stop_for_shutdown(self):
        # Signal the worker's poller_loop thread to gracefully shutdown
        # TODO: Once ESM state is de-coupled from lambda store, re-think this approach.
        self._shutdown_event.set()
        self._graceful_shutdown_triggered = True

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

        error_boff = ExponentialBackoff(initial_interval=2, max_interval=MAX_BACKOFF_POLL_ERROR_SEC)
        empty_boff = ExponentialBackoff(initial_interval=1, max_interval=MAX_BACKOFF_POLL_EMPTY_SEC)

        poll_interval_duration = POLL_INTERVAL_SEC

        while not self._shutdown_event.is_set():
            try:
                # TODO: update state transition reason?
                self.poller.poll_events()

                # If no exception encountered, reset the backoff
                error_boff.reset()
                empty_boff.reset()

                # Set the poll frequency back to the default
                poll_interval_duration = POLL_INTERVAL_SEC
            except EmptyPollResultsException as miss_ex:
                # If the event source is empty, backoff
                poll_interval_duration = empty_boff.next_backoff()
                LOG.debug(
                    "The event source %s is empty. Backing off for %.2f seconds until next request.",
                    miss_ex.source_arn,
                    poll_interval_duration,
                )
            except Exception as e:
                LOG.error(
                    "Error while polling messages for event source %s: %s",
                    self.esm_config.get("EventSourceArn")
                    or self.esm_config.get("SelfManagedEventSource"),
                    e,
                    exc_info=LOG.isEnabledFor(logging.DEBUG),
                )
                # Wait some time between retries to avoid running into the problem right again
                poll_interval_duration = error_boff.next_backoff()
            finally:
                self._shutdown_event.wait(poll_interval_duration)

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
            elif not self._graceful_shutdown_triggered:
                # HACK: If we reach this state and a graceful shutdown was not triggered, log a warning to indicate
                # an unexpected state.
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
