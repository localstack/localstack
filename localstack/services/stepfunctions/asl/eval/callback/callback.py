import abc
from collections import OrderedDict
from threading import Event
from typing import Final, Optional

from localstack.utils.strings import long_uid

CallbackId = str


class CallbackOutcome(abc.ABC):
    callback_id: Final[CallbackId]

    def __init__(self, callback_id: str):
        self.callback_id = callback_id


class CallbackOutcomeSuccess(CallbackOutcome):
    output: Final[str]

    def __init__(self, callback_id: CallbackId, output: str):
        super().__init__(callback_id=callback_id)
        self.output = output


class CallbackOutcomeFailure(CallbackOutcome):
    error: Final[str]
    cause: Final[str]

    def __init__(self, callback_id: CallbackId, error: str, cause: str):
        super().__init__(callback_id=callback_id)
        self.error = error
        self.cause = cause


class CallbackTimeoutError(TimeoutError):
    pass


class CallbackConsumerError(abc.ABC):
    ...


class CallbackConsumerTimeout(CallbackConsumerError):
    pass


class CallbackConsumerLeft(CallbackConsumerError):
    pass


class HeartbeatEndpoint:
    _next_heartbeat_event: Final[Event]
    _heartbeat_seconds: Final[int]

    def __init__(self, heartbeat_seconds: int):
        self._next_heartbeat_event = Event()
        self._heartbeat_seconds = heartbeat_seconds

    def clear_and_wait(self) -> bool:
        self._next_heartbeat_event.clear()
        return self._next_heartbeat_event.wait(timeout=self._heartbeat_seconds)

    def notify(self):
        self._next_heartbeat_event.set()


class HeartbeatTimeoutError(TimeoutError):
    pass


class CallbackEndpoint:
    callback_id: Final[CallbackId]
    _notify_event: Final[Event]
    _outcome: Optional[CallbackOutcome]
    consumer_error: Optional[CallbackConsumerError]
    _heartbeat_endpoint: Optional[HeartbeatEndpoint]

    def __init__(self, callback_id: CallbackId):
        self.callback_id = callback_id
        self._notify_event = Event()
        self._outcome = None
        self.consumer_error = None
        self._heartbeat_endpoint = None

    def setup_heartbeat_endpoint(self, heartbeat_seconds: int) -> HeartbeatEndpoint:
        self._heartbeat_endpoint = HeartbeatEndpoint(heartbeat_seconds=heartbeat_seconds)
        return self._heartbeat_endpoint

    def notify(self, outcome: CallbackOutcome):
        self._outcome = outcome
        self._notify_event.set()
        if self._heartbeat_endpoint:
            self._heartbeat_endpoint.notify()

    def notify_heartbeat(self) -> bool:
        if not self._heartbeat_endpoint:
            return False
        self._heartbeat_endpoint.notify()
        return True

    def wait(self, timeout: Optional[float] = None) -> Optional[CallbackOutcome]:
        self._notify_event.wait(timeout=timeout)
        return self._outcome

    def get_outcome(self) -> Optional[CallbackOutcome]:
        return self._outcome

    def report(self, consumer_error: CallbackConsumerError) -> None:
        self.consumer_error = consumer_error


class CallbackNotifyConsumerError(RuntimeError):
    callback_consumer_error: CallbackConsumerError

    def __init__(self, callback_consumer_error: CallbackConsumerError):
        self.callback_consumer_error = callback_consumer_error


class CallbackOutcomeFailureError(RuntimeError):
    callback_outcome_failure: CallbackOutcomeFailure

    def __init__(self, callback_outcome_failure: CallbackOutcomeFailure):
        self.callback_outcome_failure = callback_outcome_failure


class CallbackPoolManager:
    _pool: dict[CallbackId, CallbackEndpoint]

    def __init__(self):
        self._pool = OrderedDict()

    def get(self, callback_id: CallbackId) -> Optional[CallbackEndpoint]:
        return self._pool.get(callback_id)

    def add(self, callback_id: CallbackId) -> CallbackEndpoint:
        if callback_id in self._pool:
            raise ValueError("Duplicate callback token id value.")
        callback_endpoint = CallbackEndpoint(callback_id=callback_id)
        self._pool[callback_id] = callback_endpoint
        return callback_endpoint

    def generate(self) -> CallbackEndpoint:
        return self.add(long_uid())

    def notify(self, callback_id: CallbackId, outcome: CallbackOutcome) -> bool:
        callback_endpoint = self._pool.get(callback_id, None)
        if callback_endpoint is None:
            return False

        consumer_error: Optional[CallbackConsumerError] = callback_endpoint.consumer_error
        if consumer_error is not None:
            raise CallbackNotifyConsumerError(callback_consumer_error=consumer_error)

        callback_endpoint.notify(outcome=outcome)
        return True

    def heartbeat(self, callback_id: CallbackId) -> bool:
        callback_endpoint = self._pool.get(callback_id, None)
        if callback_endpoint is None:
            return False

        consumer_error: Optional[CallbackConsumerError] = callback_endpoint.consumer_error
        if consumer_error is not None:
            raise CallbackNotifyConsumerError(callback_consumer_error=consumer_error)

        return callback_endpoint.notify_heartbeat()
