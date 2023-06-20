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


class CallbackConsumerError(abc.ABC):
    ...


class CallbackConsumerTimeout(CallbackConsumerError):
    pass


class CallbackConsumerLeft(CallbackConsumerError):
    pass


class CallbackEndpoint:
    callback_id: Final[CallbackId]
    _notify_event: Final[Event]
    _outcome: Optional[CallbackOutcome]
    consumer_error: Optional[CallbackConsumerError]

    def __init__(self, callback_id: CallbackId):
        self.callback_id = callback_id
        self._notify_event = Event()
        self._outcome = None
        self.consumer_error = None

    def notify(self, outcome: CallbackOutcome):
        self._outcome = outcome
        self._notify_event.set()

    def wait(self, timeout: Optional[float] = None) -> Optional[CallbackOutcome]:
        self._notify_event.wait(timeout=timeout)
        return self._outcome

    def report(self, consumer_error: CallbackConsumerError) -> None:
        self.consumer_error = consumer_error


class CallbackNotifyConsumerError(RuntimeError):
    callback_consumer_error: CallbackConsumerError

    def __init__(self, callback_consumer_error: CallbackConsumerError):
        self.callback_consumer_error = callback_consumer_error


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
        callback_endpoint = self._pool.pop(callback_id, None)
        if callback_endpoint is None:
            return False

        consumer_error: Optional[CallbackConsumerError] = callback_endpoint.consumer_error
        if consumer_error is not None:
            raise CallbackNotifyConsumerError(callback_consumer_error=consumer_error)

        callback_endpoint.notify(outcome=outcome)
        return True
