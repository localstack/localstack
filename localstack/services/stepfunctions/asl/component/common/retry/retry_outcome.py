from enum import Enum


class RetryOutcome(Enum):
    CanRetry = 0
    CannotRetry = 1
    NoRetrier = 2
