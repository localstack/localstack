import random
import time

from pydantic import Field
from pydantic.dataclasses import dataclass


@dataclass
class ExponentialBackoff:
    """
    ExponentialBackoff implements exponential backoff with randomization.
    The backoff period increases exponentially for each retry attempt, with
    optional randomization within a defined range.

    next_backoff() is calculated using the following formula:
        ```
        randomized_interval = random_between(retry_interval * (1 - randomization_factor), retry_interval * (1 + randomization_factor))
        ```

    For example, given:
        `initial_interval` = 2
        `randomization_factor` = 0.5
        `multiplier` = 2

    The next backoff will be between 1 and 3 seconds (2 * [0.5, 1.5]).
    The following backoff will be between 2 and 6 seconds (4 * [0.5, 1.5]).

    Note:
        - `max_interval` caps the base interval, not the randomized value
        - Returns 0 when `max_retries` or `max_time_elapsed` is exceeded
        - The implementation is not thread-safe

    Example sequence with defaults (initial_interval=0.5, randomization_factor=0.5, multiplier=1.5):

    | Request # | Retry Interval (seconds) | Randomized Interval (seconds) |
    |-----------|----------------------|----------------------------|
    | 1         | 0.5                  | [0.25, 0.75]              |
    | 2         | 0.75                 | [0.375, 1.125]            |
    | 3         | 1.125                | [0.562, 1.687]            |
    | 4         | 1.687                | [0.8435, 2.53]            |
    | 5         | 2.53                 | [1.265, 3.795]            |
    | 6         | 3.795                | [1.897, 5.692]            |
    | 7         | 5.692                | [2.846, 8.538]            |
    | 8         | 8.538                | [4.269, 12.807]           |
    | 9         | 12.807               | [6.403, 19.210]           |
    | 10        | 19.210               | 0                         |

    Note: The sequence stops at request #10 when `max_retries` or `max_time_elapsed` is exceeded
    """

    initial_interval: float = Field(0.5, title="Initial backoff interval in seconds", gt=0)
    randomization_factor: float = Field(0.5, title="Factor to randomize backoff", ge=0, le=1)
    multiplier: float = Field(1.5, title="Multiply interval by this factor each retry", gt=1)
    max_interval: float = Field(60.0, title="Maximum backoff interval in seconds", gt=0)
    max_retries: int = Field(-1, title="Max retry attempts (-1 for unlimited)", ge=-1)
    max_time_elapsed: float = Field(-1, title="Max total time in seconds (-1 for unlimited)", ge=-1)

    def __post_init__(self):
        self.retry_interval: float = 0
        self.retries: int = 0
        self.start_time: float = 0.0

    @property
    def elapsed_duration(self) -> float:
        return max(time.monotonic() - self.start_time, 0)

    def reset(self) -> None:
        self.retry_interval = 0
        self.retries = 0
        self.start_time = 0

    def next_backoff(self) -> float:
        if self.retry_interval == 0:
            self.retry_interval = self.initial_interval
            self.start_time = time.monotonic()

        self.retries += 1

        # return 0 when max_retries is set and exceeded
        if self.max_retries >= 0 and self.retries > self.max_retries:
            return 0

        # return 0 when max_time_elapsed is set and exceeded
        if self.max_time_elapsed > 0 and self.elapsed_duration > self.max_time_elapsed:
            return 0

        next_interval = self.retry_interval
        if 0 < self.randomization_factor <= 1:
            min_interval = self.retry_interval * (1 - self.randomization_factor)
            max_interval = self.retry_interval * (1 + self.randomization_factor)
            # NOTE: the jittered value can exceed the max_interval
            next_interval = random.uniform(min_interval, max_interval)

        # do not allow the next retry interval to exceed max_interval
        self.retry_interval = min(self.max_interval, self.retry_interval * self.multiplier)

        return next_interval
