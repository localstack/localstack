import abc
import datetime
import threading
from collections import OrderedDict
from typing import Final, Optional

from localstack.aws.api.stepfunctions import (
    Arn,
    DescribeMapRunOutput,
    LongArn,
    MapRunExecutionCounts,
    MapRunItemCounts,
    MapRunListItem,
    MapRunStatus,
    Timestamp,
)
from localstack.utils.strings import long_uid


class Counter:
    _mutex: Final[threading.Lock]
    _count: int

    def __init__(self):
        self._mutex = threading.Lock()
        self._count = 0

    def count(self, increment: int = 1):
        with self._mutex:
            self._count += increment

    def get(self) -> int:
        return self._count


class ProgressCounter(abc.ABC):
    aborted: Final[Counter]
    failed: Final[Counter]
    pending: Final[Counter]
    results_written: Final[Counter]
    running: Final[Counter]
    succeeded: Final[Counter]
    timed_out: Final[Counter]
    total: Final[Counter]

    def __init__(self):
        self.aborted = Counter()
        self.failed = Counter()
        self.pending = Counter()
        self.results_written = Counter()
        self.running = Counter()
        self.succeeded = Counter()
        self.timed_out = Counter()
        self.total = Counter()


class ExecutionCounter(ProgressCounter):
    def describe(self) -> MapRunExecutionCounts:
        return MapRunExecutionCounts(
            aborted=self.aborted.get(),
            failed=self.failed.get(),
            pending=self.pending.get(),
            resultsWritten=self.results_written.get(),
            running=self.running.get(),
            succeeded=self.succeeded.get(),
            timedOut=self.timed_out.get(),
            total=self.total.get(),
        )


class ItemCounter(ProgressCounter):
    def describe(self) -> MapRunItemCounts:
        return MapRunItemCounts(
            aborted=self.aborted.get(),
            failed=self.failed.get(),
            pending=self.pending.get(),
            resultsWritten=self.results_written.get(),
            running=self.running.get(),
            succeeded=self.succeeded.get(),
            timedOut=self.timed_out.get(),
            total=self.total.get(),
        )


class MapRunRecord:
    update_event: Final[threading.Event]
    state_machine_arn: Final[Arn]
    execution_arn: Final[Arn]
    map_run_arn: Final[LongArn]
    max_concurrency: int
    execution_counter: Final[ExecutionCounter]
    item_counter: Final[ItemCounter]
    start_date: Timestamp
    status: MapRunStatus
    stop_date: Optional[Timestamp]
    # TODO: add support for failure toleration fields.
    tolerated_failure_count: int
    tolerated_failure_percentage: float

    def __init__(self, state_machine_arn: Arn, execution_arn: Arn, max_concurrency: int):
        self.update_event = threading.Event()
        self.state_machine_arn = state_machine_arn
        self.execution_arn = execution_arn
        self.map_run_arn = f"{execution_arn}/{long_uid()}:{long_uid()}"
        self.max_concurrency = max_concurrency
        self.execution_counter = ExecutionCounter()
        self.item_counter = ItemCounter()
        self.start_date = datetime.datetime.now()
        self.status = MapRunStatus.RUNNING
        self.stop_date = None
        self.tolerated_failure_count = 0
        self.tolerated_failure_percentage = 0

    def describe(self) -> DescribeMapRunOutput:
        describe_output = DescribeMapRunOutput(
            mapRunArn=self.map_run_arn,
            executionArn=self.execution_arn,
            status=self.status,
            startDate=self.start_date,
            maxConcurrency=self.max_concurrency,
            toleratedFailurePercentage=self.tolerated_failure_percentage,
            toleratedFailureCount=self.tolerated_failure_count,
            itemCounts=self.item_counter.describe(),
            executionCounts=self.execution_counter.describe(),
        )
        stop_date = self.stop_date
        if stop_date is not None:
            describe_output["stopDate"] = self.stop_date
        return describe_output

    def list_item(self) -> MapRunListItem:
        list_item = MapRunListItem(
            executionArn=self.execution_arn,
            mapRunArn=self.map_run_arn,
            stateMachineArn=self.state_machine_arn,
            startDate=self.start_date,
        )
        if self.stop_date:
            list_item["stopDate"] = self.stop_date
        return list_item

    def update(
        self,
        max_concurrency: Optional[int],
        tolerated_failure_count: Optional[int],
        tolerated_failure_percentage: Optional[float],
    ) -> None:
        if max_concurrency is not None:
            self.max_concurrency = max_concurrency
        if tolerated_failure_count is not None:
            self.tolerated_failure_count = tolerated_failure_count
        if tolerated_failure_percentage is not None:
            self.tolerated_failure_percentage = tolerated_failure_percentage
        self.update_event.set()


class MapRunRecordPoolManager:
    _pool: dict[LongArn, MapRunRecord]

    def __init__(self):
        self._pool = OrderedDict()

    def add(self, map_run_record: MapRunRecord) -> None:
        self._pool[map_run_record.map_run_arn] = map_run_record

    def get(self, map_run_arn: LongArn) -> Optional[MapRunRecord]:
        return self._pool.get(map_run_arn)

    def get_all(self) -> list[MapRunRecord]:
        return list(self._pool.values())
