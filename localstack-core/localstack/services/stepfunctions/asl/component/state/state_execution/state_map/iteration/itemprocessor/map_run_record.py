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

    def offset(self, offset: int) -> None:
        with self._mutex:
            self._count = self._count + offset

    def count(self, increment: int = 1) -> None:
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
    map_state_machine_arn: Final[
        LongArn
    ]  # This is the original state machine arn plut the map run arn postfix.
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

    def __init__(
        self,
        state_machine_arn: Arn,
        execution_arn: Arn,
        max_concurrency: int,
        tolerated_failure_count: int,
        tolerated_failure_percentage: float,
        label: Optional[str],
    ):
        self.update_event = threading.Event()
        (
            map_state_machine_arn,
            map_run_arn,
        ) = self._generate_map_run_arns(state_machine_arn=state_machine_arn, label=label)
        self.map_run_arn = map_run_arn
        self.map_state_machine_arn = map_state_machine_arn
        self.execution_arn = execution_arn
        self.max_concurrency = max_concurrency
        self.execution_counter = ExecutionCounter()
        self.item_counter = ItemCounter()
        self.start_date = datetime.datetime.now(tz=datetime.timezone.utc)
        self.status = MapRunStatus.RUNNING
        self.stop_date = None
        self.tolerated_failure_count = tolerated_failure_count
        self.tolerated_failure_percentage = tolerated_failure_percentage

    @staticmethod
    def _generate_map_run_arns(
        state_machine_arn: Arn, label: Optional[str]
    ) -> tuple[LongArn, LongArn]:
        # Generate a new MapRunArn given the StateMachineArn, such that:
        # inp: arn:aws:states:<region>:111111111111:stateMachine:<ArnPart_0idx>
        # MRA: arn:aws:states:<region>:111111111111:mapRun:<ArnPart_0idx>/<MapRunArnPart0_0idx>:<MapRunArnPart1_0idx>
        # SMA: arn:aws:states:<region>:111111111111:mapRun:<ArnPart_0idx>/<MapRunArnPart0_0idx>
        map_run_arn = state_machine_arn.replace(":stateMachine:", ":mapRun:")
        part_1 = long_uid() if label is None else label
        map_run_arn = f"{map_run_arn}/{part_1}:{long_uid()}"
        return f"{state_machine_arn}/{part_1}", map_run_arn

    def set_stop(self, status: MapRunStatus):
        self.status = status
        self.stop_date = datetime.datetime.now(tz=datetime.timezone.utc)

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
            stateMachineArn=self.map_state_machine_arn,
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
