import threading
import time
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Tuple

import pytest

from localstack.utils.scheduler import ScheduledTask, Scheduler
from localstack.utils.sync import poll_condition


class DummyTask:
    def __init__(self, fn=None) -> None:
        super().__init__()
        self.i = 0
        self.invocations = list()
        self.completions = list()
        self.fn = fn

    def __call__(self, *args, **kwargs):
        self.invoke(*args, **kwargs)

    def invoke(self, *args, **kwargs):
        self.i += 1
        invoked = time.time()
        self.invocations.append((self.i, invoked, args, kwargs))

        if self.fn:
            self.fn(*args, **kwargs)

        self.completions.append((self.i, time.time(), args, kwargs))


@pytest.fixture
def dispatcher():
    executor = ThreadPoolExecutor(4)
    yield executor
    executor.shutdown()


class TestScheduler:
    @staticmethod
    def create_and_start(dispatcher) -> Tuple[Scheduler, threading.Thread]:
        scheduler = Scheduler(executor=dispatcher)
        thread = threading.Thread(target=scheduler.run)
        thread.start()

        return scheduler, thread

    def test_single_scheduled_run(self, dispatcher):
        scheduler, thread = self.create_and_start(dispatcher)

        task = DummyTask()
        invocation_time = time.time() + 0.2

        scheduler.schedule(task, start=invocation_time)

        assert poll_condition(lambda: len(task.invocations) >= 1, timeout=5)

        scheduler.close()
        thread.join(5)

        assert len(task.invocations) == 1
        assert task.invocations[0][0] == 1

        assert task.invocations[0][1] == pytest.approx(invocation_time, 0.1)

    def test_period_run_nonfixed(self):
        task = DummyTask()
        scheduler, thread = self.create_and_start(None)

        scheduler.schedule(task, period=0.1, fixed_rate=False)
        scheduler.schedule(scheduler.close, start=time.time() + 0.5)
        thread.join(5)

        assert task.invocations[1][1] + 0.1 == pytest.approx(task.invocations[2][1], 0.05)
        assert task.invocations[2][1] + 0.1 == pytest.approx(task.invocations[3][1], 0.05)
        assert task.invocations[3][1] + 0.1 == pytest.approx(task.invocations[4][1], 0.05)

    def test_periodic_run_fixed_with_longer_task(self):
        task = DummyTask(fn=lambda: time.sleep(1))

        scheduler, thread = self.create_and_start(None)

        scheduler.schedule(task, period=0.5, fixed_rate=True)
        scheduler.schedule(scheduler.close, start=time.time() + 1.25)

        thread.join(5)

        assert len(task.invocations) == 3

        first = task.invocations[0][1]
        assert first + 0.5 == pytest.approx(task.invocations[1][1], 0.1)
        assert first + 1 == pytest.approx(task.invocations[2][1], 0.1)

        assert poll_condition(lambda: len(task.completions) >= 3, timeout=5)

    def test_periodic_change_period(self, dispatcher):
        task = DummyTask()
        scheduler, thread = self.create_and_start(dispatcher)

        stask = scheduler.schedule(task, period=1, fixed_rate=True)

        def change_period(t: ScheduledTask, period: float):
            t.period = period

        scheduler.schedule(change_period, start=time.time() + 1.25, args=(stask, 0.5))
        scheduler.schedule(scheduler.close, start=time.time() + 3)

        thread.join(5)

        first = task.invocations[0][1]
        second = task.invocations[1][1]
        third = task.invocations[2][1]
        fourth = task.invocations[3][1]
        assert first + 1 == pytest.approx(second, 0.1)
        assert second + 1 == pytest.approx(third, 0.1)
        # changed to 0.5
        assert third + 0.5 == pytest.approx(fourth, 0.1)

    def test_cancel_task(self, dispatcher):
        task1 = DummyTask()
        task2 = DummyTask()
        scheduler, thread = self.create_and_start(dispatcher)

        scheduler.schedule(task2.invoke, period=0.5)
        stask = scheduler.schedule(task1.invoke, period=0.5)

        scheduler.schedule(stask.cancel, start=time.time() + 0.75)
        scheduler.schedule(scheduler.close, start=time.time() + 1.5)

        thread.join(5)

        assert len(task1.invocations) == 2
        assert len(task2.invocations) == 4

    def test_error_handler(self):
        scheduler = Scheduler()

        event = threading.Event()

        def invoke():
            raise ValueError("unittest")

        def on_error(e):
            event.set()

        scheduler.schedule(invoke, on_error=on_error)
        scheduler.schedule(scheduler.close)

        scheduler.run()

        assert event.wait(5)

    def test_scheduling_reordering(self, dispatcher):
        task = DummyTask()
        scheduler, thread = self.create_and_start(dispatcher)

        t = time.time()
        scheduler.schedule(task, args=("task2",), start=t + 1)  # task two gets scheduled first
        time.sleep(0.25)
        scheduler.schedule(
            task, args=("task1",), start=t + 0.5
        )  # but task one has the shorter deadline

        scheduler.schedule(scheduler.close, start=t + 1.5)

        thread.join(5)

        assert len(task.invocations) == 2
        assert task.invocations[0][2][0] == "task1"
        assert task.invocations[1][2][0] == "task2"

    def test_close_interrupts_waiting_tasks(self, dispatcher):
        task = DummyTask()
        scheduler, thread = self.create_and_start(dispatcher)

        scheduler.schedule(task, start=time.time() + 1)
        time.sleep(0.25)
        scheduler.close()

        thread.join(5)

        assert len(task.invocations) == 0
