import queue
import threading
import time
from concurrent.futures import Executor
from typing import Any, Callable, List, Mapping, Optional, Tuple, Union


class ScheduledTask:
    """
    Internal representation of a task (a callable) and its scheduling parameters.
    """

    def __init__(
        self,
        task: Callable,
        period: Optional[float] = None,
        fixed_rate: bool = True,
        start: Optional[float] = None,
        on_error: Callable[[Exception], None] = None,
        args: Optional[Union[tuple, list]] = None,
        kwargs: Optional[Mapping[str, Any]] = None,
    ) -> None:
        super().__init__()
        self.task = task
        self.fixed_rate = fixed_rate
        self.period = period
        self.start = start
        self.on_error = on_error
        self.args = args or tuple()
        self.kwargs = kwargs or dict()

        self.deadline = None
        self.error = None
        self._cancelled = False

    @property
    def is_periodic(self) -> bool:
        return self.period is not None

    @property
    def is_cancelled(self) -> bool:
        return self._cancelled

    def set_next_deadline(self):
        """
        Internal method to update the next deadline of this task based on the period and the current time.
        """
        if not self.deadline:
            raise ValueError("Deadline was not initialized")

        if self.fixed_rate:
            self.deadline = self.deadline + self.period
        else:
            self.deadline = time.time() + self.period

    def cancel(self):
        self._cancelled = True

    def run(self):
        """
        Executes the task function. If the function raises and Exception, ``on_error`` is called (if set).
        """
        try:
            self.task(*self.args, **self.kwargs)
        except Exception as e:
            if self.on_error:
                self.on_error(e)


class Scheduler:
    """
    An event-loop based task scheduler that can manage multiple scheduled tasks with different periods,
    can be parallelized with an executor.
    """

    POISON = (-1, "__POISON__")

    def __init__(self, executor: Optional[Executor] = None) -> None:
        """
        Creates a new Scheduler. If an executor is passed, then that executor will be used to run the scheduled tasks
        asynchronously, otherwise they will be executed synchronously inside the event loop. Running tasks
        asynchronously in an executor means that they will be effectively executed at a fixed rate (scheduling with
        ``fixed_rate = False``, will have no effect).

        :param executor: an optional executor that tasks will be submitted to.
        """
        super().__init__()
        self.executor = executor

        self._queue = queue.PriorityQueue()
        self._condition = threading.Condition()

    def schedule(
        self,
        func: Callable,
        period: Optional[float] = None,
        fixed_rate: bool = True,
        start: Optional[float] = None,
        on_error: Callable[[Exception], None] = None,
        args: Optional[Union[Tuple, List[Any]]] = None,
        kwargs: Optional[Mapping[str, Any]] = None,
    ) -> ScheduledTask:
        """
        Schedules a given task (function call).

        :param func: the task to schedule
        :param period: the period in which to run the task (in seconds). if not set, task will run once
        :param fixed_rate: whether the to run at a fixed rate (neglecting execution duration of the task)
        :param start: start time
        :param on_error: error callback
        :param args: additional positional arguments to pass to the function
        :param kwargs: additional keyword arguments to pass to the function
        :return: a ScheduledTask instance
        """
        st = ScheduledTask(
            func,
            period=period,
            fixed_rate=fixed_rate,
            start=start,
            on_error=on_error,
            args=args,
            kwargs=kwargs,
        )
        self.schedule_task(st)
        return st

    def schedule_task(self, task: ScheduledTask) -> None:
        """
        Schedules the given task and sets the deadline of the task to either ``task.start`` or the current time.

        :param task: the task to schedule
        """
        task.deadline = max(task.start or 0, time.time())
        self.add(task)

    def add(self, task: ScheduledTask) -> None:
        """
        Schedules the given task. Requires that the task has a deadline set. It's better to use ``schedule_task``.

        :param task: the task to schedule.
        """
        if task.deadline is None:
            raise ValueError

        task._cancelled = False

        with self._condition:
            self._queue.put((task.deadline, task))
            self._condition.notify()

    def close(self) -> None:
        """
        Terminates the run loop.
        """
        with self._condition:
            self._queue.put(self.POISON)
            self._condition.notify()

    def run(self):
        q = self._queue
        cond = self._condition
        executor = self.executor
        poison = self.POISON

        task: ScheduledTask
        while True:
            deadline, task = q.get()

            if (deadline, task) == poison:
                break

            if task.is_cancelled:
                continue

            # wait until the task should be executed
            wait = max(0, deadline - time.time())
            if wait > 0:
                with cond:
                    interrupted = cond.wait(timeout=wait)
                    if interrupted:
                        # something with a potentially earlier deadline has arrived while waiting, so we re-queue and
                        # continue. this could be optimized by checking the deadline of the added element(s) first,
                        # but that would be fairly involved. the assumption is that `schedule` is not invoked frequently
                        q.put((task.deadline, task))
                        continue

            # run or submit the task
            if not task.is_cancelled:
                if executor:
                    executor.submit(task.run)
                else:
                    task.run()

            if task.is_periodic:
                try:
                    task.set_next_deadline()
                except ValueError:
                    # task deadline couldn't be set because it was cancelled
                    continue
                q.put((task.deadline, task))
