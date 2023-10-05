import logging
import re
import threading
import time
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import timedelta
from typing import Callable

from crontab import CronTab

from localstack.utils.common import short_uid
from localstack.utils.scheduler import ScheduledTask, Scheduler

LOG = logging.getLogger(__name__)


class CronScheduledTask(ScheduledTask):
    """
    Special implementation of a ScheduledTask that dynamically determines the next deadline based on a
    CronTab expression.
    """

    schedule: CronTab

    def __init__(
        self, task: Callable, schedule: CronTab, on_error: Callable[[Exception], None] = None
    ) -> None:
        super().__init__(task, on_error=on_error)
        self.schedule = schedule
        self.set_next_deadline()

    def is_periodic(self) -> bool:
        return True

    def set_next_deadline(self):
        delay = self.schedule.next()
        self.deadline = time.time() + delay


JobId = str


class Job:
    """Glue between JobScheduler and Scheduler API"""

    func: Callable
    schedule_expression: str
    job_id: JobId
    enabled: bool
    task: ScheduledTask | None
    schedule: CronTab | timedelta

    def __init__(self, func: Callable, scheduler_expression: str):
        self.func = func
        self.schedule_expression = scheduler_expression
        self.job_id = short_uid()
        self.task = None
        self.schedule = parse_schedule_expression(scheduler_expression)

    @property
    def enabled(self) -> bool:
        return self.task is not None

    def disable(self):
        if self.task:
            LOG.debug("Disabling job %s", self.job_id)
            self.task.cancel()
            self.task = None

    def enable(self, scheduler: Scheduler):
        if self.task:
            return

        schedule = parse_schedule_expression(self.schedule_expression)

        if isinstance(schedule, CronTab):
            LOG.debug("Scheduling job %s with crontab %s", self.job_id, schedule)
            self.task = CronScheduledTask(
                self.func,
                schedule=CronTab(self.schedule_expression),
                on_error=self.on_execute_error,
            )
        elif isinstance(schedule, timedelta):
            LOG.debug("Scheduling job %s every %d seconds", self.job_id, schedule.seconds)
            self.task = ScheduledTask(
                self.func,
                period=schedule.seconds,
                on_error=self.on_execute_error,
            )
        else:
            raise ValueError(f"unexpected return type {type(schedule)}")

        scheduler.schedule_task(self.task)

    def on_execute_error(self, exception: Exception):
        LOG.error("Error executing job %s", self.job_id, exc_info=exception)


class JobScheduler:
    """
    A singleton wrapper around a Scheduler that allows you to toggle scheduled tasks based on a unique job id.
    """

    def __init__(self):
        self.jobs: dict[str, Job] = {}
        self.mutex = threading.RLock()
        self.executor = ThreadPoolExecutor(10, thread_name_prefix="events-jobscheduler-worker")
        self.scheduler = Scheduler(executor=self.executor)

    def add_job(self, job_func: Callable, schedule_expression: str, enabled: bool = True) -> JobId:
        with self.mutex:
            job = Job(job_func, schedule_expression)
            self.jobs[job.job_id] = job
            if enabled:
                job.enable(self.scheduler)
            return job.job_id

    def get_job(self, job_id: JobId) -> Job | None:
        return self.jobs.get(job_id)

    def enable_job(self, job_id: JobId):
        with self.mutex:
            try:
                self.jobs[job_id].enable(self.scheduler)
            except KeyError:
                raise ValueError(f"No job with id {job_id}")

    def disable_job(self, job_id: JobId):
        with self.mutex:
            try:
                self.jobs[job_id].disable()
            except KeyError:
                raise ValueError(f"No job with id {job_id}")

    def cancel_job(self, job_id: JobId):
        with self.mutex:
            try:
                self.jobs.pop(job_id).disable()
            except KeyError:
                raise ValueError(f"No job with id {job_id}")

    def shutdown(self):
        self.scheduler.close()
        self.executor.shutdown(cancel_futures=True)

    def start(self):
        thread = threading.Thread(
            target=self.scheduler.run,
            name="events-jobscheduler-loop",
            daemon=True,
        )
        thread.start()


def parse_schedule_expression(expression: str) -> CronTab | timedelta:
    """
    Parses a scheduling expression which can either be ``cron(<crontab expression>)`` or
    ``rate(<value> <unit>)``. In the first case, a ``CronTab`` object will be returned, and in the second case
    a ``timedelta`` object will be returned.

    See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html

    :param expression: the expression
    :return: a CronTab or timedelta
    """
    if expression.startswith("cron"):
        return parse_cron_expression(expression)
    if expression.startswith("rate"):
        return parse_rate_expression(expression)

    raise ValueError("Syntax error in expression")


def parse_rate_expression(expression: str) -> timedelta:
    """
    Parses a rate expression as defined in
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rate-expressions.html.

    :param expression: a rate expression, e.g. rate(5 minutes)
    :return: a timedelta describing the rate
    """
    rate_pattern = r"rate\(([0-9]+) (minutes?|hours?|days?)\)"

    if matcher := re.match(rate_pattern, expression):
        value = int(matcher.group(1))
        unit = matcher.group(2)

        if value < 1:
            raise ValueError("Value needs to be larger than 0")
        if value == 1 and unit.endswith("s"):
            raise ValueError("If the value is equal to 1, then the unit must be singular")
        if value > 1 and not unit.endswith("s"):
            raise ValueError("If the value is greater than 1, the unit must be plural")

        if unit.startswith("minute"):
            return timedelta(minutes=value)
        elif unit.startswith("hour"):
            return timedelta(hours=value)
        elif unit.startswith("day"):
            return timedelta(days=value)
        else:
            raise ValueError(f"Unknown rate unit {unit}")

    raise ValueError(f"Rate expression did not match pattern {rate_pattern}")


def parse_cron_expression(expression: str) -> CronTab:
    """
    Parses a crontab expression as defined in
    https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-cron-expressions.html.

    :param expression: a cron expression, e.g., cron(0 12 * * ? *)
    :return: a CronTab instance
    """
    if not expression.startswith("cron(") or not expression.endswith(")"):
        raise ValueError("Cron expression did not match pattern cron(<expression>)")

    expression = expression[5:-1]
    if expression.startswith(" ") or expression.endswith(" "):
        raise ValueError("Superfluous whitespaces in cron expression")

    return CronTab(expression)
