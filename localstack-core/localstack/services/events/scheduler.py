import logging
import re
import threading

from crontab import CronTab

from localstack.utils.common import short_uid
from localstack.utils.run import FuncThread

LOG = logging.getLogger(__name__)

CRON_REGEX = re.compile(r"\s*cron\s*\(([^\)]*)\)\s*")
RATE_REGEX = re.compile(r"\s*rate\s*\(([^\)]*)\)\s*")


def convert_schedule_to_cron(schedule):
    """Convert Events schedule like "cron(0 20 * * ? *)" or "rate(5 minutes)" """
    cron_match = CRON_REGEX.match(schedule)
    if cron_match:
        return cron_match.group(1)

    rate_match = RATE_REGEX.match(schedule)
    if rate_match:
        rate = rate_match.group(1)
        rate_value, rate_unit = re.split(r"\s+", rate.strip())
        rate_value = int(rate_value)

        if rate_value < 1:
            raise ValueError("Rate value must be larger than 0")
        # see https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rate-expressions.html
        if rate_value == 1 and rate_unit.endswith("s"):
            raise ValueError("If the value is equal to 1, then the unit must be singular")
        if rate_value > 1 and not rate_unit.endswith("s"):
            raise ValueError("If the value is greater than 1, the unit must be plural")

        if "minute" in rate_unit:
            return f"*/{rate_value} * * * *"
        if "hour" in rate_unit:
            return f"0 */{rate_value} * * *"
        if "day" in rate_unit:
            return f"0 0 */{rate_value} * *"

        # TODO: cover via test
        # raise ValueError(f"Unable to parse events schedule expression: {schedule}")

    return schedule


class Job:
    def __init__(self, job_func, schedule, enabled):
        self.job_func = job_func
        self.schedule = schedule
        self.job_id = short_uid()
        self.is_enabled = enabled

    def run(self):
        try:
            if self.should_run_now() and self.is_enabled:
                self.do_run()
        except Exception as e:
            LOG.debug("Unable to run scheduled function %s: %s", self.job_func, e)

    def should_run_now(self):
        schedule = CronTab(self.schedule)
        delay_secs = schedule.next(
            default_utc=True
        )  # utc default time format for rule schedule cron
        # TODO fix execute on exact cron time
        return delay_secs is not None and delay_secs < 60

    def do_run(self):
        FuncThread(self.job_func, name="events-job-run").start()


class JobScheduler:
    _instance = None

    def __init__(self):
        # TODO: introduce RLock for mutating jobs list
        self.jobs = []
        self.thread = None
        self._stop_event = threading.Event()

    def add_job(self, job_func, schedule, enabled=True):
        job = Job(job_func, schedule, enabled=enabled)
        self.jobs.append(job)
        return job.job_id

    def get_job(self, job_id) -> Job | None:
        for job in self.jobs:
            if job.job_id == job_id:
                return job
        return None

    def disable_job(self, job_id):
        for job in self.jobs:
            if job.job_id == job_id:
                job.is_enabled = False
                break

    def cancel_job(self, job_id):
        self.jobs = [job for job in self.jobs if job.job_id != job_id]

    def loop(self, *args):
        while not self._stop_event.is_set():
            try:
                for job in list(self.jobs):
                    job.run()
            except Exception:
                pass
            # This is a simple heuristic to cause the loop to run approximately every minute
            # TODO: we should keep track of jobs execution times, to avoid duplicate executions
            self._stop_event.wait(timeout=59.9)

    def start_loop(self):
        self.thread = FuncThread(self.loop, name="events-jobscheduler-loop")
        self.thread.start()

    @classmethod
    def instance(cls):
        if not cls._instance:
            cls._instance = JobScheduler()
        return cls._instance

    @classmethod
    def start(cls):
        instance = cls.instance()
        if not instance.thread:
            instance.start_loop()
        return instance

    @classmethod
    def shutdown(cls):
        instance = cls.instance()
        if instance.thread:
            instance._stop_event.set()
