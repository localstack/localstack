import logging
import time

from crontab import CronTab

from localstack.utils.common import short_uid
from localstack.utils.run import FuncThread

LOG = logging.getLogger(__name__)


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
        delay_secs = schedule.next()
        return delay_secs is not None and delay_secs < 60

    def do_run(self):
        FuncThread(self.job_func).start()


class JobScheduler:

    _instance = None

    def __init__(self):
        # TODO: introduce RLock for mutating jobs list
        self.jobs = []
        self.thread = None

    def add_job(self, job_func, schedule, enabled=True):
        job = Job(job_func, schedule, enabled=enabled)
        self.jobs.append(job)
        return job.job_id

    def disable_job(self, job_id):
        for job in self.jobs:
            if job.job_id == job_id:
                job.is_enabled = False
                break

    def cancel_job(self, job_id):
        i = 0
        while i < len(self.jobs):
            if self.jobs[i].job_id == job_id:
                del self.jobs[i]
            else:
                i += 1

    def loop(self, *args):
        while True:
            try:
                for job in list(self.jobs):
                    job.run()
            except Exception:
                pass
            # This is a simple heuristic to cause the loop to run apprx every minute
            # TODO: we should keep track of jobs execution times, to avoid duplicate executions
            time.sleep(59.9)

    def start_loop(self):
        self.thread = FuncThread(self.loop)
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
