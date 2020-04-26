import time
import logging
from crontab import CronTab
from localstack.utils.common import FuncThread, short_uid

LOG = logging.getLogger(__name__)


class Job(object):

    def __init__(self, job_func, schedule):
        self.job_func = job_func
        self.schedule = schedule
        self.job_id = short_uid()

    def run(self):
        try:
            if self.should_run_now():
                self.do_run()
        except Exception as e:
            LOG.debug('Unable to run scheduled function %s: %s' % (self.job_func, e))

    def should_run_now(self):
        schedule = CronTab(self.schedule)
        delay_secs = schedule.next()
        return delay_secs < 60

    def do_run(self):
        FuncThread(self.job_func).start()


class JobScheduler(object):

    _instance = None

    def __init__(self):
        self.jobs = []
        self.thread = None

    def add_job(self, job_func, schedule):
        job = Job(job_func, schedule)
        self.jobs.append(job)
        return job.job_id

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
