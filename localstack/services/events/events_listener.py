import json
import logging
import os
import re
import time

from localstack import config
from localstack.constants import MOTO_ACCOUNT_ID, TEST_AWS_ACCOUNT_ID
from localstack.services.events.scheduler import JobScheduler
from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.aws import aws_stack
from localstack.utils.common import TMP_FILES, mkdir, replace_response_content, save_file, to_str
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

EVENTS_TMP_DIR = os.path.join(config.TMP_FOLDER, "cw_events")

DEFAULT_EVENT_BUS_NAME = "default"


class EventsBackend(RegionBackend):
    def __init__(self):
        # maps event bus name to set of event rules - TODO: check if still required, or available upstream?
        self.event_rules = {DEFAULT_EVENT_BUS_NAME: set()}
        # maps rule to job_id
        self.rule_scheduled_jobs = {}


def fix_account_id(response):
    return aws_stack.fix_account_id_in_arns(
        response, existing=MOTO_ACCOUNT_ID, replace=TEST_AWS_ACCOUNT_ID
    )


def fix_date_format(response):
    """Normalize date to format '2019-06-13T18:10:09.1234Z'"""
    pattern = r"<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>"
    replacement = r"<CreateDate>\1T\2Z</CreateDate>"
    replace_response_content(response, pattern, replacement)


def _create_and_register_temp_dir():
    if EVENTS_TMP_DIR not in TMP_FILES:
        mkdir(EVENTS_TMP_DIR)
        TMP_FILES.append(EVENTS_TMP_DIR)


def _dump_events_to_files(events_with_added_uuid):
    current_time_millis = int(round(time.time() * 1000))
    for event in events_with_added_uuid:
        save_file(
            os.path.join(EVENTS_TMP_DIR, "%s_%s" % (current_time_millis, event["uuid"])),
            json.dumps(event["event"]),
        )


def get_scheduled_rule_func(data):
    def func(*args, **kwargs):
        rule_name = data.get("Name")
        client = aws_stack.connect_to_service("events")
        targets = client.list_targets_by_rule(Rule=rule_name)["Targets"]
        if targets:
            LOG.debug(
                "Notifying %s targets in response to triggered Events rule %s"
                % (len(targets), rule_name)
            )
        for target in targets:
            arn = target.get("Arn")
            event = json.loads(target.get("Input") or "{}")
            attr = aws_stack.get_events_target_attributes(target)
            aws_stack.send_event_to_target(arn, event, target_attributes=attr)

    return func


def convert_schedule_to_cron(schedule):
    """Convert Events schedule like "cron(0 20 * * ? *)" or "rate(5 minutes)" """
    cron_regex = r"\s*cron\s*\(([^\)]*)\)\s*"
    if re.match(cron_regex, schedule):
        cron = re.sub(cron_regex, r"\1", schedule)
        return cron
    rate_regex = r"\s*rate\s*\(([^\)]*)\)\s*"
    if re.match(rate_regex, schedule):
        rate = re.sub(rate_regex, r"\1", schedule)
        value, unit = re.split(r"\s+", rate.strip())
        if "minute" in unit:
            return "*/%s * * * *" % value
        if "hour" in unit:
            return "* */%s * * *" % value
        if "day" in unit:
            return "* * */%s * *" % value
        raise Exception("Unable to parse events schedule expression: %s" % schedule)
    return schedule


def handle_put_rule(data):
    schedule = data.get("ScheduleExpression")
    enabled = data.get("State") != "DISABLED"

    if schedule:
        job_func = get_scheduled_rule_func(data)
        cron = convert_schedule_to_cron(schedule)
        LOG.debug("Adding new scheduled Events rule with cron schedule %s" % cron)

        job_id = JobScheduler.instance().add_job(job_func, cron, enabled)
        rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
        rule_scheduled_jobs[data["Name"]] = job_id

    return True


def handle_delete_rule(rule_name):
    rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
    job_id = rule_scheduled_jobs.get(rule_name)
    if job_id:
        LOG.debug("Removing scheduled Events: {} | job_id: {}".format(rule_name, job_id))
        JobScheduler.instance().cancel_job(job_id=job_id)


def handle_disable_rule(rule_name):
    rule_scheduled_jobs = EventsBackend.get().rule_scheduled_jobs
    job_id = rule_scheduled_jobs.get(rule_name)
    if job_id:
        LOG.debug("Disabling Rule: {} | job_id: {}".format(rule_name, job_id))
        JobScheduler.instance().disable_job(job_id=job_id)


class ProxyListenerEvents(ProxyListener):
    svc = TaggingService()

    def forward_request(self, method, path, data, headers):
        if method == "OPTIONS":
            return 200

        action = headers.get("X-Amz-Target")
        if method == "POST" and path == "/":
            parsed_data = json.loads(to_str(data))

            if action == "AWSEvents.PutRule":
                return handle_put_rule(parsed_data)

            elif action == "AWSEvents.DeleteRule":
                handle_delete_rule(rule_name=parsed_data.get("Name", None))

            elif action == "AWSEvents.DisableRule":
                handle_disable_rule(rule_name=parsed_data.get("Name", None))

        return True

    def return_response(self, method, path, data, headers, response, request_handler=None):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            fix_account_id(response)

            # fix dates returned from this API (fixes an issue with Terraform)
            fix_date_format(response)

            # fix Content-Length header
            response.headers["Content-Length"] = len(response._content)


# instantiate listener
UPDATE_EVENTS = ProxyListenerEvents()
