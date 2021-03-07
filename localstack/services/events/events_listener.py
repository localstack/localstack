import os
import re
import json
import time
import logging
from localstack import config
from localstack.constants import TEST_AWS_ACCOUNT_ID, MOTO_ACCOUNT_ID
from localstack.utils.aws import aws_stack
from localstack.utils.common import to_str, save_file, TMP_FILES, mkdir, replace_response_content
from localstack.utils.tagging import TaggingService
from localstack.services.generic_proxy import ProxyListener
from localstack.services.events.scheduler import JobScheduler

LOG = logging.getLogger(__name__)

EVENTS_TMP_DIR = os.path.join(config.TMP_FOLDER, 'cw_events')

# maps rule to job_id
RULE_SCHEDULED_JOBS = {}


def fix_account_id(response):
    return aws_stack.fix_account_id_in_arns(response, existing=MOTO_ACCOUNT_ID, replace=TEST_AWS_ACCOUNT_ID)


def fix_date_format(response):
    """ Normalize date to format '2019-06-13T18:10:09.1234Z' """
    pattern = r'<CreateDate>([^<]+) ([^<+]+)(\+[^<]*)?</CreateDate>'
    replacement = r'<CreateDate>\1T\2Z</CreateDate>'
    replace_response_content(response, pattern, replacement)


def _create_and_register_temp_dir():
    if EVENTS_TMP_DIR not in TMP_FILES:
        mkdir(EVENTS_TMP_DIR)
        TMP_FILES.append(EVENTS_TMP_DIR)


def _dump_events_to_files(events_with_added_uuid):
    current_time_millis = int(round(time.time() * 1000))
    for event in events_with_added_uuid:
        save_file(
            os.path.join(EVENTS_TMP_DIR, '%s_%s' % (current_time_millis, event['uuid'])),
            json.dumps(event['event'])
        )


def get_scheduled_rule_func(data):
    def func(*args):
        rule_name = data.get('Name')
        client = aws_stack.connect_to_service('events')
        targets = client.list_targets_by_rule(Rule=rule_name)['Targets']
        if targets:
            LOG.debug('Notifying %s targets in response to triggered Events rule %s' % (len(targets), rule_name))
        for target in targets:
            arn = target.get('Arn')
            event = json.loads(target.get('Input') or '{}')
            attr = aws_stack.get_events_target_attributes(target)
            aws_stack.send_event_to_target(arn, event, target_attributes=attr)
    return func


def convert_schedule_to_cron(schedule):
    """ Convert Events schedule like "cron(0 20 * * ? *)" or "rate(5 minutes)" """
    cron_regex = r'\s*cron\s*\(([^\)]*)\)\s*'
    if re.match(cron_regex, schedule):
        cron = re.sub(cron_regex, r'\1', schedule)
        return cron
    rate_regex = r'\s*rate\s*\(([^\)]*)\)\s*'
    if re.match(rate_regex, schedule):
        rate = re.sub(rate_regex, r'\1', schedule)
        value, unit = re.split(r'\s+', rate.strip())
        if 'minute' in unit:
            return '*/%s * * * *' % value
        if 'hour' in unit:
            return '* */%s * * *' % value
        if 'day' in unit:
            return '* * */%s * *' % value
        raise Exception('Unable to parse events schedule expression: %s' % schedule)
    return schedule


def handle_put_rule(data):
    schedule = data.get('ScheduleExpression')
    enabled = data.get('State') != 'DISABLED'

    if schedule:
        job_func = get_scheduled_rule_func(data)
        cron = convert_schedule_to_cron(schedule)
        LOG.debug('Adding new scheduled Events rule with cron schedule %s' % cron)

        job_id = JobScheduler.instance().add_job(job_func, cron, enabled)
        region = aws_stack.get_region()
        RULE_SCHEDULED_JOBS[region] = RULE_SCHEDULED_JOBS.get(region) or {}
        RULE_SCHEDULED_JOBS[region][data['Name']] = job_id

    return True


def handle_delete_rule(rule_name):
    region = aws_stack.get_region()
    job_id = RULE_SCHEDULED_JOBS.get(region, {}).get(rule_name)
    if job_id:
        LOG.debug('Removing scheduled Events: {} | job_id: {}'.format(rule_name, job_id))
        JobScheduler.instance().cancel_job(job_id=job_id)


def handle_disable_rule(rule_name):
    region = aws_stack.get_region()
    job_id = RULE_SCHEDULED_JOBS.get(region, {}).get(rule_name)
    if job_id:
        LOG.debug('Disabling Rule: {} | job_id: {}'.format(rule_name, job_id))
        JobScheduler.instance().disable_job(job_id=job_id)


class ProxyListenerEvents(ProxyListener):
    svc = TaggingService()

    def forward_request(self, method, path, data, headers):
        if method == 'OPTIONS':
            return 200

        action = headers.get('X-Amz-Target')
        if method == 'POST' and path == '/':
            parsed_data = json.loads(to_str(data))

            if action == 'AWSEvents.PutRule':
                return handle_put_rule(parsed_data)

            elif action == 'AWSEvents.DeleteRule':
                handle_delete_rule(rule_name=parsed_data.get('Name', None))

            elif action == 'AWSEvents.ListTagsForResource':
                return self.svc.list_tags_for_resource(parsed_data['ResourceARN']) or {}

            elif action == 'AWSEvents.TagResource':
                self.svc.tag_resource(parsed_data['ResourceARN'], parsed_data['Tags'])
                return {}

            elif action == 'AWSEvents.UntagResource':
                self.svc.untag_resource(parsed_data['ResourceARN'], parsed_data['TagKeys'])
                return {}

            elif action == 'AWSEvents.DisableRule':
                handle_disable_rule(rule_name=parsed_data.get('Name', None))

        return True

    def return_response(self, method, path, data, headers, response, request_handler=None):
        if response.content:
            # fix hardcoded account ID in ARNs returned from this API
            fix_account_id(response)

            # fix dates returned from this API (fixes an issue with Terraform)
            fix_date_format(response)

            # fix Content-Length header
            response.headers['Content-Length'] = len(response._content)


# instantiate listener
UPDATE_EVENTS = ProxyListenerEvents()
