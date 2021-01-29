import re
import datetime
import json
import uuid
import logging
import ipaddress
from moto.events.models import Rule as rule_model
from moto.events.responses import EventsHandler as events_handler
from localstack import config
from localstack.constants import (
    APPLICATION_AMZ_JSON_1_1, TEST_AWS_ACCOUNT_ID)
from localstack.utils.aws import aws_stack
from localstack.utils.common import short_uid, to_bytes, extract_jsonpath
from localstack.services.infra import start_moto_server
from localstack.services.events.scheduler import JobScheduler
from localstack.services.awslambda.lambda_api import run_lambda
from localstack.services.events.events_listener import _create_and_register_temp_dir, _dump_events_to_files


LOG = logging.getLogger(__name__)

DEFAULT_EVENT_BUS_NAME = 'default'

# Event rules storage
EVENT_RULES = {
    DEFAULT_EVENT_BUS_NAME: set()
}

CONTENT_BASE_FILTER_KEYWORDS = [
    'prefix', 'anything-but', 'numeric', 'cidr', 'exists'
]


def send_event_to_sqs(event, arn):
    region = arn.split(':')[3]
    queue_url = aws_stack.get_sqs_queue_url(arn)
    sqs_client = aws_stack.connect_to_service('sqs', region_name=region)
    sqs_client.send_message(QueueUrl=queue_url, MessageBody=json.dumps(event))


def send_event_to_sns(event, arn):
    region = arn.split(':')[3]
    sns_client = aws_stack.connect_to_service('sns', region_name=region)
    sns_client.publish(TopicArn=arn, Message=json.dumps(event))


def send_event_to_lambda(event, arn):
    run_lambda(event=event, context={}, func_arn=arn, asynchronous=True)


def send_event_to_firehose(event, arn):
    delivery_stream_name = aws_stack.firehose_name(arn)
    firehose_client = aws_stack.connect_to_service('firehose')
    firehose_client.put_record(
        DeliveryStreamName=delivery_stream_name,
        Record={'Data': to_bytes(json.dumps(event))})


def filter_event_with_target_input_path(target, event):
    input_path = target.get('InputPath')
    if input_path:
        event = extract_jsonpath(event, input_path)
    return event


def filter_event_based_on_event_format(self, rule, event):
    def filter_event(event_pattern, event):
        for key, value in event_pattern.items():
            event_value = event.get(key.lower())
            if not event_value:
                return False

            if isinstance(value, list) and not identify_content_base_parameter_in_pattern(value):
                if isinstance(event_value, list) and \
                   get_two_lists_intersection(value, event_value) == []:
                    return False
                elif not isinstance(event_value, list) and \
                        isinstance(event_value, (str, int)) and \
                        event_value not in value:
                    return False

            elif isinstance(value, list) and identify_content_base_parameter_in_pattern(value):
                if not filter_event_with_content_base_parameter(value, event_value):
                    return False

            elif isinstance(value, (str, int)):
                try:
                    if isinstance(json.loads(value), dict) and \
                       not filter_event(json.loads(value), event_value):
                        return False
                except json.decoder.JSONDecodeError:
                    return False
        return True

    rule_information = self.events_backend.describe_rule(rule)
    if rule_information.event_pattern:
        event_pattern = json.loads(rule_information.event_pattern)
        if not filter_event(event_pattern, event):
            return False
    return True


def process_events(event, targets):
    for target in targets:
        arn = target['Arn']
        service = arn.split(':')[2]
        changed_event = filter_event_with_target_input_path(target, event)
        if service == 'sqs':
            send_event_to_sqs(changed_event, arn)

        elif service == 'sns':
            send_event_to_sns(changed_event, arn)

        elif service == 'lambda':
            send_event_to_lambda(changed_event, arn)

        elif service == 'firehose':
            send_event_to_firehose(changed_event, arn)

        else:
            LOG.warning('Unsupported Events target service type "%s"' % service)


def apply_patches():
    # Fix events arn
    def rule_model_generate_arn(self, name):
        return 'arn:aws:events:{region_name}:{account_id}:rule/{name}'.format(
            region_name=self.region_name, account_id=TEST_AWS_ACCOUNT_ID, name=name
        )

    events_handler_put_rule_orig = events_handler.put_rule

    def events_handler_put_rule(self):
        name = self._get_param('Name')
        event_bus = self._get_param('EventBusName') or DEFAULT_EVENT_BUS_NAME

        if event_bus not in EVENT_RULES:
            EVENT_RULES[event_bus] = set()

        EVENT_RULES[event_bus].add(name)

        return events_handler_put_rule_orig(self)

    events_handler_delete_rule_orig = events_handler.delete_rule

    def events_handler_delete_rule(self):
        name = self._get_param('Name')
        event_bus = self._get_param('EventBusName') or DEFAULT_EVENT_BUS_NAME

        EVENT_RULES.get(event_bus, set()).remove(name)

        return events_handler_delete_rule_orig(self)

    # 2101 Events put-targets does not respond
    def events_handler_put_targets(self):
        rule_name = self._get_param('Rule')
        targets = self._get_param('Targets')

        if not rule_name:
            return self.error('ValidationException', 'Parameter Rule is required.')

        if not targets:
            return self.error('ValidationException', 'Parameter Targets is required.')

        if not self.events_backend.put_targets(rule_name, targets):
            return self.error(
                'ResourceNotFoundException', 'Rule ' + rule_name + ' does not exist.'
            )

        return json.dumps({'FailedEntryCount': 0, 'FailedEntries': []}), self.response_headers

    def events_handler_put_events(self):
        entries = self._get_param('Entries')
        events = list(
            map(lambda event: {'event': event, 'uuid': str(uuid.uuid4())}, entries)
        )

        _create_and_register_temp_dir()
        _dump_events_to_files(events)

        for event_envelope in events:
            event = event_envelope['event']
            event_bus = event.get('EventBusName') or DEFAULT_EVENT_BUS_NAME

            rules = EVENT_RULES.get(event_bus, [])

            formatted_event = {
                'version': '0',
                'id': event_envelope['uuid'],
                'detail-type': event.get('DetailType'),
                'source': event.get('Source'),
                'account': TEST_AWS_ACCOUNT_ID,
                'time': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
                'region': self.region,
                'resources': event.get('Resources', []),
                'detail': json.loads(event.get('Detail')),
            }

            targets = []
            for rule in rules:
                if filter_event_based_on_event_format(self, rule, formatted_event):
                    targets.extend(self.events_backend.list_targets_by_rule(rule)['Targets'])

            # process event
            process_events(formatted_event, targets)

        content = {
            'Entries': list(map(lambda event: {'EventId': event['uuid']}, events))
        }

        self.response_headers.update({
            'Content-Type': APPLICATION_AMZ_JSON_1_1,
            'x-amzn-RequestId': short_uid()
        })

        return json.dumps(content), self.response_headers

    rule_model._generate_arn = rule_model_generate_arn
    events_handler.put_rule = events_handler_put_rule
    events_handler.delete_rule = events_handler_delete_rule
    events_handler.put_targets = events_handler_put_targets
    events_handler.put_events = events_handler_put_events


def start_scheduler():
    JobScheduler.start()


def start_events(port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_EVENTS

    apply_patches()
    start_scheduler()

    return start_moto_server(
        key='events',
        port=port,
        name='Cloudwatch Events',
        asynchronous=asynchronous,
        update_listener=update_listener
    )


# ---------------
# HELPER METHODS
# ---------------


def get_two_lists_intersection(lst1, lst2):
    lst3 = [value for value in lst1 if value in lst2]
    return lst3


def identify_content_base_parameter_in_pattern(parameters):
    if any([list(param.keys())[0] in CONTENT_BASE_FILTER_KEYWORDS for param in parameters if isinstance(param, dict)]):
        return True


def filter_event_with_content_base_parameter(pattern_value, event_value):
    for element in pattern_value:
        if (isinstance(element, (str, int))) \
           and (event_value == element or element in event_value):
            return True
        elif isinstance(element, dict):
            element_key = list(element.keys())[0]
            element_value = element.get(element_key)
            if element_key.lower() == 'prefix':
                if re.match(r'^{}'.format(element_value), event_value):
                    return True
            elif element_key.lower() == 'exists':
                if element_value and event_value:
                    return True
                elif not element_value and not event_value:
                    return True
            elif element_key.lower() == 'cidr':
                ips = [str(ip) for ip in ipaddress.IPv4Network(element_value)]
                if event_value in ips:
                    return True
            elif element_key.lower() == 'numeric':
                if check_valid_numeric_content_base_rule(element_value):
                    for index in range(len(element_value)):
                        if isinstance(element_value[index], int):
                            continue
                        if element_value[index] == '>' and \
                            isinstance(element_value[index + 1], int) and \
                                event_value <= element_value[index + 1]:
                            break
                        elif element_value[index] == '>=' and \
                            isinstance(element_value[index + 1], int) and \
                                event_value < element_value[index + 1]:
                            break
                        elif element_value[index] == '<' and \
                            isinstance(element_value[index + 1], int) and \
                                event_value >= element_value[index + 1]:
                            break
                        elif element_value[index] == '<=' and \
                            isinstance(element_value[index + 1], int) and \
                                event_value > element_value[index + 1]:
                            break
                    else:
                        return True

            elif element_key.lower() == 'anything-but':
                if isinstance(element_value, list) and \
                        event_value not in element_value:
                    return True
                elif (isinstance(element_value, (str, int))) and \
                        event_value != element_value:
                    return True
                elif isinstance(element_value, dict):
                    nested_key = list(element_value)[0]
                    if nested_key == 'prefix' and \
                            not re.match(r'^{}'.format(element_value.get(nested_key)), event_value):
                        return True
    return False


def check_valid_numeric_content_base_rule(list_of_operators):
    if len(list_of_operators) > 4:
        return False

    if '=' in list_of_operators:
        return False

    if len(list_of_operators) > 2:
        upper_limit = None
        lower_limit = None
        for index in range(len(list_of_operators)):
            if not isinstance(list_of_operators[index], int) and \
               '<' in list_of_operators[index]:
                upper_limit = list_of_operators[index + 1]
            if not isinstance(list_of_operators[index], int) and \
               '>' in list_of_operators[index]:
                lower_limit = list_of_operators[index + 1]
            if upper_limit and lower_limit and upper_limit < lower_limit:
                return False
            index = index + 1
    return True
