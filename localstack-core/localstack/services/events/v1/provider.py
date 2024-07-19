import datetime
import json
import logging
import os
import re
import time
from typing import Any, Dict, Optional

from moto.events import events_backends
from moto.events.responses import EventsHandler as MotoEventsHandler
from werkzeug import Request
from werkzeug.exceptions import NotFound

from localstack import config
from localstack.aws.api import RequestContext
from localstack.aws.api.core import CommonServiceException, ServiceException
from localstack.aws.api.events import (
    Boolean,
    ConnectionAuthorizationType,
    ConnectionDescription,
    ConnectionName,
    CreateConnectionAuthRequestParameters,
    CreateConnectionResponse,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    InvalidEventPatternException,
    PutRuleResponse,
    PutTargetsResponse,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleState,
    ScheduleExpression,
    String,
    TagList,
    TargetList,
    TestEventPatternResponse,
)
from localstack.constants import APPLICATION_AMZ_JSON_1_1
from localstack.http import route
from localstack.services.edge import ROUTER
from localstack.services.events.event_ruler import matches_rule
from localstack.services.events.models import (
    InvalidEventPatternException as InternalInvalidEventPatternException,
)
from localstack.services.events.scheduler import JobScheduler
from localstack.services.events.v1.models import EventsStore, events_stores
from localstack.services.events.v1.utils import matches_event
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws.arns import event_bus_arn, parse_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.message_forwarding import send_event_to_target
from localstack.utils.collections import pick_attributes
from localstack.utils.common import TMP_FILES, mkdir, save_file, truncate
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import long_uid, short_uid
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp

LOG = logging.getLogger(__name__)

# list of events used to run assertions during integration testing (not exposed to the user)
TEST_EVENTS_CACHE = []
EVENTS_TMP_DIR = "cw_events"
DEFAULT_EVENT_BUS_NAME = "default"
CONNECTION_NAME_PATTERN = re.compile("^[\\.\\-_A-Za-z0-9]+$")


class ValidationException(ServiceException):
    code: str = "ValidationException"
    sender_fault: bool = True
    status_code: int = 400


class EventsProvider(EventsApi, ServiceLifecycleHook):
    def __init__(self):
        apply_patches()

    def on_after_init(self):
        ROUTER.add(self.trigger_scheduled_rule)

    def on_before_start(self):
        JobScheduler.start()

    def on_before_stop(self):
        JobScheduler.shutdown()

    @route("/_aws/events/rules/<path:rule_arn>/trigger")
    def trigger_scheduled_rule(self, request: Request, rule_arn: str):
        """Developer endpoint to trigger a scheduled rule."""
        arn_data = parse_arn(rule_arn)
        account_id = arn_data["account"]
        region = arn_data["region"]
        rule_name = arn_data["resource"].split("/", maxsplit=1)[-1]

        job_id = events_stores[account_id][region].rule_scheduled_jobs.get(rule_name)
        if not job_id:
            raise NotFound()
        job = JobScheduler().instance().get_job(job_id)
        if not job:
            raise NotFound()

        # TODO: once job scheduler is refactored, we can update the deadline of the task instead of running
        #  it here
        job.run()

    @staticmethod
    def get_store(context: RequestContext) -> EventsStore:
        return events_stores[context.account_id][context.region]

    def test_event_pattern(
        self, context: RequestContext, event_pattern: EventPattern, event: String, **kwargs
    ) -> TestEventPatternResponse:
        """Test event pattern uses EventBridge event pattern matching:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
        """
        if config.EVENT_RULE_ENGINE == "java":
            try:
                result = matches_rule(event, event_pattern)
            except InternalInvalidEventPatternException as e:
                raise InvalidEventPatternException(e.message) from e
        else:
            event_pattern_dict = json.loads(event_pattern)
            event_dict = json.loads(event)
            result = matches_event(event_pattern_dict, event_dict)

        # TODO: unify the different implementations below:
        # event_pattern_dict = json.loads(event_pattern)
        # event_dict = json.loads(event)

        # EventBridge:
        # result = matches_event(event_pattern_dict, event_dict)

        # Lambda EventSourceMapping:
        # from localstack.services.lambda_.event_source_listeners.utils import does_match_event
        #
        # result = does_match_event(event_pattern_dict, event_dict)

        # moto-ext EventBridge:
        # from moto.events.models import EventPattern as EventPatternMoto
        #
        # event_pattern = EventPatternMoto.load(event_pattern)
        # result = event_pattern.matches_event(event_dict)

        # SNS: The SNS rule engine seems to differ slightly, for example not allowing the wildcard pattern.
        # from localstack.services.sns.publisher import SubscriptionFilter
        # subscription_filter = SubscriptionFilter()
        # result = subscription_filter._evaluate_nested_filter_policy_on_dict(event_pattern_dict, event_dict)

        # moto-ext SNS:
        # from moto.sns.utils import FilterPolicyMatcher
        # filter_policy_matcher = FilterPolicyMatcher(event_pattern_dict, "MessageBody")
        # result = filter_policy_matcher._body_based_match(event_dict)

        return TestEventPatternResponse(Result=result)

    @staticmethod
    def get_scheduled_rule_func(
        store: EventsStore,
        rule_name: RuleName,
        event_bus_name_or_arn: Optional[EventBusNameOrArn] = None,
    ):
        def func(*args, **kwargs):
            account_id = store._account_id
            region = store._region_name
            moto_backend = events_backends[account_id][region]
            event_bus_name = get_event_bus_name(event_bus_name_or_arn)
            event_bus = moto_backend.event_buses[event_bus_name]
            rule = event_bus.rules.get(rule_name)
            if not rule:
                LOG.info("Unable to find rule `%s` for event bus `%s`", rule_name, event_bus_name)
                return
            if rule.targets:
                LOG.debug(
                    "Notifying %s targets in response to triggered Events rule %s",
                    len(rule.targets),
                    rule_name,
                )

            default_event = {
                "version": "0",
                "id": long_uid(),
                "detail-type": "Scheduled Event",
                "source": "aws.events",
                "account": account_id,
                "time": timestamp(format=TIMESTAMP_FORMAT_TZ),
                "region": region,
                "resources": [rule.arn],
                "detail": {},
            }

            for target in rule.targets:
                arn = target.get("Arn")

                if input_ := target.get("Input"):
                    event = json.loads(input_)
                else:
                    event = default_event
                    if target.get("InputPath"):
                        event = filter_event_with_target_input_path(target, event)
                    if input_transformer := target.get("InputTransformer"):
                        event = process_event_with_input_transformer(input_transformer, event)

                attr = pick_attributes(target, ["$.SqsParameters", "$.KinesisParameters"])

                try:
                    send_event_to_target(
                        arn,
                        event,
                        target_attributes=attr,
                        role=target.get("RoleArn"),
                        target=target,
                        source_arn=rule.arn,
                        source_service=ServicePrincipal.events,
                    )
                except Exception as e:
                    LOG.info(
                        "Unable to send event notification %s to target %s: %s",
                        truncate(event),
                        target,
                        e,
                    )

        return func

    @staticmethod
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

            value = int(value)
            if value < 1:
                raise ValueError("Rate value must be larger than 0")
            # see https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rate-expressions.html
            if value == 1 and unit.endswith("s"):
                raise ValueError("If the value is equal to 1, then the unit must be singular")
            if value > 1 and not unit.endswith("s"):
                raise ValueError("If the value is greater than 1, the unit must be plural")

            if "minute" in unit:
                return "*/%s * * * *" % value
            if "hour" in unit:
                return "0 */%s * * *" % value
            if "day" in unit:
                return "0 0 */%s * *" % value
            raise ValueError("Unable to parse events schedule expression: %s" % schedule)
        return schedule

    @staticmethod
    def put_rule_job_scheduler(
        store: EventsStore,
        name: Optional[RuleName],
        state: Optional[RuleState],
        schedule_expression: Optional[ScheduleExpression],
        event_bus_name_or_arn: Optional[EventBusNameOrArn] = None,
    ):
        if not schedule_expression:
            return

        try:
            cron = EventsProvider.convert_schedule_to_cron(schedule_expression)
        except ValueError as e:
            LOG.error("Error parsing schedule expression: %s", e)
            raise ValidationException("Parameter ScheduleExpression is not valid.") from e

        job_func = EventsProvider.get_scheduled_rule_func(
            store, name, event_bus_name_or_arn=event_bus_name_or_arn
        )
        LOG.debug("Adding new scheduled Events rule with cron schedule %s", cron)

        enabled = state != "DISABLED"
        job_id = JobScheduler.instance().add_job(job_func, cron, enabled)
        rule_scheduled_jobs = store.rule_scheduled_jobs
        rule_scheduled_jobs[name] = job_id

    def put_rule(
        self,
        context: RequestContext,
        name: RuleName,
        schedule_expression: ScheduleExpression = None,
        event_pattern: EventPattern = None,
        state: RuleState = None,
        description: RuleDescription = None,
        role_arn: RoleArn = None,
        tags: TagList = None,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutRuleResponse:
        store = self.get_store(context)
        self.put_rule_job_scheduler(
            store, name, state, schedule_expression, event_bus_name_or_arn=event_bus_name
        )
        return call_moto(context)

    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> None:
        rule_scheduled_jobs = self.get_store(context).rule_scheduled_jobs
        job_id = rule_scheduled_jobs.get(name)
        if job_id:
            LOG.debug("Removing scheduled Events: {} | job_id: {}".format(name, job_id))
            JobScheduler.instance().cancel_job(job_id=job_id)
        call_moto(context)

    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        rule_scheduled_jobs = self.get_store(context).rule_scheduled_jobs
        job_id = rule_scheduled_jobs.get(name)
        if job_id:
            LOG.debug("Disabling Rule: {} | job_id: {}".format(name, job_id))
            JobScheduler.instance().disable_job(job_id=job_id)
        call_moto(context)

    def create_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription = None,
        **kwargs,
    ) -> CreateConnectionResponse:
        errors = []

        if not CONNECTION_NAME_PATTERN.match(name):
            error = f"{name} at 'name' failed to satisfy: Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+"
            errors.append(error)

        if len(name) > 64:
            error = f"{name} at 'name' failed to satisfy: Member must have length less than or equal to 64"
            errors.append(error)

        if authorization_type not in ["BASIC", "API_KEY", "OAUTH_CLIENT_CREDENTIALS"]:
            error = f"{authorization_type} at 'authorizationType' failed to satisfy: Member must satisfy enum value set: [BASIC, OAUTH_CLIENT_CREDENTIALS, API_KEY]"
            errors.append(error)

        if len(errors) > 0:
            error_description = "; ".join(errors)
            error_plural = "errors" if len(errors) > 1 else "error"
            errors_amount = len(errors)
            message = f"{errors_amount} validation {error_plural} detected: {error_description}"
            raise CommonServiceException(message=message, code="ValidationException")

        return call_moto(context)

    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutTargetsResponse:
        validation_errors = []

        id_regex = re.compile(r"^[\.\-_A-Za-z0-9]+$")
        for index, target in enumerate(targets):
            id = target.get("Id")
            if not id_regex.match(id):
                validation_errors.append(
                    f"Value '{id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\.\\-_A-Za-z0-9]+"
                )

            if len(id) > 64:
                validation_errors.append(
                    f"Value '{id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must have length less than or equal to 64"
                )

        if validation_errors:
            errors_message = "; ".join(validation_errors)
            message = f"{len(validation_errors)} validation {'errors' if len(validation_errors) > 1 else 'error'} detected: {errors_message}"
            raise CommonServiceException(message=message, code="ValidationException")

        return call_moto(context)


def _get_events_tmp_dir():
    return os.path.join(config.dirs.tmp, EVENTS_TMP_DIR)


def _create_and_register_temp_dir():
    tmp_dir = _get_events_tmp_dir()
    if not os.path.exists(tmp_dir):
        mkdir(tmp_dir)
        TMP_FILES.append(tmp_dir)
    return tmp_dir


def _dump_events_to_files(events_with_added_uuid):
    try:
        _create_and_register_temp_dir()
        current_time_millis = int(round(time.time() * 1000))
        for event in events_with_added_uuid:
            target = os.path.join(
                _get_events_tmp_dir(),
                "%s_%s" % (current_time_millis, event["uuid"]),
            )
            save_file(target, json.dumps(event["event"]))
    except Exception as e:
        LOG.info("Unable to dump events to tmp dir %s: %s", _get_events_tmp_dir(), e)


def filter_event_based_on_event_format(
    self, rule_name: str, event_bus_name: str, event: dict[str, Any]
):
    rule_information = self.events_backend.describe_rule(
        rule_name, event_bus_arn(event_bus_name, self.current_account, self.region)
    )

    if not rule_information:
        LOG.info('Unable to find rule "%s" in backend: %s', rule_name, rule_information)
        return False
    if rule_information.event_pattern._pattern:
        event_pattern = rule_information.event_pattern._pattern
        if config.EVENT_RULE_ENGINE == "java":
            event_str = json.dumps(event)
            event_pattern_str = json.dumps(event_pattern)
            match_result = matches_rule(event_str, event_pattern_str)
        else:
            match_result = matches_event(event_pattern, event)
        if not match_result:
            return False
    return True


def filter_event_with_target_input_path(target: Dict, event: Dict) -> Dict:
    input_path = target.get("InputPath")
    if input_path:
        event = extract_jsonpath(event, input_path)
    return event


def process_event_with_input_transformer(input_transformer: Dict, event: Dict) -> Dict:
    """
    Process the event with the input transformer of the target event,
    by replacing the message with the populated InputTemplate.
    docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html
    """
    try:
        input_paths = input_transformer["InputPathsMap"]
        input_template = input_transformer["InputTemplate"]
    except KeyError as e:
        LOG.error("%s key does not exist in input_transformer.", e)
        raise e
    for key, path in input_paths.items():
        value = extract_jsonpath(event, path)
        if not value:
            value = ""
        input_template = input_template.replace(f"<{key}>", value)
    templated_event = re.sub('"', "", input_template)
    return templated_event


def process_events(event: Dict, targets: list[Dict]):
    for target in targets:
        arn = target["Arn"]
        changed_event = filter_event_with_target_input_path(target, event)
        if input_transformer := target.get("InputTransformer"):
            changed_event = process_event_with_input_transformer(input_transformer, changed_event)
        if target.get("Input"):
            changed_event = json.loads(target.get("Input"))
        try:
            send_event_to_target(
                arn,
                changed_event,
                pick_attributes(target, ["$.SqsParameters", "$.KinesisParameters"]),
                role=target.get("RoleArn"),
                target=target,
                source_service=ServicePrincipal.events,
                source_arn=target.get("RuleArn"),
            )
        except Exception as e:
            LOG.info(f"Unable to send event notification {truncate(event)} to target {target}: {e}")


def get_event_bus_name(event_bus_name_or_arn: Optional[EventBusNameOrArn] = None) -> str:
    event_bus_name_or_arn = event_bus_name_or_arn or DEFAULT_EVENT_BUS_NAME
    return event_bus_name_or_arn.split("/")[-1]


# specific logic for put_events which forwards matching events to target listeners
def events_handler_put_events(self):
    entries = self._get_param("Entries")

    # keep track of events for local integration testing
    if config.is_local_test_mode():
        TEST_EVENTS_CACHE.extend(entries)

    events = [{"event": event, "uuid": str(long_uid())} for event in entries]

    _dump_events_to_files(events)

    for event_envelope in events:
        event = event_envelope["event"]
        event_bus_name = get_event_bus_name(event.get("EventBusName"))
        event_bus = self.events_backend.event_buses.get(event_bus_name)
        if not event_bus:
            continue

        matching_rules = [
            r
            for r in event_bus.rules.values()
            if r.event_bus_name == event_bus_name and not r.scheduled_expression
        ]
        if not matching_rules:
            continue

        event_time = datetime.datetime.utcnow()
        if event_timestamp := event.get("Time"):
            try:
                # if provided, use the time from event
                event_time = datetime.datetime.utcfromtimestamp(event_timestamp)
            except ValueError:
                # if we can't parse it, pass and keep using `utcnow`
                LOG.debug(
                    "Could not parse the `Time` parameter, falling back to `utcnow` for the following Event: '%s'",
                    event,
                )

        # See https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-events.html
        formatted_event = {
            "version": "0",
            "id": event_envelope["uuid"],
            "detail-type": event.get("DetailType"),
            "source": event.get("Source"),
            "account": self.current_account,
            "time": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "region": self.region,
            "resources": event.get("Resources", []),
            "detail": json.loads(event.get("Detail", "{}")),
        }

        targets = []
        for rule in matching_rules:
            if filter_event_based_on_event_format(self, rule.name, event_bus_name, formatted_event):
                rule_targets, _ = self.events_backend.list_targets_by_rule(
                    rule.name, event_bus_arn(event_bus_name, self.current_account, self.region)
                )
                targets.extend([{"RuleArn": rule.arn} | target for target in rule_targets])
        # process event
        process_events(formatted_event, targets)

    content = {
        "FailedEntryCount": 0,  # TODO: dynamically set proper value when refactoring
        "Entries": [{"EventId": event["uuid"]} for event in events],
    }

    self.response_headers.update(
        {"Content-Type": APPLICATION_AMZ_JSON_1_1, "x-amzn-RequestId": short_uid()}
    )

    return json.dumps(content), self.response_headers


def apply_patches():
    MotoEventsHandler.put_events = events_handler_put_events
