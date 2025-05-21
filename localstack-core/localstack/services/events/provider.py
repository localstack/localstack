import base64
import json
import logging
import re
from typing import Callable, Optional

from localstack.aws.api import RequestContext, handler
from localstack.aws.api.config import TagsList
from localstack.aws.api.events import (
    Action,
    ApiDestinationDescription,
    ApiDestinationHttpMethod,
    ApiDestinationInvocationRateLimitPerSecond,
    ApiDestinationName,
    ApiDestinationResponseList,
    ArchiveDescription,
    ArchiveName,
    ArchiveResponseList,
    ArchiveState,
    Arn,
    Boolean,
    CancelReplayResponse,
    Condition,
    ConnectionArn,
    ConnectionAuthorizationType,
    ConnectionDescription,
    ConnectionName,
    ConnectionResponseList,
    ConnectionState,
    ConnectivityResourceParameters,
    CreateApiDestinationResponse,
    CreateArchiveResponse,
    CreateConnectionAuthRequestParameters,
    CreateConnectionResponse,
    CreateEventBusResponse,
    DeadLetterConfig,
    DeleteApiDestinationResponse,
    DeleteArchiveResponse,
    DeleteConnectionResponse,
    DescribeApiDestinationResponse,
    DescribeArchiveResponse,
    DescribeConnectionResponse,
    DescribeEventBusResponse,
    DescribeReplayResponse,
    DescribeRuleResponse,
    EndpointId,
    EventBusArn,
    EventBusDescription,
    EventBusList,
    EventBusName,
    EventBusNameOrArn,
    EventPattern,
    EventsApi,
    EventSourceName,
    HttpsEndpoint,
    InternalException,
    KmsKeyIdentifier,
    LimitMax100,
    ListApiDestinationsResponse,
    ListArchivesResponse,
    ListConnectionsResponse,
    ListEventBusesResponse,
    ListReplaysResponse,
    ListRuleNamesByTargetResponse,
    ListRulesResponse,
    ListTagsForResourceResponse,
    ListTargetsByRuleResponse,
    NextToken,
    NonPartnerEventBusName,
    Principal,
    PutEventsRequestEntry,
    PutEventsRequestEntryList,
    PutEventsResponse,
    PutEventsResultEntry,
    PutEventsResultEntryList,
    PutPartnerEventsRequestEntryList,
    PutPartnerEventsResponse,
    PutRuleResponse,
    PutTargetsResponse,
    RemoveTargetsResponse,
    ReplayDescription,
    ReplayDestination,
    ReplayList,
    ReplayName,
    ReplayState,
    ResourceAlreadyExistsException,
    ResourceNotFoundException,
    RetentionDays,
    RoleArn,
    RuleDescription,
    RuleName,
    RuleResponseList,
    RuleState,
    ScheduleExpression,
    StartReplayResponse,
    StatementId,
    String,
    TagKeyList,
    TagList,
    TagResourceResponse,
    Target,
    TargetArn,
    TargetId,
    TargetIdList,
    TargetList,
    TestEventPatternResponse,
    Timestamp,
    UntagResourceResponse,
    UpdateApiDestinationResponse,
    UpdateArchiveResponse,
    UpdateConnectionAuthRequestParameters,
    UpdateConnectionResponse,
)
from localstack.aws.api.events import ApiDestination as ApiTypeApiDestination
from localstack.aws.api.events import Archive as ApiTypeArchive
from localstack.aws.api.events import Connection as ApiTypeConnection
from localstack.aws.api.events import EventBus as ApiTypeEventBus
from localstack.aws.api.events import Replay as ApiTypeReplay
from localstack.aws.api.events import Rule as ApiTypeRule
from localstack.services.events.api_destination import (
    APIDestinationService,
    ApiDestinationServiceDict,
)
from localstack.services.events.archive import ArchiveService, ArchiveServiceDict
from localstack.services.events.connection import (
    ConnectionService,
    ConnectionServiceDict,
)
from localstack.services.events.event_bus import EventBusService, EventBusServiceDict
from localstack.services.events.models import (
    ApiDestination,
    ApiDestinationDict,
    Archive,
    ArchiveDict,
    Connection,
    ConnectionDict,
    EventBus,
    EventBusDict,
    EventsStore,
    FormattedEvent,
    Replay,
    ReplayDict,
    ResourceType,
    Rule,
    RuleDict,
    TargetDict,
    ValidationException,
    events_stores,
)
from localstack.services.events.replay import ReplayService, ReplayServiceDict
from localstack.services.events.rule import RuleService, RuleServiceDict
from localstack.services.events.scheduler import JobScheduler
from localstack.services.events.target import (
    TargetSender,
    TargetSenderDict,
    TargetSenderFactory,
)
from localstack.services.events.utils import (
    TARGET_ID_PATTERN,
    extract_connection_name,
    extract_event_bus_name,
    extract_region_and_account_id,
    format_event,
    get_resource_type,
    get_trace_header_encoded_region_account,
    is_archive_arn,
    recursive_remove_none_values_from_dict,
)
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.common import truncate
from localstack.utils.event_matcher import matches_event
from localstack.utils.strings import long_uid
from localstack.utils.time import TIMESTAMP_FORMAT_TZ, timestamp
from localstack.utils.xray.trace_header import TraceHeader

from .analytics import InvocationStatus, rule_invocation

LOG = logging.getLogger(__name__)

ARCHIVE_TARGET_ID_NAME_PATTERN = re.compile(r"^Events-Archive-(?P<name>[a-zA-Z0-9_-]+)$")


def decode_next_token(token: NextToken) -> int:
    """Decode a pagination token from base64 to integer."""
    return int.from_bytes(base64.b64decode(token), "big")


def encode_next_token(token: int) -> NextToken:
    """Encode a pagination token to base64 from integer."""
    return base64.b64encode(token.to_bytes(128, "big")).decode("utf-8")


def get_filtered_dict(name_prefix: str, input_dict: dict) -> dict:
    """Filter dictionary by prefix."""
    return {name: value for name, value in input_dict.items() if name.startswith(name_prefix)}


def validate_event(event: PutEventsRequestEntry) -> None | PutEventsResultEntry:
    if not event.get("Source"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter Source is not valid. Reason: Source is a required argument.",
        }
    elif not event.get("DetailType"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter DetailType is not valid. Reason: DetailType is a required argument.",
        }
    elif not event.get("Detail"):
        return {
            "ErrorCode": "InvalidArgument",
            "ErrorMessage": "Parameter Detail is not valid. Reason: Detail is a required argument.",
        }
    elif event.get("Detail") and len(event["Detail"]) >= 262144:
        raise ValidationException("Total size of the entries in the request is over the limit.")
    elif event.get("Detail"):
        try:
            json_detail = json.loads(event.get("Detail"))
            if isinstance(json_detail, dict):
                return
        except json.JSONDecodeError:
            pass

        return {
            "ErrorCode": "MalformedDetail",
            "ErrorMessage": "Detail is malformed.",
        }


def check_unique_tags(tags: TagsList) -> None:
    unique_tag_keys = {tag["Key"] for tag in tags}
    if len(unique_tag_keys) < len(tags):
        raise ValidationException("Invalid parameter: Duplicated keys are not allowed.")


class EventsProvider(EventsApi, ServiceLifecycleHook):
    # api methods are grouped by resource type and sorted in alphabetical order
    # functions in each group is sorted alphabetically
    def __init__(self):
        self._event_bus_services_store: EventBusServiceDict = {}
        self._rule_services_store: RuleServiceDict = {}
        self._target_sender_store: TargetSenderDict = {}
        self._archive_service_store: ArchiveServiceDict = {}
        self._replay_service_store: ReplayServiceDict = {}
        self._connection_service_store: ConnectionServiceDict = {}
        self._api_destination_service_store: ApiDestinationServiceDict = {}

    def on_before_start(self):
        JobScheduler.start()

    def on_before_stop(self):
        JobScheduler.shutdown()

    ##################
    # API Destinations
    ##################
    @handler("CreateApiDestination")
    def create_api_destination(
        self,
        context: RequestContext,
        name: ApiDestinationName,
        connection_arn: ConnectionArn,
        invocation_endpoint: HttpsEndpoint,
        http_method: ApiDestinationHttpMethod,
        description: ApiDestinationDescription = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond = None,
        **kwargs,
    ) -> CreateApiDestinationResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if name in store.api_destinations:
            raise ResourceAlreadyExistsException(f"An api-destination '{name}' already exists.")
        APIDestinationService.validate_input(name, connection_arn, http_method, invocation_endpoint)
        connection_name = extract_connection_name(connection_arn)
        connection = self.get_connection(connection_name, store)
        api_destination_service = self.create_api_destinations_service(
            name,
            region,
            account_id,
            connection_arn,
            connection,
            invocation_endpoint,
            http_method,
            invocation_rate_limit_per_second,
            description,
        )
        store.api_destinations[api_destination_service.api_destination.name] = (
            api_destination_service.api_destination
        )

        response = CreateApiDestinationResponse(
            ApiDestinationArn=api_destination_service.arn,
            ApiDestinationState=api_destination_service.state,
            CreationTime=api_destination_service.creation_time,
            LastModifiedTime=api_destination_service.last_modified_time,
        )
        return response

    @handler("DescribeApiDestination")
    def describe_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DescribeApiDestinationResponse:
        store = self.get_store(context.region, context.account_id)
        api_destination = self.get_api_destination(name, store)

        response = self._api_destination_to_api_type_api_destination(api_destination)
        return response

    @handler("DeleteApiDestination")
    def delete_api_destination(
        self, context: RequestContext, name: ApiDestinationName, **kwargs
    ) -> DeleteApiDestinationResponse:
        store = self.get_store(context.region, context.account_id)
        if api_destination := self.get_api_destination(name, store):
            del self._api_destination_service_store[api_destination.arn]
            del store.api_destinations[name]
            del store.TAGS[api_destination.arn]

        return DeleteApiDestinationResponse()

    @handler("ListApiDestinations")
    def list_api_destinations(
        self,
        context: RequestContext,
        name_prefix: ApiDestinationName = None,
        connection_arn: ConnectionArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListApiDestinationsResponse:
        store = self.get_store(context.region, context.account_id)
        api_destinations = (
            get_filtered_dict(name_prefix, store.api_destinations)
            if name_prefix
            else store.api_destinations
        )
        limited_rules, next_token = self._get_limited_dict_and_next_token(
            api_destinations, next_token, limit
        )

        response = ListApiDestinationsResponse(
            ApiDestinations=list(
                self._api_destination_dict_to_api_destination_response_list(limited_rules)
            )
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("UpdateApiDestination")
    def update_api_destination(
        self,
        context: RequestContext,
        name: ApiDestinationName,
        description: ApiDestinationDescription = None,
        connection_arn: ConnectionArn = None,
        invocation_endpoint: HttpsEndpoint = None,
        http_method: ApiDestinationHttpMethod = None,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond = None,
        **kwargs,
    ) -> UpdateApiDestinationResponse:
        store = self.get_store(context.region, context.account_id)
        api_destination = self.get_api_destination(name, store)
        api_destination_service = self._api_destination_service_store[api_destination.arn]
        if connection_arn:
            connection_name = extract_connection_name(connection_arn)
            connection = self.get_connection(connection_name, store)
        else:
            connection = api_destination_service.connection
        api_destination_service.update(
            connection,
            invocation_endpoint,
            http_method,
            invocation_rate_limit_per_second,
            description,
        )

        response = UpdateApiDestinationResponse(
            ApiDestinationArn=api_destination_service.arn,
            ApiDestinationState=api_destination_service.state,
            CreationTime=api_destination_service.creation_time,
            LastModifiedTime=api_destination_service.last_modified_time,
        )
        return response

    #############
    # Connections
    #############
    @handler("CreateConnection")
    def create_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription = None,
        invocation_connectivity_parameters: ConnectivityResourceParameters = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> CreateConnectionResponse:
        # TODO add support for kms_key_identifier
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if name in store.connections:
            raise ResourceAlreadyExistsException(f"Connection {name} already exists.")
        connection_service = self.create_connection_service(
            name,
            region,
            account_id,
            authorization_type,
            auth_parameters,
            description,
            invocation_connectivity_parameters,
        )
        store.connections[connection_service.connection.name] = connection_service.connection

        response = CreateConnectionResponse(
            ConnectionArn=connection_service.arn,
            ConnectionState=connection_service.state,
            CreationTime=connection_service.creation_time,
            LastModifiedTime=connection_service.last_modified_time,
        )
        return response

    @handler("DescribeConnection")
    def describe_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DescribeConnectionResponse:
        store = self.get_store(context.region, context.account_id)
        connection = self.get_connection(name, store)

        response = self._connection_to_api_type_connection(connection)
        return response

    @handler("DeleteConnection")
    def delete_connection(
        self, context: RequestContext, name: ConnectionName, **kwargs
    ) -> DeleteConnectionResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if connection := self.get_connection(name, store):
            connection_service = self._connection_service_store.pop(connection.arn)
            connection_service.delete()
            del store.connections[name]
            del store.TAGS[connection.arn]

        response = DeleteConnectionResponse(
            ConnectionArn=connection.arn,
            ConnectionState=connection.state,
            CreationTime=connection.creation_time,
            LastModifiedTime=connection.last_modified_time,
            LastAuthorizedTime=connection.last_authorized_time,
        )
        return response

    @handler("ListConnections")
    def list_connections(
        self,
        context: RequestContext,
        name_prefix: ConnectionName = None,
        connection_state: ConnectionState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListConnectionsResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        connections = (
            get_filtered_dict(name_prefix, store.connections) if name_prefix else store.connections
        )
        limited_rules, next_token = self._get_limited_dict_and_next_token(
            connections, next_token, limit
        )

        response = ListConnectionsResponse(
            Connections=list(self._connection_dict_to_connection_response_list(limited_rules))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("UpdateConnection")
    def update_connection(
        self,
        context: RequestContext,
        name: ConnectionName,
        description: ConnectionDescription = None,
        authorization_type: ConnectionAuthorizationType = None,
        auth_parameters: UpdateConnectionAuthRequestParameters = None,
        invocation_connectivity_parameters: ConnectivityResourceParameters = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> UpdateConnectionResponse:
        # TODO add support for kms_key_identifier
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        connection = self.get_connection(name, store)
        connection_service = self._connection_service_store[connection.arn]
        connection_service.update(
            description, authorization_type, auth_parameters, invocation_connectivity_parameters
        )

        response = UpdateConnectionResponse(
            ConnectionArn=connection_service.arn,
            ConnectionState=connection_service.state,
            CreationTime=connection_service.creation_time,
            LastModifiedTime=connection_service.last_modified_time,
            LastAuthorizedTime=connection_service.last_authorized_time,
        )
        return response

    ##########
    # EventBus
    ##########

    @handler("CreateEventBus")
    def create_event_bus(
        self,
        context: RequestContext,
        name: EventBusName,
        event_source_name: EventSourceName = None,
        description: EventBusDescription = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        dead_letter_config: DeadLetterConfig = None,
        tags: TagList = None,
        **kwargs,
    ) -> CreateEventBusResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if name in store.event_buses:
            raise ResourceAlreadyExistsException(f"Event bus {name} already exists.")
        event_bus_service = self.create_event_bus_service(
            name, region, account_id, event_source_name, description, tags
        )
        store.event_buses[event_bus_service.event_bus.name] = event_bus_service.event_bus

        if tags:
            self.tag_resource(context, event_bus_service.arn, tags)

        response = CreateEventBusResponse(
            EventBusArn=event_bus_service.arn,
        )
        if description := getattr(event_bus_service.event_bus, "description", None):
            response["Description"] = description
        return response

    @handler("DeleteEventBus")
    def delete_event_bus(self, context: RequestContext, name: EventBusName, **kwargs) -> None:
        if name == "default":
            raise ValidationException("Cannot delete event bus default.")
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        try:
            if event_bus := self.get_event_bus(name, store):
                del self._event_bus_services_store[event_bus.arn]
                if rules := event_bus.rules:
                    self._delete_rule_services(rules)
                del store.event_buses[name]
                del store.TAGS[event_bus.arn]
        except ResourceNotFoundException as error:
            return error

    @handler("DescribeEventBus")
    def describe_event_bus(
        self, context: RequestContext, name: EventBusNameOrArn = None, **kwargs
    ) -> DescribeEventBusResponse:
        name = extract_event_bus_name(name)
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(name, store)

        response = self._event_bus_to_api_type_event_bus(event_bus)
        return response

    @handler("ListEventBuses")
    def list_event_buses(
        self,
        context: RequestContext,
        name_prefix: EventBusName = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListEventBusesResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_buses = (
            get_filtered_dict(name_prefix, store.event_buses) if name_prefix else store.event_buses
        )
        limited_event_buses, next_token = self._get_limited_dict_and_next_token(
            event_buses, next_token, limit
        )

        response = ListEventBusesResponse(
            EventBuses=self._event_bust_dict_to_event_bus_response_list(limited_event_buses)
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("PutPermission")
    def put_permission(
        self,
        context: RequestContext,
        event_bus_name: NonPartnerEventBusName = None,
        action: Action = None,
        principal: Principal = None,
        statement_id: StatementId = None,
        condition: Condition = None,
        policy: String = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(event_bus_name, store)
        event_bus_service = self._event_bus_services_store[event_bus.arn]
        event_bus_service.put_permission(action, principal, statement_id, condition, policy)

    @handler("RemovePermission")
    def remove_permission(
        self,
        context: RequestContext,
        statement_id: StatementId = None,
        remove_all_permissions: Boolean = None,
        event_bus_name: NonPartnerEventBusName = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus = self.get_event_bus(event_bus_name, store)
        event_bus_service = self._event_bus_services_store[event_bus.arn]
        if remove_all_permissions:
            event_bus_service.event_bus.policy = None
            return
        if not statement_id:
            raise ValidationException("Parameter StatementId is required.")
        event_bus_service.revoke_put_events_permission(statement_id)

    #######
    # Rules
    #######
    @handler("EnableRule")
    def enable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)
        rule.state = RuleState.ENABLED

    @handler("DeleteRule")
    def delete_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        try:
            rule = self.get_rule(name, event_bus)
            if rule.targets and not force:
                raise ValidationException("Rule can't be deleted since it has targets.")
            self._delete_rule_services(rule)
            del event_bus.rules[name]
            del store.TAGS[rule.arn]
        except ResourceNotFoundException as error:
            return error

    @handler("DescribeRule")
    def describe_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> DescribeRuleResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)

        response = self._rule_to_api_type_rule(rule)
        return response

    @handler("DisableRule")
    def disable_rule(
        self,
        context: RequestContext,
        name: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> None:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(name, event_bus)
        rule.state = RuleState.DISABLED

    @handler("ListRules")
    def list_rules(
        self,
        context: RequestContext,
        name_prefix: RuleName = None,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRulesResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rules = get_filtered_dict(name_prefix, event_bus.rules) if name_prefix else event_bus.rules
        limited_rules, next_token = self._get_limited_dict_and_next_token(rules, next_token, limit)

        response = ListRulesResponse(
            Rules=list(self._rule_dict_to_rule_response_list(limited_rules))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("ListRuleNamesByTarget")
    def list_rule_names_by_target(
        self,
        context: RequestContext,
        target_arn: TargetArn,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListRuleNamesByTargetResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)

        # Find all rules that have a target with the specified ARN
        matching_rule_names = []
        for rule_name, rule in event_bus.rules.items():
            for target_id, target in rule.targets.items():
                if target["Arn"] == target_arn:
                    matching_rule_names.append(rule_name)
                    break  # Found a match in this rule, no need to check other targets

        limited_rules, next_token = self._get_limited_list_and_next_token(
            matching_rule_names, next_token, limit
        )

        response = ListRuleNamesByTargetResponse(RuleNames=limited_rules)
        if next_token is not None:
            response["NextToken"] = next_token

        return response

    @handler("PutRule")
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
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        existing_rule = event_bus.rules.get(name)
        targets = existing_rule.targets if existing_rule else None
        rule_service = self.create_rule_service(
            name,
            region,
            account_id,
            schedule_expression,
            event_pattern,
            state,
            description,
            role_arn,
            tags,
            event_bus_name,
            targets,
        )
        event_bus.rules[name] = rule_service.rule

        if tags:
            self.tag_resource(context, rule_service.arn, tags)

        response = PutRuleResponse(RuleArn=rule_service.arn)
        return response

    @handler("TestEventPattern")
    def test_event_pattern(
        self, context: RequestContext, event_pattern: EventPattern, event: str, **kwargs
    ) -> TestEventPatternResponse:
        """Test event pattern uses EventBridge event pattern matching:
        https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-patterns.html
        """
        try:
            json_event = json.loads(event)
        except json.JSONDecodeError:
            raise ValidationException("Parameter Event is not valid.")

        mandatory_fields = {
            "id",
            "account",
            "source",
            "time",
            "region",
            "detail-type",
        }
        # https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_TestEventPattern.html
        # the documentation says that `resources` is mandatory, but it is not in reality

        if not isinstance(json_event, dict) or not mandatory_fields.issubset(json_event):
            raise ValidationException("Parameter Event is not valid.")

        result = matches_event(event_pattern, event)
        return TestEventPatternResponse(Result=result)

    #########
    # Targets
    #########

    @handler("ListTargetsByRule")
    def list_targets_by_rule(
        self,
        context: RequestContext,
        rule: RuleName,
        event_bus_name: EventBusNameOrArn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListTargetsByRuleResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(rule, event_bus)
        targets = rule.targets
        limited_targets, next_token = self._get_limited_dict_and_next_token(
            targets, next_token, limit
        )

        response = ListTargetsByRuleResponse(Targets=list(limited_targets.values()))
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("PutTargets")
    def put_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        targets: TargetList,
        event_bus_name: EventBusNameOrArn = None,
        **kwargs,
    ) -> PutTargetsResponse:
        region = context.region
        account_id = context.account_id
        rule_service = self.get_rule_service(region, account_id, rule, event_bus_name)
        failed_entries = rule_service.add_targets(targets)
        rule_arn = rule_service.arn
        rule_name = rule_service.rule.name
        for index, target in enumerate(targets):  # TODO only add successful targets
            target_id = target["Id"]
            if len(target_id) > 64:
                raise ValidationException(
                    rf"1 validation error detected: Value '{target_id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must have length less than or equal to 64"
                )
            if not bool(TARGET_ID_PATTERN.match(target_id)):
                raise ValidationException(
                    rf"1 validation error detected: Value '{target_id}' at 'targets.{index + 1}.member.id' failed to satisfy constraint: Member must satisfy regular expression pattern: [\.\-_A-Za-z0-9]+"
                )
            self.create_target_sender(target, rule_arn, rule_name, region, account_id)

        if rule_service.schedule_cron:
            schedule_job_function = self._get_scheduled_rule_job_function(
                account_id, region, rule_service.rule
            )
            rule_service.create_schedule_job(schedule_job_function)
        response = PutTargetsResponse(
            FailedEntryCount=len(failed_entries), FailedEntries=failed_entries
        )
        return response

    @handler("RemoveTargets")
    def remove_targets(
        self,
        context: RequestContext,
        rule: RuleName,
        ids: TargetIdList,
        event_bus_name: EventBusNameOrArn = None,
        force: Boolean = None,
        **kwargs,
    ) -> RemoveTargetsResponse:
        region = context.region
        account_id = context.account_id
        rule_service = self.get_rule_service(region, account_id, rule, event_bus_name)
        failed_entries = rule_service.remove_targets(ids)
        self._delete_target_sender(ids, rule_service.rule)

        response = RemoveTargetsResponse(
            FailedEntryCount=len(failed_entries), FailedEntries=failed_entries
        )
        return response

    #########
    # Archive
    #########
    @handler("CreateArchive")
    def create_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        event_source_arn: EventBusArn,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> CreateArchiveResponse:
        # TODO add support for kms_key_identifier
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if archive_name in store.archives:
            raise ResourceAlreadyExistsException(f"Archive {archive_name} already exists.")
        self._check_event_bus_exists(event_source_arn, store)
        archive_service = self.create_archive_service(
            archive_name,
            region,
            account_id,
            event_source_arn,
            description,
            event_pattern,
            retention_days,
        )
        store.archives[archive_service.archive.name] = archive_service.archive

        response = CreateArchiveResponse(
            ArchiveArn=archive_service.arn,
            State=archive_service.state,
            CreationTime=archive_service.creation_time,
        )
        return response

    @handler("DeleteArchive")
    def delete_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DeleteArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if archive := self.get_archive(archive_name, store):
            try:
                archive_service = self._archive_service_store.pop(archive.arn)
                archive_service.delete()
                del store.archives[archive_name]
            except ResourceNotFoundException as error:
                return error

    @handler("DescribeArchive")
    def describe_archive(
        self, context: RequestContext, archive_name: ArchiveName, **kwargs
    ) -> DescribeArchiveResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        archive = self.get_archive(archive_name, store)

        response = self._archive_to_describe_archive_response(archive)
        return response

    @handler("ListArchives")
    def list_archives(
        self,
        context: RequestContext,
        name_prefix: ArchiveName = None,
        event_source_arn: Arn = None,
        state: ArchiveState = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListArchivesResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if event_source_arn:
            self._check_event_bus_exists(event_source_arn, store)
            archives = {
                key: archive
                for key, archive in store.archives.items()
                if archive.event_source_arn == event_source_arn
            }
        elif name_prefix:
            archives = get_filtered_dict(name_prefix, store.archives)
        else:
            archives = store.archives
        limited_archives, next_token = self._get_limited_dict_and_next_token(
            archives, next_token, limit
        )

        response = ListArchivesResponse(
            Archives=list(self._archive_dict_to_archive_response_list(limited_archives))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("UpdateArchive")
    def update_archive(
        self,
        context: RequestContext,
        archive_name: ArchiveName,
        description: ArchiveDescription = None,
        event_pattern: EventPattern = None,
        retention_days: RetentionDays = None,
        kms_key_identifier: KmsKeyIdentifier = None,
        **kwargs,
    ) -> UpdateArchiveResponse:
        # TODO add support for kms_key_identifier
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        try:
            archive = self.get_archive(archive_name, store)
        except ResourceNotFoundException:
            raise InternalException("Service encountered unexpected problem. Please try again.")
        archive_service = self._archive_service_store[archive.arn]
        archive_service.update(description, event_pattern, retention_days)

        response = UpdateArchiveResponse(
            ArchiveArn=archive_service.arn,
            State=archive.state,
            # StateReason=archive.state_reason,
            CreationTime=archive.creation_time,
        )
        return response

    ########
    # Events
    ########

    @handler("PutEvents")
    def put_events(
        self,
        context: RequestContext,
        entries: PutEventsRequestEntryList,
        endpoint_id: EndpointId = None,
        **kwargs,
    ) -> PutEventsResponse:
        if len(entries) > 10:
            formatted_entries = [self._event_to_error_type_event(entry) for entry in entries]
            formatted_entries = f"[{', '.join(formatted_entries)}]"
            raise ValidationException(
                f"1 validation error detected: Value '{formatted_entries}' at 'entries' failed to satisfy constraint: Member must have length less than or equal to 10"
            )
        entries, failed_entry_count = self._process_entries(context, entries)

        response = PutEventsResponse(
            Entries=entries,
            FailedEntryCount=failed_entry_count,
        )
        return response

    @handler("PutPartnerEvents")
    def put_partner_events(
        self,
        context: RequestContext,
        entries: PutPartnerEventsRequestEntryList,
        **kwargs,
    ) -> PutPartnerEventsResponse:
        raise NotImplementedError

    ########
    # Replay
    ########

    @handler("CancelReplay")
    def cancel_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> CancelReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        replay = self.get_replay(replay_name, store)
        replay_service = self._replay_service_store[replay.arn]
        replay_service.stop()
        response = CancelReplayResponse(
            ReplayArn=replay_service.arn,
            State=replay_service.state,
            # StateReason=replay_service.state_reason,
        )
        return response

    @handler("DescribeReplay")
    def describe_replay(
        self, context: RequestContext, replay_name: ReplayName, **kwargs
    ) -> DescribeReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        replay = self.get_replay(replay_name, store)

        response = self._replay_to_describe_replay_response(replay)
        return response

    @handler("ListReplays")
    def list_replays(
        self,
        context: RequestContext,
        name_prefix: ReplayName = None,
        state: ReplayState = None,
        event_source_arn: Arn = None,
        next_token: NextToken = None,
        limit: LimitMax100 = None,
        **kwargs,
    ) -> ListReplaysResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if event_source_arn:
            replays = {
                key: replay
                for key, replay in store.replays.items()
                if replay.event_source_arn == event_source_arn
            }
        elif name_prefix:
            replays = get_filtered_dict(name_prefix, store.replays)
        else:
            replays = store.replays
        limited_replays, next_token = self._get_limited_dict_and_next_token(
            replays, next_token, limit
        )

        response = ListReplaysResponse(
            Replays=list(self._replay_dict_to_replay_response_list(limited_replays))
        )
        if next_token is not None:
            response["NextToken"] = next_token
        return response

    @handler("StartReplay")
    def start_replay(
        self,
        context: RequestContext,
        replay_name: ReplayName,
        event_source_arn: Arn,  # Archive Arn
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        destination: ReplayDestination,
        description: ReplayDescription = None,
        **kwargs,
    ) -> StartReplayResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        if replay_name in store.replays:
            raise ResourceAlreadyExistsException(f"Replay {replay_name} already exists.")
        self._validate_replay_time(event_start_time, event_end_time)
        if event_source_arn not in self._archive_service_store:
            archive_name = event_source_arn.split("/")[-1]
            raise ValidationException(
                f"Parameter EventSourceArn is not valid. Reason: Archive {archive_name} does not exist."
            )
        self._validate_replay_destination(destination, event_source_arn)
        replay_service = self.create_replay_service(
            replay_name,
            region,
            account_id,
            event_source_arn,
            destination,
            event_start_time,
            event_end_time,
            description,
        )
        store.replays[replay_service.replay.name] = replay_service.replay
        archive_service = self._archive_service_store[event_source_arn]
        events_to_replay = archive_service.get_events(
            replay_service.event_start_time, replay_service.event_end_time
        )
        replay_service.start(events_to_replay)
        if events_to_replay:
            re_formatted_event_to_replay = replay_service.re_format_events_from_archive(
                events_to_replay, replay_name
            )
            self._process_entries(context, re_formatted_event_to_replay)
        replay_service.finish()

        response = StartReplayResponse(
            ReplayArn=replay_service.arn,
            State=replay_service.state,
            StateReason=replay_service.state_reason,
            ReplayStartTime=replay_service.replay_start_time,
        )
        return response

    ######
    # Tags
    ######

    @handler("ListTagsForResource")
    def list_tags_for_resource(
        self, context: RequestContext, resource_arn: Arn, **kwargs
    ) -> ListTagsForResourceResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        tags = store.TAGS.list_tags_for_resource(resource_arn)
        return ListTagsForResourceResponse(tags)

    @handler("TagResource")
    def tag_resource(
        self, context: RequestContext, resource_arn: Arn, tags: TagList, **kwargs
    ) -> TagResourceResponse:
        # each tag key must be unique
        # https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html#tag-best-practices
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        check_unique_tags(tags)
        store.TAGS.tag_resource(resource_arn, tags)

    @handler("UntagResource")
    def untag_resource(
        self, context: RequestContext, resource_arn: Arn, tag_keys: TagKeyList, **kwargs
    ) -> UntagResourceResponse:
        region = context.region
        account_id = context.account_id
        store = self.get_store(region, account_id)
        resource_type = get_resource_type(resource_arn)
        self._check_resource_exists(resource_arn, resource_type, store)
        store.TAGS.untag_resource(resource_arn, tag_keys)

    #########
    # Methods
    #########

    def get_store(self, region: str, account_id: str) -> EventsStore:
        """Returns the events store for the account and region.
        On first call, creates the default event bus for the account region."""
        store = events_stores[account_id][region]
        # create default event bus for account region on first call
        default_event_bus_name = "default"
        if default_event_bus_name not in store.event_buses:
            event_bus_service = self.create_event_bus_service(
                default_event_bus_name, region, account_id, None, None, None
            )
            store.event_buses[event_bus_service.event_bus.name] = event_bus_service.event_bus
        return store

    def get_event_bus(self, name: EventBusName, store: EventsStore) -> EventBus:
        if event_bus := store.event_buses.get(name):
            return event_bus
        raise ResourceNotFoundException(f"Event bus {name} does not exist.")

    def get_rule(self, name: RuleName, event_bus: EventBus) -> Rule:
        if rule := event_bus.rules.get(name):
            return rule
        raise ResourceNotFoundException(f"Rule {name} does not exist on EventBus {event_bus.name}.")

    def get_target(self, target_id: TargetId, rule: Rule) -> Target:
        if target := rule.targets.get(target_id):
            return target
        raise ResourceNotFoundException(f"Target {target_id} does not exist on Rule {rule.name}.")

    def get_archive(self, name: ArchiveName, store: EventsStore) -> Archive:
        if archive := store.archives.get(name):
            return archive
        raise ResourceNotFoundException(f"Archive {name} does not exist.")

    def get_replay(self, name: ReplayName, store: EventsStore) -> Replay:
        if replay := store.replays.get(name):
            return replay
        raise ResourceNotFoundException(f"Replay {name} does not exist.")

    def get_connection(self, name: ConnectionName, store: EventsStore) -> Connection:
        if connection := store.connections.get(name):
            return connection
        raise ResourceNotFoundException(
            f"Failed to describe the connection(s). Connection '{name}' does not exist."
        )

    def get_api_destination(self, name: ApiDestinationName, store: EventsStore) -> ApiDestination:
        if api_destination := store.api_destinations.get(name):
            return api_destination
        raise ResourceNotFoundException(
            f"Failed to describe the api-destination(s). An api-destination '{name}' does not exist."
        )

    def get_rule_service(
        self,
        region: str,
        account_id: str,
        rule_name: RuleName,
        event_bus_name: EventBusName,
    ) -> RuleService:
        store = self.get_store(region, account_id)
        event_bus_name = extract_event_bus_name(event_bus_name)
        event_bus = self.get_event_bus(event_bus_name, store)
        rule = self.get_rule(rule_name, event_bus)
        return self._rule_services_store[rule.arn]

    def create_event_bus_service(
        self,
        name: EventBusName,
        region: str,
        account_id: str,
        event_source_name: Optional[EventSourceName],
        description: Optional[EventBusDescription],
        tags: Optional[TagList],
    ) -> EventBusService:
        event_bus_service = EventBusService.create_event_bus_service(
            name,
            region,
            account_id,
            event_source_name,
            description,
            tags,
        )
        self._event_bus_services_store[event_bus_service.arn] = event_bus_service
        return event_bus_service

    def create_rule_service(
        self,
        name: RuleName,
        region: str,
        account_id: str,
        schedule_expression: Optional[ScheduleExpression],
        event_pattern: Optional[EventPattern],
        state: Optional[RuleState],
        description: Optional[RuleDescription],
        role_arn: Optional[RoleArn],
        tags: Optional[TagList],
        event_bus_name: Optional[EventBusName],
        targets: Optional[TargetDict],
    ) -> RuleService:
        rule_service = RuleService.create_rule_service(
            name,
            region,
            account_id,
            schedule_expression,
            event_pattern,
            state,
            description,
            role_arn,
            tags,
            event_bus_name,
            targets,
        )
        self._rule_services_store[rule_service.arn] = rule_service
        return rule_service

    def create_target_sender(
        self, target: Target, rule_arn: Arn, rule_name: RuleName, region: str, account_id: str
    ) -> TargetSender:
        target_sender = TargetSenderFactory(
            target, rule_arn, rule_name, region, account_id
        ).get_target_sender()
        self._target_sender_store[target_sender.unique_id] = target_sender
        return target_sender

    def create_archive_service(
        self,
        archive_name: ArchiveName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        description: ArchiveDescription,
        event_pattern: EventPattern,
        retention_days: RetentionDays,
    ) -> ArchiveService:
        archive_service = ArchiveService.create_archive_service(
            archive_name,
            region,
            account_id,
            event_source_arn,
            description,
            event_pattern,
            retention_days,
        )
        archive_service.register_archive_rule_and_targets()
        self._archive_service_store[archive_service.arn] = archive_service
        return archive_service

    def create_replay_service(
        self,
        name: ReplayName,
        region: str,
        account_id: str,
        event_source_arn: Arn,
        destination: ReplayDestination,
        event_start_time: Timestamp,
        event_end_time: Timestamp,
        description: ReplayDescription,
    ) -> ReplayService:
        replay_service = ReplayService(
            name,
            region,
            account_id,
            event_source_arn,
            destination,
            event_start_time,
            event_end_time,
            description,
        )
        self._replay_service_store[replay_service.arn] = replay_service
        return replay_service

    def create_connection_service(
        self,
        name: ConnectionName,
        region: str,
        account_id: str,
        authorization_type: ConnectionAuthorizationType,
        auth_parameters: CreateConnectionAuthRequestParameters,
        description: ConnectionDescription,
        invocation_connectivity_parameters: ConnectivityResourceParameters,
    ) -> ConnectionService:
        connection_service = ConnectionService(
            name,
            region,
            account_id,
            authorization_type,
            auth_parameters,
            description,
            invocation_connectivity_parameters,
        )
        self._connection_service_store[connection_service.arn] = connection_service
        return connection_service

    def create_api_destinations_service(
        self,
        name: ConnectionName,
        region: str,
        account_id: str,
        connection_arn: ConnectionArn,
        connection: Connection,
        invocation_endpoint: HttpsEndpoint,
        http_method: ApiDestinationHttpMethod,
        invocation_rate_limit_per_second: ApiDestinationInvocationRateLimitPerSecond,
        description: ApiDestinationDescription,
    ) -> APIDestinationService:
        api_destination_service = APIDestinationService(
            name,
            region,
            account_id,
            connection_arn,
            connection,
            invocation_endpoint,
            http_method,
            invocation_rate_limit_per_second,
            description,
        )
        self._api_destination_service_store[api_destination_service.arn] = api_destination_service
        return api_destination_service

    def _delete_connection(self, connection_arn: Arn) -> None:
        del self._connection_service_store[connection_arn]

    def _delete_rule_services(self, rules: RuleDict | Rule) -> None:
        """
        Delete all rule services associated to the input from the store.
        Accepts a single Rule object or a dict of Rule objects as input.
        """
        if isinstance(rules, Rule):
            rules = {rules.name: rules}
        for rule in rules.values():
            del self._rule_services_store[rule.arn]

    def _delete_target_sender(self, ids: TargetIdList, rule) -> None:
        for target_id in ids:
            if target := rule.targets.get(target_id):
                target_unique_id = f"{rule.arn}-{target_id}"
                try:
                    del self._target_sender_store[target_unique_id]
                except KeyError:
                    LOG.error("Error deleting target service %s.", target["Arn"])

    def _get_limited_dict_and_next_token(
        self, input_dict: dict, next_token: NextToken | None, limit: LimitMax100 | None
    ) -> tuple[dict, NextToken]:
        """Return a slice of the given dictionary starting from next_token with length of limit
        and new last index encoded as a next_token for pagination."""
        input_dict_len = len(input_dict)
        start_index = decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else input_dict_len
        limited_dict = dict(list(input_dict.items())[start_index:end_index])

        next_token = (
            encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all items are returned
            if end_index < input_dict_len
            else None
        )
        return limited_dict, next_token

    def _get_limited_list_and_next_token(
        self, input_list: list, next_token: NextToken | None, limit: LimitMax100 | None
    ) -> tuple[list, NextToken]:
        """Return a slice of the given list starting from next_token with length of limit
        and new last index encoded as a next_token for pagination."""
        input_list_len = len(input_list)
        start_index = decode_next_token(next_token) if next_token is not None else 0
        end_index = start_index + limit if limit is not None else input_list_len
        limited_list = input_list[start_index:end_index]

        next_token = (
            encode_next_token(end_index)
            # return a next_token (encoded integer of next starting index) if not all items are returned
            if end_index < input_list_len
            else None
        )
        return limited_list, next_token

    def _check_resource_exists(
        self, resource_arn: Arn, resource_type: ResourceType, store: EventsStore
    ) -> None:
        if resource_type == ResourceType.EVENT_BUS:
            event_bus_name = extract_event_bus_name(resource_arn)
            self.get_event_bus(event_bus_name, store)
        if resource_type == ResourceType.RULE:
            event_bus_name = extract_event_bus_name(resource_arn)
            event_bus = self.get_event_bus(event_bus_name, store)
            rule_name = resource_arn.split("/")[-1]
            self.get_rule(rule_name, event_bus)

    def _get_scheduled_rule_job_function(self, account_id, region, rule: Rule) -> Callable:
        def func(*args, **kwargs):
            """Create custom scheduled event and send it to all targets specified by associated rule using respective TargetSender"""
            for target in rule.targets.values():
                if custom_input := target.get("Input"):
                    event = json.loads(custom_input)
                else:
                    event = {
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
                target_unique_id = f"{rule.arn}-{target['Id']}"
                target_sender = self._target_sender_store[target_unique_id]
                new_trace_header = (
                    TraceHeader().ensure_root_exists()
                )  # scheduled events will always start a new trace
                try:
                    target_sender.process_event(event.copy(), trace_header=new_trace_header)
                except Exception as e:
                    LOG.info(
                        "Unable to send event notification %s to target %s: %s",
                        truncate(event),
                        target,
                        e,
                    )

        return func

    def _check_event_bus_exists(
        self, event_bus_name_or_arn: EventBusNameOrArn, store: EventsStore
    ) -> None:
        event_bus_name = extract_event_bus_name(event_bus_name_or_arn)
        self.get_event_bus(event_bus_name, store)

    def _validate_replay_time(self, event_start_time: Timestamp, event_end_time: Timestamp) -> None:
        if event_end_time <= event_start_time:
            raise ValidationException(
                "Parameter EventEndTime is not valid. Reason: EventStartTime must be before EventEndTime."
            )

    def _validate_replay_destination(
        self, destination: ReplayDestination, event_source_arn: Arn
    ) -> None:
        archive_service = self._archive_service_store[event_source_arn]
        if destination_arn := destination.get("Arn"):
            if destination_arn != archive_service.archive.event_source_arn:
                if destination_arn in self._event_bus_services_store:
                    raise ValidationException(
                        "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted."
                    )
                else:
                    event_bus_name = extract_event_bus_name(destination_arn)
                    raise ResourceNotFoundException(f"Event bus {event_bus_name} does not exist.")

    # Internal type to API type remappings

    def _event_bust_dict_to_event_bus_response_list(
        self, event_buses: EventBusDict
    ) -> EventBusList:
        """Return a converted dict of EventBus model objects as a list of event buses in API type EventBus format."""
        event_bus_list = [
            self._event_bus_to_api_type_event_bus(event_bus) for event_bus in event_buses.values()
        ]
        return event_bus_list

    def _event_bus_to_api_type_event_bus(self, event_bus: EventBus) -> ApiTypeEventBus:
        event_bus_api_type = {
            "Name": event_bus.name,
            "Arn": event_bus.arn,
        }
        if getattr(event_bus, "description", None):
            event_bus_api_type["Description"] = event_bus.description
        if event_bus.creation_time:
            event_bus_api_type["CreationTime"] = event_bus.creation_time
        if event_bus.last_modified_time:
            event_bus_api_type["LastModifiedTime"] = event_bus.last_modified_time
        if event_bus.policy:
            event_bus_api_type["Policy"] = json.dumps(
                recursive_remove_none_values_from_dict(event_bus.policy)
            )

        return event_bus_api_type

    def _event_to_error_type_event(self, entry: PutEventsRequestEntry) -> str:
        detail = (
            json.dumps(json.loads(entry["Detail"]), separators=(", ", ": "))
            if entry.get("Detail")
            else "null"
        )
        return (
            f"PutEventsRequestEntry("
            f"time={entry.get('Time', 'null')}, "
            f"source={entry.get('Source', 'null')}, "
            f"resources={entry.get('Resources', 'null')}, "
            f"detailType={entry.get('DetailType', 'null')}, "
            f"detail={detail}, "
            f"eventBusName={entry.get('EventBusName', 'null')}, "
            f"traceHeader={entry.get('TraceHeader', 'null')}, "
            f"kmsKeyIdentifier={entry.get('kmsKeyIdentifier', 'null')}, "
            f"internalMetadata={entry.get('internalMetadata', 'null')}"
            f")"
        )

    def _rule_dict_to_rule_response_list(self, rules: RuleDict) -> RuleResponseList:
        """Return a converted dict of Rule model objects as a list of rules in API type Rule format."""
        rule_list = [self._rule_to_api_type_rule(rule) for rule in rules.values()]
        return rule_list

    def _rule_to_api_type_rule(self, rule: Rule) -> ApiTypeRule:
        rule = {
            "Name": rule.name,
            "Arn": rule.arn,
            "EventPattern": rule.event_pattern,
            "State": rule.state,
            "Description": rule.description,
            "ScheduleExpression": rule.schedule_expression,
            "RoleArn": rule.role_arn,
            "ManagedBy": rule.managed_by,
            "EventBusName": rule.event_bus_name,
            "CreatedBy": rule.created_by,
        }
        return {key: value for key, value in rule.items() if value is not None}

    def _archive_dict_to_archive_response_list(self, archives: ArchiveDict) -> ArchiveResponseList:
        """Return a converted dict of Archive model objects as a list of archives in API type Archive format."""
        archive_list = [self._archive_to_api_type_archive(archive) for archive in archives.values()]
        return archive_list

    def _archive_to_api_type_archive(self, archive: Archive) -> ApiTypeArchive:
        archive = {
            "ArchiveName": archive.name,
            "EventSourceArn": archive.event_source_arn,
            "State": archive.state,
            # TODO add "StateReason": archive.state_reason,
            "RetentionDays": archive.retention_days,
            "SizeBytes": archive.size_bytes,
            "EventCount": archive.event_count,
            "CreationTime": archive.creation_time,
        }
        return {key: value for key, value in archive.items() if value is not None}

    def _archive_to_describe_archive_response(self, archive: Archive) -> DescribeArchiveResponse:
        archive_dict = {
            "ArchiveArn": archive.arn,
            "ArchiveName": archive.name,
            "EventSourceArn": archive.event_source_arn,
            "State": archive.state,
            # TODO add "StateReason": archive.state_reason,
            "RetentionDays": archive.retention_days,
            "SizeBytes": archive.size_bytes,
            "EventCount": archive.event_count,
            "CreationTime": archive.creation_time,
            "EventPattern": archive.event_pattern,
            "Description": archive.description,
        }
        return {key: value for key, value in archive_dict.items() if value is not None}

    def _replay_dict_to_replay_response_list(self, replays: ReplayDict) -> ReplayList:
        """Return a converted dict of Replay model objects as a list of replays in API type Replay format."""
        replay_list = [self._replay_to_api_type_replay(replay) for replay in replays.values()]
        return replay_list

    def _replay_to_api_type_replay(self, replay: Replay) -> ApiTypeReplay:
        replay = {
            "ReplayName": replay.name,
            "EventSourceArn": replay.event_source_arn,
            "State": replay.state,
            # # "StateReason": replay.state_reason,
            "EventStartTime": replay.event_start_time,
            "EventEndTime": replay.event_end_time,
            "EventLastReplayedTime": replay.event_last_replayed_time,
            "ReplayStartTime": replay.replay_start_time,
            "ReplayEndTime": replay.replay_end_time,
        }
        return {key: value for key, value in replay.items() if value is not None}

    def _replay_to_describe_replay_response(self, replay: Replay) -> DescribeReplayResponse:
        replay_dict = {
            "ReplayName": replay.name,
            "ReplayArn": replay.arn,
            "Description": replay.description,
            "State": replay.state,
            # # "StateReason": replay.state_reason,
            "EventSourceArn": replay.event_source_arn,
            "Destination": replay.destination,
            "EventStartTime": replay.event_start_time,
            "EventEndTime": replay.event_end_time,
            "EventLastReplayedTime": replay.event_last_replayed_time,
            "ReplayStartTime": replay.replay_start_time,
            "ReplayEndTime": replay.replay_end_time,
        }
        return {key: value for key, value in replay_dict.items() if value is not None}

    def _connection_to_api_type_connection(self, connection: Connection) -> ApiTypeConnection:
        connection = {
            "ConnectionArn": connection.arn,
            "Name": connection.name,
            "ConnectionState": connection.state,
            # "StateReason": connection.state_reason, # TODO implement state reason
            "AuthorizationType": connection.authorization_type,
            "AuthParameters": connection.auth_parameters,
            "SecretArn": connection.secret_arn,
            "CreationTime": connection.creation_time,
            "LastModifiedTime": connection.last_modified_time,
            "LastAuthorizedTime": connection.last_authorized_time,
        }
        return {key: value for key, value in connection.items() if value is not None}

    def _connection_dict_to_connection_response_list(
        self, connections: ConnectionDict
    ) -> ConnectionResponseList:
        """Return a converted dict of Connection model objects as a list of connections in API type Connection format."""
        connection_list = [
            self._connection_to_api_type_connection(connection)
            for connection in connections.values()
        ]
        return connection_list

    def _api_destination_to_api_type_api_destination(
        self, api_destination: ApiDestination
    ) -> ApiTypeApiDestination:
        api_destination = {
            "ApiDestinationArn": api_destination.arn,
            "Name": api_destination.name,
            "ConnectionArn": api_destination.connection_arn,
            "ApiDestinationState": api_destination.state,
            "InvocationEndpoint": api_destination.invocation_endpoint,
            "HttpMethod": api_destination.http_method,
            "InvocationRateLimitPerSecond": api_destination.invocation_rate_limit_per_second,
            "CreationTime": api_destination.creation_time,
            "LastModifiedTime": api_destination.last_modified_time,
            "Description": api_destination.description,
        }
        return {key: value for key, value in api_destination.items() if value is not None}

    def _api_destination_dict_to_api_destination_response_list(
        self, api_destinations: ApiDestinationDict
    ) -> ApiDestinationResponseList:
        """Return a converted dict of ApiDestination model objects as a list of connections in API type ApiDestination format."""
        api_destination_list = [
            self._api_destination_to_api_type_api_destination(api_destination)
            for api_destination in api_destinations.values()
        ]
        return api_destination_list

    def _put_to_archive(
        self,
        region: str,
        account_id: str,
        archive_target_id: str,
        event: FormattedEvent,
    ) -> None:
        archive_name = ARCHIVE_TARGET_ID_NAME_PATTERN.match(archive_target_id).group("name")

        store = self.get_store(region, account_id)
        archive = self.get_archive(archive_name, store)
        archive_service = self._archive_service_store[archive.arn]
        archive_service.put_events([event])

    def _process_entries(
        self, context: RequestContext, entries: PutEventsRequestEntryList
    ) -> tuple[PutEventsResultEntryList, int]:
        """Main method to process events put to an event bus.
        Events are validated to contain the proper fields and formatted.
        Events are matched against all the rules of the respective event bus.
        For matching rules the event is either sent to the respective target,
        via the target sender put to the defined archived."""
        processed_entries = []
        failed_entry_count = {"count": 0}
        for event in entries:
            self._process_entry(event, processed_entries, failed_entry_count, context)
        return processed_entries, failed_entry_count["count"]

    def _process_entry(
        self,
        entry: PutEventsRequestEntry,
        processed_entries: PutEventsResultEntryList,
        failed_entry_count: dict[str, int],
        context: RequestContext,
    ) -> None:
        event_bus_name_or_arn = entry.get("EventBusName", "default")
        event_bus_name = extract_event_bus_name(event_bus_name_or_arn)
        if event_failed_validation := validate_event(entry):
            processed_entries.append(event_failed_validation)
            failed_entry_count["count"] += 1
            LOG.info(json.dumps(event_failed_validation))
            return

        region, account_id = extract_region_and_account_id(event_bus_name_or_arn, context)

        # TODO check interference with x-ray trace header
        if encoded_trace_header := get_trace_header_encoded_region_account(
            entry, context.region, context.account_id, region, account_id
        ):
            entry["TraceHeader"] = encoded_trace_header

        event_formatted = format_event(entry, region, account_id, event_bus_name)
        store = self.get_store(region, account_id)

        try:
            event_bus = self.get_event_bus(event_bus_name, store)
        except ResourceNotFoundException:
            # ignore events for non-existing event buses but add processed event
            processed_entries.append({"EventId": event_formatted["id"]})
            LOG.info(
                json.dumps(
                    {
                        "ErrorCode": "ResourceNotFoundException at get_event_bus",
                        "ErrorMessage": f"Event_bus {event_bus_name} does not exist",
                    }
                )
            )
            return

        trace_header = context.trace_context["aws_trace_header"]

        self._proxy_capture_input_event(event_formatted, trace_header, region, account_id)

        # Always add the successful EventId entry, even if target processing might fail
        processed_entries.append({"EventId": event_formatted["id"]})

        if configured_rules := list(event_bus.rules.values()):
            for rule in configured_rules:
                self._process_rules(rule, region, account_id, event_formatted, trace_header)
        else:
            LOG.info(
                json.dumps(
                    {
                        "InfoCode": "InternalInfoEvents at process_rules",
                        "InfoMessage": f"No rules attached to event_bus: {event_bus_name}",
                    }
                )
            )

    def _proxy_capture_input_event(
        self, event: FormattedEvent, trace_header: TraceHeader, region: str, account_id: str
    ) -> None:
        # only required for EventStudio to capture input event if no rule is configured
        pass

    def _process_rules(
        self,
        rule: Rule,
        region: str,
        account_id: str,
        event_formatted: FormattedEvent,
        trace_header: TraceHeader,
    ) -> None:
        """Process rules for an event. Note that we no longer handle entries here as AWS returns success regardless of target failures."""
        event_pattern = rule.event_pattern

        if matches_event(event_pattern, event_formatted):
            if not rule.targets:
                LOG.info(
                    json.dumps(
                        {
                            "InfoCode": "InternalInfoEvents at iterate over targets",
                            "InfoMessage": f"No target configured for matched rule: {rule}",
                        }
                    )
                )
                return

            for target in rule.targets.values():
                target_id = target["Id"]
                if is_archive_arn(target["Arn"]):
                    self._put_to_archive(
                        region,
                        account_id,
                        archive_target_id=target_id,
                        event=event_formatted,
                    )
                else:
                    target_unique_id = f"{rule.arn}-{target_id}"
                    target_sender = self._target_sender_store[target_unique_id]
                    try:
                        target_sender.process_event(event_formatted.copy(), trace_header)
                        rule_invocation.labels(
                            status=InvocationStatus.success,
                            service=target_sender.service,
                        ).increment()

                    except Exception as error:
                        rule_invocation.labels(
                            status=InvocationStatus.error,
                            service=target_sender.service,
                        ).increment()
                        # Log the error but don't modify the response
                        LOG.info(
                            json.dumps(
                                {
                                    "ErrorCode": "TargetDeliveryFailure",
                                    "ErrorMessage": f"Failed to deliver to target {target_id}: {str(error)}",
                                }
                            )
                        )
        else:
            LOG.info(
                json.dumps(
                    {
                        "InfoCode": "InternalInfoEvents at matches_rule",
                        "InfoMessage": f"No rules matched for formatted event: {event_formatted}",
                    }
                )
            )
