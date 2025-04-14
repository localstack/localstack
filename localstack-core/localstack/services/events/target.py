import datetime
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, Set, Type
from urllib.parse import urlencode

import requests
from botocore.client import BaseClient

from localstack import config
from localstack.aws.api.events import (
    Arn,
    InputTransformer,
    RuleName,
    Target,
    TargetInputPath,
)
from localstack.aws.connect import connect_to
from localstack.services.events.api_destination import add_api_destination_authorization
from localstack.services.events.models import (
    FormattedEvent,
    TransformedEvent,
    ValidationException,
)
from localstack.services.events.utils import (
    event_time_to_time_string,
    get_trace_header_encoded_region_account,
    is_nested_in_string,
    to_json_str,
)
from localstack.utils import collections
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    extract_service_from_arn,
    firehose_name,
    parse_arn,
    sqs_queue_url_for_arn,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.aws.message_forwarding import (
    add_target_http_parameters,
)
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import to_bytes
from localstack.utils.time import now_utc
from localstack.utils.xray.trace_header import TraceHeader

LOG = logging.getLogger(__name__)

# https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-transform-target-input.html#eb-transform-input-predefined
AWS_PREDEFINED_PLACEHOLDERS_STRING_VALUES = {
    "aws.events.rule-arn",
    "aws.events.rule-name",
    "aws.events.event.ingestion-time",
}
AWS_PREDEFINED_PLACEHOLDERS_JSON_VALUES = {"aws.events.event", "aws.events.event.json"}

PREDEFINED_PLACEHOLDERS: Set[str] = AWS_PREDEFINED_PLACEHOLDERS_STRING_VALUES.union(
    AWS_PREDEFINED_PLACEHOLDERS_JSON_VALUES
)

TRANSFORMER_PLACEHOLDER_PATTERN = re.compile(r"<(.*?)>")
TRACE_HEADER_KEY = "X-Amzn-Trace-Id"


def transform_event_with_target_input_path(
    input_path: TargetInputPath, event: FormattedEvent
) -> TransformedEvent:
    formatted_event = extract_jsonpath(event, input_path)
    return formatted_event


def get_template_replacements(
    input_transformer: InputTransformer, event: FormattedEvent
) -> dict[str, Any]:
    """Extracts values from the event using the input paths map keys and places them in the input template dict."""
    template_replacements = {}
    transformer_path_map = input_transformer.get("InputPathsMap", {})
    for placeholder, transformer_path in transformer_path_map.items():
        if placeholder in PREDEFINED_PLACEHOLDERS:
            continue
        value = extract_jsonpath(event, transformer_path)
        if not value:
            value = ""  # default value is empty string
        template_replacements[placeholder] = value
    return template_replacements


def replace_template_placeholders(
    template: str, replacements: dict[str, Any], is_json_template: bool
) -> TransformedEvent:
    """Replace placeholders defined by <key> in the template with the values from the replacements dict.
    Can handle single template string or template dict."""

    def replace_placeholder(match):
        key = match.group(1)
        value = replacements.get(key, "")  # handle non defined placeholders
        if isinstance(value, datetime.datetime):
            return event_time_to_time_string(value)
        if isinstance(value, dict):
            json_str = to_json_str(value).replace('\\"', '"')
            if is_json_template:
                return json_str
            return json_str.replace('"', "")
        if isinstance(value, list):
            if is_json_template:
                return json.dumps(value)
            return f"[{','.join(value)}]"
        if is_nested_in_string(template, match):
            return value
        if is_json_template:
            return json.dumps(value)
        return value

    formatted_template = TRANSFORMER_PLACEHOLDER_PATTERN.sub(replace_placeholder, template).replace(
        "\\n", "\n"
    )

    if is_json_template:
        try:
            loaded_json_template = json.loads(formatted_template)
            return loaded_json_template
        except json.JSONDecodeError:
            LOG.info(
                json.dumps(
                    {
                        "InfoCode": "InternalInfoEvents at transform_event",
                        "InfoMessage": f"Replaced template is not valid json: {formatted_template}",
                    }
                )
            )
    else:
        return formatted_template[1:-1]


class TargetSender(ABC):
    target: Target
    rule_arn: Arn
    rule_name: RuleName
    service: str

    region: str  # region of the event bus
    account_id: str  # region of the event bus
    target_region: str
    target_account_id: str
    _client: BaseClient | None

    def __init__(
        self,
        target: Target,
        rule_arn: Arn,
        rule_name: RuleName,
        service: str,
        region: str,
        account_id: str,
    ):
        self.target = target
        self.rule_arn = rule_arn
        self.rule_name = rule_name
        self.service = service
        self.region = region
        self.account_id = account_id

        self.target_region = extract_region_from_arn(self.target["Arn"])
        self.target_account_id = extract_account_id_from_arn(self.target["Arn"])

        self._validate_input(target)
        self._client: BaseClient | None = None

    @property
    def arn(self):
        return self.target["Arn"]

    @property
    def target_id(self):
        return self.target["Id"]

    @property
    def unique_id(self):
        """Necessary to distinguish between targets with the same ARN but for different rules.
        The unique_id is a combination of the rule ARN and the Target Id.
        This is necessary since input path and input transformer can be different for the same target ARN,
        attached to different rules."""
        return f"{self.rule_arn}-{self.target_id}"

    @property
    def client(self):
        """Lazy initialization of internal botoclient factory."""
        if self._client is None:
            self._client = self._initialize_client()
        return self._client

    @abstractmethod
    def send_event(self, event: FormattedEvent | TransformedEvent, trace_header: TraceHeader):
        pass

    def process_event(self, event: FormattedEvent, trace_header: TraceHeader):
        """Processes the event and send it to the target."""
        if input_ := self.target.get("Input"):
            event = json.loads(input_)
        if isinstance(event, dict):
            event.pop("event-bus-name", None)
        if not input_:
            if input_path := self.target.get("InputPath"):
                event = transform_event_with_target_input_path(input_path, event)
            if input_transformer := self.target.get("InputTransformer"):
                event = self.transform_event_with_target_input_transformer(input_transformer, event)
        if event:
            self.send_event(event, trace_header)
        else:
            LOG.info("No event to send to target %s", self.target.get("Id"))

    def transform_event_with_target_input_transformer(
        self, input_transformer: InputTransformer, event: FormattedEvent
    ) -> TransformedEvent:
        input_template = input_transformer["InputTemplate"]
        template_replacements = get_template_replacements(input_transformer, event)
        predefined_template_replacements = self._get_predefined_template_replacements(event)
        template_replacements.update(predefined_template_replacements)

        is_json_template = input_template.strip().startswith(("{"))
        populated_template = replace_template_placeholders(
            input_template, template_replacements, is_json_template
        )

        return populated_template

    def _validate_input(self, target: Target):
        """Provide a default implementation extended for each target based on specifications."""
        # TODO add For Lambda and Amazon SNS resources, EventBridge relies on resource-based policies.
        if "InputPath" in target and "InputTransformer" in target:
            raise ValidationException(
                f"Only one of Input, InputPath, or InputTransformer must be provided for target {target.get('Id')}."
            )
        if input_transformer := target.get("InputTransformer"):
            self._validate_input_transformer(input_transformer)

    def _initialize_client(self) -> BaseClient:
        """Initializes internal boto client.
        If a role from a target is provided, the client will be initialized with the assumed role.
        If no role is provided, the client will be initialized with the account ID and region.
        In both cases event bridge is requested as service principal"""
        service_principal = ServicePrincipal.events
        role_arn = self.target.get("RoleArn")
        if role_arn:  # required for cross account
            # assumed role sessions expire after 6 hours in AWS, currently no expiration in LocalStack
            client_factory = connect_to.with_assumed_role(
                role_arn=role_arn,
                service_principal=service_principal,
                region_name=self.region,
            )
        else:
            client_factory = connect_to(aws_access_key_id=self.account_id, region_name=self.region)
        client = client_factory.get_client(self.service)
        client = client.request_metadata(
            service_principal=service_principal, source_arn=self.rule_arn
        )
        self._register_client_hooks(client)
        return client

    def _validate_input_transformer(self, input_transformer: InputTransformer):
        # TODO: cover via test
        # if "InputTemplate" not in input_transformer:
        #     raise ValueError("InputTemplate is required for InputTransformer")
        input_template = input_transformer["InputTemplate"]
        input_paths_map = input_transformer.get("InputPathsMap", {})
        placeholders = TRANSFORMER_PLACEHOLDER_PATTERN.findall(input_template)
        for placeholder in placeholders:
            if placeholder not in input_paths_map and placeholder not in PREDEFINED_PLACEHOLDERS:
                raise ValidationException(
                    f"InputTemplate for target {self.target.get('Id')} contains invalid placeholder {placeholder}."
                )

    def _get_predefined_template_replacements(self, event: FormattedEvent) -> dict[str, Any]:
        """Extracts predefined values from the event."""
        predefined_template_replacements = {}
        predefined_template_replacements["aws.events.rule-arn"] = self.rule_arn
        predefined_template_replacements["aws.events.rule-name"] = self.rule_name
        predefined_template_replacements["aws.events.event.ingestion-time"] = event["time"]
        predefined_template_replacements["aws.events.event"] = {
            "detailType" if k == "detail-type" else k: v  # detail-type is is returned as detailType
            for k, v in event.items()
            if k != "detail"  # detail is not part of .event placeholder
        }
        predefined_template_replacements["aws.events.event.json"] = event

        return predefined_template_replacements

    def _register_client_hooks(self, client: BaseClient):
        """Register client hooks to inject trace header into requests."""

        def handle_extract_params(params, context, **kwargs):
            trace_header = params.pop("TraceHeader", None)
            if trace_header is None:
                return
            context[TRACE_HEADER_KEY] = trace_header.to_header_str()

        def handle_inject_headers(params, context, **kwargs):
            if trace_header_str := context.pop(TRACE_HEADER_KEY, None):
                params["headers"][TRACE_HEADER_KEY] = trace_header_str

        client.meta.events.register(
            f"provide-client-params.{self.service}.*", handle_extract_params
        )
        client.meta.events.register(f"before-call.{self.service}.*", handle_inject_headers)


TargetSenderDict = dict[str, TargetSender]  # rule_arn-target_id as global unique id

# Target Senders are ordered alphabetically by service name


class ApiGatewayTargetSender(TargetSender):
    """
    ApiGatewayTargetSender is a TargetSender that sends events to an API Gateway target.
    """

    PROHIBITED_HEADERS = [
        "authorization",
        "connection",
        "content-encoding",
        "content-length",
        "host",
        "max-forwards",
        "te",
        "transfer-encoding",
        "trailer",
        "upgrade",
        "via",
        "www-authenticate",
        "x-forwarded-for",
    ]  # https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-gateway-target.html

    ALLOWED_HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

    def send_event(self, event, trace_header):
        # Parse the ARN to extract api_id, stage_name, http_method, and resource path
        # Example ARN: arn:{partition}:execute-api:{region}:{account_id}:{api_id}/{stage_name}/{method}/{resource_path}
        arn_parts = parse_arn(self.target["Arn"])
        api_gateway_info = arn_parts["resource"]  # e.g., 'myapi/dev/POST/pets/*/*'
        api_gateway_info_parts = api_gateway_info.split("/")

        api_id = api_gateway_info_parts[0]
        stage_name = api_gateway_info_parts[1]
        http_method = api_gateway_info_parts[2].upper()
        resource_path_parts = api_gateway_info_parts[3:]  # may contain wildcards

        if http_method not in self.ALLOWED_HTTP_METHODS:
            LOG.error("Unsupported HTTP method: %s", http_method)
            return

        # Replace wildcards in resource path with PathParameterValues
        path_params_values = self.target.get("HttpParameters", {}).get("PathParameterValues", [])
        resource_path_segments = []
        path_param_index = 0
        for part in resource_path_parts:
            if part == "*":
                if path_param_index < len(path_params_values):
                    resource_path_segments.append(path_params_values[path_param_index])
                    path_param_index += 1
                else:
                    # Use empty string if no path parameter is provided
                    resource_path_segments.append("")
            else:
                resource_path_segments.append(part)
        resource_path = "/".join(resource_path_segments)

        # Ensure resource path starts and ends with '/'
        resource_path = f"/{resource_path.strip('/')}/"

        # Construct query string parameters
        query_params = self.target.get("HttpParameters", {}).get("QueryStringParameters", {})
        query_string = urlencode(query_params) if query_params else ""

        # Construct headers
        headers = self.target.get("HttpParameters", {}).get("HeaderParameters", {})
        headers = {k: v for k, v in headers.items() if k.lower() not in self.PROHIBITED_HEADERS}
        # Add Host header to ensure proper routing in LocalStack

        host = f"{api_id}.execute-api.localhost.localstack.cloud"
        headers["Host"] = host

        # Ensure Content-Type is set
        headers.setdefault("Content-Type", "application/json")

        # Construct the full URL
        resource_path = f"/{resource_path.strip('/')}/"

        # Construct the full URL using urljoin
        from urllib.parse import urljoin

        base_url = config.internal_service_url()
        base_path = f"/{stage_name}"
        full_path = urljoin(base_path + "/", resource_path.lstrip("/"))
        url = urljoin(base_url + "/", full_path.lstrip("/"))

        if query_string:
            url += f"?{query_string}"

        # Serialize the event, converting datetime objects to strings
        event_json = json.dumps(event, default=str)

        # Add trace header
        headers[TRACE_HEADER_KEY] = trace_header.to_header_str()

        # Send the HTTP request
        response = requests.request(
            method=http_method, url=url, headers=headers, data=event_json, timeout=5
        )
        if not response.ok:
            LOG.warning(
                "API Gateway target invocation failed with status code %s, response: %s",
                response.status_code,
                response.text,
            )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via test
        # if not collections.get_safe(target, "$.RoleArn"):
        #     raise ValueError("RoleArn is required for ApiGateway target")

    def _get_predefined_template_replacements(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Extracts predefined values from the event."""
        predefined_template_replacements = {}
        predefined_template_replacements["aws.events.rule-arn"] = self.rule_arn
        predefined_template_replacements["aws.events.rule-name"] = self.rule_name
        predefined_template_replacements["aws.events.event.ingestion-time"] = event.get("time", "")
        predefined_template_replacements["aws.events.event"] = {
            "detailType" if k == "detail-type" else k: v for k, v in event.items() if k != "detail"
        }
        predefined_template_replacements["aws.events.event.json"] = event

        return predefined_template_replacements


class AppSyncTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        raise NotImplementedError("AppSync target is not yet implemented")


class BatchTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        raise NotImplementedError("Batch target is not yet implemented")

    def _validate_input(self, target: Target):
        # TODO: cover via test and fix (only required if we have BatchParameters)
        # if not collections.get_safe(target, "$.BatchParameters.JobDefinition"):
        #     raise ValueError("BatchParameters.JobDefinition is required for Batch target")
        # if not collections.get_safe(target, "$.BatchParameters.JobName"):
        #     raise ValueError("BatchParameters.JobName is required for Batch target")
        pass


class ECSTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        raise NotImplementedError("ECS target is a pro feature, please use LocalStack Pro")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via test
        # if not collections.get_safe(target, "$.EcsParameters.TaskDefinitionArn"):
        #     raise ValueError("EcsParameters.TaskDefinitionArn is required for ECS target")


class EventsTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        # TODO add validation and tests for eventbridge to eventbridge requires Detail, DetailType, and Source
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/events/client/put_events.html
        source = self._get_source(event)
        detail_type = self._get_detail_type(event)
        detail = event.get("detail", event)
        resources = self._get_resources(event)
        entries = [
            {
                "EventBusName": self.target["Arn"],  # use arn for target account and region
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps(detail),
                "Resources": resources,
            }
        ]
        if encoded_original_id := get_trace_header_encoded_region_account(
            event, self.region, self.account_id, self.target_region, self.target_account_id
        ):
            entries[0]["TraceHeader"] = encoded_original_id

        self.client.put_events(Entries=entries, TraceHeader=trace_header)

    def _get_source(self, event: FormattedEvent | TransformedEvent) -> str:
        if isinstance(event, dict) and (source := event.get("source")):
            return source
        else:
            return self.service or ""

    def _get_detail_type(self, event: FormattedEvent | TransformedEvent) -> str:
        if isinstance(event, dict) and (detail_type := event.get("detail-type")):
            return detail_type
        else:
            return ""

    def _get_resources(self, event: FormattedEvent | TransformedEvent) -> list[str]:
        if isinstance(event, dict) and (resources := event.get("resources")):
            return resources
        else:
            return []


class EventsApiDestinationTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        """Send an event to an EventBridge API destination
        See https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-api-destinations.html"""
        target_arn = self.target["Arn"]
        target_region = extract_region_from_arn(target_arn)
        target_account_id = extract_account_id_from_arn(target_arn)
        api_destination_name = target_arn.split(":")[-1].split("/")[1]

        events_client = connect_to(
            aws_access_key_id=target_account_id, region_name=target_region
        ).events
        destination = events_client.describe_api_destination(Name=api_destination_name)

        # get destination endpoint details
        method = destination.get("HttpMethod", "GET")
        endpoint = destination.get("InvocationEndpoint")
        state = destination.get("ApiDestinationState") or "ACTIVE"

        LOG.debug(
            'Calling EventBridge API destination (state "%s"): %s %s', state, method, endpoint
        )
        headers = {
            # default headers AWS sends with every api destination call
            "User-Agent": "Amazon/EventBridge/ApiDestinations",
            "Content-Type": "application/json; charset=utf-8",
            "Range": "bytes=0-1048575",
            "Accept-Encoding": "gzip,deflate",
            "Connection": "close",
        }

        endpoint = add_api_destination_authorization(destination, headers, event)
        if http_parameters := self.target.get("HttpParameters"):
            endpoint = add_target_http_parameters(http_parameters, endpoint, headers, event)

        # add trace header
        headers[TRACE_HEADER_KEY] = trace_header.to_header_str()

        result = requests.request(
            method=method, url=endpoint, data=json.dumps(event or {}), headers=headers
        )
        if result.status_code >= 400:
            LOG.debug(
                "Received code %s forwarding events: %s %s", result.status_code, method, endpoint
            )
            if result.status_code == 429 or 500 <= result.status_code <= 600:
                pass  # TODO: retry logic (only retry on 429 and 5xx response status)


class FirehoseTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        delivery_stream_name = firehose_name(self.target["Arn"])

        self.client.put_record(
            DeliveryStreamName=delivery_stream_name,
            Record={"Data": to_bytes(to_json_str(event))},
        )


class KinesisTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        partition_key_path = collections.get_safe(
            self.target,
            "$.KinesisParameters.PartitionKeyPath",
            default_value="$.id",
        )
        stream_name = self.target["Arn"].split("/")[-1]
        partition_key = collections.get_safe(event, partition_key_path, event["id"])

        self.client.put_record(
            StreamName=stream_name,
            Data=to_bytes(to_json_str(event)),
            PartitionKey=partition_key,
        )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via tests
        # if not collections.get_safe(target, "$.RoleArn"):
        #     raise ValueError("RoleArn is required for Kinesis target")
        # if not collections.get_safe(target, "$.KinesisParameters.PartitionKeyPath"):
        #     raise ValueError("KinesisParameters.PartitionKeyPath is required for Kinesis target")


class LambdaTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        self.client.invoke(
            FunctionName=self.target["Arn"],
            Payload=to_bytes(to_json_str(event)),
            InvocationType="Event",
            TraceHeader=trace_header,
        )


class LogsTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        log_group_name = self.target["Arn"].split(":")[6]
        log_stream_name = str(uuid.uuid4())  # Unique log stream name

        self.client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        self.client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    "timestamp": now_utc(millis=True),
                    "message": to_json_str(event),
                }
            ],
        )


class RedshiftTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        raise NotImplementedError("Redshift target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via test
        # if not collections.get_safe(target, "$.RedshiftDataParameters.Database"):
        #     raise ValueError("RedshiftDataParameters.Database is required for Redshift target")


class SagemakerTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        raise NotImplementedError("Sagemaker target is not yet implemented")


class SnsTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        self.client.publish(TopicArn=self.target["Arn"], Message=to_json_str(event))


class SqsTargetSender(TargetSender):
    def send_event(self, event, trace_header):
        queue_url = sqs_queue_url_for_arn(self.target["Arn"])
        msg_group_id = self.target.get("SqsParameters", {}).get("MessageGroupId", None)
        kwargs = {"MessageGroupId": msg_group_id} if msg_group_id else {}

        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody=to_json_str(event),
            **kwargs,
        )


class StatesTargetSender(TargetSender):
    """Step Functions Target Sender"""

    def send_event(self, event, trace_header):
        self.service = "stepfunctions"

        self.client.start_execution(
            stateMachineArn=self.target["Arn"], name=event["id"], input=to_json_str(event)
        )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via test
        # if not collections.get_safe(target, "$.RoleArn"):
        #     raise ValueError("RoleArn is required for StepFunctions target")


class SystemsManagerSender(TargetSender):
    """EC2 Run Command Target Sender"""

    def send_event(self, event, trace_header):
        raise NotImplementedError("Systems Manager target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        # TODO: cover via test
        # if not collections.get_safe(target, "$.RoleArn"):
        #     raise ValueError(
        #         "RoleArn is required for SystemManager target to invoke a EC2 run command"
        #     )
        # if not collections.get_safe(target, "$.RunCommandParameters.RunCommandTargets"):
        #     raise ValueError(
        #         "RunCommandParameters.RunCommandTargets is required for Systems Manager target"
        #     )


class TargetSenderFactory:
    # supported targets: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
    target: Target
    rule_arn: Arn
    rule_name: RuleName
    region: str
    account_id: str

    target_map = {
        "apigateway": ApiGatewayTargetSender,
        "appsync": AppSyncTargetSender,
        "batch": BatchTargetSender,
        "ecs": ECSTargetSender,
        "events": EventsTargetSender,
        "events_api_destination": EventsApiDestinationTargetSender,
        "firehose": FirehoseTargetSender,
        "kinesis": KinesisTargetSender,
        "lambda": LambdaTargetSender,
        "logs": LogsTargetSender,
        "redshift": RedshiftTargetSender,
        "sns": SnsTargetSender,
        "sqs": SqsTargetSender,
        "sagemaker": SagemakerTargetSender,
        "ssm": SystemsManagerSender,
        "states": StatesTargetSender,
        "execute-api": ApiGatewayTargetSender,
        # TODO custom endpoints via http target
    }

    def __init__(
        self, target: Target, rule_arn: Arn, rule_name: RuleName, region: str, account_id: str
    ):
        self.target = target
        self.rule_arn = rule_arn
        self.rule_name = rule_name
        self.region = region
        self.account_id = account_id

    @classmethod
    def register_target_sender(cls, service_name: str, sender_class: Type[TargetSender]):
        cls.target_map[service_name] = sender_class

    def get_target_sender(self) -> TargetSender:
        target_arn = self.target["Arn"]
        service = extract_service_from_arn(target_arn)
        if ":api-destination/" in target_arn or ":destination/" in target_arn:
            service = "events_api_destination"
        if service in self.target_map:
            target_sender_class = self.target_map[service]
        else:
            raise Exception(f"Unsupported target for Service: {service}")
        target_sender = target_sender_class(
            self.target, self.rule_arn, self.rule_name, service, self.region, self.account_id
        )
        return target_sender
