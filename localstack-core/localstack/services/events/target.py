import datetime
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from typing import Any, Set

from botocore.client import BaseClient

from localstack.aws.api.events import Arn, InputTransformer, RuleName, Target, TargetInputPath
from localstack.aws.connect import connect_to
from localstack.services.events.models import FormattedEvent, TransformedEvent, ValidationException
from localstack.services.events.utils import EventJSONEncoder, event_time_to_time_string
from localstack.utils import collections
from localstack.utils.aws.arns import (
    extract_account_id_from_arn,
    extract_region_from_arn,
    extract_resource_from_arn,
    extract_service_from_arn,
    firehose_name,
    sqs_queue_url_for_arn,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import to_bytes
from localstack.utils.time import now_utc

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
    template: str, replacements: dict[str, Any], is_json: bool
) -> TransformedEvent:
    """Replace placeholders defined by <key> in the template with the values from the replacements dict.
    Can handle single template string or template dict."""

    def replace_placeholder(match):
        key = match.group(1)
        value = replacements.get(key, match.group(0))  # handle non defined placeholders
        if is_json:
            return json.dumps(value, cls=EventJSONEncoder)
        if isinstance(value, datetime.datetime):
            return event_time_to_time_string(value)
        return value

    formatted_template = TRANSFORMER_PLACEHOLDER_PATTERN.sub(replace_placeholder, template)

    return json.loads(formatted_template) if is_json else formatted_template[1:-1]


class TargetSender(ABC):
    def __init__(
        self,
        target: Target,
        rule_arn: Arn,
        rule_name: RuleName,
        service: str,
    ):
        self.target = target
        self.rule_arn = rule_arn
        self.rule_name = rule_name
        self.service = service

        self.region = extract_region_from_arn(self.target["Arn"])
        self.account_id = extract_account_id_from_arn(self.target["Arn"])

        self._validate_input(target)
        self._client: BaseClient | None = None

    @property
    def arn(self):
        return self.target["Arn"]

    @property
    def client(self):
        """Lazy initialization of internal botoclient factory."""
        if self._client is None:
            self._client = self._initialize_client()
        return self._client

    @abstractmethod
    def send_event(self, event: FormattedEvent | TransformedEvent):
        pass

    def process_event(self, event: FormattedEvent):
        """Processes the event and send it to the target."""
        if input_path := self.target.get("InputPath"):
            event = transform_event_with_target_input_path(input_path, event)
        if input_transformer := self.target.get("InputTransformer"):
            event = self.transform_event_with_target_input_transformer(input_transformer, event)
        self.send_event(event)

    def transform_event_with_target_input_transformer(
        self, input_transformer: InputTransformer, event: FormattedEvent
    ) -> TransformedEvent:
        input_template = input_transformer["InputTemplate"]
        template_replacements = get_template_replacements(input_transformer, event)
        predefined_template_replacements = self._get_predefined_template_replacements(event)
        template_replacements.update(predefined_template_replacements)

        is_json_format = input_template.strip().startswith(("{"))
        populated_template = replace_template_placeholders(
            input_template, template_replacements, is_json_format
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
        If no role is provided or the role is not in the target account,
        the client will be initialized with the account ID and region.
        In both cases event bridge is requested as service principal"""
        service_principal = ServicePrincipal.events
        role_arn = self.target.get("RoleArn")
        if role_arn and self.account_id == extract_account_id_from_arn(
            role_arn
        ):  # required for cross account
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
        return client

    def _validate_input_transformer(self, input_transformer: InputTransformer):
        if "InputTemplate" not in input_transformer:
            raise ValueError("InputTemplate is required for InputTransformer")
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


TargetSenderDict = dict[Arn, TargetSender]

# Target Senders are ordered alphabetically by service name


class ApiGatewayTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("ApiGateway target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RoleArn"):
            raise ValueError("RoleArn is required for ApiGateway target")


class AppSyncTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("AppSync target is not yet implemented")


class BatchTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("Batch target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.BatchParameters.JobDefinition"):
            raise ValueError("BatchParameters.JobDefinition is required for Batch target")
        if not collections.get_safe(target, "$.BatchParameters.JobName"):
            raise ValueError("BatchParameters.JobName is required for Batch target")


class ContainerTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("ECS target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.EcsParameters.TaskDefinitionArn"):
            raise ValueError("EcsParameters.TaskDefinitionArn is required for ECS target")


class EventsTargetSender(TargetSender):
    def send_event(self, event):
        # TODO add validation and tests for eventbridge to eventbridge requires Detail, DetailType, and Source
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/events/client/put_events.html
        event_bus_name = extract_resource_from_arn(self.target["Arn"]).split("/")[-1]
        source = self._get_source(event)
        detail_type = self._get_detail_type(event)
        detail = event.get("detail", event)
        resources = self._get_resources(event)
        entries = [
            {
                "EventBusName": event_bus_name,
                "Source": source,
                "DetailType": detail_type,
                "Detail": json.dumps(detail),
                "Resources": resources,
            }
        ]
        if encoded_original_id := self._get_trace_header_encoded_region_account(event):
            entries[0]["TraceHeader"] = encoded_original_id
        self.client.put_events(Entries=entries)

    def _get_trace_header_encoded_region_account(self, event: FormattedEvent) -> str | None:
        """Encode the original region and account_id for cross-region and cross-account
        event bus communication in the trace header. For event bus to event bus communication
        in a different account the event id is preserved. This is not the case if the region differs."""
        original_id = event.get("id")
        original_account = event.get("account")
        original_region = event.get("region")
        if original_region != self.region and original_account != self.account_id:
            return json.dumps(
                {
                    "original_region": original_region,
                    "original_account": original_account,
                }
            )
        if original_region != self.region:
            return json.dumps({"original_region": original_region})
        if original_account != self.account_id:
            return json.dumps({"original_id": original_id, "original_account": original_account})

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


class FirehoseTargetSender(TargetSender):
    def send_event(self, event):
        delivery_stream_name = firehose_name(self.target["Arn"])
        self.client.put_record(
            DeliveryStreamName=delivery_stream_name,
            Record={"Data": to_bytes(json.dumps(event, cls=EventJSONEncoder))},
        )


class KinesisTargetSender(TargetSender):
    def send_event(self, event):
        partition_key_path = self.target["KinesisParameters"]["PartitionKeyPath"]
        stream_name = self.target["Arn"].split("/")[-1]
        partition_key = event.get(partition_key_path, event["id"])
        self.client.put_record(
            StreamName=stream_name,
            Data=to_bytes(json.dumps(event, cls=EventJSONEncoder)),
            PartitionKey=partition_key,
        )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RoleArn"):
            raise ValueError("RoleArn is required for Kinesis target")
        if not collections.get_safe(target, "$.KinesisParameters.PartitionKeyPath"):
            raise ValueError("KinesisParameters.PartitionKeyPath is required for Kinesis target")


class LambdaTargetSender(TargetSender):
    def send_event(self, event):
        asynchronous = True  # TODO clarify default behavior of AWS
        self.client.invoke(
            FunctionName=self.target["Arn"],
            Payload=to_bytes(json.dumps(event, cls=EventJSONEncoder)),
            InvocationType="Event" if asynchronous else "RequestResponse",
        )


class LogsTargetSender(TargetSender):
    def send_event(self, event):
        log_group_name = self.target["Arn"].split(":")[6]
        log_stream_name = str(uuid.uuid4())  # Unique log stream name
        self.client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        self.client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[
                {
                    "timestamp": now_utc(millis=True),
                    "message": json.dumps(event, cls=EventJSONEncoder),
                }
            ],
        )


class RedshiftTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("Redshift target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RedshiftDataParameters.Database"):
            raise ValueError("RedshiftDataParameters.Database is required for Redshift target")


class SagemakerTargetSender(TargetSender):
    def send_event(self, event):
        raise NotImplementedError("Sagemaker target is not yet implemented")


class SnsTargetSender(TargetSender):
    def send_event(self, event):
        self.client.publish(
            TopicArn=self.target["Arn"], Message=json.dumps(event, cls=EventJSONEncoder)
        )


class SqsTargetSender(TargetSender):
    def send_event(self, event):
        queue_url = sqs_queue_url_for_arn(self.target["Arn"])
        msg_group_id = self.target.get("SqsParameters", {}).get("MessageGroupId", None)
        kwargs = {"MessageGroupId": msg_group_id} if msg_group_id else {}
        self.client.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(
                event,
                separators=(",", ":"),
                cls=EventJSONEncoder,
            ),
            **kwargs,
        )


class StatesTargetSender(TargetSender):
    """Step Functions Target Sender"""

    def send_event(self, event):
        self.client.start_execution(
            stateMachineArn=self.target["Arn"], input=json.dumps(event, cls=EventJSONEncoder)
        )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RoleArn"):
            raise ValueError("RoleArn is required for StepFunctions target")


class SystemsManagerSender(TargetSender):
    """EC2 Run Command Target Sender"""

    def send_event(self, event):
        raise NotImplementedError("Systems Manager target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RoleArn"):
            raise ValueError(
                "RoleArn is required for SystemManager target to invoke a EC2 run command"
            )
        if not collections.get_safe(target, "$.RunCommandParameters.RunCommandTargets"):
            raise ValueError(
                "RunCommandParameters.RunCommandTargets is required for Systems Manager target"
            )


class TargetSenderFactory:
    # supported targets: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
    target_map = {
        "apigateway": ApiGatewayTargetSender,
        "appsync": AppSyncTargetSender,
        "batch": BatchTargetSender,
        "ecs": ContainerTargetSender,
        "events": EventsTargetSender,
        "firehose": FirehoseTargetSender,
        "kinesis": KinesisTargetSender,
        "lambda": LambdaTargetSender,
        "logs": LogsTargetSender,
        "redshift": RedshiftTargetSender,
        "sns": SnsTargetSender,
        "sqs": SqsTargetSender,
        "sagemaker": SagemakerTargetSender,
        "ssm": SystemsManagerSender,
        # TODO custom endpoints via http target
    }

    def __init__(self, target: Target, rule_arn: Arn, rule_name: RuleName):
        self.target = target
        self.rule_arn = rule_arn
        self.rule_name = rule_name

    def get_target_sender(self) -> TargetSender:
        service = extract_service_from_arn(self.target["Arn"])
        if service in self.target_map:
            target_sender_class = self.target_map[service]
        else:
            raise Exception(f"Unsupported target for Service: {service}")
        target_sender = target_sender_class(self.target, self.rule_arn, self.rule_name, service)
        return target_sender
