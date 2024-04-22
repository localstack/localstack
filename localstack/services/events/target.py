import json
import logging
import uuid
from abc import ABC, abstractmethod

from botocore.client import BaseClient

from localstack.aws.api.events import (
    Arn,
    Target,
)
from localstack.aws.connect import connect_to
from localstack.utils import collections
from localstack.utils.aws.arns import (
    extract_service_from_arn,
    firehose_name,
    sqs_queue_url_for_arn,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.strings import to_bytes
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)


class TargetService(ABC):
    def __init__(
        self,
        target: Target,
        region: str,
        account_id: str,
        rule_arn: Arn,
        service: str,
    ):
        self.target = target
        self.region = region
        self.account_id = account_id
        self.rule_arn = rule_arn
        self.service = service

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
    def send_event(self):
        pass

    def _validate_input(self, target: Target):
        """Provide a default implementation that does nothing if no specific validation is needed."""
        # TODO add For EC2 instances, Kinesis Data Streams, Step Functions state machines and API Gateway APIs, EventBridge relies on IAM roles that you specify in the RoleARN argument in PutTargets.
        # TODO add For Lambda and Amazon SNS resources, EventBridge relies on resource-based policies.
        pass

    def _initialize_client(self) -> BaseClient:
        """Initializes internal botocore client.
        If a role from a target is provided, the client will be initialized with the assumed role.
        If no role is provided the client will be initialized with the account ID and region.
        In both cases event bridge is requested as service principal"""
        service_principal = ServicePrincipal.events
        if role_arn := self.target.get("role_arn"):
            client_factory = connect_to.with_assumed_role(
                role_arn=role_arn, service_principal=service_principal, region_name=self.region
            )
        else:
            client_factory = connect_to(aws_access_key_id=self.account_id, region_name=self.region)
        client = client_factory.get_client(self.service)
        client = client.request_metadata(
            service_principal=service_principal, source_arn=self.rule_arn
        )
        return client


TargetServiceDict = dict[Arn, TargetService]


class ApiGatewayTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("ApiGateway target is not yet implemented")


class AppSyncTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("AppSync target is not yet implemented")


class BatchTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("Batch target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.BatchParameters.JobDefinition"):
            raise ValueError("BatchParameters.JobDefinition is required for Batch target")
        if not collections.get_safe(target, "$.BatchParameters.JobName"):
            raise ValueError("BatchParameters.JobName is required for Batch target")


class ContainerTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("ECS target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.EcsParameters.TaskDefinitionArn"):
            raise ValueError("EcsParameters.TaskDefinitionArn is required for ECS target")


class EventsTargetService(TargetService):
    def send_event(self, event):
        eventbus_name = self.target["Arn"].split(":")[-1].split("/")[-1]
        source = (
            event.get("source")
            if event.get("source") is not None
            else self.service
            if self.service
            else ""
        )
        detail_type = event.get("detail-type") if event.get("detail-type") is not None else ""
        # TODO add validation and tests for eventbridge to eventbridge requires Detail, DetailType, and Source
        # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/events/client/put_events.html
        detail = event.get("detail", event)
        resources = (
            event.get("resources")
            if event.get("resources") is not None
            else ([self.rule_arn] if self.rule_arn else [])
        )

        self.client.put_events(
            Entries=[
                {
                    "EventBusName": eventbus_name,
                    "Source": source,
                    "DetailType": detail_type,
                    "Detail": json.dumps(detail),
                    "Resources": resources,
                }
            ]
        )


class FirehoseTargetService(TargetService):
    def send_event(self, event):
        delivery_stream_name = firehose_name(self.target["Arn"])
        self.client.put_record(
            DeliveryStreamName=delivery_stream_name, Record={"Data": to_bytes(json.dumps(event))}
        )


class KinesisTargetService(TargetService):
    def send_event(self, event):
        partition_key_path = self.target["KinesisParameters"]["PartitionKeyPath"]
        stream_name = self.target["Arn"].split("/")[-1]
        partition_key = event.get(partition_key_path, event["id"])
        self.client.put_record(
            StreamName=stream_name,
            Data=to_bytes(json.dumps(event)),
            PartitionKey=partition_key,
        )

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.KinesisParameters.PartitionKeyPath"):
            raise ValueError("KinesisParameters.PartitionKeyPath is required for Kinesis target")


class LambdaTargetService(TargetService):
    def send_event(self, event):
        asynchronous = True  # TODO clarify default behavior of AWS
        self.client.invoke(
            FunctionName=self.target["Arn"],
            Payload=to_bytes(json.dumps(event)),
            InvocationType="Event" if asynchronous else "RequestResponse",
        )


class LogsTargetService(TargetService):
    def send_event(self, event):
        log_group_name = self.target["Arn"].split(":")[6]
        log_stream_name = str(uuid.uuid4())  # Unique log stream name
        self.client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        self.client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": now_utc(millis=True), "message": json.dumps(event)}],
        )


class RedshiftTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("Redshift target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RedshiftDataParameters.Database"):
            raise ValueError("RedshiftDataParameters.Database is required for Redshift target")


class SagemakerTargetService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("Sagemaker target is not yet implemented")


class SnsTargetService(TargetService):
    def send_event(self, event):
        self.client.publish(TopicArn=self.target["Arn"], Message=json.dumps(event))


class SqsTargetService(TargetService):
    def send_event(self, event):
        queue_url = sqs_queue_url_for_arn(self.target["Arn"])
        msg_group_id = self.target.get("SqsParameters", {}).get("MessageGroupId", None)
        kwargs = {"MessageGroupId": msg_group_id} if msg_group_id else {}
        self.client.send_message(
            QueueUrl=queue_url, MessageBody=json.dumps(event, separators=(",", ":")), **kwargs
        )


class StatesTargetService(TargetService):
    """Step Functions Target Sender"""

    def send_event(self, event):
        self.client.start_execution(stateMachineArn=self.target["Arn"], input=json.dumps(event))


class SystemsManagerService(TargetService):
    def send_event(self, event):
        raise NotImplementedError("Systems Manager target is not yet implemented")

    def _validate_input(self, target: Target):
        super()._validate_input(target)
        if not collections.get_safe(target, "$.RunCommandParameters.RunCommandTargets"):
            raise ValueError(
                "RunCommandParameters.RunCommandTargets is required for Systems Manager target"
            )


class TargetServiceFactory:
    # supported targets: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
    target_map = {
        "apigateway": ApiGatewayTargetService,
        "appsync": AppSyncTargetService,
        "batch": BatchTargetService,
        "ecs": ContainerTargetService,
        "events": EventsTargetService,
        "firehose": FirehoseTargetService,
        "kinesis": KinesisTargetService,
        "lambda": LambdaTargetService,
        "logs": LogsTargetService,
        "redshift": RedshiftTargetService,
        "sns": SnsTargetService,
        "sqs": SqsTargetService,
        "sagemaker": SagemakerTargetService,
        "ssm": SystemsManagerService,
        # TODO custom endpoints via http target
    }

    def __init__(self, target: Target, region: str, account_id: str, rule_arn: Arn):
        self.target = target
        self.region = region
        self.account_id = account_id
        self.rule_arn = rule_arn

    def get_target_service(self) -> TargetService:
        service = extract_service_from_arn(self.target["Arn"])
        if service in self.target_map:
            target_service_class = self.target_map[service]
        else:
            raise Exception(f"Unsupported target for Service: {service}")
        target_service = target_service_class(
            self.target, self.region, self.account_id, self.rule_arn, service
        )
        return target_service
