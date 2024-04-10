from __future__ import annotations

import json
import logging
import uuid
from abc import ABC, abstractmethod

from localstack.aws.api.events import (
    Arn,
    Target,
    TargetId,
)
from localstack.aws.connect import ServiceLevelClientFactory, connect_to
from localstack.utils import collections
from localstack.utils.aws.arns import (
    firehose_name,
    parse_arn,
    sqs_queue_url_for_arn,
)
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.strings import to_bytes
from localstack.utils.time import now_utc

LOG = logging.getLogger(__name__)


class TargetWorker(ABC):
    """https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html"""

    def __init__(
        self,
        region: str,
        account_id: str,
        target: Target,
        rule_arn: Arn,
        service: str,
    ):
        self.region = region
        self.account_id = account_id
        self.target = target
        self.rule_arn = rule_arn
        self.service = service

        self._validate_input(self.target)
        self._clients: ServiceLevelClientFactory | None = None

    @property
    def arn(self):
        return self.target["Arn"]

    @property
    def clients(self):
        """Lazy initialization of AWS service clients."""
        if self._clients is None:
            self._clients = self._initialize_clients()
        return self._clients

    @abstractmethod
    def send_event(self):
        pass

    @abstractmethod
    def _validate_input(self, target: Target):
        pass

    @staticmethod
    def connect_with_role(role_arn: str, region_name: str) -> ServiceLevelClientFactory:
        """Connects using an assumed role."""
        service_principal = ServicePrincipal.events
        try:
            return connect_to.with_assumed_role(
                role_arn=role_arn, service_principal=service_principal, region_name=region_name
            )
        except ValueError as e:
            LOG.debug(f"Could not connect with assumed role {role_arn}. Error: {e}")
            return None

    def _initialize_clients(self) -> ServiceLevelClientFactory:
        """Initializes AWS service clients, with or without assuming a role of service source.
        If a role from a target is provided, the client will be initialized with the assumed role and events service principal.
        If no role is provided e.g. calling send_events directly, the client will be initialized with the account ID and region."""
        if role_arn := self.target.get("role_arn"):
            clients = TargetWorker.connect_with_role(role_arn, self.region)
            if not clients:
                clients = connect_to(aws_access_key_id=self.account_id, region_name=self.region)
        else:
            clients = connect_to(aws_access_key_id=self.account_id, region_name=self.region)
        return clients


class LambdaTargetWorker(TargetWorker):
    def send_event(self, event):
        asynchronous = True
        lambda_client = self.clients.lambda_.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        lambda_client.invoke(
            FunctionName=self.target["Arn"],
            Payload=to_bytes(json.dumps(event)),
            InvocationType="Event" if asynchronous else "RequestResponse",
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class SnsTargetWorker(TargetWorker):
    def send_event(self, event):
        sns_client = self.clients.sns.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        sns_client.publish(TopicArn=self.target["Arn"], Message=json.dumps(event))

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class SqsTargetWorker(TargetWorker):
    def send_event(self, event):
        sqs_client = self.clients.sqs.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        queue_url = sqs_queue_url_for_arn(self.target["Arn"])
        msg_group_id = collections.get_safe(self.target, "$.SqsParameters.MessageGroupId")
        kwargs = {"MessageGroupId": msg_group_id} if msg_group_id else {}
        sqs_client.send_message(
            QueueUrl=queue_url, MessageBody=json.dumps(event, separators=(",", ":")), **kwargs
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class StatesTargetWorker(TargetWorker):
    """Step Functions Target Sender"""

    def send_event(self, event):
        stepfunctions_client = self.clients.stepfunctions.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        stepfunctions_client.start_execution(
            stateMachineArn=self.target["Arn"], input=json.dumps(event)
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class FirehoseTargetWorker(TargetWorker):
    def send_event(self, event):
        firehose_client = self.clients.firehose.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        delivery_stream_name = firehose_name(self.target["Arn"])
        firehose_client.put_record(
            DeliveryStreamName=delivery_stream_name, Record={"Data": to_bytes(json.dumps(event))}
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class EventsTargetWorker(TargetWorker):
    def send_event(self, event):
        events_client = self.clients.events.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        eventbus_name = self.target["Arn"].split(":")[-1].split("/")[-1]
        detail = event.get("detail") or event
        resources = event.get("resources") or [self.rule_arn] if self.rule_arn else []
        events_client.put_events(
            Entries=[
                {
                    "EventBusName": eventbus_name,
                    "Source": event.get("source", self.service) or "",
                    "DetailType": event.get("detail-type", ""),
                    "Detail": json.dumps(detail),
                    "Resources": resources,
                }
            ]
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class KinesisTargetWorker(TargetWorker):
    def send_event(self, event):
        kinesis_client = self.clients.kinesis.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        partition_key_path = collections.get_safe(
            self.target["KinesisParameters"],
            "$.KinesisParameters.PartitionKeyPath",
            default_value="$.id",
        )
        stream_name = self.target["Arn"].split("/")[-1]
        partition_key = collections.get_safe(event, partition_key_path, event["id"])
        kinesis_client.put_record(
            StreamName=stream_name,
            Data=to_bytes(json.dumps(event)),
            PartitionKey=partition_key,
        )

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.KinesisParameters.PartitionKeyPath"):
            raise ValueError("KinesisParameters.PartitionKeyPath is required for Kinesis target")
        # TODO add more validation


class LogsTargetWorker(TargetWorker):
    def send_event(self, event):
        logs_client = self.clients.logs.request_metadata(
            service_principal=self.service, source_arn=self.rule_arn
        )
        log_group_name = self.target["Arn"].split(":")[6]
        log_stream_name = str(uuid.uuid4())  # Unique log stream name
        logs_client.create_log_stream(logGroupName=log_group_name, logStreamName=log_stream_name)
        logs_client.put_log_events(
            logGroupName=log_group_name,
            logStreamName=log_stream_name,
            logEvents=[{"timestamp": now_utc(millis=True), "message": json.dumps(event)}],
        )

    def _validate_input(self, target: Target):
        # TODO add more validation
        pass


class SystemsManagerWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("Systems Manager target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.RunCommandParameters.RunCommandTargets"):
            raise ValueError(
                "RunCommandParameters.RunCommandTargets is required for Systems Manager target"
            )
        # TODO add more validation


class ContainerTargetWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("ECS target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.EcsParameters.TaskDefinitionArn"):
            raise ValueError("EcsParameters.TaskDefinitionArn is required for ECS target")
        # TODO add more validation


class BatchTargetWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("Batch target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.BatchParameters.JobDefinition"):
            raise ValueError("BatchParameters.JobDefinition is required for Batch target")
        if not collections.get_safe(target, "$.BatchParameters.JobName"):
            raise ValueError("BatchParameters.JobName is required for Batch target")
        # TODO add more validation


class RedshiftTargetWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("Redshift target is not yet implemented")

    def _validate_input(self, target: Target):
        if not collections.get_safe(target, "$.RedshiftDataParameters.Database"):
            raise ValueError("RedshiftDataParameters.Database is required for Redshift target")
        # TODO add more validation


class SagemakerTargetWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("Sagemaker target is not yet implemented")


class AppSyncTargetWorker(TargetWorker):
    def send_event(self, event):
        raise NotImplementedError("AppSync target is not yet implemented")


class TargetWorkerFactory:
    # supported targets: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-targets.html
    target_map = {
        "lambda": LambdaTargetWorker,
        "sqs": SqsTargetWorker,
        "sns": SnsTargetWorker,
        "kinesis": KinesisTargetWorker,
        "firehose": FirehoseTargetWorker,
        "logs": LogsTargetWorker,
        "events": EventsTargetWorker,
        "ssm": SystemsManagerWorker,
        "ecs": ContainerTargetWorker,
        "batch": BatchTargetWorker,
        "redshift": RedshiftTargetWorker,
        "sagemaker": SagemakerTargetWorker,
        "appsync": AppSyncTargetWorker,
        # TODO api gateway & custom endpoints via http target
    }

    def __init__(self, region: str, account_id: str, target: Target, rule_arn: Arn):
        self.region = region
        self.account_id = account_id
        self.target = target
        self.rule_arn = rule_arn

    @staticmethod
    def extract_service_from_arn(arn: Arn) -> str:
        arn = parse_arn(arn)
        return arn["service"]

    def get_target_worker(self) -> TargetWorker:
        service = TargetWorkerFactory.extract_service_from_arn(self.target["Arn"])
        if service in self.target_map:
            target_worker_class = self.target_map[service]
        else:
            raise Exception(f"Unsupported target for Service: {service}")
        target_worker = target_worker_class(
            self.region, self.account_id, self.target, self.rule_arn, service
        )
        return target_worker


TargetWorkerDict = dict[TargetId, TargetWorker]