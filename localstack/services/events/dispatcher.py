import abc
import dataclasses
import json
import logging
from datetime import datetime
from typing import TypedDict

from localstack.aws.api.events import Target
from localstack.aws.connect import connect_to
from localstack.utils.aws.arns import parse_arn, sqs_queue_url_for_arn
from localstack.utils.aws.client_types import ServicePrincipal
from localstack.utils.json import extract_jsonpath
from localstack.utils.strings import long_uid, truncate
from localstack.utils.time import TIMESTAMP_FORMAT_TZ

LOG = logging.getLogger(__name__)

EventDict = TypedDict(
    "EventDict",
    {
        "version": str,
        "id": str,
        "detail-type": str,
        "source": str,
        "account": str,
        "time": str,
        "region": str,
        "resources": list[str],
        "detail": dict,
    },
)


@dataclasses.dataclass
class Event:
    detail_type: str
    source: str
    account: str
    region: str
    resources: str | list[str]
    details: dict = dataclasses.field(default_factory=dict)
    time: datetime = dataclasses.field(default_factory=datetime.utcnow)
    id: str = dataclasses.field(default_factory=long_uid)

    def to_event_dict(self) -> EventDict:
        return {
            "version": "0",
            "id": self.id,
            "detail-type": self.detail_type,
            "source": self.source,
            "account": self.account,
            "time": self.time.strftime(TIMESTAMP_FORMAT_TZ),
            "region": self.region,
            "resources": self.resources if isinstance(self.resources, list) else [self.resources],
            "detail": self.details,
        }


class EventDispatcher(abc.ABC):
    target_service: str

    def dispatch(self, event: Event, target: Target):
        raise NotImplementedError

    @staticmethod
    def dispatcher_for_target(target_arn: str) -> "EventDispatcher":
        service = parse_arn(target_arn)["service"]

        # TODO: split out `send_event_to_target` into individual dispatcher classes
        if service == "sqs":
            return SqsEventDispatcher()

        return LegacyScheduledEventDispatcher()


class LegacyScheduledEventDispatcher(EventDispatcher):
    target_service = None

    def dispatch(self, event: Event, target: Target):
        from localstack.utils.aws.message_forwarding import send_event_to_target
        from localstack.utils.collections import pick_attributes

        # TODO generate event matching aws in case no Input has been specified
        event_str = target.get("Input")
        event_data = json.loads(event_str) if event_str is not None else event.to_event_dict()
        attr = pick_attributes(target, ["$.SqsParameters", "$.KinesisParameters"])

        try:
            LOG.debug(
                "Event rule %s sending event to target %s: %s",
                event.resources[0],
                target["Arn"],
                event,
            )

            send_event_to_target(
                target["Arn"],
                event_data,
                target_attributes=attr,
                role=target.get("RoleArn"),
                target=target,
                source_arn=event.resources[0],
                source_service=ServicePrincipal.events,
            )
        except Exception as e:
            LOG.error(
                "Unable to send event notification %s to target %s: %s",
                truncate(event_data),
                target,
                e,
                exc_info=e if LOG.isEnabledFor(logging.DEBUG) else None,
            )


class SqsEventDispatcher(EventDispatcher):
    target_service = "sqs"

    def dispatch(self, event: Event, target: Target):
        if input_ := target.get("Input"):
            body = input_
        else:
            body = json.dumps(self.create_event(event, target))

        request = {
            "QueueUrl": self.get_queue_url(target),
            "MessageBody": body,
            **target.get("SqsParameters", {}),
        }

        connect_to().sqs.send_message(**request)

    def get_queue_url(self, target: Target) -> str:
        return sqs_queue_url_for_arn(target["Arn"])

    def create_event(self, event: Event, target: Target) -> dict:
        event_data = event.to_event_dict()
        if input_path := target.get("InputPath"):
            event_data = extract_jsonpath(event_data, input_path)

        if target.get("InputTransformer"):
            LOG.warning("InputTransformer is currently not supported for SQS")

        return event_data
