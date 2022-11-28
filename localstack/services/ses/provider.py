import dataclasses
import json
import logging
import os
from datetime import date, datetime, time, timezone
from typing import Any, Dict, Optional, Protocol

from moto.ses import ses_backends
from moto.ses.models import SESBackend

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.ses import (
    Address,
    AddressList,
    AmazonResourceName,
    CloneReceiptRuleSetResponse,
    ConfigurationSetDoesNotExistException,
    ConfigurationSetName,
    CreateConfigurationSetEventDestinationResponse,
    DeleteConfigurationSetEventDestinationResponse,
    DeleteConfigurationSetResponse,
    DeleteTemplateResponse,
    Destination,
    EventDestination,
    EventDestinationDoesNotExistException,
    EventDestinationName,
    GetIdentityVerificationAttributesResponse,
    IdentityList,
    IdentityVerificationAttributes,
    ListTemplatesResponse,
    MaxItems,
    Message,
    MessageId,
    MessageRejected,
    MessageTagList,
    NextToken,
    RawMessage,
    ReceiptRuleSetName,
    SendEmailResponse,
    SendRawEmailResponse,
    SendTemplatedEmailResponse,
    SesApi,
    TemplateData,
    TemplateName,
    VerificationAttributes,
    VerificationStatus,
)
from localstack.constants import TEST_AWS_SECRET_ACCESS_KEY
from localstack.services.internal import get_internal_apis
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.utils.aws import arns, aws_stack
from localstack.utils.files import mkdir
from localstack.utils.strings import long_uid, to_str
from localstack.utils.time import timestamp, timestamp_millis

LOGGER = logging.getLogger(__name__)

# Keep record of all sent emails
# These can be retrieved via a service endpoint
EMAILS: Dict[MessageId, Dict[str, Any]] = {}

# Endpoint to access all the sent emails
# (relative to LocalStack internal HTTP resources base endpoint)
EMAILS_ENDPOINT = "/ses"

_EMAILS_ENDPOINT_REGISTERED = False


def save_for_retrospection(id: str, region: str, **kwargs: Dict[str, Any]):
    """Save a message for retrospection.

    The email is saved to filesystem and is also made accessible via a service endpoint.

    kwargs should consist of following keys related to the email:
    - Body
    - Destinations
    - RawData
    - Source
    - Subject
    - Template
    - TemplateData
    """
    ses_dir = os.path.join(config.dirs.data or config.dirs.tmp, "ses")

    mkdir(ses_dir)
    path = os.path.join(ses_dir, id + ".json")

    email = {"Id": id, "Timestamp": timestamp(), "Region": region, **kwargs}

    EMAILS[id] = email

    def _serialize(obj):
        """JSON serializer for timestamps."""
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        return obj.__dict__

    with open(path, "w") as f:
        f.write(json.dumps(email, default=_serialize))

    LOGGER.debug("Email saved at: %s", path)


def get_ses_backend(context: RequestContext) -> SESBackend:
    return ses_backends[context.account_id]["global"]


class SesServiceApiResource:
    """Provides a REST API for retrospective access to emails sent via SES.

    This is registered as a LocalStack internal HTTP resource.

    This endpoint accepts:
    - GET param `email`: filter for `source` field in SES message
    """

    def on_get(self, request):
        filter_source = request.args.get("email")
        messages = []

        for msg in EMAILS.values():
            if filter_source in (msg.get("Source"), None, ""):
                messages.append(msg)

        return {
            "messages": messages,
        }


def register_ses_api_resource():
    """Register the email retrospection endpoint as an internal LocalStack endpoint."""
    # Use a global to indicate whether the resource has already been registered
    # This is cheaper than iterating over the registered routes in the Router object
    global _EMAILS_ENDPOINT_REGISTERED

    if not _EMAILS_ENDPOINT_REGISTERED:
        get_internal_apis().add(EMAILS_ENDPOINT, SesServiceApiResource())
        _EMAILS_ENDPOINT_REGISTERED = True


class SesProvider(SesApi, ServiceLifecycleHook):

    #
    # Lifecycle Hooks
    #

    def on_after_init(self):
        # Allow sent emails to be retrieved from the SES emails endpoint
        register_ses_api_resource()

    #
    # Helpers
    #

    def get_source_from_raw(self, raw_data: str) -> Optional[str]:
        """Given a raw representation of email, return the source/from field."""
        entities = raw_data.split("\n")
        for entity in entities:
            if "From:" in entity:
                return entity.replace("From:", "").strip()
        return None

    #
    # Implementations for SES operations
    #

    @handler("CreateConfigurationSetEventDestination")
    def create_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination: EventDestination,
    ) -> CreateConfigurationSetEventDestinationResponse:
        result = call_moto(context)

        # send SES test event if an SNS topic is attached
        sns_topic_arn = event_destination.get("SNSDestination", {}).get("TopicARN")
        if sns_topic_arn is not None:
            emitter = SNSEmitter(context)
            emitter.emit_create_configuration_set_event_destination_test_message(sns_topic_arn)

        return result

    @handler("DeleteConfigurationSet")
    def delete_configuration_set(
        self, context: RequestContext, configuration_set_name: ConfigurationSetName
    ) -> DeleteConfigurationSetResponse:
        # not implemented in moto
        # TODO: contribute upstream?
        backend = get_ses_backend(context)
        try:
            backend.config_set.pop(configuration_set_name)
        except KeyError:
            raise ConfigurationSetDoesNotExistException(
                f"Configuration set <{configuration_set_name}> does not exist."
            )

        return DeleteConfigurationSetResponse()

    @handler("DeleteConfigurationSetEventDestination")
    def delete_configuration_set_event_destination(
        self,
        context: RequestContext,
        configuration_set_name: ConfigurationSetName,
        event_destination_name: EventDestinationName,
    ) -> DeleteConfigurationSetEventDestinationResponse:
        # not implemented in moto
        # TODO: contribute upstream?
        backend = get_ses_backend(context)
        try:
            backend.config_set_event_destination.pop(configuration_set_name)
        except KeyError:
            raise EventDestinationDoesNotExistException(
                f"No EventDestination found for {configuration_set_name}"
            )

        return DeleteConfigurationSetEventDestinationResponse()

    @handler("ListTemplates")
    def list_templates(
        self, context: RequestContext, next_token: NextToken = None, max_items: MaxItems = None
    ) -> ListTemplatesResponse:
        backend = get_ses_backend(context)
        for template in backend.list_templates():
            if isinstance(template["Timestamp"], (date, datetime)):
                template["Timestamp"] = timestamp_millis(template["Timestamp"])
        return call_moto(context)

    @handler("DeleteTemplate")
    def delete_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DeleteTemplateResponse:
        backend = get_ses_backend(context)
        if template_name in backend.templates:
            del backend.templates[template_name]
        return DeleteTemplateResponse()

    @handler("GetIdentityVerificationAttributes")
    def get_identity_verification_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityVerificationAttributesResponse:
        attributes: VerificationAttributes = {}

        for identity in identities:
            if "@" in identity:
                attributes[identity] = IdentityVerificationAttributes(
                    VerificationStatus=VerificationStatus.Success,
                )
            else:
                attributes[identity] = IdentityVerificationAttributes(
                    VerificationStatus=VerificationStatus.Success,
                    VerificationToken=long_uid(),
                )

        return GetIdentityVerificationAttributesResponse(
            VerificationAttributes=attributes,
        )

    @handler("SendEmail")
    def send_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        message: Message,
        reply_to_addresses: AddressList = None,
        return_path: Address = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendEmailResponse:
        response = call_moto(context)

        backend = get_ses_backend(context)
        emitter = SNSEmitter(context)
        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=response["MessageId"],
                sender_email=source,
                destination_addresses=destination["ToAddresses"],
            )
            emitter.emit_send_event(payload, sns_destination_arn)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        text_part = message["Body"].get("Text", {}).get("Data")
        html_part = message["Body"].get("Html", {}).get("Data")

        save_for_retrospection(
            response["MessageId"],
            context.region,
            Source=source,
            Destination=destination,
            Subject=message["Subject"].get("Data"),
            Body=dict(text_part=text_part, html_part=html_part),
        )

        return response

    @handler("SendTemplatedEmail")
    def send_templated_email(
        self,
        context: RequestContext,
        source: Address,
        destination: Destination,
        template: TemplateName,
        template_data: TemplateData,
        reply_to_addresses: AddressList = None,
        return_path: Address = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
        template_arn: AmazonResourceName = None,
    ) -> SendTemplatedEmailResponse:
        response = call_moto(context)

        backend = get_ses_backend(context)
        emitter = SNSEmitter(context)
        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=response["MessageId"],
                sender_email=source,
                destination_addresses=destination["ToAddresses"],
            )
            emitter.emit_send_event(payload, sns_destination_arn, emit_source_arn=False)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        save_for_retrospection(
            response["MessageId"],
            context.region,
            Source=source,
            Template=template,
            TemplateData=template_data,
            Destination=destination,
        )

        return response

    @handler("SendRawEmail")
    def send_raw_email(
        self,
        context: RequestContext,
        raw_message: RawMessage,
        source: Address = None,
        destinations: AddressList = None,
        from_arn: AmazonResourceName = None,
        source_arn: AmazonResourceName = None,
        return_path_arn: AmazonResourceName = None,
        tags: MessageTagList = None,
        configuration_set_name: ConfigurationSetName = None,
    ) -> SendRawEmailResponse:
        response = call_moto(context)
        raw_data = to_str(raw_message["Data"])

        if source is None or not source.strip():
            LOGGER.debug("Raw email:\n%s\nEOT", raw_data)

            source = self.get_source_from_raw(raw_data)
            if not source:
                LOGGER.warning("Source not specified. Rejecting message.")
                raise MessageRejected()

        if destinations is None:
            destinations = []

        backend = get_ses_backend(context)
        message = backend.send_raw_email(source, destinations, raw_data, context.region)

        emitter = SNSEmitter(context)
        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=response["MessageId"],
                sender_email=source,
                destination_addresses=destinations,
            )
            emitter.emit_send_event(payload, sns_destination_arn)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        save_for_retrospection(
            message.id,
            context.region,
            Source=source or message.source,
            Destination=destinations,
            RawData=raw_data,
        )

        return SendRawEmailResponse(MessageId=message.id)

    @handler("CloneReceiptRuleSet")
    def clone_receipt_rule_set(
        self,
        context: RequestContext,
        rule_set_name: ReceiptRuleSetName,
        original_rule_set_name: ReceiptRuleSetName,
    ) -> CloneReceiptRuleSetResponse:
        backend = get_ses_backend(context)

        backend.create_receipt_rule_set(rule_set_name)
        original_rule_set = backend.describe_receipt_rule_set(original_rule_set_name)

        for rule in original_rule_set:
            backend.create_receipt_rule(rule_set_name, rule)

        return CloneReceiptRuleSetResponse()


class SNSClient(Protocol):
    def publish(self, TopicArn: str, Message: str, Subject: Optional[str] = None):
        ...


@dataclasses.dataclass(frozen=True)
class SNSPayload:
    message_id: str
    sender_email: Address
    destination_addresses: AddressList


class SNSEmitter:
    def __init__(
        self,
        context: RequestContext,
    ):
        self.context = context

    def emit_create_configuration_set_event_destination_test_message(
        self, sns_topic_arn: str
    ) -> None:
        client = self._client_for_topic(sns_topic_arn)
        client.publish(
            TopicArn=sns_topic_arn,
            Message="Successfully validated SNS topic for Amazon SES event publishing.",
        )

    def emit_send_event(
        self, payload: SNSPayload, sns_topic_arn: str, emit_source_arn: bool = True
    ):
        now = datetime.now(tz=timezone.utc)

        event_payload = {
            "eventType": "Send",
            "mail": {
                "timestamp": now.isoformat(),
                "source": payload.sender_email,
                "sendingAccountId": self.context.account_id,
                "destination": payload.destination_addresses,
                "messageId": payload.message_id,
            },
            "send": {},
        }

        if emit_source_arn:
            event_payload["mail"][
                "sourceArn"
            ] = f"arn:aws:ses:{self.context.region}:{self.context.account_id}:identity/{payload.sender_email}"

        client = self._client_for_topic(sns_topic_arn)
        client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(event_payload),
            Subject="Amazon SES Email Event Notification",
        )

    def emit_delivery_event(self, payload: SNSPayload, sns_topic_arn: str):
        now = datetime.now(tz=timezone.utc)

        event_payload = {
            "eventType": "Delivery",
            "mail": {
                "timestamp": now.isoformat(),
                "source": payload.sender_email,
                "sourceArn": f"arn:aws:ses:{self.context.region}:{self.context.account_id}:identity/{payload.sender_email}",
                "sendingAccountId": self.context.account_id,
                "destination": payload.destination_addresses,
                "messageId": payload.message_id,
            },
            "delivery": {
                "recipients": payload.destination_addresses,
                "timestamp": now.isoformat(),
            },
        }
        client = self._client_for_topic(sns_topic_arn)
        client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(event_payload),
            Subject="Amazon SES Email Event Notification",
        )

    @staticmethod
    def _client_for_topic(topic_arn: str) -> SNSClient:
        arn_parameters = arns.parse_arn(topic_arn)
        region = arn_parameters["region"]
        access_key_id = arn_parameters["account"]

        return aws_stack.connect_to_service(
            "sns",
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        )
