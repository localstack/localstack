import dataclasses
import json
import logging
import os
import re
from collections import defaultdict
from datetime import date, datetime, time, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from botocore.exceptions import ClientError
from moto.ses import ses_backends
from moto.ses.models import SESBackend

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.core import CommonServiceException
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
    InvalidSNSDestinationException,
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
from localstack.aws.connect import connect_to
from localstack.constants import TEST_AWS_SECRET_ACCESS_KEY
from localstack.http import Resource, Response
from localstack.services.internal import DeprecatedResource, get_internal_apis
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
from localstack.services.ses.models import SentEmail, SentEmailBody
from localstack.utils.aws import arns
from localstack.utils.files import mkdir
from localstack.utils.strings import long_uid, to_str
from localstack.utils.time import timestamp, timestamp_millis

if TYPE_CHECKING:
    from mypy_boto3_sns import SNSClient

LOGGER = logging.getLogger(__name__)

# Keep record of all sent emails
# These can be retrieved via a service endpoint
EMAILS: Dict[MessageId, Dict[str, Any]] = {}

# Endpoint to access all the sent emails
# (relative to LocalStack internal HTTP resources base endpoint)
EMAILS_ENDPOINT = "/_aws/ses"

_EMAILS_ENDPOINT_REGISTERED = False

ALLOWED_TAG_CHARS = "^[A-Za-z0-9_-]*$"

ALLOWED_TAG_LEN = 255


def save_for_retrospection(sent_email: SentEmail):
    """
    Save a message for retrospection.

    The contents of the email is saved to filesystem. It can also be accessed via a service endpoint.
    """
    message_id = sent_email["Id"]
    ses_dir = os.path.join(config.dirs.data or config.dirs.tmp, "ses")
    mkdir(ses_dir)

    path = os.path.join(ses_dir, message_id + ".json")

    if not sent_email.get("Timestamp"):
        sent_email["Timestamp"] = timestamp()

    EMAILS[message_id] = sent_email

    def _serialize(obj):
        """JSON serializer for timestamps."""
        if isinstance(obj, (datetime, date, time)):
            return obj.isoformat()
        return obj.__dict__

    with open(path, "w") as f:
        f.write(json.dumps(sent_email, default=_serialize))

    LOGGER.debug("Email saved at: %s", path)


def recipients_from_destination(destination: Destination) -> List[str]:
    """Get list of recipient email addresses from a Destination object."""
    return (
        destination.get("ToAddresses", [])
        + destination.get("CcAddresses", [])
        + destination.get("BccAddresses", [])
    )


def get_ses_backend(context: RequestContext) -> SESBackend:
    return ses_backends[context.account_id][context.region]


class SesServiceApiResource:
    """Provides a REST API for retrospective access to emails sent via SES.

    This is registered as a LocalStack internal HTTP resource.

    This endpoint accepts:
    - GET param `id`: filter for `id` field in SES message
    - GET param `email`: filter for `source` field in SES message, when `id` filter is specified then filters on both
    """

    def on_get(self, request):
        filter_id = request.args.get("id")
        filter_source = request.args.get("email")
        messages = []

        for msg in EMAILS.values():
            if filter_id in (msg.get("Id"), None, ""):
                if filter_source in (msg.get("Source"), None, ""):
                    messages.append(msg)

        return {
            "messages": messages,
        }

    def on_delete(self, request):
        filter_id = request.args.get("id")
        if filter_id is not None:
            del EMAILS[filter_id]
        else:
            EMAILS.clear()
        return Response(status=204)


def register_ses_api_resource():
    """Register the email retrospection endpoint as an internal LocalStack endpoint."""
    # Use a global to indicate whether the resource has already been registered
    # This is cheaper than iterating over the registered routes in the Router object
    global _EMAILS_ENDPOINT_REGISTERED

    if not _EMAILS_ENDPOINT_REGISTERED:
        ses_service_api_resource = SesServiceApiResource()
        get_internal_apis().add(
            Resource(
                "/_localstack/ses",
                DeprecatedResource(
                    ses_service_api_resource,
                    previous_path="/_localstack/ses",
                    deprecation_version="1.4.0",
                    new_path="/_aws/ses",
                ),
            )
        )

        from localstack.services.edge import ROUTER

        ROUTER.add(Resource(EMAILS_ENDPOINT, ses_service_api_resource))

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
        # send SES test event if an SNS topic is attached
        sns_topic_arn = event_destination.get("SNSDestination", {}).get("TopicARN")
        if sns_topic_arn is not None:
            emitter = SNSEmitter(context)
            emitter.emit_create_configuration_set_event_destination_test_message(sns_topic_arn)

        # only register the event destiation if emitting the message worked
        try:
            result = call_moto(context)
        except CommonServiceException as e:
            if e.code == "ConfigurationSetDoesNotExist":
                raise ConfigurationSetDoesNotExistException(
                    f"Configuration set <{configuration_set_name}> does not exist."
                )
            else:
                raise

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

        # the configuration set must exist
        if configuration_set_name not in backend.config_set:
            raise ConfigurationSetDoesNotExistException(
                f"Configuration set <{configuration_set_name}> does not exist."
            )

        # the event destination must exist
        if configuration_set_name not in backend.config_set_event_destination:
            raise EventDestinationDoesNotExistException(
                f"No EventDestination found for {configuration_set_name}"
            )

        if event_destination_name in backend.event_destinations:
            backend.event_destinations.pop(event_destination_name)
        else:
            # FIXME: inconsistent state
            LOGGER.warning("inconsistent state encountered in ses backend")

        backend.config_set_event_destination.pop(configuration_set_name)

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
        if tags:
            for tag in tags:
                tag_name = tag.get("Name", "")
                tag_value = tag.get("Value", "")
                if tag_name == "":
                    raise InvalidParameterValue("The tag name must be specified.")
                if tag_value == "":
                    raise InvalidParameterValue("The tag value must be specified.")
                if len(tag_name) > 255:
                    raise InvalidParameterValue("Tag name cannot exceed 255 characters.")
                if not re.match(ALLOWED_TAG_CHARS, tag_name):
                    raise InvalidParameterValue(
                        f"Invalid tag name <{tag_name}>: only alphanumeric ASCII characters, '_', and '-' are allowed.",
                    )
                if len(tag_value) > 255:
                    raise InvalidParameterValue("Tag value cannot exceed 255 characters.")
                if not re.match(ALLOWED_TAG_CHARS, tag_value):
                    raise InvalidParameterValue(
                        f"Invalid tag value <{tag_value}>: only alphanumeric ASCII characters, '_', and '-' are allowed.",
                    )

        response = call_moto(context)

        backend = get_ses_backend(context)
        emitter = SNSEmitter(context)
        recipients = recipients_from_destination(destination)

        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=response["MessageId"],
                sender_email=source,
                destination_addresses=recipients,
                tags=tags,
            )
            emitter.emit_send_event(payload, sns_destination_arn)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        text_part = message["Body"].get("Text", {}).get("Data")
        html_part = message["Body"].get("Html", {}).get("Data")

        save_for_retrospection(
            SentEmail(
                Id=response["MessageId"],
                Region=context.region,
                Destination=destination,
                Source=source,
                Subject=message["Subject"].get("Data"),
                Body=SentEmailBody(text_part=text_part, html_part=html_part),
            )
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
        recipients = recipients_from_destination(destination)

        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=response["MessageId"],
                sender_email=source,
                destination_addresses=recipients,
                tags=tags,
            )
            emitter.emit_send_event(payload, sns_destination_arn, emit_source_arn=False)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        save_for_retrospection(
            SentEmail(
                Id=response["MessageId"],
                Region=context.region,
                Source=source,
                Template=template,
                TemplateData=template_data,
                Destination=destination,
            )
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
        raw_data = to_str(raw_message["Data"])

        if source is None or not source.strip():
            LOGGER.debug("Raw email:\n%s\nEOT", raw_data)

            source = self.get_source_from_raw(raw_data)
            if not source:
                LOGGER.warning("Source not specified. Rejecting message.")
                raise MessageRejected()

        # TODO: On AWS, `destinations` is ignored if the `To` field is set in the raw email.
        destinations = destinations or []

        backend = get_ses_backend(context)
        message = backend.send_raw_email(source, destinations, raw_data)

        emitter = SNSEmitter(context)
        for event_destination in backend.config_set_event_destination.values():
            if not event_destination["Enabled"]:
                continue

            sns_destination_arn = event_destination.get("SNSDestination")
            if not sns_destination_arn:
                continue

            payload = SNSPayload(
                message_id=message.id,
                sender_email=source,
                destination_addresses=destinations,
                tags=tags,
            )
            emitter.emit_send_event(payload, sns_destination_arn)
            emitter.emit_delivery_event(payload, sns_destination_arn)

        save_for_retrospection(
            SentEmail(
                Id=message.id,
                Region=context.region,
                Source=source or message.source,
                RawData=raw_data,
            )
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


@dataclasses.dataclass(frozen=True)
class SNSPayload:
    message_id: str
    sender_email: Address
    destination_addresses: AddressList
    tags: Optional[MessageTagList]


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
        # topic must exist
        try:
            client.get_topic_attributes(TopicArn=sns_topic_arn)
        except ClientError as exc:
            if "NotFound" in exc.response["Error"]["Code"]:
                raise InvalidSNSDestinationException(f"SNS topic <{sns_topic_arn}> not found.")
            raise

        client.publish(
            TopicArn=sns_topic_arn,
            Message="Successfully validated SNS topic for Amazon SES event publishing.",
        )

    def emit_send_event(
        self, payload: SNSPayload, sns_topic_arn: str, emit_source_arn: bool = True
    ):
        now = datetime.now(tz=timezone.utc)

        tags = defaultdict(list)
        for every in payload.tags or []:
            tags[every["Name"]].append(every["Value"])

        event_payload = {
            "eventType": "Send",
            "mail": {
                "timestamp": now.isoformat(),
                "source": payload.sender_email,
                "sendingAccountId": self.context.account_id,
                "destination": payload.destination_addresses,
                "messageId": payload.message_id,
                "tags": tags,
            },
            "send": {},
        }

        if emit_source_arn:
            event_payload["mail"][
                "sourceArn"
            ] = f"arn:aws:ses:{self.context.region}:{self.context.account_id}:identity/{payload.sender_email}"

        client = self._client_for_topic(sns_topic_arn)
        try:
            client.publish(
                TopicArn=sns_topic_arn,
                Message=json.dumps(event_payload),
                Subject="Amazon SES Email Event Notification",
            )
        except ClientError:
            LOGGER.exception("sending SNS message")

    def emit_delivery_event(self, payload: SNSPayload, sns_topic_arn: str):
        now = datetime.now(tz=timezone.utc)

        tags = defaultdict(list)
        for every in payload.tags or []:
            tags[every["Name"]].append(every["Value"])

        event_payload = {
            "eventType": "Delivery",
            "mail": {
                "timestamp": now.isoformat(),
                "source": payload.sender_email,
                "sourceArn": f"arn:aws:ses:{self.context.region}:{self.context.account_id}:identity/{payload.sender_email}",
                "sendingAccountId": self.context.account_id,
                "destination": payload.destination_addresses,
                "messageId": payload.message_id,
                "tags": tags,
            },
            "delivery": {
                "recipients": payload.destination_addresses,
                "timestamp": now.isoformat(),
            },
        }
        client = self._client_for_topic(sns_topic_arn)
        try:
            client.publish(
                TopicArn=sns_topic_arn,
                Message=json.dumps(event_payload),
                Subject="Amazon SES Email Event Notification",
            )
        except ClientError:
            LOGGER.exception("sending SNS message")

    @staticmethod
    def _client_for_topic(topic_arn: str) -> "SNSClient":
        arn_parameters = arns.parse_arn(topic_arn)
        region = arn_parameters["region"]
        access_key_id = arn_parameters["account"]

        return connect_to(
            region_name=region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=TEST_AWS_SECRET_ACCESS_KEY,
        ).sns


class InvalidParameterValue(CommonServiceException):
    def __init__(self, message=None):
        super().__init__("InvalidParameterValue", status_code=400, message=message)
