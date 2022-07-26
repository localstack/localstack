import json
import logging
import os
from datetime import date, datetime, time
from typing import Any, Dict, Optional

from moto.ses import ses_backends
from moto.ses.models import SESBackend

from localstack import config
from localstack.aws.api import RequestContext, handler
from localstack.aws.api.ses import (
    Address,
    AddressList,
    AmazonResourceName,
    ConfigurationSetName,
    DeleteTemplateResponse,
    Destination,
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
    SendEmailResponse,
    SendRawEmailResponse,
    SendTemplatedEmailResponse,
    SesApi,
    TemplateData,
    TemplateName,
    VerificationAttributes,
    VerificationStatus,
)
from localstack.services.internal import get_internal_apis
from localstack.services.moto import call_moto
from localstack.services.plugins import ServiceLifecycleHook
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
            if filter_source in (msg["Source"], None, ""):
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


def ses_global_backend() -> SESBackend:
    return ses_backends["global"]


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

    @handler("ListTemplates")
    def list_templates(
        self, context: RequestContext, next_token: NextToken = None, max_items: MaxItems = None
    ) -> ListTemplatesResponse:
        for template in ses_global_backend().list_templates():
            if isinstance(template["Timestamp"], (date, datetime)):
                template["Timestamp"] = timestamp_millis(template["Timestamp"])
        return call_moto(context)

    @handler("DeleteTemplate")
    def delete_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DeleteTemplateResponse:
        if template_name in ses_global_backend().templates:
            del ses_global_backend().templates[template_name]
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
        raw_data = to_str(raw_message["Data"])

        if source is None or not source.strip():
            LOGGER.debug("Raw email:\n%s\nEOT", raw_data)

            source = self.get_source_from_raw(raw_data)
            if not source:
                LOGGER.warning("Source not specified. Rejecting message.")
                raise MessageRejected()

        message = ses_global_backend().send_raw_email(
            source, destinations, raw_data, context.region
        )

        save_for_retrospection(
            message.id, context.region, Source=source, Destination=destinations, RawData=raw_data
        )

        return SendRawEmailResponse(MessageId=message.id)
