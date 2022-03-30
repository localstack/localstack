import json
import logging
import os
from abc import ABC
from datetime import date, datetime
from typing import Any, Dict, Optional

from moto.ses import ses_backend

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
from localstack.services.moto import call_moto
from localstack.utils.files import mkdir
from localstack.utils.strings import to_str
from localstack.utils.time import timestamp_millis

LOGGER = logging.getLogger(__name__)


class SesProvider(SesApi, ABC):

    #
    # Helpers
    #

    def log_email_to_data_dir(self, id: str, email: dict):
        """Save a copy of the sent email to filesystem for debugging purposes."""
        ses_dir = os.path.join(config.dirs.data or config.dirs.tmp, "ses")

        mkdir(ses_dir)
        path = os.path.join(ses_dir, id + ".json")

        with open(path, "w") as f:
            f.write(json.dumps(email))

        LOGGER.debug(f"Email saved at: {path}")

    def get_email_log_object(
        self, source, region, destinations, subject=None, body=None, raw_data=None
    ) -> Dict[str, Any]:
        """Build a structured object representing an email."""
        email = {"Source": source, "Region": region, "Destinations": destinations}

        if subject is not None:
            email["Subject"] = subject
        if body is not None:
            email["Body"] = body
        if raw_data is not None:
            email["RawData"] = raw_data

        return email

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
        for template in ses_backend.list_templates():
            if isinstance(template["Timestamp"], (date, datetime)):
                template["Timestamp"] = timestamp_millis(template["Timestamp"])
        return call_moto(context)

    @handler("DeleteTemplate")
    def delete_template(
        self, context: RequestContext, template_name: TemplateName
    ) -> DeleteTemplateResponse:
        if template_name in ses_backend.templates:
            del ses_backend.templates[template_name]
        return DeleteTemplateResponse()

    @handler("GetIdentityVerificationAttributes")
    def get_identity_verification_attributes(
        self, context: RequestContext, identities: IdentityList
    ) -> GetIdentityVerificationAttributesResponse:
        attributes: VerificationAttributes = {}

        for identity in identities:
            attributes[identity] = IdentityVerificationAttributes(
                VerificationStatus=VerificationStatus.Success,
            )

        return GetIdentityVerificationAttributesResponse(
            VerificationAttributes=attributes,
        )

    @handler("SendEmail", expand=True)
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

        log_obj = self.get_email_log_object(
            source, context.region, destination, subject=message["Subject"], body=message["Body"]
        )
        self.log_email_to_data_dir(response["MessageId"], log_obj)

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
        message = ses_backend.send_templated_email(
            source, [template], template_data, destination, context.region
        )

        self.log_email_to_data_dir(
            message.id,
            {
                "Source": source,
                "Template": template,
                "TemplateData": template_data,
                "Destinations": destination,
                "Region": context.region,
            },
        )

        return SendTemplatedEmailResponse(MessageId=message.id)

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

        message = ses_backend.send_raw_email(source, destinations, raw_data, context.region)

        log_obj = self.get_email_log_object(source, context.region, destinations, raw_data=raw_data)
        self.log_email_to_data_dir(message.id, log_obj)

        return SendRawEmailResponse(MessageId=message.id)
