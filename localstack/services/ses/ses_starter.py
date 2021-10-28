import base64
import json
import logging
import os
from datetime import date, datetime

from moto.ses.exceptions import MessageRejectedError
from moto.ses.models import SESBackend
from moto.ses.responses import EmailResponse as email_responses
from moto.ses.responses import ses_backend

from localstack import config
from localstack.services.infra import start_moto_server
from localstack.utils.common import mkdir, timestamp_millis, to_str

LOGGER = logging.getLogger(__name__)

DELETE_IDENTITY_RESPONSE = """<DeleteTemplateResponse xmlns="http://ses.amazonaws.com/doc/2010-12-01/">
    <DeleteTemplateResult/>
    <ResponseMetadata>
      <RequestId>d96bd875-9bf2-11e1-8ee7-c98a0037a2b6</RequestId>
    </ResponseMetadata>
</DeleteTemplateResponse>"""

GET_IDENTITY_VERIFICATION_ATTRIBUTES_RESPONSE = """<GetIdentityVerificationAttributesResponse xmlns="http://ses.amazonaws.com/doc/2010-12-01/">
    <GetIdentityVerificationAttributesResult>
    <VerificationAttributes>
    {% for resource in resources %}
        <entry>
            <key>{{ resource }}</key>
            <value>
                <VerificationStatus>Success</VerificationStatus>
                {% if '@' not in resource %}
                    <VerificationToken>QTKknzFg2J4ygwa+XvHAxUl1hyHoY0gVfZdfjIedHZ0=</VerificationToken>
                {% endif %}
            </value>
        </entry>
    {% endfor %}
    </VerificationAttributes>
    </GetIdentityVerificationAttributesResult>
    <ResponseMetadata>
        <RequestId>1d0c29f1-9bf3-11e1-8ee7-c98a0037a2b6</RequestId>
    </ResponseMetadata>
</GetIdentityVerificationAttributesResponse>"""


def apply_patches():
    def get_source_from_raw(raw_data):
        entities = raw_data.split("\n")
        for entity in entities:
            if "From: " in entity:
                return entity.replace("From: ", "").strip()

        return None

    email_responses_send_raw_email_orig = email_responses.send_raw_email

    def email_responses_send_raw_email(self):
        (source,) = self.querystring.get("Source", [""])
        if source.strip():
            return email_responses_send_raw_email_orig(self)

        raw_data = to_str(base64.b64decode(self.querystring.get("RawMessage.Data")[0]))

        LOGGER.debug("Raw email:\n%s" % raw_data)

        source = get_source_from_raw(raw_data)
        if not source:
            raise MessageRejectedError("Source not specified")

        self.querystring["Source"] = [source]
        return email_responses_send_raw_email_orig(self)

    email_responses.send_raw_email = email_responses_send_raw_email

    email_responses_send_email_orig = email_responses.send_email

    def email_responses_send_email(self):
        bodydatakey = "Message.Body.Text.Data"
        if "Message.Body.Html.Data" in self.querystring:
            bodydatakey = "Message.Body.Html.Data"

        body = self.querystring.get(bodydatakey)[0]
        source = self.querystring.get("Source")[0]
        subject = self.querystring.get("Message.Subject.Data")[0]
        destinations = {"ToAddresses": [], "CcAddresses": [], "BccAddresses": []}
        for dest_type in destinations:
            # consume up to 51 to allow exception
            for i in range(1, 52):
                field = "Destination.%s.member.%s" % (dest_type, i)
                address = self.querystring.get(field)
                if address is None:
                    break
                destinations[dest_type].append(address[0])

        LOGGER.debug(
            "Raw email\nFrom: %s\nTo: %s\nSubject: %s\nBody:\n%s"
            % (source, destinations, subject, body)
        )

        return email_responses_send_email_orig(self)

    email_responses.send_email = email_responses_send_email

    email_responses_list_templates_orig = email_responses.list_templates

    def list_templates(self):
        email_templates = ses_backend.list_templates()
        for template in email_templates:
            if isinstance(template["Timestamp"], (date, datetime)):
                # Hack to change the last digits to Java SDKv2 compatible format
                template["Timestamp"] = timestamp_millis(template["Timestamp"])
        return email_responses_list_templates_orig(self)

    email_responses.list_templates = list_templates

    def delete_template(self):
        template_name = self._get_param("TemplateName")
        templates = ses_backend.templates
        if template_name in templates:
            del templates[template_name]
        ses_backend.templates = templates
        template = self.response_template(DELETE_IDENTITY_RESPONSE)
        return template.render()

    email_responses.delete_template = delete_template

    def get_identity_verification_attributes(self):
        resources = [
            self.querystring[identity][0]
            for identity in self.querystring.keys()
            if "Identities.member" in identity
        ]
        template = self.response_template(GET_IDENTITY_VERIFICATION_ATTRIBUTES_RESPONSE)
        return template.render(resources=resources)

    email_responses.get_identity_verification_attributes = get_identity_verification_attributes

    def get_email_log_object(source, region, destinations, subject=None, body=None, raw_data=None):
        email = {"Source": source, "Region": region, "Destinations": destinations}

        if subject is not None:
            email["Subject"] = subject
        if body is not None:
            email["Body"] = body
        if raw_data is not None:
            email["RawData"] = raw_data

        return email

    def log_email_to_data_dir(id, email):
        ses_dir = os.path.join(config.DATA_DIR or config.TMP_FOLDER, "ses")
        mkdir(ses_dir)

        with open(os.path.join(ses_dir, id + ".json"), "w") as f:
            f.write(json.dumps(email))

    backend_send_email_orig = SESBackend.send_email

    def send_email_save_contents(self, source, subject, body, destinations, region):
        message = backend_send_email_orig(self, source, subject, body, destinations, region)

        log_email = get_email_log_object(source, region, destinations, subject, body)
        log_email_to_data_dir(message.id, log_email)

        return message

    SESBackend.send_email = send_email_save_contents

    backend_send_raw_email_orig = SESBackend.send_raw_email

    def send_raw_email_save_contents(self, source, destinations, raw_data, region):
        message = backend_send_raw_email_orig(self, source, destinations, raw_data, region)

        log_email = get_email_log_object(source, region, destinations, raw_data=raw_data)
        log_email_to_data_dir(message.id, log_email)

        return message

    SESBackend.send_raw_email = send_raw_email_save_contents

    backend_send_templated_email_template_orig = SESBackend.send_templated_email

    def send_templated_email_save_contents(
        self, source, template, template_data, destinations, region
    ):
        message = backend_send_templated_email_template_orig(
            self, source, template, template_data, destinations, region
        )

        ses_dir = os.path.join(config.DATA_DIR or config.TMP_FOLDER, "ses")
        mkdir(ses_dir)

        with open(os.path.join(ses_dir, message.id + ".json"), "w") as f:
            f.write(
                json.dumps(
                    {
                        "Source": source,
                        "Template": template,
                        "TemplateData": template_data,
                        "Destinations": destinations,
                        "Region": region,
                    }
                )
            )
        return message

    SESBackend.send_templated_email = send_templated_email_save_contents


def start_ses(port=None, backend_port=None, asynchronous=None, update_listener=None):
    port = port or config.PORT_SES
    apply_patches()
    return start_moto_server(
        key="ses",
        name="SES",
        port=port,
        backend_port=backend_port,
        asynchronous=asynchronous,
        update_listener=update_listener,
    )
