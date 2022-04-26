import json
import os
from datetime import date, datetime

import pytest
import requests

import localstack.config as config
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.services.ses.provider import EMAILS_ENDPOINT

TEST_TEMPLATE_ATTRIBUTES = {
    "TemplateName": "hello-world",
    "SubjectPart": "Subject test",
    "TextPart": "hello\nworld",
    "HtmlPart": "hello<br/>world",
}


@pytest.fixture
def create_template(ses_client):
    created_template_names = []

    def _create_template(Template):
        ses_client.create_template(Template=Template)
        created_template_names.append(Template["TemplateName"])

    yield _create_template

    for name in created_template_names:
        ses_client.delete_template(TemplateName=name)


class TestSES:
    def test_list_templates(self, ses_client, create_template):
        create_template(Template=TEST_TEMPLATE_ATTRIBUTES)
        templ_list = ses_client.list_templates()["TemplatesMetadata"]
        assert 1 == len(templ_list)
        created_template = templ_list[0]
        assert TEST_TEMPLATE_ATTRIBUTES["TemplateName"] == created_template["Name"]
        assert type(created_template["CreatedTimestamp"]) in (date, datetime)

        # Should not fail after 2 consecutive tries
        templ_list = ses_client.list_templates()["TemplatesMetadata"]
        assert 1 == len(templ_list)
        created_template = templ_list[0]
        assert TEST_TEMPLATE_ATTRIBUTES["TemplateName"] == created_template["Name"]
        assert type(created_template["CreatedTimestamp"]) in (date, datetime)

    def test_delete_template(self, ses_client, create_template):
        templ_list = ses_client.list_templates()["TemplatesMetadata"]
        assert 0 == len(templ_list)
        create_template(Template=TEST_TEMPLATE_ATTRIBUTES)
        templ_list = ses_client.list_templates()["TemplatesMetadata"]
        assert 1 == len(templ_list)
        ses_client.delete_template(TemplateName=TEST_TEMPLATE_ATTRIBUTES["TemplateName"])
        templ_list = ses_client.list_templates()["TemplatesMetadata"]
        assert 0 == len(templ_list)

    def test_get_identity_verification_attributes(self, ses_client):
        domain = "example.com"
        email = "user@example.com"
        test_values = [domain, email]
        response = ses_client.get_identity_verification_attributes(Identities=test_values)[
            "VerificationAttributes"
        ]
        assert 2 == len(response)
        for value in test_values:
            assert "Success" == response[value]["VerificationStatus"]
        assert "VerificationToken" in response[domain]
        assert "VerificationToken" not in response[email]

    def test_send_email_can_retrospect(self, ses_client):
        # Test that sent emails can be retrospected through saved file and API access
        data_dir = config.dirs.data or config.dirs.tmp
        email = "user@example.com"
        ses_client.verify_email_address(EmailAddress=email)
        message = ses_client.send_email(
            Source=email,
            Message={
                "Subject": {
                    "Data": "A_SUBJECT",
                },
                "Body": {
                    "Text": {
                        "Data": "A_MESSAGE",
                    },
                    "Html": {
                        "Data": "A_HTML",
                    },
                },
            },
            Destination={
                "ToAddresses": ["success@example.com"],
            },
        )
        message_id = message["MessageId"]

        with open(os.path.join(data_dir, "ses", message_id + ".json"), "r") as f:
            message = f.read()

        contents = json.loads(message)

        assert email == contents["Source"]
        assert "A_SUBJECT" == contents["Subject"]
        assert "A_MESSAGE" == contents["Body"]
        assert "A_HTML" == contents["HtmlBody"]
        assert ["success@example.com"] == contents["Destination"]["ToAddresses"]

        emails_url = config.get_edge_url() + INTERNAL_RESOURCE_PATH + EMAILS_ENDPOINT
        api_contents = requests.get(emails_url).json()
        api_contents = {msg["Id"]: msg for msg in api_contents["messages"]}
        assert message_id in api_contents
        assert api_contents[message_id] == contents

    def test_send_templated_email_can_retrospect(self, ses_client, create_template):
        # Test that sent emails can be retrospected through saved file and API access
        data_dir = config.dirs.data or config.dirs.tmp
        email = "user@example.com"
        ses_client.verify_email_address(EmailAddress=email)
        ses_client.delete_template(TemplateName=TEST_TEMPLATE_ATTRIBUTES["TemplateName"])
        create_template(Template=TEST_TEMPLATE_ATTRIBUTES)

        message = ses_client.send_templated_email(
            Source=email,
            Template=TEST_TEMPLATE_ATTRIBUTES["TemplateName"],
            TemplateData='{"A key": "A value"}',
            Destination={
                "ToAddresses": ["success@example.com"],
            },
        )
        message_id = message["MessageId"]

        with open(os.path.join(data_dir, "ses", message_id + ".json"), "r") as f:
            message = f.read()

        contents = json.loads(message)

        assert email == contents["Source"]
        assert TEST_TEMPLATE_ATTRIBUTES["TemplateName"] == contents["Template"]
        assert '{"A key": "A value"}' == contents["TemplateData"]
        assert ["success@example.com"] == contents["Destination"]["ToAddresses"]

        api_contents = requests.get("http://localhost:4566/_localstack/ses").json()
        api_contents = {msg["Id"]: msg for msg in api_contents["messages"]}
        assert message_id in api_contents
        assert api_contents[message_id] == contents
