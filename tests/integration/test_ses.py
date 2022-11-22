import json
import os
from datetime import date, datetime

import pytest
import requests

import localstack.config as config
from localstack.constants import INTERNAL_RESOURCE_PATH
from localstack.services.ses.provider import EMAILS_ENDPOINT
from localstack.utils.strings import short_uid

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
        email = f"user-{short_uid()}@example.com"
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
        email = f"user-{short_uid()}@example.com"
        ses_client.verify_email_address(EmailAddress=email)

        # Send a regular message and a raw message
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

        raw_message_data = f"From: {email}\nTo: recipient@example.com\nSubject: test\n\nThis is the message body.\n\n"
        ses_client.send_raw_email(RawMessage={"Data": raw_message_data})

        # Ensure the message is saved to filesystem for retrospection
        with open(os.path.join(data_dir, "ses", message_id + ".json"), "r") as f:
            message = f.read()

        contents = json.loads(message)

        assert email == contents["Source"]
        assert "A_SUBJECT" == contents["Subject"]
        assert {"text_part": "A_MESSAGE", "html_part": "A_HTML"} == contents["Body"]
        assert ["success@example.com"] == contents["Destination"]["ToAddresses"]

        emails_url = config.get_edge_url() + INTERNAL_RESOURCE_PATH + EMAILS_ENDPOINT
        api_contents = requests.get(emails_url).json()
        api_contents = {msg["Id"]: msg for msg in api_contents["messages"]}
        assert len(api_contents) >= 1
        assert message_id in api_contents
        assert api_contents[message_id] == contents

        # Ensure messages can be filtered by email source via the REST endpoint
        emails_url = (
            config.get_edge_url()
            + INTERNAL_RESOURCE_PATH
            + EMAILS_ENDPOINT
            + "?email=none@example.com"
        )
        assert len(requests.get(emails_url).json()["messages"]) == 0
        emails_url = (
            config.get_edge_url() + INTERNAL_RESOURCE_PATH + EMAILS_ENDPOINT + f"?email={email}"
        )
        assert len(requests.get(emails_url).json()["messages"]) == 2

    def test_send_templated_email_can_retrospect(self, ses_client, create_template):
        # Test that sent emails can be retrospected through saved file and API access
        data_dir = config.dirs.data or config.dirs.tmp
        email = f"user-{short_uid()}@example.com"
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

    def test_clone_receipt_rule_set(self, ses_client):
        # Test that rule set is cloned properly

        original_rule_set_name = "RuleSetToClone"
        rule_set_name = "RuleSetToCreate"
        rule_names = ["MyRule1", "MyRule2"]

        # Create mock rule set called RuleSetToClone
        ses_client.create_receipt_rule_set(RuleSetName=original_rule_set_name)
        ses_client.create_receipt_rule(
            After="",
            Rule={
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": "MyBucket",
                            "ObjectKeyPrefix": "email",
                        },
                    },
                ],
                "Enabled": True,
                "Name": rule_names[0],
                "ScanEnabled": True,
                "TlsPolicy": "Optional",
            },
            RuleSetName=original_rule_set_name,
        )
        ses_client.create_receipt_rule(
            After="",
            Rule={
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": "MyBucket",
                            "ObjectKeyPrefix": "template",
                        },
                    },
                ],
                "Enabled": True,
                "Name": rule_names[1],
                "ScanEnabled": True,
                "TlsPolicy": "Optional",
            },
            RuleSetName=original_rule_set_name,
        )

        # Clone RuleSetToClone into RuleSetToCreate
        ses_client.clone_receipt_rule_set(
            RuleSetName=rule_set_name, OriginalRuleSetName=original_rule_set_name
        )

        original_rule_set = ses_client.describe_receipt_rule_set(RuleSetName=original_rule_set_name)
        rule_set = ses_client.describe_receipt_rule_set(RuleSetName=rule_set_name)

        assert original_rule_set["Metadata"]["Name"] == original_rule_set_name
        assert rule_set["Metadata"]["Name"] == rule_set_name
        assert original_rule_set["Rules"] == rule_set["Rules"]
        assert [x["Name"] for x in rule_set["Rules"]] == rule_names

    @pytest.mark.only_localstack
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Signature",
            "$..SigningCertURL",
            "$..TopicArn",
            "$..UnsubscribeURL",
            "$..Message.delivery.processingTimeMillis",
            "$..Message.delivery.reportingMTA",
            "$..Message.delivery.smtpResponse",
            "$..Message.mail.messageId",
            "$..Message.mail.commonHeaders",
            "$..Message.mail.headers",
            "$..Message.mail.headersTruncated",
            "$..Message.mail.tags",
            "$..Message.mail.timestamp",
        ]
    )
    def test_ses_sns_topic_integration(
        self,
        ses_client,
        sqs_queue,
        sns_topic,
        sns_create_sqs_subscription,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        ses_verify_identity,
        sqs_receive_num_messages,
        snapshot,
    ):
        """
        Repro for #7184 - test that this test is not runnable in the sandbox account since it
        requires a
        validated email address. We do not have support for this yet.
        """
        sender_email_address = f"repro-7184-{short_uid()}@example.com"
        recipient_email_address = f"repro-7184-{short_uid()}@example.com"

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email_address, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email_address, "<recipient-email-address>"),
            ]
            + snapshot.transform.sns_api()
        )

        ses_verify_identity(sender_email_address)
        ses_verify_identity(recipient_email_address)

        # create queue to listen for for SES -> SNS events
        topic_arn = sns_topic["Attributes"]["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        # create the config set
        config_set_name = f"config-set-{short_uid()}"
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        # send an email to trigger the SNS message and SQS message
        destination = {
            "ToAddresses": [recipient_email_address],
        }
        message = {
            "Subject": {
                "Data": "foo subject",
            },
            "Body": {
                "Text": {
                    "Data": "saml body",
                },
            },
        }
        ses_client.send_email(
            Destination=destination,
            Message=message,
            ConfigurationSetName=config_set_name,
            Source=sender_email_address,
        )

        messages = sqs_receive_num_messages(sqs_queue, 3)
        snapshot.match("messages", messages)
