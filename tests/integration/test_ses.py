import json
import os
from datetime import date, datetime
from typing import TYPE_CHECKING, Optional, Tuple

import pytest
import requests
from botocore.exceptions import ClientError

import localstack.config as config
from localstack.services.ses.provider import EMAILS_ENDPOINT
from localstack.utils.strings import short_uid

if TYPE_CHECKING:
    from mypy_boto3_ses import SESClient

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


@pytest.fixture
def setup_email_addresses(ses_verify_identity):
    """
    If the test is running against AWS then assume the email addresses passed are already
    verified, and passes the given email addresses through. Otherwise, it generates two random
    email addresses and verifies them.
    """

    def inner(
        sender_email_address: Optional[str] = None, recipient_email_address: Optional[str] = None
    ) -> Tuple[str, str]:
        if os.getenv("TEST_TARGET") == "AWS_CLOUD":
            if sender_email_address is None:
                raise ValueError(
                    "sender_email_address must be specified to run this test against AWS"
                )
            if recipient_email_address is None:
                raise ValueError(
                    "recipient_email_address must be specified to run this test against AWS"
                )
        else:
            # overwrite the given parameters with localstack specific ones
            sender_email_address = f"sender-{short_uid()}@example.com"
            recipient_email_address = f"recipient-{short_uid()}@example.com"
            ses_verify_identity(sender_email_address)
            ses_verify_identity(recipient_email_address)

        return sender_email_address, recipient_email_address

    return inner


def sort_mail_sqs_messages(message):
    if "Successfully validated" in message["Message"]:
        return 0
    elif json.loads(message["Message"])["eventType"] == "Send":
        return 1
    elif json.loads(message["Message"])["eventType"] == "Delivery":
        return 2
    else:
        raise ValueError("bad")


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

        def _read_message_from_filesystem(message_id: str) -> dict:
            """Given a message ID, read the message from filesystem and deserialise it."""
            data_dir = config.dirs.data or config.dirs.tmp
            with open(os.path.join(data_dir, "ses", message_id + ".json"), "r") as f:
                message = f.read()
            return json.loads(message)

        email = f"user-{short_uid()}@example.com"
        ses_client.verify_email_address(EmailAddress=email)

        # Send a regular message
        message1 = ses_client.send_email(
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
        message1_id = message1["MessageId"]

        # Ensure saved message
        contents1 = _read_message_from_filesystem(message1_id)
        assert contents1["Id"] == message1_id
        assert contents1["Timestamp"]
        assert contents1["Region"]
        assert contents1["Source"] == email
        assert contents1["Destination"] == {"ToAddresses": ["success@example.com"]}
        assert contents1["Subject"] == "A_SUBJECT"
        assert contents1["Body"] == {"text_part": "A_MESSAGE", "html_part": "A_HTML"}
        assert "RawData" not in contents1

        # Send a raw message
        raw_message_data = f"From: {email}\nTo: recipient@example.com\nSubject: test\n\nThis is the message body.\n\n"
        message2 = ses_client.send_raw_email(RawMessage={"Data": raw_message_data})
        message2_id = message2["MessageId"]

        # Ensure saved raw message
        contents2 = _read_message_from_filesystem(message2_id)
        assert contents2["Id"] == message2_id
        assert contents2["Timestamp"]
        assert contents2["Region"]
        assert contents2["Source"] == email
        assert contents2["RawData"] == raw_message_data
        assert "Destination" not in contents2
        assert "Subject" not in contents2
        assert "Body" not in contents2

        # Ensure all sent messages can be retrieved using the API endpoint
        emails_url = config.get_edge_url() + EMAILS_ENDPOINT
        api_contents = requests.get(emails_url).json()
        api_contents = {msg["Id"]: msg for msg in api_contents["messages"]}
        assert len(api_contents) >= 1
        assert message1_id in api_contents
        assert message2_id in api_contents
        assert api_contents[message1_id] == contents1
        assert api_contents[message2_id] == contents2

        # Ensure messages can be filtered by email source via the REST endpoint
        emails_url = config.get_edge_url() + EMAILS_ENDPOINT + "?email=none@example.com"
        assert len(requests.get(emails_url).json()["messages"]) == 0
        emails_url = config.get_edge_url() + EMAILS_ENDPOINT + f"?email={email}"
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
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Message.delivery.processingTimeMillis",
            "$..Message.delivery.reportingMTA",
            "$..Message.delivery.smtpResponse",
            "$..Message.mail.commonHeaders",
            "$..Message.mail.headers",
            "$..Message.mail.headersTruncated",
            "$..Message.mail.tags.'ses:caller-identity'",
            "$..Message.mail.tags.'ses:configuration-set'",
            "$..Message.mail.tags.'ses:from-domain'",
            "$..Message.mail.tags.'ses:operation'",
            "$..Message.mail.tags.'ses:outgoing-ip'",
            "$..Message.mail.tags.'ses:source-ip'",
            "$..Message.mail.timestamp",
        ]
    )
    def test_ses_sns_topic_integration_send_email(
        self,
        ses_client,
        sqs_queue,
        sns_topic,
        sns_create_sqs_subscription,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
    ):
        """
        Repro for #7184 - test that this test is not runnable in the sandbox account since it
        requires a validated email address. We do not have support for this yet.
        """

        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email_address, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email_address, "<recipient-email-address>"),
                snapshot.transform.key_value("messageId"),
            ]
            + snapshot.transform.sns_api()
        )

        # create queue to listen for SES -> SNS events
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
            Tags=[
                {
                    "Name": "custom-tag",
                    "Value": "tag-value",
                }
            ],
        )

        messages = sqs_receive_num_messages(sqs_queue, 3)
        messages.sort(key=sort_mail_sqs_messages)
        snapshot.match("messages", messages)

    @pytest.mark.only_localstack
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Message.delivery.processingTimeMillis",
            "$..Message.delivery.reportingMTA",
            "$..Message.delivery.smtpResponse",
            "$..Message.mail.commonHeaders",
            "$..Message.mail.headers",
            "$..Message.mail.headersTruncated",
            "$..Message.mail.tags.'ses:caller-identity'",
            "$..Message.mail.tags.'ses:configuration-set'",
            "$..Message.mail.tags.'ses:from-domain'",
            "$..Message.mail.tags.'ses:operation'",
            "$..Message.mail.tags.'ses:outgoing-ip'",
            "$..Message.mail.tags.'ses:source-ip'",
            "$..Message.mail.timestamp",
        ]
    )
    def test_ses_sns_topic_integration_send_templated_email(
        self,
        ses_client,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        ses_email_template,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_queue,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email_address, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email_address, "<recipient-email-address>"),
                snapshot.transform.key_value("messageId"),
            ]
            + snapshot.transform.sns_api()
        )

        template_name = f"template-{short_uid()}"
        ses_email_template(template_name, "Test template")

        # create queue to listen for SES -> SNS events
        topic_arn = sns_create_topic()["TopicArn"]
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
        ses_client.send_templated_email(
            Destination=destination,
            Template=template_name,
            TemplateData=json.dumps({}),
            ConfigurationSetName=config_set_name,
            Source=sender_email_address,
            Tags=[
                {
                    "Name": "custom-tag",
                    "Value": "tag-value",
                }
            ],
        )

        messages = sqs_receive_num_messages(sqs_queue, 3)
        messages.sort(key=sort_mail_sqs_messages)
        snapshot.match("messages", messages)

    @pytest.mark.only_localstack
    @pytest.mark.aws_validated
    @pytest.mark.skip_snapshot_verify(
        paths=[
            "$..Message.delivery.processingTimeMillis",
            "$..Message.delivery.reportingMTA",
            "$..Message.delivery.smtpResponse",
            "$..Message.mail.commonHeaders",
            "$..Message.mail.headers",
            "$..Message.mail.headersTruncated",
            "$..Message.mail.tags.'ses:caller-identity'",
            "$..Message.mail.tags.'ses:configuration-set'",
            "$..Message.mail.tags.'ses:from-domain'",
            "$..Message.mail.tags.'ses:operation'",
            "$..Message.mail.tags.'ses:outgoing-ip'",
            "$..Message.mail.tags.'ses:source-ip'",
            "$..Message.mail.timestamp",
        ]
    )
    def test_ses_sns_topic_integration_send_raw_email(
        self,
        ses_client,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_queue,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email_address, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email_address, "<recipient-email-address>"),
                snapshot.transform.key_value("messageId"),
            ]
            + snapshot.transform.sns_api()
        )

        # create queue to listen for SES -> SNS events
        topic_arn = sns_create_topic()["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        # create the config set
        config_set_name = f"config-set-{short_uid()}"
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        # send an email to trigger the SNS message and SQS message
        ses_client.send_raw_email(
            Destinations=[recipient_email_address],
            RawMessage={
                "Data": b"",
            },
            ConfigurationSetName=config_set_name,
            Source=sender_email_address,
            Tags=[
                {
                    "Name": "custom-tag",
                    "Value": "tag-value",
                }
            ],
        )

        messages = sqs_receive_num_messages(sqs_queue, 3)
        messages.sort(key=sort_mail_sqs_messages)
        snapshot.match("messages", messages)

    def test_cannot_create_event_for_no_topic(
        self, ses_configuration_set, ses_client, snapshot, account_id
    ):
        topic_name = f"missing-topic-{short_uid()}"
        topic_arn = f"arn:aws:sns:{ses_client.meta.region_name}:{account_id}:{topic_name}"
        snapshot.add_transformer(snapshot.transform.regex(topic_arn, "<arn>"))

        config_set_name = f"config-set-{short_uid()}"
        ses_configuration_set(config_set_name)

        event_destination_name = f"config-set-event-destination-{short_uid()}"

        # check if job is gone
        with pytest.raises(ClientError) as e_info:
            ses_client.create_configuration_set_event_destination(
                ConfigurationSetName=config_set_name,
                EventDestination={
                    "Name": event_destination_name,
                    "Enabled": True,
                    "MatchingEventTypes": ["send", "bounce", "delivery", "open", "click"],
                    "SNSDestination": {
                        "TopicARN": topic_arn,
                    },
                },
            )
        snapshot.match("create-error", e_info.value.response)

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
            "$..Message.mail.commonHeaders",
            "$..Message.mail.headers",
            "$..Message.mail.headersTruncated",
            "$..Message.mail.tags",
            "$..Message.mail.timestamp",
        ]
    )
    def test_sending_to_deleted_topic(
        self,
        ses_client,
        sqs_queue,
        sns_create_sqs_subscription,
        sns_client,
        sns_topic,
        sns_wait_for_topic_delete,
        ses_configuration_set,
        sqs_receive_num_messages,
        ses_configuration_set_sns_event_destination,
        setup_email_addresses,
        snapshot,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()

        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email_address, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email_address, "<recipient-email-address>"),
            ]
            + snapshot.transform.sns_api()
        )

        topic_arn = sns_topic["Attributes"]["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        config_set_name = f"config-set-{short_uid()}"
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

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

        # FIXME: there will be an issue with the fixture deleting the topic. Currently it logs
        #  only, but this may change in the future.
        sns_client.delete_topic(TopicArn=topic_arn)
        sns_wait_for_topic_delete(topic_arn=topic_arn)

        ses_client.send_email(
            Destination=destination,
            Message=message,
            ConfigurationSetName=config_set_name,
            Source=sender_email_address,
        )

        messages = sqs_receive_num_messages(sqs_queue, 1)
        snapshot.match("messages", messages)

    def test_creating_event_destination_without_configuration_set(
        self, sns_topic, ses_client: "SESClient", snapshot
    ):
        config_set_name = f"nonexistent-configuration-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))

        topic_arn = sns_topic["Attributes"]["TopicArn"]
        event_destination_name = f"event-destination-{short_uid()}"
        with pytest.raises(ClientError) as e_info:
            ses_client.create_configuration_set_event_destination(
                ConfigurationSetName=config_set_name,
                EventDestination={
                    "Name": event_destination_name,
                    "Enabled": True,
                    "MatchingEventTypes": ["send", "bounce", "delivery", "open", "click"],
                    "SNSDestination": {
                        "TopicARN": topic_arn,
                    },
                },
            )
        snapshot.match("create-error", e_info.value.response)

    def test_deleting_non_existent_configuration_set(self, ses_client, snapshot):
        config_set_name = f"config-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))

        with pytest.raises(ClientError) as e_info:
            ses_client.delete_configuration_set(ConfigurationSetName=config_set_name)
        snapshot.match("delete-error", e_info.value.response)

    def test_deleting_non_existent_configuration_set_event_destination(
        self, ses_configuration_set, ses_client, snapshot
    ):
        config_set_name = f"config-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))
        ses_configuration_set(config_set_name)

        event_destination_name = f"non-existent-configuration-set-{short_uid()}"
        # check if job is gone
        with pytest.raises(ClientError) as e_info:
            ses_client.delete_configuration_set_event_destination(
                ConfigurationSetName=config_set_name,
                EventDestinationName=event_destination_name,
            )
        snapshot.match("delete-error", e_info.value.response)

    def test_trying_to_delete_event_destination_from_non_existent_configuration_set(
        self,
        ses_configuration_set,
        ses_client,
        ses_configuration_set_sns_event_destination,
        sns_topic,
        snapshot,
    ):
        config_set_name = f"config-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))

        ses_configuration_set(config_set_name)

        event_destination_name = f"event-destination-{short_uid()}"
        snapshot.add_transformer(
            snapshot.transform.regex(event_destination_name, "<event-destination>")
        )
        topic_arn = sns_topic["Attributes"]["TopicArn"]
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        with pytest.raises(ClientError) as e_info:
            ses_client.delete_configuration_set_event_destination(
                ConfigurationSetName="non-existent-configuration-set",
                EventDestinationName=event_destination_name,
            )
        snapshot.match("delete-error", e_info.value.response)
