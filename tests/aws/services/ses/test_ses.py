import contextlib
import json
import os
from datetime import date, datetime
from typing import Optional, Tuple

import pytest
import requests
from botocore.exceptions import ClientError

import localstack.config as config
from localstack.services.ses.provider import EMAILS, EMAILS_ENDPOINT
from localstack.testing.aws.util import is_aws_cloud
from localstack.testing.pytest import markers
from localstack.utils.strings import short_uid
from localstack.utils.sync import retry

SAMPLE_TEMPLATE = {
    "TemplateName": "hello-world",
    "SubjectPart": "Subject test",
    "TextPart": "hello\nworld",
    "HtmlPart": "hello<br/>world",
}

SAMPLE_SIMPLE_EMAIL = {
    "Subject": {
        "Data": "SOME_SUBJECT",
    },
    "Body": {
        "Text": {
            "Data": "SOME_MESSAGE",
        },
        "Html": {
            "Data": "<p>SOME_HTML</p>",
        },
    },
}


@pytest.fixture
def create_template(aws_client):
    created_template_names = []

    def _create_template(template):
        response = aws_client.ses.create_template(Template=template)
        created_template_names.append(template["TemplateName"])
        return response

    yield _create_template

    for name in created_template_names:
        aws_client.ses.delete_template(TemplateName=name)


@pytest.fixture
def ses_create_receipt_rule_set(aws_client):
    receipt_rule_sets = []

    def _create(**kwargs):
        response = aws_client.ses.create_receipt_rule_set(**kwargs)
        receipt_rule_sets.append(kwargs.get("RuleSetName"))
        return response

    yield _create

    for name in receipt_rule_sets:
        with contextlib.suppress(ClientError):
            aws_client.ses.delete_receipt_rule_set(RuleSetName=name)


@pytest.fixture
def ses_clone_receipt_rule_set(aws_client):
    receipt_rule_sets = []

    def _clone(**kwargs):
        response = aws_client.ses.clone_receipt_rule_set(**kwargs)
        receipt_rule_sets.append(kwargs.get("RuleSetName"))
        return response

    yield _clone

    for name in receipt_rule_sets:
        with contextlib.suppress(ClientError):
            aws_client.ses.delete_receipt_rule_set(RuleSetName=name)


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
        if is_aws_cloud():
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


@pytest.fixture
def setup_sender_email_address(ses_verify_identity):
    """
    If the test is running against AWS then assume the email address passed is already
    verified, and passes the given email address through. Otherwise, it generates one random
    email address and verify them.
    """

    def inner(sender_email_address: Optional[str] = None) -> str:
        if is_aws_cloud():
            if sender_email_address is None:
                raise ValueError(
                    "sender_email_address must be specified to run this test against AWS"
                )
        else:
            # overwrite the given parameters with localstack specific ones
            sender_email_address = f"sender-{short_uid()}@example.com"
            ses_verify_identity(sender_email_address)

        return sender_email_address

    return inner


@pytest.fixture
def add_snapshot_transformer_for_sns_event(snapshot):
    def _inner(sender_email, recipient_email, config_set_name):
        snapshot.add_transformers_list(
            [
                snapshot.transform.regex(sender_email, "<sender-email-address>"),
                snapshot.transform.regex(recipient_email, "<recipient-email-address>"),
                snapshot.transform.regex(config_set_name, "<config-set-name>"),
                snapshot.transform.key_value("messageId"),
                snapshot.transform.key_value(
                    "processingTimeMillis",
                    value_replacement="processing-time",
                    reference_replacement=False,
                ),
                snapshot.transform.jsonpath(
                    "$..Message.mail.tags.'ses:outgoing-ip'[0]", value_replacement="ses-outgoing-ip"
                ),
                snapshot.transform.jsonpath(
                    "$..Message.mail.tags.'ses:source-ip'[0]", value_replacement="ses-source-ip"
                ),
                snapshot.transform.jsonpath(
                    "$..Message.mail.tags.'ses:caller-identity'[0]",
                    value_replacement="ses-caller-identity",
                ),
                snapshot.transform.jsonpath(
                    "$..Message.mail.tags.'ses:from-domain'[0]", value_replacement="ses-from-domain"
                ),
                snapshot.transform.jsonpath(
                    "$..Message.mail.timestamp",
                    value_replacement="mail-timestamp",
                    reference_replacement=False,
                ),
            ]
            + snapshot.transform.sns_api()
        )

    return _inner


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
    @markers.aws.validated
    def test_list_templates(self, create_template, aws_client, snapshot):
        create_templ = create_template(template=SAMPLE_TEMPLATE)
        snapshot.match("create-template", create_templ)

        list_templates = aws_client.ses.list_templates()
        snapshot.match("list-templates-1", list_templates)

        assert len(list_templates["TemplatesMetadata"]) == 1
        created_template = list_templates["TemplatesMetadata"][0]
        assert created_template["Name"] == SAMPLE_TEMPLATE["TemplateName"]
        assert type(created_template["CreatedTimestamp"]) in (date, datetime)

        # Should not fail after 2 consecutive tries
        list_templates = aws_client.ses.list_templates()
        snapshot.match("list-templates-2", list_templates)

        assert len(list_templates["TemplatesMetadata"]) == 1
        created_template = list_templates["TemplatesMetadata"][0]
        assert created_template["Name"] == SAMPLE_TEMPLATE["TemplateName"]
        assert type(created_template["CreatedTimestamp"]) in (date, datetime)

    @markers.aws.validated
    def test_delete_template(self, create_template, aws_client, snapshot):
        list_templates = aws_client.ses.list_templates()
        snapshot.match("list-templates-empty", list_templates)
        assert len(list_templates["TemplatesMetadata"]) == 0

        create_template(template=SAMPLE_TEMPLATE)

        list_templates = aws_client.ses.list_templates()
        snapshot.match("list-templates-after-create", list_templates)
        assert len(list_templates["TemplatesMetadata"]) == 1

        delete_template = aws_client.ses.delete_template(
            TemplateName=SAMPLE_TEMPLATE["TemplateName"]
        )
        snapshot.match("delete-template", delete_template)

        list_templates = aws_client.ses.list_templates()
        snapshot.match("list-templates-after-delete", list_templates)
        assert len(list_templates["TemplatesMetadata"]) == 0

    @markers.aws.manual_setup_required
    def test_get_identity_verification_attributes_for_email(
        self, aws_client, snapshot, setup_sender_email_address
    ):
        email_address = setup_sender_email_address()
        response = aws_client.ses.get_identity_verification_attributes(Identities=[email_address])
        verif_attrs = response["VerificationAttributes"][email_address]
        assert verif_attrs["VerificationStatus"] == "Success"
        assert "VerificationToken" not in verif_attrs

    @markers.aws.needs_fixing
    def test_get_identity_verification_attributes_for_domain(self, aws_client):
        # need to have access to a domain and its DNS configuration, and to validate it with DKIM on SES console.
        domain = "example.com"
        response = aws_client.ses.get_identity_verification_attributes(Identities=[domain])

        verif_attrs = response["VerificationAttributes"]
        assert len(verif_attrs) == 1
        assert "Success" == verif_attrs[domain]["VerificationStatus"]
        assert "VerificationToken" in verif_attrs[domain]

    @markers.aws.needs_fixing  # TODO: couldn't verify on AWS, the Quota would not go up, maybe due to Sandbox account
    def test_sent_message_counter(
        self, create_template, aws_client, snapshot, setup_email_addresses
    ):
        # Ensure all email send operations correctly update the `sent` email counter

        def _assert_sent_quota(expected_counter: int) -> dict:
            _send_quota = aws_client.ses.get_send_quota()
            assert _send_quota["SentLast24Hours"] == expected_counter
            return _send_quota

        retries = 10 if is_aws_cloud() else 1

        sender_email, recipient_email = setup_email_addresses()
        send_quota = aws_client.ses.get_send_quota()
        snapshot.match("get-quota-0", send_quota)
        counter = send_quota["SentLast24Hours"]

        aws_client.ses.send_email(
            Source=sender_email,
            Message=SAMPLE_SIMPLE_EMAIL,
            Destination={
                "ToAddresses": [recipient_email],
            },
        )

        send_quota = retry(
            _assert_sent_quota, expected_counter=counter + 1, retries=retries, sleep=1
        )
        # snapshot.match('get-quota-1', send_quota)
        counter = send_quota["SentLast24Hours"]

        create_template(template=SAMPLE_TEMPLATE)
        aws_client.ses.send_templated_email(
            Source=sender_email,
            Template=SAMPLE_TEMPLATE["TemplateName"],
            TemplateData='{"A key": "A value"}',
            Destination={
                "ToAddresses": [recipient_email, sender_email],
            },
        )

        send_quota = retry(
            _assert_sent_quota, expected_counter=counter + 2, retries=retries, sleep=1
        )
        # snapshot.match('get-quota-2', send_quota)
        counter = send_quota["SentLast24Hours"]

        raw_message_data = f"From: {sender_email}\nTo: {recipient_email}\nSubject: test\n\nThis is the message body.\n\n"
        aws_client.ses.send_raw_email(RawMessage={"Data": raw_message_data})

        _ = retry(_assert_sent_quota, expected_counter=counter + 1, retries=retries, sleep=1)
        # snapshot.match('get-quota-3', _)

    @markers.aws.validated
    @markers.snapshot.skip_snapshot_verify(
        paths=[
            "$..Rules..Actions..AddHeaderAction",
            "$..Rules..Recipients",
            "$..Rules..Recipients",
            "$..Rules..Actions..S3Action.KmsKeyArn",
            "$..Rules..Actions..S3Action.TopicArn",
        ]
    )
    def test_clone_receipt_rule_set(
        self,
        aws_client,
        ses_create_receipt_rule_set,
        ses_clone_receipt_rule_set,
        snapshot,
        s3_bucket,
    ):
        snapshot.add_transformer(snapshot.transform.key_value("BucketName"))
        # Test that rule set is cloned properly
        # TODO: add some negative testing
        original_rule_set_name = "RuleSetToClone"
        rule_set_name = "RuleSetToCreate"
        rule_names = ["MyRule1", "MyRule2"]

        # Create mock rule set called RuleSetToClone
        create_receipt_rule_set = ses_create_receipt_rule_set(RuleSetName=original_rule_set_name)
        snapshot.match("create-receipt-rule-set", create_receipt_rule_set)

        # moto does not support AddHeaderAction, added it because it does not need permissions
        aws_client.ses.create_receipt_rule(
            Rule={
                "Actions": [
                    {
                        "AddHeaderAction": {
                            "HeaderName": "test-header",
                            "HeaderValue": "test",
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

        aws_client.s3.put_bucket_policy(
            Bucket=s3_bucket,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowSESPuts",
                            "Effect": "Allow",
                            "Principal": {"Service": "ses.amazonaws.com"},
                            "Action": "s3:PutObject",
                            "Resource": f"arn:aws:s3:::{s3_bucket}/*",
                        }
                    ],
                }
            ),
        )

        aws_client.ses.create_receipt_rule(
            After=rule_names[0],
            Rule={
                "Actions": [
                    {
                        "S3Action": {
                            "BucketName": s3_bucket,
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
        clone_receipt_rule_set = ses_clone_receipt_rule_set(
            RuleSetName=rule_set_name, OriginalRuleSetName=original_rule_set_name
        )
        snapshot.match("clone-receipt-rule-set", clone_receipt_rule_set)

        original_rule_set = aws_client.ses.describe_receipt_rule_set(
            RuleSetName=original_rule_set_name
        )
        snapshot.match("original-rule-set", original_rule_set)
        cloned_rule_set = aws_client.ses.describe_receipt_rule_set(RuleSetName=rule_set_name)
        snapshot.match("cloned-rule-set", cloned_rule_set)

        assert original_rule_set["Metadata"]["Name"] == original_rule_set_name
        assert cloned_rule_set["Metadata"]["Name"] == rule_set_name
        assert cloned_rule_set["Rules"] == original_rule_set["Rules"]
        assert [x["Name"] for x in cloned_rule_set["Rules"]] == rule_names

    @markers.aws.manual_setup_required
    @markers.snapshot.skip_snapshot_verify(
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
        sqs_queue,
        sns_topic,
        sns_create_sqs_subscription,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
        aws_client,
        add_snapshot_transformer_for_sns_event,
    ):
        """
        Repro for #7184 - test that this test is not runnable in the sandbox account since it
        requires a validated email address. We do not have support for this yet.
        """

        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()
        config_set_name = f"config-set-{short_uid()}"

        add_snapshot_transformer_for_sns_event(
            sender_email_address, recipient_email_address, config_set_name
        )

        # create queue to listen for SES -> SNS events
        topic_arn = sns_topic["Attributes"]["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        # create the config set
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        # send an email to trigger the SNS message and SQS message
        destination = {
            "ToAddresses": [recipient_email_address],
        }
        aws_client.ses.send_email(
            Destination=destination,
            Message=SAMPLE_SIMPLE_EMAIL,
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

    @markers.aws.manual_setup_required
    @markers.snapshot.skip_snapshot_verify(
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
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        ses_email_template,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_queue,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
        aws_client,
        add_snapshot_transformer_for_sns_event,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()
        config_set_name = f"config-set-{short_uid()}"

        add_snapshot_transformer_for_sns_event(
            sender_email_address, recipient_email_address, config_set_name
        )

        template_name = f"template-{short_uid()}"
        ses_email_template(template_name, "Test template")

        # create queue to listen for SES -> SNS events
        topic_arn = sns_create_topic()["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        # create the config set
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        # send an email to trigger the SNS message and SQS message
        destination = {
            "ToAddresses": [recipient_email_address],
        }
        aws_client.ses.send_templated_email(
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

    @markers.aws.manual_setup_required
    @markers.snapshot.skip_snapshot_verify(
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
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        sns_create_sqs_subscription,
        sns_create_topic,
        sqs_queue,
        sqs_receive_num_messages,
        setup_email_addresses,
        snapshot,
        aws_client,
        add_snapshot_transformer_for_sns_event,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()
        config_set_name = f"config-set-{short_uid()}"

        add_snapshot_transformer_for_sns_event(
            sender_email_address, recipient_email_address, config_set_name
        )

        # create queue to listen for SES -> SNS events
        topic_arn = sns_create_topic()["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

        # create the config set
        ses_configuration_set(config_set_name)
        event_destination_name = f"config-set-event-destination-{short_uid()}"
        ses_configuration_set_sns_event_destination(
            config_set_name, event_destination_name, topic_arn
        )

        # send an email to trigger the SNS message and SQS message
        aws_client.ses.send_raw_email(
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

    @markers.aws.validated
    def test_cannot_create_event_for_no_topic(
        self, ses_configuration_set, snapshot, account_id, aws_client
    ):
        topic_name = f"missing-topic-{short_uid()}"
        topic_arn = f"arn:aws:sns:{aws_client.ses.meta.region_name}:{account_id}:{topic_name}"
        snapshot.add_transformer(snapshot.transform.regex(topic_arn, "<arn>"))

        config_set_name = f"config-set-{short_uid()}"
        ses_configuration_set(config_set_name)

        event_destination_name = f"config-set-event-destination-{short_uid()}"

        # check if job is gone
        with pytest.raises(ClientError) as e_info:
            aws_client.ses.create_configuration_set_event_destination(
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

    @markers.aws.manual_setup_required
    def test_sending_to_deleted_topic(
        self,
        sqs_queue,
        sns_create_sqs_subscription,
        sns_topic,
        sns_wait_for_topic_delete,
        ses_configuration_set,
        sqs_receive_num_messages,
        ses_configuration_set_sns_event_destination,
        setup_email_addresses,
        snapshot,
        aws_client,
        add_snapshot_transformer_for_sns_event,
    ):
        # add your email addresses in here to verify against AWS
        sender_email_address, recipient_email_address = setup_email_addresses()
        config_set_name = f"config-set-{short_uid()}"

        add_snapshot_transformer_for_sns_event(
            sender_email_address, recipient_email_address, config_set_name
        )

        topic_arn = sns_topic["Attributes"]["TopicArn"]
        sns_create_sqs_subscription(topic_arn=topic_arn, queue_url=sqs_queue)

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
        aws_client.sns.delete_topic(TopicArn=topic_arn)
        sns_wait_for_topic_delete(topic_arn=topic_arn)

        aws_client.ses.send_email(
            Destination=destination,
            Message=message,
            ConfigurationSetName=config_set_name,
            Source=sender_email_address,
        )

        messages = sqs_receive_num_messages(sqs_queue, 1)
        snapshot.match("messages", messages)

    @markers.aws.validated
    def test_creating_event_destination_without_configuration_set(
        self, sns_topic, snapshot, aws_client
    ):
        config_set_name = f"nonexistent-configuration-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))

        topic_arn = sns_topic["Attributes"]["TopicArn"]
        event_destination_name = f"event-destination-{short_uid()}"
        with pytest.raises(ClientError) as e_info:
            aws_client.ses.create_configuration_set_event_destination(
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

    @markers.aws.validated
    def test_deleting_non_existent_configuration_set(self, snapshot, aws_client):
        config_set_name = f"config-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))

        with pytest.raises(ClientError) as e_info:
            aws_client.ses.delete_configuration_set(ConfigurationSetName=config_set_name)
        snapshot.match("delete-error", e_info.value.response)

    @markers.aws.validated
    def test_deleting_non_existent_configuration_set_event_destination(
        self, ses_configuration_set, snapshot, aws_client
    ):
        config_set_name = f"config-set-{short_uid()}"
        snapshot.add_transformer(snapshot.transform.regex(config_set_name, "<config-set>"))
        ses_configuration_set(config_set_name)

        event_destination_name = f"non-existent-configuration-set-{short_uid()}"
        # check if job is gone
        with pytest.raises(ClientError) as e_info:
            aws_client.ses.delete_configuration_set_event_destination(
                ConfigurationSetName=config_set_name,
                EventDestinationName=event_destination_name,
            )
        snapshot.match("delete-error", e_info.value.response)

    @markers.aws.validated
    def test_trying_to_delete_event_destination_from_non_existent_configuration_set(
        self,
        ses_configuration_set,
        ses_configuration_set_sns_event_destination,
        sns_topic,
        snapshot,
        aws_client,
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
            aws_client.ses.delete_configuration_set_event_destination(
                ConfigurationSetName="non-existent-configuration-set",
                EventDestinationName=event_destination_name,
            )
        snapshot.match("delete-error", e_info.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tag_name,tag_value",
        [
            ("test_invalid_name:123", "test"),
            ("test", "test_invalid_value:123"),
            ("test_invalid_name:123", "test_invalid_value:123"),
            pytest.param("test_invalid_name_len" * 100, "test", id="test_invalid_name_len"),
            pytest.param("test", "test_invalid_value_len" * 100, id="test_invalid_value_len"),
            pytest.param(
                "test_invalid_name@123",
                "test_invalid_value_len" * 100,
                id="test_priority_name_value",
            ),
            ("", ""),
            ("", "test"),
            ("test", ""),
        ],
    )
    def test_invalid_tags_send_email(self, tag_name, tag_value, snapshot, aws_client):
        source = f"user-{short_uid()}@example.com"
        destination = "success@example.com"

        with pytest.raises(ClientError) as e:
            aws_client.ses.send_email(
                Source=source,
                Tags=[
                    {
                        "Name": tag_name,
                        "Value": tag_value,
                    }
                ],
                Message=SAMPLE_SIMPLE_EMAIL,
                Destination={
                    "ToAddresses": [destination],
                },
            )
        snapshot.match("response", e.value.response)

    @markers.aws.validated
    @pytest.mark.parametrize(
        "tag_name,tag_value",
        [
            ("ses:feedback-id-a", "this-marketing-campaign"),
            ("ses:feedback-id-b", "that-campaign"),
        ],
    )
    def test_special_tags_send_email(self, tag_name, tag_value, aws_client):
        source = f"user-{short_uid()}@example.com"
        destination = "success@example.com"

        # Ensure that request passes validation and throws MessageRejected instead
        with pytest.raises(ClientError) as exc:
            aws_client.ses.send_email(
                Source=source,
                Tags=[
                    {
                        "Name": tag_name,
                        "Value": tag_value,
                    }
                ],
                Message=SAMPLE_SIMPLE_EMAIL,
                Destination={
                    "ToAddresses": [destination],
                },
            )

        assert exc.match("MessageRejected")


@pytest.mark.usefixtures("openapi_validate")
class TestSESRetrospection:
    @markers.aws.only_localstack
    def test_send_email_can_retrospect(self, aws_client):
        # Test that sent emails can be retrospected through saved file and API access

        # reset endpoint stored messages
        EMAILS.clear()

        def _read_message_from_filesystem(message_id: str) -> dict:
            """Given a message ID, read the message from filesystem and deserialise it."""
            data_dir = config.dirs.data or config.dirs.tmp
            with open(os.path.join(data_dir, "ses", message_id + ".json"), "r") as f:
                message = f.read()
            return json.loads(message)

        email = f"user-{short_uid()}@example.com"
        aws_client.ses.verify_email_address(EmailAddress=email)

        # Send a regular message
        message1 = aws_client.ses.send_email(
            Source=email,
            Message=SAMPLE_SIMPLE_EMAIL,
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
        assert contents1["Subject"] == SAMPLE_SIMPLE_EMAIL["Subject"]["Data"]
        assert contents1["Body"] == {
            "text_part": SAMPLE_SIMPLE_EMAIL["Body"]["Text"]["Data"],
            "html_part": SAMPLE_SIMPLE_EMAIL["Body"]["Html"]["Data"],
        }
        assert "RawData" not in contents1

        # Send a raw message
        raw_message_data = f"From: {email}\nTo: recipient@example.com\nSubject: test\n\nThis is the message body.\n\n"
        message2 = aws_client.ses.send_raw_email(RawMessage={"Data": raw_message_data})
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
        emails_url = config.internal_service_url() + EMAILS_ENDPOINT
        api_contents = []
        api_contents.extend(requests.get(emails_url + f"?id={message1_id}").json()["messages"])
        api_contents.extend(requests.get(emails_url + f"?id={message2_id}").json()["messages"])
        api_contents = {msg["Id"]: msg for msg in api_contents}
        assert len(api_contents) >= 1
        assert message1_id in api_contents
        assert message2_id in api_contents
        assert api_contents[message1_id] == contents1
        assert api_contents[message2_id] == contents2

        # Ensure messages can be filtered by email source via the REST endpoint
        emails_url = config.internal_service_url() + EMAILS_ENDPOINT + "?email=none@example.com"
        assert len(requests.get(emails_url).json()["messages"]) == 0
        emails_url = config.internal_service_url() + EMAILS_ENDPOINT + f"?email={email}"
        assert len(requests.get(emails_url).json()["messages"]) == 2

        emails_url = config.internal_service_url() + EMAILS_ENDPOINT
        assert requests.delete(emails_url + f"?id={message1_id}").status_code == 204
        assert requests.delete(emails_url + f"?id={message2_id}").status_code == 204
        assert requests.get(emails_url).json() == {"messages": []}

    @markers.aws.only_localstack
    def test_send_templated_email_can_retrospect(self, create_template, aws_client):
        # Test that sent emails can be retrospected through saved file and API access

        # reset endpoint stored messages
        EMAILS.clear()

        data_dir = config.dirs.data or config.dirs.tmp
        email = f"user-{short_uid()}@example.com"
        aws_client.ses.verify_email_address(EmailAddress=email)
        aws_client.ses.delete_template(TemplateName=SAMPLE_TEMPLATE["TemplateName"])
        create_template(template=SAMPLE_TEMPLATE)

        message = aws_client.ses.send_templated_email(
            Source=email,
            Template=SAMPLE_TEMPLATE["TemplateName"],
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
        assert SAMPLE_TEMPLATE["TemplateName"] == contents["Template"]
        assert '{"A key": "A value"}' == contents["TemplateData"]
        assert ["success@example.com"] == contents["Destination"]["ToAddresses"]

        api_contents = requests.get("http://localhost:4566/_aws/ses").json()
        api_contents = {msg["Id"]: msg for msg in api_contents["messages"]}
        assert message_id in api_contents
        assert api_contents[message_id] == contents

        assert requests.delete("http://localhost:4566/_aws/ses").status_code == 204
        assert requests.get("http://localhost:4566/_aws/ses").json() == {"messages": []}
