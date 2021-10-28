import ast
import asyncio
import base64
import json
import logging
import traceback
import uuid

import requests
import six
import xmltodict
from flask import Response as FlaskResponse
from moto.sns.exceptions import DuplicateSnsEndpointError
from moto.sns.models import SNSBackend as MotoSNSBackend
from requests.models import Request, Response
from six.moves.urllib import parse as urlparse

from localstack.config import external_service_url
from localstack.constants import MOTO_ACCOUNT_ID, TEST_AWS_ACCOUNT_ID
from localstack.services.awslambda import lambda_api
from localstack.services.generic_proxy import RegionBackend
from localstack.services.install import SQS_BACKEND_IMPL
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import create_sqs_system_attributes, response_regex_replace
from localstack.utils.aws.dead_letter_queue import sns_error_to_dead_letter_queue
from localstack.utils.common import (
    parse_request_data,
    short_uid,
    start_thread,
    timestamp_millis,
    to_bytes,
    to_str,
)
from localstack.utils.persistence import PersistingProxyListener

# set up logger
LOG = logging.getLogger(__name__)

# additional attributes used for HTTP subscriptions
HTTP_SUBSCRIPTION_ATTRIBUTES = ["UnsubscribeURL"]


class SNSBackend(RegionBackend):
    def __init__(self):
        # maps topic ARN to list of subscriptions
        self.sns_subscriptions = {}
        # maps subscription ARN to subscription status
        self.subscription_status = {}
        # maps topic ARN to list of tags
        self.sns_tags = {}
        # cache of topic ARN to platform endpoint messages (used primarily for testing)
        self.platform_endpoint_messages = {}
        # maps phone numbers to list of sent messages
        self.sms_messages = []
        # actions to be skipped from persistence
        self.skip_persistence_actions = [
            "Subscribe",
            "ConfirmSubscription",
            "Unsubscribe",
        ]


class ProxyListenerSNS(PersistingProxyListener):
    def api_name(self):
        return "sns"

    def forward_request(self, method, path, data, headers):
        if method == "OPTIONS":
            return 200

        # check region
        try:
            aws_stack.check_valid_region(headers)
            aws_stack.set_default_region_in_headers(headers)
        except Exception as e:
            return make_error(message=str(e), code=400)

        if method == "POST":
            # parse payload and extract fields
            req_data = urlparse.parse_qs(to_str(data), keep_blank_values=True)

            # parse data from query path
            if not req_data:
                parsed_path = urlparse.urlparse(path)
                req_data = urlparse.parse_qs(parsed_path.query, keep_blank_values=True)

            req_action = req_data["Action"][0]
            topic_arn = (
                req_data.get("TargetArn") or req_data.get("TopicArn") or req_data.get("ResourceArn")
            )
            if topic_arn:
                topic_arn = topic_arn[0]
                topic_arn = aws_stack.fix_account_id_in_arns(topic_arn)
            if req_action == "SetSubscriptionAttributes":
                sub = get_subscription_by_arn(req_data["SubscriptionArn"][0])
                if not sub:
                    return make_error(message="Unable to find subscription for given ARN", code=400)

                attr_name = req_data["AttributeName"][0]
                attr_value = req_data["AttributeValue"][0]
                sub[attr_name] = attr_value
                return make_response(req_action)

            elif req_action == "GetSubscriptionAttributes":
                sub = get_subscription_by_arn(req_data["SubscriptionArn"][0])
                if not sub:
                    return make_error(
                        message="Subscription with arn {0} not found".format(
                            req_data["SubscriptionArn"][0]
                        ),
                        code=404,
                        code_string="NotFound",
                    )

                content = "<Attributes>"
                for key, value in sub.items():
                    if key in HTTP_SUBSCRIPTION_ATTRIBUTES:
                        continue
                    content += "<entry><key>%s</key><value>%s</value></entry>\n" % (
                        key,
                        value,
                    )
                content += "</Attributes>"
                return make_response(req_action, content=content)

            elif req_action == "Subscribe":
                if "Endpoint" not in req_data:
                    return make_error(message="Endpoint not specified in subscription", code=400)

            elif req_action == "ConfirmSubscription":
                if "TopicArn" not in req_data:
                    return make_error(
                        message="TopicArn not specified in confirm subscription request",
                        code=400,
                    )

                if "Token" not in req_data:
                    return make_error(
                        message="Token not specified in confirm subscription request",
                        code=400,
                    )

                do_confirm_subscription(req_data.get("TopicArn")[0], req_data.get("Token")[0])

            elif req_action == "Unsubscribe":
                if "SubscriptionArn" not in req_data:
                    return make_error(
                        message="SubscriptionArn not specified in unsubscribe request",
                        code=400,
                    )

                do_unsubscribe(req_data.get("SubscriptionArn")[0])

            elif req_action == "DeleteTopic":
                do_delete_topic(topic_arn)

            elif req_action == "Publish":
                if req_data.get("Subject") == [""]:
                    return make_error(code=400, code_string="InvalidParameter", message="Subject")
                sns_backend = SNSBackend.get()
                # No need to create a topic to send SMS or single push notifications with SNS
                # but we can't mock a sending so we only return that it went well
                if "PhoneNumber" not in req_data and "TargetArn" not in req_data:
                    if topic_arn not in sns_backend.sns_subscriptions:
                        return make_error(
                            code=404,
                            code_string="NotFound",
                            message="Topic does not exist",
                        )

                message_id = publish_message(topic_arn, req_data, headers)

                # return response here because we do not want the request to be forwarded to SNS backend
                return make_response(req_action, message_id=message_id)

            elif req_action == "ListTagsForResource":
                tags = do_list_tags_for_resource(topic_arn)
                content = "<Tags/>"
                if len(tags) > 0:
                    content = "<Tags>"
                    for tag in tags:
                        content += "<member>"
                        content += "<Key>%s</Key>" % tag["Key"]
                        content += "<Value>%s</Value>" % tag["Value"]
                        content += "</member>"
                    content += "</Tags>"
                return make_response(req_action, content=content)

            elif req_action == "CreateTopic":
                sns_backend = SNSBackend.get()
                topic_arn = aws_stack.sns_topic_arn(req_data["Name"][0])
                tag_resource_success = self._extract_tags(topic_arn, req_data, True, sns_backend)
                sns_backend.sns_subscriptions[topic_arn] = (
                    sns_backend.sns_subscriptions.get(topic_arn) or []
                )
                # in case if there is an error it returns an error , other wise it will continue as expected.
                if not tag_resource_success:
                    return make_error(
                        code=400,
                        code_string="InvalidParameter",
                        message="Topic already exists with different tags",
                    )

            elif req_action == "TagResource":
                sns_backend = SNSBackend.get()
                self._extract_tags(topic_arn, req_data, False, sns_backend)
                return make_response(req_action)

            elif req_action == "UntagResource":
                tags_to_remove = []
                req_tags = {k: v for k, v in req_data.items() if k.startswith("TagKeys.member.")}
                req_tags = req_tags.values()
                for tag in req_tags:
                    tags_to_remove.append(tag[0])
                do_untag_resource(topic_arn, tags_to_remove)
                return make_response(req_action)

            data = self._reset_account_id(data)
            return Request(data=data, headers=headers, method=method)

        return True

    @staticmethod
    def _extract_tags(topic_arn, req_data, is_create_topic_request, sns_backend):
        tags = []
        req_tags = {k: v for k, v in req_data.items() if k.startswith("Tags.member.")}
        existing_tags = sns_backend.sns_tags.get(topic_arn, None)
        # TODO: use aws_responses.extract_tags(...) here!
        for i in range(int(len(req_tags.keys()) / 2)):
            key = req_tags["Tags.member." + str(i + 1) + ".Key"][0]
            value = req_tags["Tags.member." + str(i + 1) + ".Value"][0]
            tag = {"Key": key, "Value": value}
            tags.append(tag)
            # this means topic already created with empty tags and when we try to create it
            # again with other tag value then it should fail according to aws documentation.
            if is_create_topic_request and existing_tags is not None and tag not in existing_tags:
                return False
        do_tag_resource(topic_arn, tags)
        return True

    @staticmethod
    def _reset_account_id(data):
        """Fix account ID in request payload. All external-facing responses contain our
        predefined account ID (defaults to 000000000000), whereas the backend endpoint
        from moto expects a different hardcoded account ID (123456789012)."""
        return aws_stack.fix_account_id_in_arns(
            data,
            colon_delimiter="%3A",
            existing=TEST_AWS_ACCOUNT_ID,
            replace=MOTO_ACCOUNT_ID,
        )

    def return_response(self, method, path, data, headers, response):
        # persist requests to disk
        super(ProxyListenerSNS, self).return_response(method, path, data, headers, response)

        if method == "POST" and path == "/":
            # convert account IDs in ARNs
            data = aws_stack.fix_account_id_in_arns(data, colon_delimiter="%3A")
            aws_stack.fix_account_id_in_arns(response)

            # remove "None" strings from result
            search = r"<entry><key>[^<]+</key>\s*<value>\s*None\s*</[^>]+>\s*</entry>"
            response_regex_replace(response, search, "")

            # parse request and extract data
            req_data = urlparse.parse_qs(to_str(data))
            req_action = req_data["Action"][0]
            if req_action == "Subscribe" and response.status_code < 400:
                response_data = xmltodict.parse(response.content)
                topic_arn = (req_data.get("TargetArn") or req_data.get("TopicArn"))[0]
                filter_policy = (req_data.get("FilterPolicy") or [None])[0]
                attributes = get_subscribe_attributes(req_data)
                sub_arn = response_data["SubscribeResponse"]["SubscribeResult"]["SubscriptionArn"]
                do_subscribe(
                    topic_arn,
                    req_data["Endpoint"][0],
                    req_data["Protocol"][0],
                    sub_arn,
                    attributes,
                    filter_policy,
                )
            if req_action == "CreateTopic" and response.status_code < 400:
                response_data = xmltodict.parse(response.content)
                topic_arn = response_data["CreateTopicResponse"]["CreateTopicResult"]["TopicArn"]
                # publish event
                event_publisher.fire_event(
                    event_publisher.EVENT_SNS_CREATE_TOPIC,
                    payload={"t": event_publisher.get_hash(topic_arn)},
                )
            if req_action == "DeleteTopic" and response.status_code < 400:
                # publish event
                topic_arn = (req_data.get("TargetArn") or req_data.get("TopicArn"))[0]
                event_publisher.fire_event(
                    event_publisher.EVENT_SNS_DELETE_TOPIC,
                    payload={"t": event_publisher.get_hash(topic_arn)},
                )

    def should_persist(self, method, path, data, headers, response):
        sns_backend = SNSBackend.get()
        req_params = parse_request_data(method, path, data)
        action = req_params.get("Action", "")
        if action in sns_backend.skip_persistence_actions:
            return False
        return super(ProxyListenerSNS, self).should_persist(method, path, data, headers, response)


def patch_moto():
    def patch_create_platform_endpoint(self, *args):
        try:
            return create_platform_endpoint_orig(self, *args)
        except DuplicateSnsEndpointError:
            custom_user_data, token = args[2], args[3]
            for endpoint in self.platform_endpoints.values():
                if endpoint.token == token:
                    if custom_user_data and custom_user_data != endpoint.custom_user_data:
                        raise DuplicateSnsEndpointError(
                            "Endpoint already exist for token: %s with different attributes" % token
                        )
                    return endpoint

    create_platform_endpoint_orig = MotoSNSBackend.create_platform_endpoint
    MotoSNSBackend.create_platform_endpoint = patch_create_platform_endpoint


patch_moto()
# instantiate listener
UPDATE_SNS = ProxyListenerSNS()


def unsubscribe_sqs_queue(queue_url):
    """Called upon deletion of an SQS queue, to remove the queue from subscriptions"""
    sns_backend = SNSBackend.get()
    for topic_arn, subscriptions in sns_backend.sns_subscriptions.items():
        subscriptions = sns_backend.sns_subscriptions.get(topic_arn, [])
        for subscriber in list(subscriptions):
            sub_url = subscriber.get("sqs_queue_url") or subscriber["Endpoint"]
            if queue_url == sub_url:
                subscriptions.remove(subscriber)


def message_to_subscribers(
    message_id,
    message,
    topic_arn,
    req_data,
    headers,
    subscription_arn=None,
    skip_checks=False,
):
    sns_backend = SNSBackend.get()
    subscriptions = sns_backend.sns_subscriptions.get(topic_arn, [])

    async def wait_for_messages_sent():
        subs = [
            message_to_subscriber(
                message_id,
                message,
                topic_arn,
                req_data,
                headers,
                subscription_arn,
                skip_checks,
                sns_backend,
                subscriber,
                subscriptions,
            )
            for subscriber in list(subscriptions)
        ]
        if subs:
            await asyncio.wait(subs)

    asyncio.run(wait_for_messages_sent())


async def message_to_subscriber(
    message_id,
    message,
    topic_arn,
    req_data,
    headers,
    subscription_arn,
    skip_checks,
    sns_backend,
    subscriber,
    subscriptions,
):

    if subscription_arn not in [None, subscriber["SubscriptionArn"]]:
        return

    filter_policy = json.loads(subscriber.get("FilterPolicy") or "{}")
    message_attributes = get_message_attributes(req_data)
    if not skip_checks and not check_filter_policy(filter_policy, message_attributes):
        LOG.info(
            "SNS filter policy %s does not match attributes %s"
            % (filter_policy, message_attributes)
        )
        return
    if subscriber["Protocol"] == "sms":
        event = {
            "topic_arn": topic_arn,
            "endpoint": subscriber["Endpoint"],
            "message_content": req_data["Message"][0],
        }
        sns_backend.sms_messages.append(event)
        LOG.info(
            "Delivering SMS message to %s: %s",
            subscriber["Endpoint"],
            req_data["Message"][0],
        )
        return

    elif subscriber["Protocol"] == "sqs":
        queue_url = None

        try:
            endpoint = subscriber["Endpoint"]

            if "sqs_queue_url" in subscriber:
                queue_url = subscriber.get("sqs_queue_url")
            elif "://" in endpoint:
                queue_url = endpoint
            else:
                queue_name = endpoint.split(":")[5]
                queue_url = aws_stack.get_sqs_queue_url(queue_name)
                subscriber["sqs_queue_url"] = queue_url

            message_group_id = (
                req_data.get("MessageGroupId")[0] if req_data.get("MessageGroupId") else ""
            )

            sqs_client = aws_stack.connect_to_service("sqs")

            # TODO remove this kwargs if we stop using ElasticMQ entirely
            kwargs = {"MessageGroupId": message_group_id} if SQS_BACKEND_IMPL == "moto" else {}
            sqs_client.send_message(
                QueueUrl=queue_url,
                MessageBody=create_sns_message_body(subscriber, req_data, message_id),
                MessageAttributes=create_sqs_message_attributes(subscriber, message_attributes),
                MessageSystemAttributes=create_sqs_system_attributes(headers),
                **kwargs,
            )
        except Exception as exc:
            LOG.info("Unable to forward SNS message to SQS: %s %s" % (exc, traceback.format_exc()))
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
            if "NonExistentQueue" in str(exc):
                LOG.info(
                    'Removing non-existent queue "%s" subscribed to topic "%s"'
                    % (queue_url, topic_arn)
                )
                subscriptions.remove(subscriber)
        return

    elif subscriber["Protocol"] == "lambda":
        try:
            external_url = external_service_url("sns")
            unsubscribe_url = "%s/?Action=Unsubscribe&SubscriptionArn=%s" % (
                external_url,
                subscriber["SubscriptionArn"],
            )
            response = lambda_api.process_sns_notification(
                subscriber["Endpoint"],
                topic_arn,
                subscriber["SubscriptionArn"],
                message,
                message_id,
                message_attributes,
                unsubscribe_url,
                subject=req_data.get("Subject", [None])[0],
            )
            if isinstance(response, Response):
                response.raise_for_status()
            elif isinstance(response, FlaskResponse):
                if response.status_code >= 400:
                    raise Exception(
                        "Error response (code %s): %s" % (response.status_code, response.data)
                    )
        except Exception as exc:
            LOG.info(
                "Unable to run Lambda function on SNS message: %s %s"
                % (exc, traceback.format_exc())
            )
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] in ["http", "https"]:
        msg_type = (req_data.get("Type") or ["Notification"])[0]
        try:
            message_body = create_sns_message_body(subscriber, req_data, message_id)
        except Exception:
            return
        try:
            response = requests.post(
                subscriber["Endpoint"],
                headers={
                    "Content-Type": "text/plain",
                    # AWS headers according to
                    # https://docs.aws.amazon.com/sns/latest/dg/sns-message-and-json-formats.html#http-header
                    "x-amz-sns-message-type": msg_type,
                    "x-amz-sns-topic-arn": subscriber["TopicArn"],
                    "x-amz-sns-subscription-arn": subscriber["SubscriptionArn"],
                    "User-Agent": "Amazon Simple Notification Service Agent",
                },
                data=message_body,
                verify=False,
            )
            response.raise_for_status()
        except Exception as exc:
            LOG.info(
                "Received error on sending SNS message, putting to DLQ (if configured): %s" % exc
            )
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] == "application":
        try:
            sns_client = aws_stack.connect_to_service("sns")
            sns_client.publish(TargetArn=subscriber["Endpoint"], Message=message)
        except Exception as exc:
            LOG.warning(
                "Unable to forward SNS message to SNS platform app: %s %s"
                % (exc, traceback.format_exc())
            )
            sns_error_to_dead_letter_queue(subscriber["SubscriptionArn"], req_data, str(exc))
        return

    elif subscriber["Protocol"] == "email":
        ses_client = aws_stack.connect_to_service("ses")
        if subscriber.get("Endpoint"):
            ses_client.verify_email_address(EmailAddress=subscriber.get("Endpoint"))
            ses_client.verify_email_address(EmailAddress="admin@localstack.com")

            ses_client.send_email(
                Source="admin@localstack.com",
                Message={
                    "Body": {"Text": {"Data": message}},
                    "Subject": {"Data": "SNS-Subscriber-Endpoint"},
                },
                Destination={"ToAddresses": [subscriber.get("Endpoint")]},
            )
    else:
        LOG.warning('Unexpected protocol "%s" for SNS subscription' % subscriber["Protocol"])


def publish_message(topic_arn, req_data, headers, subscription_arn=None, skip_checks=False):
    sns_backend = SNSBackend.get()
    message = req_data["Message"][0]
    message_id = str(uuid.uuid4())

    if topic_arn and ":endpoint/" in topic_arn:
        # cache messages published to platform endpoints
        cache = sns_backend.platform_endpoint_messages[topic_arn] = (
            sns_backend.platform_endpoint_messages.get(topic_arn) or []
        )
        cache.append(req_data)

    LOG.debug("Publishing message to TopicArn: %s | Message: %s" % (topic_arn, message))
    start_thread(
        lambda _: message_to_subscribers(
            message_id,
            message,
            topic_arn,
            req_data,
            headers,
            subscription_arn,
            skip_checks,
        )
    )
    return message_id


def do_delete_topic(topic_arn):
    sns_backend = SNSBackend.get()
    sns_backend.sns_subscriptions.pop(topic_arn, None)
    sns_backend.sns_tags.pop(topic_arn, None)


def do_confirm_subscription(topic_arn, token):
    sns_backend = SNSBackend.get()
    for k, v in sns_backend.subscription_status.items():
        if v["Token"] == token and v["TopicArn"] == topic_arn:
            v["Status"] = "Subscribed"


def do_subscribe(topic_arn, endpoint, protocol, subscription_arn, attributes, filter_policy=None):
    sns_backend = SNSBackend.get()
    topic_subs = sns_backend.sns_subscriptions[topic_arn] = (
        sns_backend.sns_subscriptions.get(topic_arn) or []
    )
    # An endpoint may only be subscribed to a topic once. Subsequent
    # subscribe calls do nothing (subscribe is idempotent).
    for existing_topic_subscription in topic_subs:
        if existing_topic_subscription.get("Endpoint") == endpoint:
            return

    subscription = {
        # http://docs.aws.amazon.com/cli/latest/reference/sns/get-subscription-attributes.html
        "TopicArn": topic_arn,
        "Endpoint": endpoint,
        "Protocol": protocol,
        "SubscriptionArn": subscription_arn,
        "FilterPolicy": filter_policy,
    }
    subscription.update(attributes)
    topic_subs.append(subscription)

    if subscription_arn not in sns_backend.subscription_status:
        sns_backend.subscription_status[subscription_arn] = {}

    sns_backend.subscription_status[subscription_arn].update(
        {"TopicArn": topic_arn, "Token": short_uid(), "Status": "Not Subscribed"}
    )
    # Send out confirmation message for HTTP(S), fix for https://github.com/localstack/localstack/issues/881
    if protocol in ["http", "https"]:
        token = short_uid()
        external_url = external_service_url("sns")
        subscription["UnsubscribeURL"] = "%s/?Action=Unsubscribe&SubscriptionArn=%s" % (
            external_url,
            subscription_arn,
        )
        confirmation = {
            "Type": ["SubscriptionConfirmation"],
            "Token": [token],
            "Message": [
                ("You have chosen to subscribe to the topic %s.\n" % topic_arn)
                + "To confirm the subscription, visit the SubscribeURL included in this message."
            ],
            "SubscribeURL": [
                "%s/?Action=ConfirmSubscription&TopicArn=%s&Token=%s"
                % (external_url, topic_arn, token)
            ],
        }
        publish_message(topic_arn, confirmation, {}, subscription_arn, skip_checks=True)


def do_unsubscribe(subscription_arn):
    sns_backend = SNSBackend.get()
    for topic_arn, existing_subs in sns_backend.sns_subscriptions.items():
        sns_backend.sns_subscriptions[topic_arn] = [
            sub for sub in existing_subs if sub["SubscriptionArn"] != subscription_arn
        ]


def _get_tags(topic_arn):
    sns_backend = SNSBackend.get()
    if topic_arn not in sns_backend.sns_tags:
        sns_backend.sns_tags[topic_arn] = []

    return sns_backend.sns_tags[topic_arn]


def do_list_tags_for_resource(topic_arn):
    return _get_tags(topic_arn)


def do_tag_resource(topic_arn, tags):
    sns_backend = SNSBackend.get()
    existing_tags = sns_backend.sns_tags.get(topic_arn, [])
    tags = [tag for idx, tag in enumerate(tags) if tag not in tags[:idx]]

    def existing_tag_index(item):
        for idx, tag in enumerate(existing_tags):
            if item["Key"] == tag["Key"]:
                return idx
        return None

    for item in tags:
        existing_index = existing_tag_index(item)
        if existing_index is None:
            existing_tags.append(item)
        else:
            existing_tags[existing_index] = item

    sns_backend.sns_tags[topic_arn] = existing_tags


def do_untag_resource(topic_arn, tag_keys):
    sns_backend = SNSBackend.get()
    sns_backend.sns_tags[topic_arn] = [t for t in _get_tags(topic_arn) if t["Key"] not in tag_keys]


# ---------------
# HELPER METHODS
# ---------------


def get_subscription_by_arn(sub_arn):
    sns_backend = SNSBackend.get()
    # TODO maintain separate map instead of traversing all items
    for key, subscriptions in sns_backend.sns_subscriptions.items():
        for sub in subscriptions:
            if sub["SubscriptionArn"] == sub_arn:
                return sub


def make_response(op_name, content="", message_id=None):
    response = Response()
    if not content:
        message_id = message_id or str(uuid.uuid4())
        content = "<MessageId>%s</MessageId>" % message_id

    response._content = """<{op_name}Response xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
        <{op_name}Result>
            {content}
        </{op_name}Result>
        <ResponseMetadata><RequestId>{req_id}</RequestId></ResponseMetadata>
        </{op_name}Response>""".format(
        op_name=op_name, content=content, req_id=short_uid()
    )
    response.status_code = 200
    return response


# TODO move to utils!
def make_error(message, code=400, code_string="InvalidParameter"):
    response = Response()
    response._content = """<ErrorResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/"><Error>
        <Type>Sender</Type>
        <Code>{code_string}</Code>
        <Message>{message}</Message>
        </Error><RequestId>{req_id}</RequestId>
        </ErrorResponse>""".format(
        message=message, code_string=code_string, req_id=short_uid()
    )
    response.status_code = code
    return response


def create_sns_message_body(subscriber, req_data, message_id=None):
    message = req_data["Message"][0]
    protocol = subscriber["Protocol"]

    if six.PY2 and type(message).__name__ == "unicode":
        # fix non-ascii unicode characters under Python 2
        message = message.encode("raw-unicode-escape")

    if req_data.get("MessageStructure") == ["json"]:
        message = json.loads(message)
        try:
            message = message.get(protocol, message["default"])
        except KeyError:
            raise Exception("Unable to find 'default' key in message payload")

    if is_raw_message_delivery(subscriber):
        return message

    data = {
        "Type": req_data.get("Type", ["Notification"])[0],
        "MessageId": message_id,
        "TopicArn": subscriber["TopicArn"],
        "Message": message,
        "Timestamp": timestamp_millis(),
        "SignatureVersion": "1",
        # TODO Add a more sophisticated solution with an actual signature
        # Hardcoded
        "Signature": "EXAMPLEpH+..",
        "SigningCertURL": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem",
    }

    for key in ["Subject", "SubscribeURL", "Token"]:
        if req_data.get(key):
            data[key] = req_data[key][0]

    for key in HTTP_SUBSCRIPTION_ATTRIBUTES:
        if key in subscriber:
            data[key] = subscriber[key]

    attributes = get_message_attributes(req_data)
    if attributes:
        data["MessageAttributes"] = attributes

    return json.dumps(data)


def create_sqs_message_attributes(subscriber, attributes):
    if not is_raw_message_delivery(subscriber):
        return {}

    message_attributes = {}
    for key, value in attributes.items():
        attribute = {"DataType": value["Type"]}
        if value["Type"] == "Binary":
            attribute["BinaryValue"] = base64.decodebytes(to_bytes(value["Value"]))
        else:
            attribute["StringValue"] = str(value.get("Value", ""))

        message_attributes[key] = attribute

    return message_attributes


def get_message_attributes(req_data):
    attributes = {}
    x = 1
    while True:
        name = req_data.get("MessageAttributes.entry." + str(x) + ".Name", [None])[0]
        if name is not None:
            attribute = {
                "Type": req_data.get(
                    "MessageAttributes.entry." + str(x) + ".Value.DataType", [None]
                )[0]
            }
            string_value = req_data.get(
                "MessageAttributes.entry." + str(x) + ".Value.StringValue", [None]
            )[0]
            binary_value = req_data.get(
                "MessageAttributes.entry." + str(x) + ".Value.BinaryValue", [None]
            )[0]
            if string_value is not None:
                attribute["Value"] = string_value
            elif binary_value is not None:
                attribute["Value"] = binary_value

            attributes[name] = attribute
            x += 1
        else:
            break

    return attributes


def get_subscribe_attributes(req_data):
    attributes = {}
    for key in req_data.keys():
        if ".key" in key:
            attributes[req_data[key][0]] = req_data[key.replace("key", "value")][0]
    defaults = {
        # TODO: this is required to get TF "aws_sns_topic_subscription" working, but this should
        # be revisited (e.g., cross-account subscriptions should not be confirmed automatically)
        "PendingConfirmation": "false"
    }
    for key, value in defaults.items():
        attributes[key] = attributes.get(key, value)
    return attributes


def is_number(x):
    try:
        float(x)
        return True
    except ValueError:
        return False


def evaluate_numeric_condition(conditions, value):
    if not is_number(value):
        return False

    for i in range(0, len(conditions), 2):
        value = float(value)
        operator = conditions[i]
        operand = float(conditions[i + 1])

        if operator == "=":
            if value != operand:
                return False
        elif operator == ">":
            if value <= operand:
                return False
        elif operator == "<":
            if value >= operand:
                return False
        elif operator == ">=":
            if value < operand:
                return False
        elif operator == "<=":
            if value > operand:
                return False

    return True


def evaluate_exists_condition(conditions, message_attributes, criteria):
    # filtering should not match any messages if the exists is set to false,As per aws docs
    # https://docs.aws.amazon.com/sns/latest/dg/sns-subscription-filter-policies.html
    if conditions:
        return bool(message_attributes.get(criteria))
    return False


def evaluate_condition(value, condition, message_attributes, criteria):
    if type(condition) is not dict:
        return value == condition
    elif condition.get("anything-but"):
        return value not in condition.get("anything-but")
    elif condition.get("prefix"):
        prefix = condition.get("prefix")
        return value.startswith(prefix)
    elif condition.get("numeric"):
        return evaluate_numeric_condition(condition.get("numeric"), value)
    elif condition.get("exists"):
        return evaluate_exists_condition(condition.get("exists"), message_attributes, criteria)

    return False


def evaluate_filter_policy_conditions(conditions, attribute, message_attributes, criteria):
    if type(conditions) is not list:
        conditions = [conditions]

    if attribute["Type"] == "String.Array":
        values = ast.literal_eval(attribute["Value"])
        for value in values:
            for condition in conditions:
                if evaluate_condition(value, condition, message_attributes, criteria):
                    return True
    else:
        for condition in conditions:
            if evaluate_condition(attribute["Value"], condition, message_attributes, criteria):
                return True

    return False


def check_filter_policy(filter_policy, message_attributes):
    if not filter_policy:
        return True

    for criteria in filter_policy:
        conditions = filter_policy.get(criteria)
        attribute = message_attributes.get(criteria)
        if attribute is None:
            return False

        if (
            evaluate_filter_policy_conditions(conditions, attribute, message_attributes, criteria)
            is False
        ):
            return False

    return True


def is_raw_message_delivery(susbcriber):
    return susbcriber.get("RawMessageDelivery") in ("true", True, "True")
