import json
import re
from typing import Dict
from urllib.parse import urlencode

import xmltodict
from moto.sqs.models import TRANSPORT_TYPE_ENCODINGS, Message
from moto.sqs.utils import parse_message_attributes
from requests.models import Request, Response

from localstack import config, constants
from localstack.config import SQS_PORT_EXTERNAL
from localstack.services.awslambda.lambda_api import EventSourceListener
from localstack.services.install import SQS_BACKEND_IMPL
from localstack.services.sns import sns_listener
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import (
    calculate_crc32,
    make_requests_error,
    parse_urlencoded_data,
    requests_response,
)
from localstack.utils.common import (
    clone,
    ensure_list,
    get_service_protocol,
    parse_request_data,
    path_from_url,
    to_str,
)
from localstack.utils.persistence import PersistingProxyListener

API_VERSION = "2012-11-05"
XMLNS_SQS = "http://queue.amazonaws.com/doc/%s/" % API_VERSION

# Valid unicode values: #x9 | #xA | #xD | #x20 to #xD7FF | #xE000 to #xFFFD | #x10000 to #x10FFFF
# https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html
MSG_CONTENT_REGEX = "^[\u0009\u000A\u000D\u0020-\uD7FF\uE000-\uFFFD\U00010000-\U0010FFFF]*$"

UNSUPPORTED_ATTRIBUTE_NAMES = [
    # elasticmq store 'FifoQueue', 'ContentBasedDeduplication' as queue's properties
    # currently can't get them as queue attributes
    "FifoQueue",
    "ContentBasedDeduplication",
    "DelaySeconds",
    "MaximumMessageSize",
    "MessageRetentionPeriod",
    "Policy",
    "RedrivePolicy",
    "KmsMasterKeyId",
    "KmsDataKeyReusePeriodSeconds",
]

# maps queue URLs to attributes set via the API
# TODO: add region as first level in the map
QUEUE_ATTRIBUTES = {}


# Format attributes as a list. Example input:
#  {
#    'AttributeName.1': ['Policy'],
#    'AttributeName.2': ['MessageRetentionPeriod']
#  }
def _format_attributes(req_data):
    result = {}
    for i in range(1, 500):
        key1 = "Attribute.%s.Name" % i
        key2 = "Attribute.%s.Value" % i
        if key1 not in req_data:
            break
        key_name = req_data[key1]
        key_value = req_data.get(key2) or ""
        result[key_name] = key_value
    return result


def _format_attributes_names(req_data):
    result = set()
    for i in range(1, 500):
        key = "AttributeName.%s" % i
        if key not in req_data:
            break
        result.add(req_data[key])
    return result


def _get_attributes_forward_request(method, path, headers, req_data, forward_attrs):
    req_data_new = {k: v for k, v in req_data.items() if not k.startswith("Attribute.")}
    i = 1
    for k, v in forward_attrs.items():
        req_data_new["Attribute.%s.Name" % i] = [k]
        req_data_new["Attribute.%s.Value" % i] = [v]
        i += 1
    data = urlencode(req_data_new, doseq=True)
    return Request(data=data, headers=headers, method=method)


def _set_queue_attributes(queue_url, req_data):
    # TODO remove this function if we stop using ElasticMQ entirely
    if SQS_BACKEND_IMPL != "elasticmq":
        return
    attrs = _format_attributes(req_data)
    # select only the attributes in UNSUPPORTED_ATTRIBUTE_NAMES
    local_attrs = {}
    for k, v in attrs.items():
        if k in UNSUPPORTED_ATTRIBUTE_NAMES:
            try:
                _v = json.loads(v)
                if isinstance(_v, dict):
                    if "maxReceiveCount" in _v:
                        _v["maxReceiveCount"] = int(_v["maxReceiveCount"])

                local_attrs.update(dict({k: json.dumps(_v)}))
            except Exception:
                local_attrs.update(dict({k: v}))

    QUEUE_ATTRIBUTES[queue_url] = QUEUE_ATTRIBUTES.get(queue_url) or {}
    QUEUE_ATTRIBUTES[queue_url].update(local_attrs)
    forward_attrs = {k: v for k, v in attrs.items() if k not in UNSUPPORTED_ATTRIBUTE_NAMES}
    return forward_attrs


def _fix_dlq_arn_in_attributes(req_data):
    """Convert queue URL to ARN for DLQ in redrive policy config."""
    attrs = _format_attributes(req_data)
    policy = json.loads(attrs.get("RedrivePolicy") or "{}")
    dlq_arn = policy.get("deadLetterTargetArn", "")
    if "://" in dlq_arn:
        # convert queue URL to queue ARN
        policy["deadLetterTargetArn"] = aws_stack.sqs_queue_arn(dlq_arn)
        attrs["RedrivePolicy"] = json.dumps(policy)
        return attrs


def _fix_redrive_policy(match):
    result = "<Attribute><Name>RedrivePolicy</Name><Value>{%s}</Value></Attribute>" % (
        match.group(1).replace(" ", "")
    )
    return result


def _add_queue_attributes(path, req_data, content_str, headers):
    # TODO remove this function if we stop using ElasticMQ entirely
    if SQS_BACKEND_IMPL != "elasticmq":
        return content_str
    flags = re.MULTILINE | re.DOTALL
    queue_url = _queue_url(path, req_data, headers)
    requested_attributes = _format_attributes_names(req_data)
    regex = r"(.*<GetQueueAttributesResult>)(.*)(</GetQueueAttributesResult>.*)"
    attrs = re.sub(regex, r"\2", content_str, flags=flags)
    for key, value in QUEUE_ATTRIBUTES.get(queue_url, {}).items():
        if (
            not requested_attributes or requested_attributes.intersection({"All", key})
        ) and not re.match(r"<Name>\s*%s\s*</Name>" % key, attrs, flags=flags):
            attrs += "<Attribute><Name>%s</Name><Value>%s</Value></Attribute>" % (
                key,
                value,
            )
    content_str = (
        re.sub(regex, r"\1", content_str, flags=flags)
        + attrs
        + re.sub(regex, r"\3", content_str, flags=flags)
    )
    return content_str


def _fire_event(req_data, response):
    action = req_data.get("Action")
    event_type = None
    queue_url = None
    if action == "CreateQueue":
        event_type = event_publisher.EVENT_SQS_CREATE_QUEUE
        response_data = xmltodict.parse(response.content)
        if "CreateQueueResponse" in response_data:
            queue_url = response_data["CreateQueueResponse"]["CreateQueueResult"]["QueueUrl"]
    elif action == "DeleteQueue":
        event_type = event_publisher.EVENT_SQS_DELETE_QUEUE
        queue_url = req_data.get("QueueUrl")

    if event_type and queue_url:
        event_publisher.fire_event(event_type, payload={"u": event_publisher.get_hash(queue_url)})


def _queue_url(path, req_data, headers):
    queue_url = req_data.get("QueueUrl")
    if queue_url:
        return queue_url
    url = config.service_url("sqs")
    if headers.get("Host"):
        url = "%s://%s" % (get_service_protocol(), headers["Host"])
    queue_url = "%s%s" % (url, path.partition("?")[0])
    return queue_url


def _list_dead_letter_source_queues(queues, queue_url):
    dead_letter_source_queues = []
    for k, v in queues.items():
        for i, j in v.items():
            if i == "RedrivePolicy":
                f = json.loads(v[i])
                queue_url_split = queue_url.split("/")
                if queue_url_split[-1] in f["deadLetterTargetArn"]:
                    dead_letter_source_queues.append(k)
    return format_list_dl_source_queues_response(dead_letter_source_queues)


def _process_sent_message(path: str, req_data: Dict[str, str], headers: Dict, response: Response):
    """Extract one or multiple messages sent via SendMessage/SendMessageBatch from the given
    request/response data and forward them to the Lambda EventSourceListener for further processing"""

    queue_url = _queue_url(path, req_data, headers)
    action = req_data.get("Action")

    # extract data from XML response - assume data is wrapped in 2 parent elements
    response_data = xmltodict.parse(response.content)

    messages = []
    if action == "SendMessage":
        response_data = response_data["SendMessageResponse"]["SendMessageResult"]
        message = clone(req_data)
        message.update(response_data)
        messages.append(message)
    elif action == "SendMessageBatch":
        response_data = response_data["SendMessageBatchResponse"]["SendMessageBatchResult"]
        messages = parse_urlencoded_data(req_data, "SendMessageBatchRequestEntry")
        # Note: only forwarding messages from 'Successful', not from 'Failed' list
        entries = response_data.get("SendMessageBatchResultEntry") or []
        entries = ensure_list(entries)
        for successful in entries:
            msg = [m for m in messages if m["Id"] == successful["Id"]][0]
            msg.update(successful)

    event = {
        "QueueUrl": queue_url,
        "Messages": messages,
    }
    EventSourceListener.process_event_via_listener("sqs", event)


def format_list_dl_source_queues_response(queues):
    content_str = """<ListDeadLetterSourceQueuesResponse xmlns="{}">
                        <ListDeadLetterSourceQueuesResult>
                        {}
                        </ListDeadLetterSourceQueuesResult>
                    </ListDeadLetterSourceQueuesResponse>"""

    queue_urls = ""
    for q in queues:
        queue_urls += "<QueueUrl>{}</QueueUrl>".format(q)

    return content_str.format(XMLNS_SQS, queue_urls)


# extract the external port used by the client to make the request
def get_external_port(headers):
    host = headers.get("Host", "")

    if not host:
        forwarded = headers.get("X-Forwarded-For", "").split(",")
        host = forwarded[-2] if len(forwarded) > 2 else forwarded[-1]

    if ":" in host:
        return int(host.split(":")[1])

    # If we cannot find the Host header, then fall back to the port of SQS itself (i.e., edge proxy).
    # (Note that this could be incorrect, e.g., if running in Docker with a host port that
    #  is different from the internal container port, but there is not much else we can do.)
    return config.service_port("sqs")


def validate_empty_message_batch(data, req_data):
    data = to_str(data).split("Entries=")
    if len(data) > 1 and not req_data.get("Entries"):
        return True
    return False


def is_sqs_queue_url(url):
    path = path_from_url(url).partition("?")[0]
    return re.match(r"^/(queue|%s)/[a-zA-Z0-9_-]+$" % constants.TEST_AWS_ACCOUNT_ID, path)


class ProxyListenerSQS(PersistingProxyListener):
    def api_name(self):
        return "sqs"

    def forward_request(self, method, path, data, headers):
        if method == "OPTIONS":
            return 200

        req_data = parse_request_data(method, path, data)

        if is_sqs_queue_url(path) and method == "GET":
            if not headers.get("Authorization"):
                headers["Authorization"] = aws_stack.mock_aws_request_headers(service="sqs")[
                    "Authorization"
                ]
            method = "POST"
            req_data = {
                "Action": "GetQueueUrl",
                "Version": API_VERSION,
                "QueueName": path.split("/")[-1],
            }

        if req_data:
            action = req_data.get("Action")

            if action in ("SendMessage", "SendMessageBatch") and SQS_BACKEND_IMPL == "moto":
                # check message contents
                for key, value in req_data.items():
                    if not re.match(MSG_CONTENT_REGEX, str(value)):
                        return make_requests_error(
                            code=400,
                            code_string="InvalidMessageContents",
                            message="Message contains invalid characters",
                        )

            elif action == "SetQueueAttributes":
                # TODO remove this function if we stop using ElasticMQ
                queue_url = _queue_url(path, req_data, headers)
                if SQS_BACKEND_IMPL == "elasticmq":
                    forward_attrs = _set_queue_attributes(queue_url, req_data)
                    if len(req_data) != len(forward_attrs):
                        # make sure we only forward the supported attributes to the backend
                        return _get_attributes_forward_request(
                            method, path, headers, req_data, forward_attrs
                        )

            elif action == "TagQueue":
                req_data = self.fix_missing_tag_values(req_data)

            elif action == "CreateQueue":
                req_data = self.fix_missing_tag_values(req_data)

                def _is_fifo():
                    for k, v in req_data.items():
                        if v == "FifoQueue":
                            return req_data[k.replace("Name", "Value")].lower() == "true"
                    return False

                if req_data.get("QueueName").endswith(".fifo") and not _is_fifo():
                    msg = "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length"
                    return make_requests_error(
                        code=400, code_string="InvalidParameterValue", message=msg
                    )
                changed_attrs = _fix_dlq_arn_in_attributes(req_data)
                if changed_attrs:
                    return _get_attributes_forward_request(
                        method, path, headers, req_data, changed_attrs
                    )

            elif action == "DeleteQueue":
                queue_url = _queue_url(path, req_data, headers)
                QUEUE_ATTRIBUTES.pop(queue_url, None)
                sns_listener.unsubscribe_sqs_queue(queue_url)

            elif action == "ListDeadLetterSourceQueues":
                # TODO remove this function if we stop using ElasticMQ entirely
                queue_url = _queue_url(path, req_data, headers)
                if SQS_BACKEND_IMPL == "elasticmq":
                    headers = {"content-type": "application/xhtml+xml"}
                    content_str = _list_dead_letter_source_queues(QUEUE_ATTRIBUTES, queue_url)
                    return requests_response(content_str, headers=headers)

            if "QueueName" in req_data:
                encoded_data = urlencode(req_data, doseq=True) if method == "POST" else ""
                modified_url = None
                if method == "GET":
                    base_path = path.partition("?")[0]
                    modified_url = "%s?%s" % (
                        base_path,
                        urlencode(req_data, doseq=True),
                    )
                return Request(data=encoded_data, url=modified_url, headers=headers, method=method)

        return True

    def return_response(self, method, path, data, headers, response):
        # persist requests to disk
        super(ProxyListenerSQS, self).return_response(method, path, data, headers, response)

        if method == "OPTIONS" and path == "/":
            # Allow CORS preflight requests to succeed.
            return 200

        if method != "POST":
            return

        region_name = aws_stack.get_region()
        req_data = parse_request_data(method, path, data)
        action = req_data.get("Action")
        content_str = content_str_original = to_str(response.content)

        if response.status_code >= 400:
            return response

        _fire_event(req_data, response)

        # patch the response and add missing attributes
        if action == "GetQueueAttributes":
            content_str = _add_queue_attributes(path, req_data, content_str, headers)

        name = r"<Name>\s*RedrivePolicy\s*<\/Name>"
        value = r"<Value>\s*{(.*)}\s*<\/Value>"
        for p1, p2 in ((name, value), (value, name)):
            content_str = re.sub(
                r"<Attribute>\s*%s\s*%s\s*<\/Attribute>" % (p1, p2),
                _fix_redrive_policy,
                content_str,
            )

        # patch the response and return the correct endpoint URLs / ARNs
        if action in (
            "CreateQueue",
            "GetQueueUrl",
            "ListQueues",
            "GetQueueAttributes",
            "ListDeadLetterSourceQueues",
        ):
            if config.USE_SSL and "<QueueUrl>http://" in content_str:
                # return https://... if we're supposed to use SSL
                content_str = re.sub(r"<QueueUrl>\s*http://", r"<QueueUrl>https://", content_str)
            # expose external hostname:port
            external_port = SQS_PORT_EXTERNAL or get_external_port(headers)
            content_str = re.sub(
                r"<QueueUrl>\s*([a-z]+)://[^<]*:([0-9]+)/([^<]*)\s*</QueueUrl>",
                r"<QueueUrl>\1://%s:%s/\3</QueueUrl>" % (config.HOSTNAME_EXTERNAL, external_port),
                content_str,
            )
            # encode account ID in queue URL
            content_str = re.sub(
                r"<QueueUrl>\s*([a-z]+)://([^/]+)/queue/([^<]*)\s*</QueueUrl>",
                r"<QueueUrl>\1://\2/%s/\3</QueueUrl>" % constants.TEST_AWS_ACCOUNT_ID,
                content_str,
            )
            # fix queue ARN
            content_str = re.sub(
                r"<([a-zA-Z0-9]+)>\s*arn:aws:sqs:elasticmq:([^<]+)</([a-zA-Z0-9]+)>",
                r"<\1>arn:aws:sqs:%s:\2</\3>" % region_name,
                content_str,
            )

            if action == "CreateQueue":
                regex = r".*<QueueUrl>(.*)</QueueUrl>"
                queue_url = re.match(regex, content_str, re.DOTALL).group(1)
                if SQS_BACKEND_IMPL == "elasticmq":
                    _set_queue_attributes(queue_url, req_data)

        elif action == "SendMessageBatch":
            if validate_empty_message_batch(data, req_data):
                msg = "There should be at least one SendMessageBatchRequestEntry in the request."
                return make_requests_error(code=404, code_string="EmptyBatchRequest", message=msg)

        # instruct listeners to process new SQS message
        if action in ("SendMessage", "SendMessageBatch"):
            _process_sent_message(path, req_data, headers, response)

        if content_str_original != content_str:
            # if changes have been made, return patched response
            response.headers["Content-Length"] = len(content_str)
            response.headers["x-amz-crc32"] = calculate_crc32(content_str)
            return requests_response(
                content_str, headers=response.headers, status_code=response.status_code
            )

    @classmethod
    # TODO still needed? (can probably be removed)
    def get_message_attributes_md5(cls, req_data):
        req_data = clone(req_data)
        orig_types = {}
        for key, entry in dict(req_data).items():
            # Fix an issue in moto where data types like 'Number.java.lang.Integer' are
            # not supported: Keep track of the original data type, and temporarily change
            # it to the short form (e.g., 'Number'), before changing it back again.
            if key.endswith("DataType"):
                parts = entry.split(".")
                if len(parts) > 2:
                    short_type_name = parts[0]
                    full_type_name = entry
                    attr_num = key.split(".")[1]
                    attr_name = req_data["MessageAttribute.%s.Name" % attr_num]
                    orig_types[attr_name] = full_type_name
                    req_data[key] = [short_type_name]
                    if full_type_name not in TRANSPORT_TYPE_ENCODINGS:
                        TRANSPORT_TYPE_ENCODINGS[full_type_name] = TRANSPORT_TYPE_ENCODINGS[
                            short_type_name
                        ]

        # moto parse_message_attributes(..) expects params to be passed as dict of lists
        req_data_lists = {k: [v] for k, v in req_data.items()}
        moto_message = Message("dummy_msg_id", "dummy_body")
        moto_message.message_attributes = parse_message_attributes(req_data_lists)
        for key, data_type in orig_types.items():
            moto_message.message_attributes[key]["data_type"] = data_type
        message_attr_hash = moto_message.attribute_md5

        return message_attr_hash

    # Fixes tags with empty strings as value
    def fix_missing_tag_values(self, req_data):
        keys_matched = []
        for k, v in req_data.items():
            match = re.match(r"^Tag\.(\d+)\.Key", k)
            if match:
                index = match.group(1)
                tag_val = "Tag.{}.Value".format(index)
                if tag_val not in req_data.keys():
                    keys_matched.append(tag_val)
        if keys_matched:
            for tag_val in keys_matched:
                req_data[tag_val] = ""
        return req_data


# instantiate listener
UPDATE_SQS = ProxyListenerSQS()
