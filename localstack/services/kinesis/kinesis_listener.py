import base64
import json
import logging
import random
import re
import time

import cbor2
from requests.models import Response

from localstack import config
from localstack.constants import APPLICATION_CBOR, APPLICATION_JSON, HEADER_AMZN_ERROR_TYPE
from localstack.services.generic_proxy import ProxyListener, RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.aws.aws_responses import convert_to_binary_event_payload
from localstack.utils.common import clone, json_safe, now_utc, to_bytes, to_str

LOG = logging.getLogger(__name__)

# action headers (should be left here - imported/required by other files)
ACTION_PREFIX = "Kinesis_20131202"
ACTION_PUT_RECORD = "%s.PutRecord" % ACTION_PREFIX
ACTION_PUT_RECORDS = "%s.PutRecords" % ACTION_PREFIX
ACTION_LIST_STREAMS = "%s.ListStreams" % ACTION_PREFIX


class KinesisBackend(RegionBackend):
    def __init__(self):
        # list of stream consumer details
        self.stream_consumers = []
        # maps stream name to list of enhanced monitoring metrics
        self.enhanced_metrics = {}


class ProxyListenerKinesis(ProxyListener):
    def forward_request(self, method, path, data, headers):
        data, encoding_type = self.decode_content(data or "{}", True)
        action = headers.get("X-Amz-Target", "").split(".")[-1]

        if action == "SubscribeToShard":
            result = subscribe_to_shard(data, headers)
            return result

        if random.random() < config.KINESIS_ERROR_PROBABILITY:
            if action in ["PutRecord", "PutRecords"]:
                return kinesis_error_response(data, action, encoding_type)

        if config.KINESIS_PROVIDER == "kinesalite":
            return self.forward_request_kinesalite(
                method, path, data, headers, action, encoding_type
            )

        return True

    def forward_request_kinesalite(self, method, path, data, headers, action, encoding_type):
        if action == "RegisterStreamConsumer" and config.KINESIS_PROVIDER == "kinesalite":
            stream_arn = data.get("StreamARN", "").strip('" ')
            cons_arn = data.get("ConsumerARN", "").strip('" ')
            cons_name = data.get("ConsumerName", "").strip('" ')
            prev_consumer = find_consumer(cons_arn, cons_name, stream_arn)

            if prev_consumer:
                msg = "Consumer %s already exists" % prev_consumer.get("ConsumerARN")
                return simple_error_response(msg, 400, "ResourceAlreadyExists", encoding_type)

            consumer = clone(data)
            consumer["ConsumerStatus"] = "ACTIVE"
            consumer["ConsumerARN"] = "%s/consumer/%s" % (stream_arn, cons_name)
            consumer["ConsumerCreationTimestamp"] = now_utc()
            consumer = json_safe(consumer)
            stream_consumers = KinesisBackend.get().stream_consumers
            stream_consumers.append(consumer)

            result = {"Consumer": consumer}

            return encoded_response(result, encoding_type)

        elif action == "DeregisterStreamConsumer" and config.KINESIS_PROVIDER == "kinesalite":

            def consumer_matches(c):
                stream_arn = data.get("StreamARN", "").strip('" ')
                cons_name = data.get("ConsumerName", "").strip('" ')
                cons_arn = data.get("ConsumerARN", "").strip('" ')
                return c.get("ConsumerARN") == cons_arn or (
                    c.get("StreamARN") == stream_arn and c.get("ConsumerName") == cons_name
                )

            region = KinesisBackend.get()
            region.stream_consumers = [
                c for c in region.stream_consumers if not consumer_matches(c)
            ]
            return {}

        elif action == "ListStreamConsumers" and config.KINESIS_PROVIDER == "kinesalite":
            stream_consumers = KinesisBackend.get().stream_consumers
            stream_arn = data.get("StreamARN", "").strip('" ')
            result = {
                "Consumers": [c for c in stream_consumers if c.get("StreamARN") == stream_arn]
            }
            return encoded_response(result, encoding_type)

        elif action == "DescribeStreamConsumer" and config.KINESIS_PROVIDER == "kinesalite":
            consumer_arn = data.get("ConsumerARN", "").strip('" ')
            consumer_name = data.get("ConsumerName", "").strip('" ')
            stream_arn = data.get("StreamARN", "").strip('" ')

            consumer_to_locate = find_consumer(consumer_arn, consumer_name, stream_arn)
            if not consumer_to_locate:
                error_msg = "Consumer %s not found." % (consumer_arn or consumer_name)
                return simple_error_response(
                    error_msg, 400, "ResourceNotFoundException", encoding_type
                )

            create_timestamp = consumer_to_locate.get("ConsumerCreationTimestamp")
            time_formated = (
                int(create_timestamp) if encoding_type is not APPLICATION_JSON else create_timestamp
            )

            result = {
                "ConsumerDescription": {
                    "ConsumerARN": consumer_to_locate.get("ConsumerARN"),
                    "ConsumerCreationTimestamp": time_formated,
                    "ConsumerName": consumer_to_locate.get("ConsumerName"),
                    "ConsumerStatus": "ACTIVE",
                    "StreamARN": data.get("StreamARN"),
                }
            }
            return encoded_response(result, encoding_type)

        elif action == "EnableEnhancedMonitoring" and config.KINESIS_PROVIDER == "kinesalite":
            stream_name = data.get("StreamName", "").strip('" ')
            metrics = data.get("ShardLevelMetrics", [])
            enhanced_metrics = KinesisBackend.get().enhanced_metrics
            stream_metrics = enhanced_metrics[stream_name] = enhanced_metrics.get(stream_name) or []
            stream_metrics += [m for m in metrics if m not in stream_metrics]
            return {}

        elif action == "DisableEnhancedMonitoring" and config.KINESIS_PROVIDER == "kinesalite":
            stream_name = data.get("StreamName", "").strip('" ')
            metrics = data.get("ShardLevelMetrics", [])
            enhanced_metrics = KinesisBackend.get().enhanced_metrics
            stream_metrics = enhanced_metrics.get(stream_name) or []
            enhanced_metrics[stream_name] = [m for m in stream_metrics if m not in metrics]
            return {}

        return True

    def return_response(self, method, path, data, headers, response):
        action = headers.get("X-Amz-Target", "").split(".")[-1]
        data, encoding_type = self.decode_content(data or "{}", True)
        response._content = self.replace_in_encoded(response.content or "")

        if action in ("CreateStream", "DeleteStream"):
            event_type = (
                event_publisher.EVENT_KINESIS_CREATE_STREAM
                if action == "CreateStream"
                else event_publisher.EVENT_KINESIS_DELETE_STREAM
            )
            payload = {"n": event_publisher.get_hash(data.get("StreamName"))}
            if action == "CreateStream":
                payload["s"] = data.get("ShardCount")
            event_publisher.fire_event(event_type, payload=payload)
        elif action == "UpdateShardCount" and config.KINESIS_PROVIDER == "kinesalite":
            # Currently kinesalite, which backs the Kinesis implementation for localstack, does
            # not support UpdateShardCount:
            # https://github.com/mhart/kinesalite/issues/61
            #
            # [Terraform](https://www.terraform.io) makes the call to UpdateShardCount when it
            # applies Kinesis resources. A Terraform run fails when this is not present.
            #
            # The code that follows just returns a successful response, bypassing the 400
            # response that kinesalite returns.
            #
            response = Response()
            response.status_code = 200
            content = {
                "CurrentShardCount": 1,
                "StreamName": data["StreamName"],
                "TargetShardCount": data["TargetShardCount"],
            }
            response.encoding = "UTF-8"
            response._content = json.dumps(content)
            return response
        elif action == "GetRecords":
            sdk_v2 = self.is_sdk_v2_request(headers)
            results, encoding_type = self.decode_content(response.content, True)

            records = results.get("Records", [])
            if not records:
                return response

            for record in records:
                if sdk_v2:
                    record["ApproximateArrivalTimestamp"] = int(
                        record["ApproximateArrivalTimestamp"]
                    )

                tmp = record["Data"]
                # "tmp" is either a base64-encoded string, or a dict {"data": <data_bytes...>}
                is_base64_encoded = isinstance(tmp, str)
                if isinstance(tmp, dict):
                    tmp = bytearray(tmp.get("data", []))

                if is_base64_encoded:
                    tmp = base64.b64decode(tmp)

                if encoding_type == APPLICATION_JSON:
                    # Remove double quotes from data written in regular JSON encoding (not for CBOR!)
                    # https://github.com/localstack/localstack/issues/3588
                    if len(tmp) >= 2 and tmp[0] == tmp[-1] == b'"'[0]:
                        tmp = tmp[1:-1]
                if encoding_type == APPLICATION_CBOR:
                    # Note: AWS Java SDK requires bytes embedded in CBOR encoding, not base64 strings!
                    tmp = to_bytes(tmp)

                if encoding_type == APPLICATION_JSON:
                    if is_base64_encoded:
                        tmp = base64.b64encode(tmp)
                    tmp = to_str(tmp)

                record["Data"] = tmp

            response._content = encode_data(results, encoding_type)
            return response

        if response.status_code >= 400:
            response_body = self.decode_content(response.content)
            if (
                response_body
                and response_body.get("__type")
                and not headers.get(HEADER_AMZN_ERROR_TYPE)
            ):
                response.headers[HEADER_AMZN_ERROR_TYPE] = str(response_body.get("__type"))

    def is_sdk_v2_request(self, headers):
        user_agent = headers.get("User-Agent", "").split(" ")[0]
        if re.search(r"\/2.\d+.\d+", user_agent):
            return True
        return False

    def replace_in_encoded(self, data):
        if not data:
            return ""

        def _replace(_data):
            return re.sub(
                r"arn:aws:kinesis:[^:]+:",
                "arn:aws:kinesis:%s:" % aws_stack.get_region(),
                _data,
            )

        decoded, type_encoding = self.decode_content(data, True)

        if type_encoding == APPLICATION_JSON:
            return _replace(to_str(data))

        if type_encoding == APPLICATION_CBOR:
            replaced = _replace(json.dumps(decoded))
            return cbor2.dumps(json.loads(replaced))

    def decode_content(self, data, describe=False):
        try:
            decoded = json.loads(to_str(data))
            content_type = APPLICATION_JSON
        except UnicodeDecodeError:
            decoded = cbor2.loads(data)
            content_type = APPLICATION_CBOR

        if describe:
            return decoded, content_type

        return decoded


def encode_data(data, encoding_type):
    if encoding_type == APPLICATION_CBOR:
        return cbor2.dumps(data)
    return json.dumps(data)


def encoded_response(data, encoding_type=APPLICATION_JSON, status_code=200):
    response = Response()
    response.status_code = status_code
    response.headers.update({"content-type": encoding_type})
    response._content = encode_data(data, encoding_type)
    return response


def subscribe_to_shard(data, headers):
    kinesis = aws_stack.connect_to_service("kinesis")
    stream_name = find_stream_for_consumer(data["ConsumerARN"])
    iter_type = data["StartingPosition"]["Type"]
    kwargs = {}
    starting_sequence_number = data["StartingPosition"].get("SequenceNumber") or "0"
    if iter_type in ["AT_SEQUENCE_NUMBER", "AFTER_SEQUENCE_NUMBER"]:
        kwargs["StartingSequenceNumber"] = starting_sequence_number
    elif iter_type in ["AT_TIMESTAMP"]:
        # or value is just an example timestamp from aws docs
        timestamp = data["StartingPosition"].get("Timestamp") or 1459799926.480
        kwargs["Timestamp"] = timestamp
    iterator = kinesis.get_shard_iterator(
        StreamName=stream_name, ShardId=data["ShardId"], ShardIteratorType=iter_type, **kwargs
    )["ShardIterator"]

    def send_events():
        yield convert_to_binary_event_payload("", event_type="initial-response")
        iter = iterator
        last_sequence_number = starting_sequence_number
        # TODO: find better way to run loop up to max 5 minutes (until connection terminates)!
        for i in range(5 * 60):
            result = None
            try:
                result = kinesis.get_records(ShardIterator=iter)
            except Exception as e:
                if "ResourceNotFoundException" in str(e):
                    LOG.debug(
                        'Kinesis stream "%s" has been deleted, closing shard subscriber',
                        stream_name,
                    )
                    return
                raise
            iter = result.get("NextShardIterator")
            records = result.get("Records", [])
            for record in records:
                record["ApproximateArrivalTimestamp"] = record[
                    "ApproximateArrivalTimestamp"
                ].timestamp()
                # boto3 automatically decodes records in get_records(), so we must re-encode
                record["Data"] = to_str(base64.b64encode(record["Data"]))
                last_sequence_number = record["SequenceNumber"]
            if not records:
                time.sleep(1)
                continue

            response = {
                "ChildShards": [],
                "ContinuationSequenceNumber": last_sequence_number,
                "MillisBehindLatest": 0,
                "Records": json_safe(records),
            }
            result = json.dumps(response)
            yield convert_to_binary_event_payload(result, event_type="SubscribeToShardEvent")

    headers = {}
    return send_events(), headers


def find_consumer(consumer_arn="", consumer_name="", stream_arn=""):
    stream_consumers = KinesisBackend.get().stream_consumers
    for consumer in stream_consumers:
        if consumer_arn and consumer_arn == consumer.get("ConsumerARN"):
            return consumer
        elif consumer_name == consumer.get("ConsumerName") and stream_arn == consumer.get(
            "StreamARN"
        ):
            return consumer


def find_stream_for_consumer(consumer_arn):
    kinesis = aws_stack.connect_to_service("kinesis")
    for stream_name in kinesis.list_streams()["StreamNames"]:
        stream_arn = aws_stack.kinesis_stream_arn(stream_name)
        for cons in kinesis.list_stream_consumers(StreamARN=stream_arn)["Consumers"]:
            if cons["ConsumerARN"] == consumer_arn:
                return stream_name
    raise Exception("Unable to find stream for stream consumer %s" % consumer_arn)


def simple_error_response(msg, code, type_error, encoding_type=APPLICATION_JSON):
    body = {"message": msg, "__type": type_error}
    return encoded_response(body, encoding_type, code)


def kinesis_error_response(data, action, encoding_type):
    error_response = Response()

    if action == "PutRecord":
        error_response.status_code = 400
        content = {
            "__type": "ProvisionedThroughputExceededException",
            "ErrorMessage": "Rate exceeded for shard X in stream Y under account Z.",
        }
    else:
        error_response.status_code = 200
        content = {"FailedRecordCount": 1, "Records": []}
        for record in data.get("Records", []):
            content["Records"].append(
                {
                    "ErrorCode": "ProvisionedThroughputExceededException",
                    "ErrorMessage": "Rate exceeded for shard X in stream Y under account Z.",
                }
            )

    error_response.headers.update({"content-type": encoding_type})
    error_response._content = encode_data(content, encoding_type)
    return error_response


# instantiate listener
UPDATE_KINESIS = ProxyListenerKinesis()
