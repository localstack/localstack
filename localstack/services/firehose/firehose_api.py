from __future__ import print_function

import base64
import json
import logging
import time
import traceback
import uuid
from typing import Dict

import requests
from boto3.dynamodb.types import TypeDeserializer
from flask import Flask, jsonify, request
from six import iteritems

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import generic_proxy
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_responses
from localstack.utils.aws.aws_stack import (
    connect_elasticsearch,
    connect_to_resource,
    extract_region_from_auth_header,
    firehose_stream_arn,
)
from localstack.utils.common import clone, short_uid, timestamp, to_str
from localstack.utils.kinesis import kinesis_connector

APP_NAME = "firehose_api"
app = Flask(APP_NAME)
ACTION_HEADER_PREFIX = "Firehose_20150804"

# logger
LOG = logging.getLogger(__name__)

# dynamodb deserializer
deser = TypeDeserializer()


class FirehoseBackend(RegionBackend):
    # maps stream names to details
    delivery_streams: Dict[str, Dict]

    def __init__(self):
        self.delivery_streams = {}


def get_delivery_stream_names():
    region = FirehoseBackend.get()
    names = []
    for name, stream in iteritems(region.delivery_streams):
        names.append(stream["DeliveryStreamName"])
    return names


def get_delivery_stream_tags(stream_name, exclusive_start_tag_key=None, limit=50):
    region = FirehoseBackend.get()
    stream = region.delivery_streams[stream_name]
    response = {}
    start_i = -1
    if exclusive_start_tag_key is not None:
        start_i = next(
            iter(
                [i for i, tag in enumerate(stream["Tags"]) if tag["Key"] == exclusive_start_tag_key]
            )
        )

    response["Tags"] = [tag for i, tag in enumerate(stream["Tags"]) if start_i < i < limit]
    response["HasMore"] = len(response["Tags"]) < len(stream["Tags"])
    return response


def put_record(stream_name, record):
    return put_records(stream_name, [record])


def put_records(stream_name, records):
    stream = get_stream(stream_name)
    if not stream:
        return error_not_found(stream_name)
    for dest in stream.get("Destinations", []):
        if "ESDestinationDescription" in dest:
            es_dest = dest["ESDestinationDescription"]
            es_index = es_dest["IndexName"]
            es_type = es_dest.get("TypeName")
            es = connect_elasticsearch(
                endpoint=es_dest.get("ClusterEndpoint"), domain=es_dest.get("DomainARN")
            )
            for record in records:
                obj_id = uuid.uuid4()

                # DirectPut
                if "Data" in record:
                    data = base64.b64decode(record["Data"])
                # KinesisAsSource
                elif "data" in record:
                    data = base64.b64decode(record["data"])

                body = json.loads(data)

                try:
                    es.create(index=es_index, doc_type=es_type, id=obj_id, body=body)
                except Exception as e:
                    LOG.error("Unable to put record to stream: %s %s" % (e, traceback.format_exc()))
                    raise e
        if "S3DestinationDescription" in dest:
            s3_dest = dest["S3DestinationDescription"]
            bucket = bucket_name(s3_dest["BucketARN"])
            prefix = s3_dest.get("Prefix", "")

            s3 = connect_to_resource("s3")
            batched_data = b"".join([base64.b64decode(r.get("Data") or r["data"]) for r in records])

            obj_path = get_s3_object_path(stream_name, prefix)
            try:
                s3.Object(bucket, obj_path).put(Body=batched_data)
            except Exception as e:
                LOG.error("Unable to put record to stream: %s %s" % (e, traceback.format_exc()))
                raise e
        if "HttpEndpointDestinationDescription" in dest:
            http_dest = dest["HttpEndpointDestinationDescription"]
            end_point = http_dest["EndpointConfiguration"]
            url = end_point["Url"]
            record_to_send = {
                "requestId": str(uuid.uuid4()),
                "timestamp": (int(time.time())),
                "records": [],
            }
            for record in records:
                data = record.get("Data") or record.get("data")
                record_to_send["records"].append({"data": data})
            headers = {
                "Content-Type": "application/json",
            }
            try:
                requests.post(url, json=record_to_send, headers=headers)
            except Exception as e:
                LOG.info(
                    "Unable to put Firehose records to HTTP endpoint %s: %s %s"
                    % (url, e, traceback.format_exc())
                )
                raise e
    return {"RecordId": str(uuid.uuid4())}


def get_s3_object_path(stream_name, prefix):
    # See https://aws.amazon.com/kinesis/data-firehose/faqs/#Data_delivery
    # Path prefix pattern: myApp/YYYY/MM/DD/HH/
    # Object name pattern: DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
    prefix = "%s%s" % (prefix, "" if prefix.endswith("/") else "/")
    pattern = "{pre}%Y/%m/%d/%H/{name}-%Y-%m-%d-%H-%M-%S-{rand}"
    path = pattern.format(pre=prefix, name=stream_name, rand=str(uuid.uuid4()))
    path = timestamp(format=path)
    return path


def get_destination(stream_name, destination_id):
    stream = get_stream(stream_name)
    destinations = stream["Destinations"]
    for dest in destinations:
        if dest["DestinationId"] == destination_id:
            return dest
    dest = {}
    dest["DestinationId"] = destination_id
    destinations.append(dest)
    return dest


def update_destination(
    stream_name,
    destination_id,
    s3_update=None,
    elasticsearch_update=None,
    http_update=None,
    version_id=None,
):
    dest = get_destination(stream_name, destination_id)
    if elasticsearch_update:
        details = dest.setdefault("ESDestinationDescription", {})
        dest.update(elasticsearch_update)
    if s3_update:
        details = dest.setdefault("S3DestinationDescription", {})
        details.update(s3_update)
    if http_update:
        details = dest.setdefault("HttpEndpointDestinationDescription", {})
        details.update(http_update)
    return dest


def process_records(records, shard_id, fh_d_stream):
    return put_records(fh_d_stream, records)


def create_stream(
    stream_name,
    delivery_stream_type="DirectPut",
    delivery_stream_type_configuration=None,
    s3_destination=None,
    elasticsearch_destination=None,
    http_destination=None,
    tags=None,
    region_name=None,
):
    region = FirehoseBackend.get()
    tags = tags or {}
    stream = {
        "DeliveryStreamType": delivery_stream_type,
        "KinesisStreamSourceConfiguration": delivery_stream_type_configuration,
        "HasMoreDestinations": False,
        "VersionId": "1",
        "CreateTimestamp": time.time(),
        "DeliveryStreamARN": firehose_stream_arn(stream_name),
        "DeliveryStreamStatus": "ACTIVE",
        "DeliveryStreamName": stream_name,
        "Destinations": [],
        "Tags": tags,
    }
    region.delivery_streams[stream_name] = stream
    if elasticsearch_destination:
        update_destination(
            stream_name=stream_name,
            destination_id=short_uid(),
            elasticsearch_update=elasticsearch_destination,
        )
    if s3_destination:
        update_destination(
            stream_name=stream_name,
            destination_id=short_uid(),
            s3_update=s3_destination,
        )
    if http_destination:
        update_destination(
            stream_name=stream_name,
            destination_id=short_uid(),
            http_update=http_destination,
        )

    # record event
    event_publisher.fire_event(
        event_publisher.EVENT_FIREHOSE_CREATE_STREAM,
        payload={"n": event_publisher.get_hash(stream_name)},
    )

    if delivery_stream_type == "KinesisStreamAsSource":
        kinesis_stream_name = delivery_stream_type_configuration.get("KinesisStreamARN").split("/")[
            1
        ]
        kinesis_connector.listen_to_kinesis(
            stream_name=kinesis_stream_name,
            fh_d_stream=stream_name,
            listener_func=process_records,
            wait_until_started=True,
            ddb_lease_table_suffix="-firehose",
            region_name=region_name,
        )
    return stream


def delete_stream(stream_name):
    region = FirehoseBackend.get()
    stream = region.delivery_streams.pop(stream_name, {})
    if not stream:
        return error_not_found(stream_name)

    # record event
    event_publisher.fire_event(
        event_publisher.EVENT_FIREHOSE_DELETE_STREAM,
        payload={"n": event_publisher.get_hash(stream_name)},
    )

    return {}


def get_stream(stream_name: str, format_s3_dest: bool = False):
    region = FirehoseBackend.get()
    result = region.delivery_streams.get(stream_name)
    if result and format_s3_dest:
        extended_attrs = [
            "ProcessingConfiguration",
            "S3BackupMode",
            "S3BackupDescription",
            "DataFormatConversionConfiguration",
        ]
        result = clone(result)
        for dest in result.get("Destinations", []):
            s3_dest = dest.get("S3DestinationDescription") or {}
            if any([s3_dest.get(attr) is not None for attr in extended_attrs]):
                dest["ExtendedS3DestinationDescription"] = dest.pop("S3DestinationDescription")
    return result


def bucket_name(bucket_arn):
    return bucket_arn.split(":::")[-1]


def role_arn(stream_name):
    return "arn:aws:iam::%s:role/%s" % (TEST_AWS_ACCOUNT_ID, stream_name)


def error_not_found(stream_name):
    msg = "Firehose %s under account %s not found." % (stream_name, TEST_AWS_ACCOUNT_ID)
    return error_response(msg, code=400, error_type="ResourceNotFoundException")


def error_response(msg, code=500, error_type="InternalFailure"):
    return aws_responses.flask_error_response_json(msg, code=code, error_type=error_type)


@app.route("/", methods=["POST"])
def post_request():
    action = request.headers.get("x-amz-target", "")
    action = action.split(".")[-1]
    data = json.loads(to_str(request.data))
    response = None
    if action == "ListDeliveryStreams":
        response = {
            "DeliveryStreamNames": get_delivery_stream_names(),
            "HasMoreDeliveryStreams": False,
        }
    elif action == "CreateDeliveryStream":
        stream_name = data["DeliveryStreamName"]
        region_name = extract_region_from_auth_header(request.headers)
        _s3_destination = data.get("S3DestinationConfiguration") or data.get(
            "ExtendedS3DestinationConfiguration"
        )
        response = create_stream(
            stream_name,
            delivery_stream_type=data.get("DeliveryStreamType"),
            delivery_stream_type_configuration=data.get("KinesisStreamSourceConfiguration"),
            s3_destination=_s3_destination,
            elasticsearch_destination=data.get("ElasticsearchDestinationConfiguration"),
            http_destination=data.get("HttpEndpointDestinationConfiguration"),
            tags=data.get("Tags"),
            region_name=region_name,
        )
    elif action == "DeleteDeliveryStream":
        stream_name = data["DeliveryStreamName"]
        response = delete_stream(stream_name)
    elif action == "DescribeDeliveryStream":
        stream_name = data["DeliveryStreamName"]
        response = get_stream(stream_name, format_s3_dest=True)
        if not response:
            return error_not_found(stream_name)
        response = {"DeliveryStreamDescription": response}
    elif action == "PutRecord":
        stream_name = data["DeliveryStreamName"]
        record = data["Record"]
        response = put_record(stream_name, record)
    elif action == "PutRecordBatch":
        stream_name = data["DeliveryStreamName"]
        records = data["Records"]
        put_records(stream_name, records)
        request_responses = []
        for i in records:
            request_responses.append({"RecordId": str(uuid.uuid4())})
        response = {"FailedPutCount": 0, "RequestResponses": request_responses}
    elif action == "UpdateDestination":
        stream_name = data["DeliveryStreamName"]
        version_id = data["CurrentDeliveryStreamVersionId"]
        destination_id = data["DestinationId"]
        s3_update = data["S3DestinationUpdate"] if "S3DestinationUpdate" in data else None
        update_destination(
            stream_name=stream_name,
            destination_id=destination_id,
            s3_update=s3_update,
            version_id=version_id,
        )
        es_update = data["ESDestinationUpdate"] if "ESDestinationUpdate" in data else None
        update_destination(
            stream_name=stream_name,
            destination_id=destination_id,
            elasticsearch_update=es_update,
            version_id=version_id,
        )
        http_update = data.get("HttpEndpointDestinationUpdate")
        update_destination(
            stream_name=stream_name,
            destination_id=destination_id,
            http_update=http_update,
            version_id=version_id,
        )
        response = {}
    elif action == "ListTagsForDeliveryStream":
        response = get_delivery_stream_tags(
            data["DeliveryStreamName"],
            data.get("ExclusiveStartTagKey"),
            data.get("Limit", 50),
        )
    else:
        response = error_response(
            'Unknown action "%s"' % action, code=400, error_type="InvalidAction"
        )

    if isinstance(response, dict):
        response = jsonify(response)
    return response


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port)
