from __future__ import print_function

import base64
import json
import logging
import threading
import time
import traceback
import uuid
from typing import Dict, List, Optional, Union

import requests
from boto3.dynamodb.types import TypeDeserializer
from flask import Flask, jsonify, request
from six import iteritems

from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import generic_proxy
from localstack.services.generic_proxy import RegionBackend
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_responses, aws_stack
from localstack.utils.aws.aws_stack import (
    connect_elasticsearch,
    connect_to_resource,
    firehose_stream_arn,
    s3_bucket_name,
)
from localstack.utils.common import (
    TIMESTAMP_FORMAT_MICROS,
    clone,
    first_char_to_lower,
    keys_to_lower,
    now_utc,
    short_uid,
    timestamp,
    to_bytes,
    to_str,
    truncate,
)
from localstack.utils.kinesis import kinesis_connector

APP_NAME = "firehose_api"
app = Flask(APP_NAME)
ACTION_HEADER_PREFIX = "Firehose_20150804"

# logger
LOG = logging.getLogger(__name__)

# dynamodb deserializer
deser = TypeDeserializer()

# attributes specific to extended S3 destinations
S3_EXTENDED_DEST_ATTRS = [
    "ProcessingConfiguration",
    "S3BackupMode",
    "S3BackupDescription",
    "DataFormatConversionConfiguration",
]

# global sequence number counter for Firehose records (these are very large long values in AWS)
SEQUENCE_NUMBER = 49546986683135544286507457936321625675700192471156785154
SEQUENCE_NUMBER_MUTEX = threading.RLock()


class FirehoseBackend(RegionBackend):
    # maps stream names to details
    delivery_streams: Dict[str, Dict]

    def __init__(self):
        self.delivery_streams = {}


def get_delivery_stream_names() -> List[str]:
    region = FirehoseBackend.get()
    names = []
    for name, stream in iteritems(region.delivery_streams):
        names.append(stream["DeliveryStreamName"])
    return names


def get_delivery_stream_tags(
    stream_name: str, exclusive_start_tag_key: str = None, limit: int = 50
) -> Dict:
    region = FirehoseBackend.get()
    stream = region.delivery_streams[stream_name]
    response = {}
    start_i = -1
    if exclusive_start_tag_key is not None:
        start_i = next(
            iter(i for i, tag in enumerate(stream["Tags"]) if tag["Key"] == exclusive_start_tag_key)
        )

    response["Tags"] = [tag for i, tag in enumerate(stream["Tags"]) if start_i < i < limit]
    response["HasMore"] = len(response["Tags"]) < len(stream["Tags"])
    return response


def preprocess_records(processor: Dict, records: List[Dict]) -> List[Dict]:
    """Preprocess the list of records by calling the given processor (e.g., Lamnda function)."""
    proc_type = processor.get("Type")
    parameters = processor.get("Parameters", [])
    parameters = {p["ParameterName"]: p["ParameterValue"] for p in parameters}
    if proc_type == "Lambda":
        lambda_arn = parameters.get("LambdaArn")
        # TODO: add support for other parameters, e.g., NumberOfRetries, BufferSizeInMBs, BufferIntervalInSeconds, ...
        client = aws_stack.connect_to_service("lambda")
        records = keys_to_lower(records)
        event = {"records": records}
        event = to_bytes(json.dumps(event))
        response = client.invoke(FunctionName=lambda_arn, Payload=event)
        result = response.get("Payload").read()
        result = json.loads(to_str(result))
        records = result.get("records", [])
    else:
        LOG.warning("Unsupported Firehose processor type '%s'", proc_type)
    return records


def add_missing_record_attributes(records: List[Dict]) -> None:
    def _get_entry(obj, key):
        return obj.get(key) or obj.get(first_char_to_lower(key))

    for record in records:
        if not _get_entry(record, "ApproximateArrivalTimestamp"):
            record["ApproximateArrivalTimestamp"] = int(now_utc(millis=True))
        if not _get_entry(record, "KinesisRecordMetadata"):
            record["kinesisRecordMetadata"] = {
                "shardId": "shardId-000000000000",
                # not really documented what AWS is using internally - simply using a random UUID here
                "partitionKey": str(uuid.uuid4()),
                "approximateArrivalTimestamp": timestamp(
                    float(_get_entry(record, "ApproximateArrivalTimestamp")) / 1000,
                    format=TIMESTAMP_FORMAT_MICROS,
                ),
                "sequenceNumber": next_sequence_number(),
                "subsequenceNumber": "",
            }


def next_sequence_number() -> int:
    """Increase and return the next global sequence number."""
    global SEQUENCE_NUMBER
    with SEQUENCE_NUMBER_MUTEX:
        SEQUENCE_NUMBER += 1
        return SEQUENCE_NUMBER


def put_record(stream_name: str, record: Dict) -> Dict:
    """Put a record to the firehose stream from a PutRecord API call"""
    return put_records(stream_name, [record])


def put_records_to_s3_bucket(
    stream_name: str, records: List[Dict], s3_configuration: Dict[str, Union[str, Dict]]
):
    bucket = s3_bucket_name(s3_configuration["BucketARN"])
    prefix = s3_configuration.get("Prefix", "")

    s3 = connect_to_resource("s3")
    batched_data = b"".join([base64.b64decode(r.get("Data", r.get("data"))) for r in records])

    obj_path = get_s3_object_path(stream_name, prefix)
    try:
        LOG.debug("Publishing to S3 destination: %s. Data: %s", bucket, batched_data)
        s3.Object(bucket, obj_path).put(Body=batched_data)
    except Exception as e:
        LOG.error(
            "Unable to put records %s to s3 bucket: %s %s", records, e, traceback.format_exc()
        )
        raise e


def put_records(stream_name: str, unprocessed_records: List[Dict]) -> Dict:
    """Put a list of records to the firehose stream - either directly from a PutRecord API call, or
    received from an underlying Kinesis stream (if 'KinesisStreamAsSource' is configured)"""
    stream = get_stream(stream_name)
    if not stream:
        return error_not_found(stream_name)

    # preprocess records, add any missing attributes
    add_missing_record_attributes(unprocessed_records)

    for dest in stream.get("Destinations", []):

        # apply processing steps to incoming items
        proc_config = {}
        for child in dest.values():
            proc_config = (
                isinstance(child, dict) and child.get("ProcessingConfiguration") or proc_config
            )
        records = unprocessed_records
        if proc_config.get("Enabled") is not False:
            for processor in proc_config.get("Processors", []):
                # TODO: run processors asynchronously, to avoid request timeouts on PutRecord API calls
                records = preprocess_records(processor, records)

        if "ESDestinationDescription" in dest:
            es_dest = dest["ESDestinationDescription"]
            es_index = es_dest["IndexName"]
            es_type = es_dest.get("TypeName")
            es = connect_elasticsearch(
                endpoint=es_dest.get("ClusterEndpoint"), domain=es_dest.get("DomainARN")
            )
            # TODO support FailedDocumentsOnly as well
            if es_dest.get("S3BackupMode") == "AllDocuments":
                s3_config = es_dest.get("S3Configuration")
                if s3_config:
                    try:
                        put_records_to_s3_bucket(
                            stream_name=stream_name,
                            records=unprocessed_records,
                            s3_configuration=s3_config,
                        )
                    except Exception as e:
                        LOG.warning("Unable to backup unprocessed records to S3. Error: %s", e)
                else:
                    LOG.warning("Passed S3BackupMode without S3Configuration. Cannot backup...")
            for record in records:
                obj_id = uuid.uuid4()

                data = "{}"
                # DirectPut
                if "Data" in record:
                    data = base64.b64decode(record["Data"])
                # KinesisAsSource
                elif "data" in record:
                    data = base64.b64decode(record["data"])

                try:
                    body = json.loads(data)
                except Exception as e:
                    LOG.warning("Elasticsearch only allows json input data!")
                    raise e

                LOG.debug("Publishing to ES destination. Data: %s", truncate(data, max_length=300))
                try:
                    es.create(index=es_index, doc_type=es_type, id=obj_id, body=body)
                except Exception as e:
                    LOG.error("Unable to put record to stream: %s %s", e, traceback.format_exc())
                    raise e
        if "S3DestinationDescription" in dest:
            s3_dest_config = dest["S3DestinationDescription"]
            put_records_to_s3_bucket(stream_name, records, s3_dest_config)
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
                    "Unable to put Firehose records to HTTP endpoint %s: %s %s",
                    url,
                    e,
                    traceback.format_exc(),
                )
                raise e
    return {"RecordId": str(uuid.uuid4())}


def get_s3_object_path(stream_name, prefix):
    # See https://aws.amazon.com/kinesis/data-firehose/faqs/#Data_delivery
    # Path prefix pattern: myApp/YYYY/MM/DD/HH/
    # Object name pattern: DeliveryStreamName-DeliveryStreamVersion-YYYY-MM-DD-HH-MM-SS-RandomString
    if not prefix.endswith("/") and prefix != "":
        prefix = prefix + "/"
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
    dest = {"DestinationId": destination_id}
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
        details.update(elasticsearch_update)
    if s3_update:
        details = dest.setdefault("S3DestinationDescription", {})
        details.update(s3_update)
    if http_update:
        details = dest.setdefault("HttpEndpointDestinationDescription", {})
        details.update(http_update)
    return dest


def process_records(records: List[Dict], shard_id: str, fh_d_stream: str):
    """Process the given records from the underlying Kinesis stream"""
    return put_records(fh_d_stream, records)


def create_stream(
    stream_name: str,
    delivery_stream_type: str = "DirectPut",
    delivery_stream_type_configuration: Dict = None,
    s3_destination: Dict = None,
    elasticsearch_destination: Dict = None,
    http_destination: Dict = None,
    tags: Dict[str, str] = None,
):
    """Create a firehose stream with destination configurations. In case 'KinesisStreamAsSource' is set,
    creates a listener to process records from the underlying kinesis stream."""
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
        )
    return stream


def delete_stream(stream_name: str) -> Dict:
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


def get_stream(stream_name: str, format_s3_dest: bool = False) -> Optional[Dict]:
    region = FirehoseBackend.get()
    result = region.delivery_streams.get(stream_name)
    if result and format_s3_dest:
        result = clone(result)
        for dest in result.get("Destinations", []):
            s3_dest = dest.get("S3DestinationDescription") or {}
            if is_extended_s3_destination(s3_dest):
                dest["ExtendedS3DestinationDescription"] = dest.pop("S3DestinationDescription")
    return result


def is_extended_s3_destination(s3_dest: Dict) -> bool:
    return any(s3_dest.get(attr) is not None for attr in S3_EXTENDED_DEST_ATTRS)


def error_not_found(stream_name: str):
    msg = "Firehose %s under account %s not found." % (stream_name, TEST_AWS_ACCOUNT_ID)
    return error_response(msg, code=400, error_type="ResourceNotFoundException")


def error_response(msg: str, code: int = 500, error_type: str = "InternalFailure"):
    return aws_responses.flask_error_response_json(msg, code=code, error_type=error_type)


@app.route("/", methods=["POST"])
def post_request():
    action = request.headers.get("x-amz-target", "")
    action = action.split(".")[-1]
    data = json.loads(to_str(request.data))
    if action == "ListDeliveryStreams":
        response = {
            "DeliveryStreamNames": get_delivery_stream_names(),
            "HasMoreDeliveryStreams": False,
        }
    elif action == "CreateDeliveryStream":
        stream_name = data["DeliveryStreamName"]
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
