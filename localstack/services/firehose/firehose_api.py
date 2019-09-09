from __future__ import print_function

import json
import uuid
import time
import logging
import base64
import traceback
from six import iteritems
from flask import Flask, jsonify, request
from boto3.dynamodb.types import TypeDeserializer
from localstack.services import generic_proxy
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.aws import aws_responses
from localstack.utils.common import short_uid, to_str
from localstack.utils.aws.aws_stack import (
    get_s3_client, firehose_stream_arn, connect_elasticsearch, extract_region_from_auth_header)
from localstack.utils.kinesis import kinesis_connector
from localstack.utils.analytics import event_publisher

APP_NAME = 'firehose_api'
app = Flask(APP_NAME)
ACTION_HEADER_PREFIX = 'Firehose_20150804'

# logger
LOG = logging.getLogger(__name__)

# maps stream names to details
DELIVERY_STREAMS = {}

# dynamodb deserializer
deser = TypeDeserializer()


def get_delivery_stream_names():
    names = []
    for name, stream in iteritems(DELIVERY_STREAMS):
        names.append(stream['DeliveryStreamName'])
    return names


def get_delivery_stream_tags(stream_name, exclusive_start_tag_key=None, limit=50):
    stream = DELIVERY_STREAMS[stream_name]
    response = {}
    start_i = -1
    if exclusive_start_tag_key is not None:
        start_i = next(iter([i for i, tag in enumerate(stream['Tags']) if tag['Key'] == exclusive_start_tag_key]))

    response['Tags'] = [tag for i, tag in enumerate(stream['Tags']) if start_i < i < limit]
    response['HasMore'] = len(response['Tags']) < len(stream['Tags'])
    return response


def put_record(stream_name, record):
    return put_records(stream_name, [record])


def put_records(stream_name, records):
    stream = get_stream(stream_name)
    for dest in stream['Destinations']:
        if 'ESDestinationDescription' in dest:
            es_dest = dest['ESDestinationDescription']
            es_index = es_dest['IndexName']
            es_type = es_dest['TypeName']
            es = connect_elasticsearch()
            for record in records:
                obj_id = uuid.uuid4()

                # DirectPut
                if 'Data' in record:
                    data = base64.b64decode(record['Data'])
                # KinesisAsSource
                elif 'data' in record:
                    data = base64.b64decode(record['data'])

                body = json.loads(data)

                try:
                    es.create(index=es_index, doc_type=es_type, id=obj_id, body=body)
                except Exception as e:
                    LOG.error('Unable to put record to stream: %s %s' % (e, traceback.format_exc()))
                    raise e
        if 'S3DestinationDescription' in dest:
            s3_dest = dest['S3DestinationDescription']
            bucket = bucket_name(s3_dest['BucketARN'])
            prefix = s3_dest.get('Prefix', '')
            s3 = get_s3_client()
            for record in records:

                # DirectPut
                if 'Data' in record:
                    data = base64.b64decode(record['Data'])
                # KinesisAsSource
                elif 'data' in record:
                    data = base64.b64decode(record['data'])

                obj_name = str(uuid.uuid4())
                obj_path = '%s%s%s' % (prefix, '' if prefix.endswith('/') else '/', obj_name)
                try:
                    s3.Object(bucket, obj_path).put(Body=data)
                except Exception as e:
                    LOG.error('Unable to put record to stream: %s %s' % (e, traceback.format_exc()))
                    raise e


def get_destination(stream_name, destination_id):
    stream = get_stream(stream_name)
    destinations = stream['Destinations']
    for dest in destinations:
        if dest['DestinationId'] == destination_id:
            return dest
    dest = {}
    dest['DestinationId'] = destination_id
    destinations.append(dest)
    return dest


def update_destination(stream_name, destination_id,
                       s3_update=None, elasticsearch_update=None, version_id=None):
    dest = get_destination(stream_name, destination_id)
    if elasticsearch_update:
        if 'ESDestinationDescription' not in dest:
            dest['ESDestinationDescription'] = {}
        for k, v in iteritems(elasticsearch_update):
            dest['ESDestinationDescription'][k] = v
    if s3_update:
        if 'S3DestinationDescription' not in dest:
            dest['S3DestinationDescription'] = {}
        for k, v in iteritems(s3_update):
            dest['S3DestinationDescription'][k] = v
    return dest


def process_records(records, shard_id, fh_d_stream):
    put_records(fh_d_stream, records)


def create_stream(stream_name, delivery_stream_type='DirectPut', delivery_stream_type_configuration=None,
                  s3_destination=None, elasticsearch_destination=None, tags=None, region_name=None):
    tags = tags or {}
    stream = {
        'DeliveryStreamType': delivery_stream_type,
        'KinesisStreamSourceConfiguration': delivery_stream_type_configuration,
        'HasMoreDestinations': False,
        'VersionId': '1',
        'CreateTimestamp': time.time(),
        'DeliveryStreamARN': firehose_stream_arn(stream_name),
        'DeliveryStreamStatus': 'ACTIVE',
        'DeliveryStreamName': stream_name,
        'Destinations': [],
        'Tags': tags
    }
    DELIVERY_STREAMS[stream_name] = stream
    if elasticsearch_destination:
        update_destination(stream_name=stream_name,
                           destination_id=short_uid(),
                           elasticsearch_update=elasticsearch_destination)
    if s3_destination:
        update_destination(stream_name=stream_name, destination_id=short_uid(), s3_update=s3_destination)

    # record event
    event_publisher.fire_event(event_publisher.EVENT_FIREHOSE_CREATE_STREAM,
        payload={'n': event_publisher.get_hash(stream_name)})

    if delivery_stream_type == 'KinesisStreamAsSource':
        kinesis_stream_name = delivery_stream_type_configuration.get('KinesisStreamARN').split('/')[1]
        kinesis_connector.listen_to_kinesis(
            stream_name=kinesis_stream_name, fh_d_stream=stream_name,
            listener_func=process_records, wait_until_started=True,
            ddb_lease_table_suffix='-firehose', region_name=region_name)
    return stream


def delete_stream(stream_name):
    stream = DELIVERY_STREAMS.pop(stream_name, {})
    if not stream:
        return error_not_found(stream_name)

    # record event
    event_publisher.fire_event(event_publisher.EVENT_FIREHOSE_DELETE_STREAM,
        payload={'n': event_publisher.get_hash(stream_name)})

    return {}


def get_stream(stream_name):
    if stream_name not in DELIVERY_STREAMS:
        return None
    return DELIVERY_STREAMS[stream_name]


def bucket_name(bucket_arn):
    return bucket_arn.split(':::')[-1]


def role_arn(stream_name):
    return 'arn:aws:iam::%s:role/%s' % (TEST_AWS_ACCOUNT_ID, stream_name)


def error_not_found(stream_name):
    msg = 'Firehose %s under account %s not found.' % (stream_name, TEST_AWS_ACCOUNT_ID)
    return error_response(msg, code=400, error_type='ResourceNotFoundException')


def error_response(msg, code=500, error_type='InternalFailure'):
    return aws_responses.flask_error_response(msg, code=code, error_type=error_type)


@app.route('/', methods=['POST'])
def post_request():
    action = request.headers.get('x-amz-target')
    data = json.loads(to_str(request.data))
    response = None
    if action == '%s.ListDeliveryStreams' % ACTION_HEADER_PREFIX:
        response = {
            'DeliveryStreamNames': get_delivery_stream_names(),
            'HasMoreDeliveryStreams': False
        }
    elif action == '%s.CreateDeliveryStream' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        region_name = extract_region_from_auth_header(request.headers)
        response = create_stream(
            stream_name, delivery_stream_type=data.get('DeliveryStreamType'),
            delivery_stream_type_configuration=data.get('KinesisStreamSourceConfiguration'),
            s3_destination=data.get('S3DestinationConfiguration'),
            elasticsearch_destination=data.get('ElasticsearchDestinationConfiguration'),
            tags=data.get('Tags'), region_name=region_name)
    elif action == '%s.DeleteDeliveryStream' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        response = delete_stream(stream_name)
    elif action == '%s.DescribeDeliveryStream' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        response = get_stream(stream_name)
        if not response:
            return error_not_found(stream_name)
        response = {
            'DeliveryStreamDescription': response
        }
    elif action == '%s.PutRecord' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        record = data['Record']
        put_record(stream_name, record)
        response = {
            'RecordId': str(uuid.uuid4())
        }
    elif action == '%s.PutRecordBatch' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        records = data['Records']
        put_records(stream_name, records)
        response = {
            'FailedPutCount': 0,
            'RequestResponses': []
        }
    elif action == '%s.UpdateDestination' % ACTION_HEADER_PREFIX:
        stream_name = data['DeliveryStreamName']
        version_id = data['CurrentDeliveryStreamVersionId']
        destination_id = data['DestinationId']
        s3_update = data['S3DestinationUpdate'] if 'S3DestinationUpdate' in data else None
        update_destination(stream_name=stream_name, destination_id=destination_id,
                           s3_update=s3_update, version_id=version_id)
        es_update = data['ESDestinationUpdate'] if 'ESDestinationUpdate' in data else None
        update_destination(stream_name=stream_name, destination_id=destination_id,
                           es_update=es_update, version_id=version_id)
        response = {}
    elif action == '%s.ListTagsForDeliveryStream' % ACTION_HEADER_PREFIX:
        response = get_delivery_stream_tags(data['DeliveryStreamName'], data.get('ExclusiveStartTagKey'),
                                            data.get('Limit', 50))
    else:
        response = error_response('Unknown action "%s"' % action, code=400, error_type='InvalidAction')

    if isinstance(response, dict):
        response = jsonify(response)
    return response


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
