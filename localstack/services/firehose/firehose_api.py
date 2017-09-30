from __future__ import print_function

import json
import uuid
import time
import logging
import base64
import traceback
from flask import Flask, jsonify, request
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.services import generic_proxy
from localstack.utils.common import short_uid, to_str
from localstack.utils.aws import aws_responses
from localstack.utils.aws.aws_stack import get_s3_client, firehose_stream_arn
from six import iteritems

APP_NAME = 'firehose_api'
app = Flask(APP_NAME)
ACTION_HEADER_PREFIX = 'Firehose_20150804'

# logger
LOG = logging.getLogger(__name__)

# maps stream names to details
DELIVERY_STREAMS = {}


def get_delivery_stream_names():
    names = []
    for name, stream in iteritems(DELIVERY_STREAMS):
        names.append(stream['DeliveryStreamName'])
    return names


def put_record(stream_name, record):
    return put_records(stream_name, [record])


def put_records(stream_name, records):
    stream = get_stream(stream_name)
    for dest in stream['Destinations']:
        if 'S3DestinationDescription' in dest:
            s3_dest = dest['S3DestinationDescription']
            bucket = bucket_name(s3_dest['BucketARN'])
            prefix = s3_dest['Prefix']
            s3 = get_s3_client()
            for record in records:
                data = base64.b64decode(record['Data'])
                obj_name = str(uuid.uuid4())
                obj_path = '%s%s' % (prefix, obj_name)
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
        LOG.warning('Firehose to Elasticsearch updates not yet implemented!')
    if s3_update:
        if 'S3DestinationDescription' not in dest:
            dest['S3DestinationDescription'] = {}
        for k, v in iteritems(s3_update):
            dest['S3DestinationDescription'][k] = v
    return dest


def create_stream(stream_name, s3_destination=None):
    stream = {
        'HasMoreDestinations': False,
        'VersionId': '1',
        'CreateTimestamp': time.time(),
        'DeliveryStreamARN': firehose_stream_arn(stream_name),
        'DeliveryStreamStatus': 'ACTIVE',
        'DeliveryStreamName': stream_name,
        'Destinations': []
    }
    DELIVERY_STREAMS[stream_name] = stream
    if s3_destination:
        update_destination(stream_name=stream_name, destination_id=short_uid(), s3_update=s3_destination)
    return stream


def delete_stream(stream_name):
    stream = DELIVERY_STREAMS.pop(stream_name, {})
    if not stream:
        return error_not_found(stream_name)
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
        response = create_stream(stream_name, s3_destination=data.get('S3DestinationConfiguration'))
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
        response = {}
    else:
        response = error_response('Unknown action "%s"' % action, code=400, error_type='InvalidAction')

    if isinstance(response, dict):
        response = jsonify(response)
    return response


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
