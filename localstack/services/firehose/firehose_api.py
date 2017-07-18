#!/usr/bin/env python
from __future__ import print_function

import os
import json
import uuid
import time
import logging
import sys
import boto3
import base64
import traceback
from datetime import datetime
from flask import Flask, jsonify, request, make_response
from localstack.config import TEST_S3_URL
from localstack.constants import *
from localstack.services.generic_proxy import GenericProxy
from localstack.utils.common import short_uid, to_str
from localstack.utils.aws.aws_stack import *
from six import iteritems


APP_NAME = 'firehose_api'

app = Flask(APP_NAME)

delivery_streams = {}


def get_delivery_stream_names():
    names = []
    for name, stream in iteritems(delivery_streams):
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
                    print("ERROR: %s" % traceback.format_exc())
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
        print('WARN: Firehose to Elasticsearch updates not yet implemented!')
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
    delivery_streams[stream_name] = stream
    if s3_destination:
        update_destination(stream_name=stream_name, destination_id=short_uid(), s3_update=s3_destination)
    return stream


def get_stream(stream_name):
    if stream_name not in delivery_streams:
        return None
    return delivery_streams[stream_name]


def bucket_name(bucket_arn):
    return bucket_arn.split(':::')[-1]


def role_arn(stream_name):
    return "arn:aws:iam::%s:role/%s" % (TEST_AWS_ACCOUNT_ID, stream_name)


@app.route('/', methods=['POST'])
def post_request():
    action = request.headers.get('x-amz-target')
    data = json.loads(to_str(request.data))
    response = None
    if action == 'Firehose_20150804.ListDeliveryStreams':
        response = {
            "DeliveryStreamNames": get_delivery_stream_names(),
            "HasMoreDeliveryStreams": False
        }
    elif action == 'Firehose_20150804.CreateDeliveryStream':
        stream_name = data['DeliveryStreamName']
        response = create_stream(stream_name, s3_destination=data.get('S3DestinationConfiguration'))
    elif action == 'Firehose_20150804.DescribeDeliveryStream':
        stream_name = data['DeliveryStreamName']
        response = get_stream(stream_name)
        if not response:
            response = {
                "__type": "ResourceNotFoundException",
                "message": "Firehose %s under account %s not found." % (stream_name, TEST_AWS_ACCOUNT_ID)
            }
            return make_response((jsonify(response), 400, {}))
        response = {
            'DeliveryStreamDescription': response
        }
    elif action == 'Firehose_20150804.PutRecord':
        stream_name = data['DeliveryStreamName']
        record = data['Record']
        put_record(stream_name, record)
        response = {
            "RecordId": str(uuid.uuid4())
        }
    elif action == 'Firehose_20150804.PutRecordBatch':
        stream_name = data['DeliveryStreamName']
        records = data['Records']
        put_records(stream_name, records)
        response = {
            "FailedPutCount": 0,
            "RequestResponses": []
        }
    elif action == 'Firehose_20150804.UpdateDestination':
        stream_name = data['DeliveryStreamName']
        version_id = data['CurrentDeliveryStreamVersionId']
        destination_id = data['DestinationId']
        s3_update = data['S3DestinationUpdate'] if 'S3DestinationUpdate' in data else None
        update_destination(stream_name=stream_name, destination_id=destination_id,
            s3_update=s3_update, version_id=version_id)
        response = {}

    return jsonify(response)


def serve(port, quiet=True):
    if quiet:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
    ssl_context = GenericProxy.get_flask_ssl_context()
    app.run(port=int(port), threaded=True, host='0.0.0.0', ssl_context=ssl_context)

if __name__ == '__main__':
    port = DEFAULT_PORT_FIREHOSE
    print("Starting server on port %s" % port)
    serve(port)
