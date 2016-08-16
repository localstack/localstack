#!/usr/bin/env python

import os
import json
import uuid
import logging
from flask import Flask, jsonify, request
import __init__
from localstack.utils.aws import aws_stack

APP_NAME = 'ddb_streams_mock'

app = Flask(APP_NAME)

DDB_STREAMS = []


def add_dynamodb_stream(table_name, view_type='NEW_AND_OLD_IMAGES', enabled=True):
    if enabled:
        stream = {
            'StreamArn': aws_stack.dynamodb_stream_arn(table_name=table_name),
            'TableName': table_name,
            'StreamLabel': 'TODO'
        }
        DDB_STREAMS.append(stream)


@app.route('/', methods=['POST'])
def post_request():
    action = request.headers.get('x-amz-target')
    data = json.loads(request.data)
    result = None
    if action == 'DynamoDBStreams_20120810.ListStreams':
        result = {
            'Streams': DDB_STREAMS,
            'LastEvaluatedStreamArn': 'TODO'
        }
    else:
        print('WARNING: Unknown operation "%s"' % action)
    return jsonify(result)


def serve(port, quiet=True):
    if quiet:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
    app.run(port=int(port), threaded=True, host='0.0.0.0')

if __name__ == '__main__':
    port = DEFAULT_PORT_DYNAMODBSTREAMS
    print("Starting server on port %s" % port)
    serve(port)
