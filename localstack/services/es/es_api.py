#!/usr/bin/env python

import os
import json
import uuid
import logging
from flask import Flask, jsonify, request, make_response
from requests.models import Response
from localstack.services.generic_proxy import GenericProxy
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import to_str

APP_NAME = 'es_api'
API_PREFIX = '/2015-01-01'

ES_DOMAINS = {}

app = Flask(APP_NAME)


def error_response(error_type, code=400, message='Unknown error.'):
    if not message:
        if error_type == 'ResourceNotFoundException':
            message = 'Resource not found.'
        elif error_type == 'ResourceAlreadyExistsException':
            message = 'Resource already exists.'
    response = make_response(jsonify({"error": message}))
    response.headers['x-amzn-errortype'] = error_type
    return response, code


def get_domain_status(domain_name, deleted=False):
    return {
        "DomainStatus": {
            "ARN": "arn:aws:es:us-east-1:123456789012:domain/streaming-logs",
            "Created": True,
            "Deleted": deleted,
            "DomainId": "%s/%s" % (TEST_AWS_ACCOUNT_ID, domain_name),
            "DomainName": domain_name,
            "ElasticsearchClusterConfig": {
                "DedicatedMasterCount": 1,
                "DedicatedMasterEnabled": True,
                "DedicatedMasterType": "m3.medium.elasticsearch",
                "InstanceCount": 1,
                "InstanceType": "m3.medium.elasticsearch",
                "ZoneAwarenessEnabled": True
            },
            "ElasticsearchVersion": "5.3",
            "Endpoint": None,
            "Processing": True
        }
    }


@app.route('%s/domain' % API_PREFIX, methods=['GET'])
def list_domain_names():
    result = {
        'DomainNames': [{'DomainName': name} for name in ES_DOMAINS.keys()]
    }
    return jsonify(result)


@app.route('%s/es/domain' % API_PREFIX, methods=['POST'])
def create_domain():
    data = json.loads(to_str(request.data))
    domain_name = data['DomainName']
    if domain_name in ES_DOMAINS:
        return error_response(error_type='ResourceAlreadyExistsException')
    ES_DOMAINS[domain_name] = data
    result = get_domain_status(domain_name)
    return jsonify(result)


@app.route('%s/es/domain/<domain_name>' % API_PREFIX, methods=['GET'])
def describe_domain(domain_name):
    if domain_name not in ES_DOMAINS:
        return error_response(error_type='ResourceNotFoundException')
    result = get_domain_status(domain_name)
    return jsonify(result)


@app.route('%s/es/domain/<domain_name>' % API_PREFIX, methods=['DELETE'])
def delete_domain(domain_name):
    if domain_name not in ES_DOMAINS:
        return error_response(error_type='ResourceNotFoundException')
    result = get_domain_status(domain_name, deleted=True)
    ES_DOMAINS.pop(domain_name)
    return jsonify(result)


def serve(port, quiet=True):
    if quiet:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.ERROR)
    ssl_context = GenericProxy.get_flask_ssl_context()
    app.run(port=int(port), threaded=True, host='0.0.0.0', ssl_context=ssl_context)

if __name__ == '__main__':
    port = DEFAULT_PORT_ES
    print("Starting server on port %s" % port)
    serve(port)
