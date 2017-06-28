#!/usr/bin/env python

import os
import json
import uuid
import logging
from flask import Flask, jsonify, request
from localstack.mock.generic_proxy import GenericProxy

APP_NAME = 'es_mock'
API_PREFIX = '/2015-01-01'

DOMAIN_NAMES = []

app = Flask(APP_NAME)


@app.route('%s/domain' % API_PREFIX, methods=['GET'])
def list_domain_names():
    result = {
        'DomainNames': DOMAIN_NAMES
    }
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
