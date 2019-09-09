import json
import time
from random import randint
from flask import Flask, jsonify, request, make_response
from localstack.config import DEFAULT_REGION
from localstack.services import generic_proxy
from localstack.utils.aws import aws_stack
from localstack.constants import TEST_AWS_ACCOUNT_ID
from localstack.utils.common import to_str
from localstack.utils.analytics import event_publisher

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
    response = make_response(jsonify({'error': message}))
    response.headers['x-amzn-errortype'] = error_type
    return response, code


def get_domain_config_status():
    return {
        'CreationDate': '%.2f' % time.time(),
        'PendingDeletion': False,
        'State': 'Active',
        'UpdateDate': '%.2f' % time.time(),
        'UpdateVersion': randint(1, 100)
    }


def get_domain_config(domain_name):
    config_status = get_domain_config_status()
    return {
        'DomainConfig': {
            'AccessPolicies': {
                'Options': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"es:*","Resource":"arn:aws:es:%s:%s:domain/%s/*"}]}' % (TEST_AWS_ACCOUNT_ID, DEFAULT_REGION, TEST_AWS_ACCOUNT_ID, domain_name),  # noqa: E501
                'Status': config_status
            },
            'AdvancedOptions': {
                'Options': {
                    'indices.fielddata.cache.size': '',
                    'rest.action.multi.allow_explicit_index': 'true'
                },
                'Status': config_status
            },
            'EBSOptions': {
                'Options': {
                    'EBSEnabled': True,
                    'EncryptionEnabled': False,
                    'Iops': 0,
                    'VolumeSize': 10,
                    'VolumeType': 'gp2'
                },
                'Status': config_status
            },
            'ElasticsearchClusterConfig': {
                'Options': {
                    'DedicatedMasterCount': 1,
                    'DedicatedMasterEnabled': True,
                    'DedicatedMasterType': 'm3.medium.elasticsearch',
                    'InstanceCount': 1,
                    'InstanceType': 'm3.medium.elasticsearch',
                    'ZoneAwarenessEnabled': False
                },
                'Status': config_status
            },
            'ElasticsearchVersion': {
                'Options': '5.3',
                'Status': config_status
            },
            'EncryptionAtRestOptions': {
                'Options': {
                    'Enabled': False,
                    'KmsKeyId': ''
                },
                'Status': config_status
            },
            'LogPublishingOptions': {
                'Options': {
                    'INDEX_SLOW_LOGS': {
                        'CloudWatchLogsLogGroupArn': 'arn:aws:logs:%s:%s:log-group:sample-domain' % (DEFAULT_REGION, TEST_AWS_ACCOUNT_ID),  # noqa: E501
                        'Enabled': False
                    },
                    'SEARCH_SLOW_LOGS': {
                        'CloudWatchLogsLogGroupArn': 'arn:aws:logs:%s:%s:log-group:sample-domain' % (DEFAULT_REGION, TEST_AWS_ACCOUNT_ID),  # noqa: E501
                        'Enabled': False,
                    }
                },
                'Status': config_status
            },
            'SnapshotOptions': {
                'Options': {
                    'AutomatedSnapshotStartHour': randint(0, 23)
                },
                'Status': config_status
            },
            'VPCOptions': {
                'Options': {
                    'AvailabilityZones': [
                        'us-east-1b'
                    ],
                    'SecurityGroupIds': [
                        'sg-12345678'
                    ],
                    'SubnetIds': [
                        'subnet-12345678'
                    ],
                    'VPCId': 'vpc-12345678'
                },
                'Status': config_status
            }
        }
    }


def get_domain_status(domain_name, deleted=False):
    return {
        'DomainStatus': {
            'ARN': 'arn:aws:es:%s:%s:domain/%s' % (DEFAULT_REGION, TEST_AWS_ACCOUNT_ID, domain_name),
            'Created': True,
            'Deleted': deleted,
            'DomainId': '%s/%s' % (TEST_AWS_ACCOUNT_ID, domain_name),
            'DomainName': domain_name,
            'ElasticsearchClusterConfig': {
                'DedicatedMasterCount': 1,
                'DedicatedMasterEnabled': True,
                'DedicatedMasterType': 'm3.medium.elasticsearch',
                'InstanceCount': 1,
                'InstanceType': 'm3.medium.elasticsearch',
                'ZoneAwarenessEnabled': False
            },
            'ElasticsearchVersion': '6.7',
            'Endpoint': aws_stack.get_elasticsearch_endpoint(domain_name),
            'Processing': False,
            'EBSOptions': {
                'EBSEnabled': True,
                'VolumeType': 'gp2',
                'VolumeSize': 10,
                'Iops': 0
            },
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
    # record event
    event_publisher.fire_event(event_publisher.EVENT_ES_CREATE_DOMAIN,
        payload={'n': event_publisher.get_hash(domain_name)})
    return jsonify(result)


@app.route('%s/es/domain/<domain_name>' % API_PREFIX, methods=['GET'])
def describe_domain(domain_name):
    if domain_name not in ES_DOMAINS:
        return error_response(error_type='ResourceNotFoundException')
    result = get_domain_status(domain_name)
    return jsonify(result)


@app.route('%s/es/domain/<domain_name>/config' % API_PREFIX, methods=['GET', 'POST'])
def domain_config(domain_name):
    config = get_domain_config(domain_name)
    return jsonify(config)


@app.route('%s/es/domain/<domain_name>' % API_PREFIX, methods=['DELETE'])
def delete_domain(domain_name):
    if domain_name not in ES_DOMAINS:
        return error_response(error_type='ResourceNotFoundException')
    result = get_domain_status(domain_name, deleted=True)
    ES_DOMAINS.pop(domain_name)
    # record event
    event_publisher.fire_event(event_publisher.EVENT_ES_DELETE_DOMAIN,
        payload={'n': event_publisher.get_hash(domain_name)})
    return jsonify(result)


@app.route('%s/tags' % API_PREFIX, methods=['GET', 'POST'])
def add_list_tags():
    if request.method == 'GET' and request.args.get('arn'):
        response = {
            'TagList': [
                {
                    'Key': 'Example1',
                    'Value': 'Value'
                },
                {
                    'Key': 'Example2',
                    'Value': 'Value'
                }
            ]
        }
        return jsonify(response)

    return jsonify({})


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
