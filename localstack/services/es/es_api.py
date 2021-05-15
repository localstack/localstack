import json
import time
import logging
import requests
from random import randint
from flask import Flask, jsonify, request, make_response
from localstack import config
from localstack.utils import persistence
from localstack.services import generic_proxy
from localstack.utils.aws import aws_stack
from localstack.constants import TEST_AWS_ACCOUNT_ID, ELASTICSEARCH_DEFAULT_VERSION, ELASTICSEARCH_URLS
from localstack.utils.common import to_str, FuncThread, get_service_protocol
from localstack.utils.tagging import TaggingService
from localstack.utils.analytics import event_publisher

LOG = logging.getLogger(__name__)

APP_NAME = 'es_api'
API_PREFIX = '/2015-01-01'

DEFAULT_ES_VERSION = '7.7'

ES_DOMAINS = {}

DEFAULT_ES_CLUSTER_CONFIG = {
    'InstanceType': 'm3.medium.elasticsearch',
    'InstanceCount': 1,
    'DedicatedMasterEnabled': True,
    'ZoneAwarenessEnabled': False,
    'DedicatedMasterType': 'm3.medium.elasticsearch',
    'DedicatedMasterCount': 1
}

TAGS = TaggingService()

app = Flask(APP_NAME)
app.url_map.strict_slashes = False


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
    status = ES_DOMAINS.get(domain_name) or {}
    cluster_cfg = status.get('ElasticsearchClusterConfig') or {}
    default_cfg = DEFAULT_ES_CLUSTER_CONFIG
    config_status = get_domain_config_status()
    return {
        'DomainConfig': {
            'AccessPolicies': {
                'Options': '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"es:*","Resource":"arn:aws:es:%s:%s:domain/%s/*"}]}' % (TEST_AWS_ACCOUNT_ID, aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, domain_name),  # noqa: E501
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
                    'DedicatedMasterCount': cluster_cfg.get(
                        'DedicatedMasterCount', default_cfg['DedicatedMasterCount']),
                    'DedicatedMasterEnabled': cluster_cfg.get(
                        'DedicatedMasterEnabled', default_cfg['DedicatedMasterEnabled']),
                    'DedicatedMasterType': cluster_cfg.get(
                        'DedicatedMasterType', default_cfg['DedicatedMasterType']),
                    'InstanceCount': cluster_cfg.get(
                        'InstanceCount', default_cfg['InstanceCount']),
                    'InstanceType': cluster_cfg.get(
                        'InstanceType', default_cfg['InstanceType']),
                    'ZoneAwarenessEnabled': cluster_cfg.get(
                        'ZoneAwarenessEnabled', default_cfg['ZoneAwarenessEnabled']),
                },
                'Status': config_status
            },
            'CognitoOptions': {
                'Enabled': False
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
                        'CloudWatchLogsLogGroupArn': 'arn:aws:logs:%s:%s:log-group:sample-domain' % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID),  # noqa: E501
                        'Enabled': False
                    },
                    'SEARCH_SLOW_LOGS': {
                        'CloudWatchLogsLogGroupArn': 'arn:aws:logs:%s:%s:log-group:sample-domain' % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID),  # noqa: E501
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
    status = ES_DOMAINS.get(domain_name) or {}
    cluster_cfg = status.get('ElasticsearchClusterConfig') or {}
    default_cfg = DEFAULT_ES_CLUSTER_CONFIG
    endpoint = '%s://%s:%s' % (get_service_protocol(), config.HOSTNAME_EXTERNAL, config.PORT_ELASTICSEARCH)
    return {
        'DomainStatus': {
            'ARN': 'arn:aws:es:%s:%s:domain/%s' % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, domain_name),
            'Created': status.get('Created', True),
            'Deleted': deleted,
            'DomainId': '%s/%s' % (TEST_AWS_ACCOUNT_ID, domain_name),
            'DomainName': domain_name,
            'ElasticsearchClusterConfig': {
                'DedicatedMasterCount': cluster_cfg.get(
                    'DedicatedMasterCount', default_cfg['DedicatedMasterCount']),
                'DedicatedMasterEnabled': cluster_cfg.get(
                    'DedicatedMasterEnabled', default_cfg['DedicatedMasterEnabled']),
                'DedicatedMasterType': cluster_cfg.get(
                    'DedicatedMasterType', default_cfg['DedicatedMasterType']),
                'InstanceCount': cluster_cfg.get(
                    'InstanceCount', default_cfg['InstanceCount']),
                'InstanceType': cluster_cfg.get(
                    'InstanceType', default_cfg['InstanceType']),
                'ZoneAwarenessEnabled': cluster_cfg.get(
                    'ZoneAwarenessEnabled', default_cfg['ZoneAwarenessEnabled']),
            },
            'ElasticsearchVersion': status.get('ElasticsearchVersion') or DEFAULT_ES_VERSION,
            'Endpoint': endpoint,
            'Processing': False,
            'EBSOptions': {
                'EBSEnabled': True,
                'VolumeType': 'gp2',
                'VolumeSize': 10,
                'Iops': 0
            },
            'CognitoOptions': {
                'Enabled': False
            },
        }
    }


def get_install_version_for_api_version(version):
    result = ELASTICSEARCH_DEFAULT_VERSION
    if version.startswith('6.'):
        result = '6.7.0'
    elif version == '7.4':
        result = '7.4.0'
    elif version == '7.7':
        result = '7.7.0'
    if not result.startswith(result):
        LOG.info('Elasticsearch version %s not yet supported, defaulting to %s' % (version, result))
    return result


def start_elasticsearch_instance(version):
    # Note: keep imports here to avoid circular dependencies
    from localstack.services.es import es_starter

    # install ES version
    install_version = get_install_version_for_api_version(version)
    es_starter.start_elasticsearch(asynchronous=False, version=install_version)


def cleanup_elasticsearch_instance(status):
    # Note: keep imports here to avoid circular dependencies
    from localstack.services.es import es_starter
    es_starter.stop_elasticsearch()


@app.route('%s/domain' % API_PREFIX, methods=['GET'])
def list_domain_names():
    result = {
        'DomainNames': [{'DomainName': name} for name in ES_DOMAINS.keys()]
    }
    return jsonify(result)


@app.route('%s/es/domain' % API_PREFIX, methods=['POST'])
def create_domain():
    from localstack.services.es import es_starter

    data = json.loads(to_str(request.data))
    domain_name = data['DomainName']
    if domain_name in ES_DOMAINS:
        return error_response(error_type='ResourceAlreadyExistsException')
    ES_DOMAINS[domain_name] = data
    data['Created'] = False

    def do_start(*args):
        # start actual Elasticsearch instance
        version = data.get('ElasticsearchVersion') or DEFAULT_ES_VERSION
        start_elasticsearch_instance(version=version)
        data['Created'] = True

    try:
        if es_starter.check_elasticsearch():
            data['Created'] = True
        else:
            LOG.error('Elasticsearch status is not healthy, please check the application status and logs')
    except requests.exceptions.ConnectionError:
        # Catch first run
        FuncThread(do_start).start()
        LOG.info('Elasticsearch is starting for the first time, please wait..')
        data['Created'] = True

    result = get_domain_status(domain_name)
    # record event
    event_publisher.fire_event(event_publisher.EVENT_ES_CREATE_DOMAIN,
        payload={'n': event_publisher.get_hash(domain_name)})
    persistence.record('es', request=request)

    return jsonify(result)


@app.route('%s/es/domain/<domain_name>' % API_PREFIX, methods=['GET'])
def describe_domain(domain_name):
    if domain_name not in ES_DOMAINS:
        return error_response(error_type='ResourceNotFoundException')
    result = get_domain_status(domain_name)
    return jsonify(result)


@app.route('%s/es/domain-info' % API_PREFIX, methods=['POST'])
def describe_domains():
    data = json.loads(to_str(request.data))
    result = []
    domain_names = data.get('DomainNames', [])
    for domain_name in ES_DOMAINS:
        if domain_name in domain_names:
            status = get_domain_status(domain_name)
            status = status.get('DomainStatus') or status
            result.append(status)
    result = {'DomainStatusList': result}
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
    status = ES_DOMAINS.pop(domain_name)
    if not ES_DOMAINS:
        cleanup_elasticsearch_instance(status)

    # record event
    event_publisher.fire_event(event_publisher.EVENT_ES_DELETE_DOMAIN,
        payload={'n': event_publisher.get_hash(domain_name)})
    persistence.record('es', request=request)

    return jsonify(result)


@app.route('%s/es/versions' % API_PREFIX, methods=['GET'])
def list_es_versions():
    result = []
    for key in ELASTICSEARCH_URLS.keys():
        result.append(key)
    return jsonify({'ElasticsearchVersions': result})


@app.route('%s/es/compatibleVersions' % API_PREFIX, methods=['GET'])
def get_compatible_versions():
    result = [{
        'SourceVersion': '6.5',
        'TargetVersions': ['6.7', '6.8']
    }, {
        'SourceVersion': '6.7',
        'TargetVersions': ['6.8']
    }, {
        'SourceVersion': '6.8',
        'TargetVersions': ['7.1']
    }, {
        'SourceVersion': '7.1',
        'TargetVersions': ['7.4', '7.7']
    }]
    return jsonify({'CompatibleElasticsearchVersions': result})


@app.route('%s/tags' % API_PREFIX, methods=['GET', 'POST'])
def add_list_tags():
    if request.method == 'POST':
        data = json.loads(to_str(request.data) or '{}')
        arn = data.get('ARN')
        TAGS.tag_resource(arn, data.get('TagList', []))
    if request.method == 'GET' and request.args.get('arn'):
        arn = request.args.get('arn')
        tags = TAGS.list_tags_for_resource(arn)
        response = {
            'TagList': tags.get('Tags')
        }
        return jsonify(response)

    return jsonify({})


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port, quiet=quiet)
