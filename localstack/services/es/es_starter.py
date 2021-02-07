import os
import json
import logging
import requests
import traceback
from localstack import config
from localstack import constants
from localstack.services import install
from localstack.services.es import es_api
from localstack.utils.common import is_root, mkdir, chmod_r, rm_rf, get_free_tcp_port, get_service_protocol
from localstack.services.infra import start_proxy_for_service, do_run, start_local_api

LOG = logging.getLogger(__name__)

STATE = {}


def delete_all_elasticsearch_data(version):
    """ This function drops ALL data in the local Elasticsearch data folder. Use with caution! """
    base_dir = install.get_elasticsearch_install_dir(version)
    data_dir = os.path.join(base_dir, 'data', 'elasticsearch', 'nodes')
    rm_rf(data_dir)


def stop_elasticsearch():
    thread = STATE.get('_thread_')
    if not thread:
        return
    LOG.info('Terminating Elasticsearch instance, as all clusters have been removed')
    thread.stop()
    if STATE['_proxy_']:
        STATE['_proxy_'].stop()
    del STATE['_thread_']
    del STATE['_proxy_']


def start_elasticsearch(port=None, version=None, delete_data=True, asynchronous=False, update_listener=None):
    if STATE.get('_thread_'):
        return STATE['_thread_']

    port = port or config.PORT_ELASTICSEARCH
    # delete Elasticsearch data that may be cached locally from a previous test run
    delete_all_elasticsearch_data(version)

    install.install_elasticsearch(version)
    backend_port = get_free_tcp_port()
    base_dir = install.get_elasticsearch_install_dir(version)
    es_data_dir = os.path.join(base_dir, 'data')
    es_tmp_dir = os.path.join(base_dir, 'tmp')
    es_mods_dir = os.path.join(base_dir, 'modules')
    if config.DATA_DIR:
        delete_data = False
        es_data_dir = '%s/elasticsearch' % config.DATA_DIR
    # Elasticsearch 5.x cannot be bound to 0.0.0.0 in some Docker environments,
    # hence we use the default bind address 127.0.0.0 and put a proxy in front of it
    backup_dir = os.path.join(config.TMP_FOLDER, 'es_backup')
    cmd = (('%s/bin/elasticsearch ' +
        '-E http.port=%s -E http.publish_port=%s -E http.compression=false ' +
        '-E path.data=%s -E path.repo=%s') %
        (base_dir, backend_port, backend_port, es_data_dir, backup_dir))
    if os.path.exists(os.path.join(es_mods_dir, 'x-pack-ml')):
        cmd += ' -E xpack.ml.enabled=false'
    env_vars = {
        'ES_JAVA_OPTS': os.environ.get('ES_JAVA_OPTS', '-Xms200m -Xmx600m'),
        'ES_TMPDIR': es_tmp_dir
    }
    LOG.debug('Starting local Elasticsearch (%s port %s)' % (get_service_protocol(), port))
    if delete_data:
        rm_rf(es_data_dir)
    # fix permissions
    chmod_r(base_dir, 0o777)
    mkdir(es_data_dir)
    chmod_r(es_data_dir, 0o777)
    mkdir(es_tmp_dir)
    chmod_r(es_tmp_dir, 0o777)
    # start proxy and ES process
    proxy = start_proxy_for_service('elasticsearch', port, backend_port,
        update_listener, quiet=True, params={'protocol_version': 'HTTP/1.0'})
    STATE['_proxy_'] = proxy
    if is_root():
        cmd = "su localstack -c '%s'" % cmd
    thread = do_run(cmd, asynchronous, env_vars=env_vars)
    STATE['_thread_'] = thread
    return thread


def check_elasticsearch(expect_shutdown=False, print_error=True):
    # Check internal endpoint for health
    endpoint = '%s://%s:%s' % (get_service_protocol(), constants.LOCALHOST, config.PORT_ELASTICSEARCH)
    try:
        req = requests.get(endpoint + '/_cluster/health')
        es_status = json.loads(req.text)
        es_status = es_status['status']
        return es_status == 'green' or es_status == 'yellow'
    except ValueError as e:
        if print_error:
            LOG.error(
                'Elasticsearch health check to endpoint %s failed (retrying...): %s %s' % (
                    endpoint, e, traceback.format_exc()))
        pass


def start_elasticsearch_service(port=None, asynchronous=False):
    port = port or config.PORT_ES
    return start_local_api('ES', port, api='es', method=es_api.serve, asynchronous=asynchronous)
