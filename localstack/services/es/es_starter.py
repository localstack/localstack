import os
import six
import logging
import traceback
from localstack import config
from localstack.services import install
from localstack.utils.aws import aws_stack
from localstack.constants import DEFAULT_PORT_ELASTICSEARCH_BACKEND, LOCALSTACK_ROOT_FOLDER
from localstack.utils.common import run, is_root, mkdir, chmod_r
from localstack.services.infra import get_service_protocol, start_proxy_for_service, do_run
from localstack.services.install import ROOT_PATH

LOGGER = logging.getLogger(__name__)


def delete_all_elasticsearch_data():
    """ This function drops ALL data in the local Elasticsearch data folder. Use with caution! """
    data_dir = os.path.join(LOCALSTACK_ROOT_FOLDER, 'infra', 'elasticsearch', 'data', 'elasticsearch', 'nodes')
    run('rm -rf "%s"' % data_dir)


def start_elasticsearch(port=None, delete_data=True, asynchronous=False, update_listener=None):
    port = port or config.PORT_ELASTICSEARCH
    # delete Elasticsearch data that may be cached locally from a previous test run
    delete_all_elasticsearch_data()

    install.install_elasticsearch()
    backend_port = DEFAULT_PORT_ELASTICSEARCH_BACKEND
    es_data_dir = '%s/infra/elasticsearch/data' % (ROOT_PATH)
    es_tmp_dir = '%s/infra/elasticsearch/tmp' % (ROOT_PATH)
    if config.DATA_DIR:
        es_data_dir = '%s/elasticsearch' % config.DATA_DIR
    # Elasticsearch 5.x cannot be bound to 0.0.0.0 in some Docker environments,
    # hence we use the default bind address 127.0.0.0 and put a proxy in front of it
    cmd = (('ES_JAVA_OPTS=\"${ES_JAVA_OPTS:--Xms200m -Xmx500m}\" ES_TMPDIR="%s" ' +
        '%s/infra/elasticsearch/bin/elasticsearch ' +
        '-E http.port=%s -E http.publish_port=%s -E http.compression=false -E path.data=%s') %
        (es_tmp_dir, ROOT_PATH, backend_port, backend_port, es_data_dir))
    print('Starting local Elasticsearch (%s port %s)...' % (get_service_protocol(), port))
    if delete_data:
        run('rm -rf %s' % es_data_dir)
    # fix permissions
    chmod_r('%s/infra/elasticsearch' % ROOT_PATH, 0o777)
    mkdir(es_data_dir)
    chmod_r(es_data_dir, 0o777)
    # start proxy and ES process
    start_proxy_for_service('elasticsearch', port, backend_port,
        update_listener, quiet=True, params={'protocol_version': 'HTTP/1.0'})
    if is_root():
        cmd = "su -c '%s' localstack" % cmd
    thread = do_run(cmd, asynchronous)
    return thread


def check_elasticsearch(expect_shutdown=False, print_error=False):
    out = None
    try:
        # check Elasticsearch
        es = aws_stack.connect_elasticsearch()
        out = es.cat.aliases()
    except Exception as e:
        if print_error:
            LOGGER.error('Elasticsearch health check failed (retrying...): %s %s' % (e, traceback.format_exc()))
    if expect_shutdown:
        assert out is None
    else:
        assert isinstance(out, six.string_types)
