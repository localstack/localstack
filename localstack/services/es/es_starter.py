import logging
import os

import requests

from localstack import config, constants
from localstack.services import install
from localstack.services.es import es_api
from localstack.services.infra import do_run, start_local_api, start_proxy_for_service
from localstack.utils.common import (
    chmod_r,
    get_free_tcp_port,
    get_service_protocol,
    is_root,
    mkdir,
    rm_rf,
)

LOG = logging.getLogger(__name__)

STATE = {}


def start_elasticsearch_service(port=None, asynchronous=False):
    """Starts the ElasticSearch management API (not the actual elasticsearch process."""
    port = port or config.PORT_ES
    return start_local_api("ES", port, api="es", method=es_api.serve, asynchronous=asynchronous)


def delete_all_elasticsearch_data(version):
    """This function drops ALL data in the local Elasticsearch data folder. Use with caution!"""
    base_dir = install.get_elasticsearch_install_dir(version)
    data_dir = os.path.join(base_dir, "data", "elasticsearch", "nodes")
    rm_rf(data_dir)


def stop_elasticsearch():
    thread = STATE.get("_thread_")
    if not thread:
        return
    LOG.info("Terminating Elasticsearch instance, as all clusters have been removed")
    thread.stop()
    if STATE["_proxy_"]:
        STATE["_proxy_"].stop()
    del STATE["_thread_"]
    del STATE["_proxy_"]


def start_elasticsearch(
    port=None, version=None, delete_data=True, asynchronous=False, update_listener=None
):
    if STATE.get("_thread_"):
        return STATE["_thread_"]

    port = port or config.PORT_ELASTICSEARCH
    # delete Elasticsearch data that may be cached locally from a previous test run
    delete_all_elasticsearch_data(version)

    install.install_elasticsearch(version)
    backend_port = get_free_tcp_port()
    base_dir = install.get_elasticsearch_install_dir(version)
    es_data_dir = os.path.join(base_dir, "data")
    es_tmp_dir = os.path.join(base_dir, "tmp")
    es_mods_dir = os.path.join(base_dir, "modules")
    if config.DATA_DIR:
        delete_data = False
        es_data_dir = "%s/elasticsearch" % config.DATA_DIR
    # Elasticsearch 5.x cannot be bound to 0.0.0.0 in some Docker environments,
    # hence we use the default bind address 127.0.0.0 and put a proxy in front of it
    backup_dir = os.path.join(config.TMP_FOLDER, "es_backup")
    cmd = (
        "%s/bin/elasticsearch "
        + "-E http.port=%s -E http.publish_port=%s -E http.compression=false "
        + "-E path.data=%s -E path.repo=%s"
    ) % (base_dir, backend_port, backend_port, es_data_dir, backup_dir)
    if os.path.exists(os.path.join(es_mods_dir, "x-pack-ml")):
        cmd += " -E xpack.ml.enabled=false"
    env_vars = {
        "ES_JAVA_OPTS": os.environ.get("ES_JAVA_OPTS", "-Xms200m -Xmx600m"),
        "ES_TMPDIR": es_tmp_dir,
    }
    LOG.debug("Starting local Elasticsearch (%s port %s)" % (get_service_protocol(), port))
    if delete_data:
        rm_rf(es_data_dir)
    # fix permissions
    chmod_r(base_dir, 0o777)
    mkdir(es_data_dir)
    chmod_r(es_data_dir, 0o777)
    mkdir(es_tmp_dir)
    chmod_r(es_tmp_dir, 0o777)
    # start proxy and ES process
    proxy = start_proxy_for_service(
        "elasticsearch",
        port,
        backend_port,
        update_listener,
        quiet=True,
        params={"protocol_version": "HTTP/1.0"},
    )
    STATE["_proxy_"] = proxy
    if is_root():
        cmd = "su localstack -c '%s'" % cmd
    thread = do_run(cmd, asynchronous, env_vars=env_vars)
    STATE["_thread_"] = thread
    return thread


def get_elasticsearch_health_status(endpoint=None):
    """
    Queries the health endpoint of elasticsearch and returns either the status ('green', 'yellow',
    ...) or None if the response returned a non-200 response.
    """
    if endpoint is None:
        endpoint = "%s://%s:%s" % (
            get_service_protocol(),
            constants.LOCALHOST,
            config.PORT_ELASTICSEARCH,
        )

    resp = requests.get(endpoint + "/_cluster/health")

    if resp and resp.ok:
        es_status = resp.json()
        es_status = es_status["status"]
        return es_status

    return None


def check_elasticsearch(expect_shutdown=False, print_error=False):
    # Check internal endpoint for health
    endpoint = "%s://%s:%s" % (
        get_service_protocol(),
        constants.LOCALHOST,
        config.PORT_ELASTICSEARCH,
    )

    if expect_shutdown:
        return _check_elasticsearch_is_up(endpoint, print_error=print_error)
    else:
        return _check_elasticsearch_is_down(endpoint)


def _check_elasticsearch_is_up(endpoint, print_error=True):
    status = None
    try:
        status = get_elasticsearch_health_status(endpoint=endpoint)
    except Exception as e:
        if print_error:
            LOG.error("Elasticsearch health check to endpoint %s failed (retrying...): %s", e)

    assert status is not None
    assert status == "green" or status == "yellow"


def _check_elasticsearch_is_down(endpoint):
    try:
        status = get_elasticsearch_health_status(endpoint=endpoint)
    except Exception as e:
        return

    assert status is None
