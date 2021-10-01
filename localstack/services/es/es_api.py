"""
Serve the elasticsearch API as a threaded Flask app.
"""
import json
import logging
import threading
import time
from random import randint
from typing import Dict, Optional

from flask import Flask, jsonify, make_response, request

from localstack import config, constants
from localstack.constants import ELASTICSEARCH_URLS, TEST_AWS_ACCOUNT_ID
from localstack.services import generic_proxy
from localstack.services.es.cluster import ProxiedElasticsearchCluster
from localstack.services.generic_proxy import RegionBackend
from localstack.utils import persistence
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.common import get_service_protocol, poll_condition, to_str
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

APP_NAME = "es_api"
API_PREFIX = "/2015-01-01"

DEFAULT_ES_VERSION = "7.7"

DEFAULT_ES_CLUSTER_CONFIG = {
    "InstanceType": "m3.medium.elasticsearch",
    "InstanceCount": 1,
    "DedicatedMasterEnabled": True,
    "ZoneAwarenessEnabled": False,
    "DedicatedMasterType": "m3.medium.elasticsearch",
    "DedicatedMasterCount": 1,
}

# timeout in seconds when giving up on waiting for the cluster to start
CLUSTER_STARTUP_TIMEOUT = 600

# ideally, each domain gets its own cluster. to save resources, we currently re-use the same
# cluster instance. this also means we lie to the client about the the elasticsearch domain
# version. the first call to create_domain with a specific version will create the cluster
# with that version. subsequent calls will believe they created a cluster with the version
# they specified.
_cluster: Optional[ProxiedElasticsearchCluster] = None

# mutex for modifying domains
_domain_mutex = threading.Lock()

app = Flask(APP_NAME)
app.url_map.strict_slashes = False


class ElasticsearchServiceBackend(RegionBackend):
    # maps cluster names to cluster details
    es_clusters: Dict[str, ProxiedElasticsearchCluster]
    # storage for domain resources (access should be protected with the _domain_mutex)
    es_domains: Dict[str, Dict]
    # static tagging service instance
    TAGS = TaggingService()

    def __init__(self):
        self.es_clusters = {}
        self.es_domains = {}


def _run_cluster_startup_monitor(cluster):
    region = ElasticsearchServiceBackend.get()
    LOG.debug("running cluster startup monitor for cluster %s", cluster)
    # wait until the cluster is started, or the timeout is reached
    status = poll_condition(cluster.is_up, timeout=CLUSTER_STARTUP_TIMEOUT, interval=5)

    LOG.debug("cluster state polling returned! status = %s", status)

    with _domain_mutex:
        LOG.debug("iterating over cluster domains %s", region.es_clusters.keys())
        for domain, domain_cluster in region.es_clusters.items():
            LOG.debug("checking cluster for domain %s", domain)
            if cluster is domain_cluster:
                if domain in region.es_domains:
                    region.es_domains[domain]["Created"] = status


def _create_cluster(domain_name, data):
    """
    Create a new entry in ES_DOMAINS if the domain does not yet exist. Start a ElasticsearchCluster if this is the first
    domain being created. NOT thread safe, needs to be called around _domain_mutex.
    """
    global _cluster
    region = ElasticsearchServiceBackend.get()

    if _cluster:
        # see comment on _cluster
        LOG.info("elasticsearch cluster already created, using existing one for %s", domain_name)
        region.es_clusters[domain_name] = _cluster
        data["Created"] = _cluster.is_up()
        return

    # creating cluster for the first time
    version = data.get("ElasticsearchVersion") or DEFAULT_ES_VERSION
    _cluster = ProxiedElasticsearchCluster(
        port=config.PORT_ELASTICSEARCH, host=constants.LOCALHOST, version=version
    )
    LOG.info("starting %s on %s:%s", type(_cluster), _cluster.host, _cluster.port)
    _cluster.start()
    region.es_clusters[domain_name] = _cluster

    # run a background thread that will update all domains that use this cluster to set
    # data['Created'] = <status> once it is started, or the CLUSTER_STARTUP_TIMEOUT is reached
    # FIXME: if the cluster doesn't start, these threads will stay open until the timeout is
    #  reached, even if the cluster is already shut down. we could fix this with an additional
    #  event, or a timer instead of Poll, but it seems like a rare case in the first place.
    threading.Thread(target=_run_cluster_startup_monitor, daemon=True, args=(_cluster,)).start()


def _cleanup_cluster(domain_name):
    global _cluster
    region = ElasticsearchServiceBackend.get()
    cluster = region.es_clusters.pop(domain_name)

    LOG.debug(
        "cleanup cluster for domain %s, %d domains remaining", domain_name, len(region.es_clusters)
    )

    if not region.es_clusters:
        # because cluster is currently always mapped to _cluster, we only shut it down if no other
        # domains are using it
        LOG.info("shutting down elasticsearch cluster after domain %s cleanup", domain_name)
        cluster.shutdown()
        # FIXME: if delete_domain() is called, then immediately after, create_domain() (without
        #  letting time pass for the proxy to shut down) there's a chance that there will be a bind
        #  exception when trying to start the proxy again (which is currently always bound to
        #  PORT_ELASTICSEARCH)
        _cluster = None


def error_response(error_type, code=400, message="Unknown error."):
    if not message:
        if error_type == "ResourceNotFoundException":
            message = "Resource not found."
        elif error_type == "ResourceAlreadyExistsException":
            message = "Resource already exists."
    response = make_response(jsonify({"error": message}))
    response.headers["x-amzn-errortype"] = error_type
    return response, code


def get_domain_config_status():
    return {
        "CreationDate": "%.2f" % time.time(),
        "PendingDeletion": False,
        "State": "Active",
        "UpdateDate": "%.2f" % time.time(),
        "UpdateVersion": randint(1, 100),
    }


def get_domain_config(domain_name):
    region = ElasticsearchServiceBackend.get()
    status = region.es_domains.get(domain_name) or {}
    cluster_cfg = status.get("ElasticsearchClusterConfig") or {}
    default_cfg = DEFAULT_ES_CLUSTER_CONFIG
    config_status = get_domain_config_status()
    return {
        "DomainConfig": {
            "AccessPolicies": {
                "Options": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::%s:root"},"Action":"es:*","Resource":"arn:aws:es:%s:%s:domain/%s/*"}]}'
                % (
                    TEST_AWS_ACCOUNT_ID,
                    aws_stack.get_region(),
                    TEST_AWS_ACCOUNT_ID,
                    domain_name,
                ),  # noqa: E501
                "Status": config_status,
            },
            "AdvancedOptions": {
                "Options": {
                    "indices.fielddata.cache.size": "",
                    "rest.action.multi.allow_explicit_index": "true",
                },
                "Status": config_status,
            },
            "EBSOptions": {
                "Options": {
                    "EBSEnabled": True,
                    "EncryptionEnabled": False,
                    "Iops": 0,
                    "VolumeSize": 10,
                    "VolumeType": "gp2",
                },
                "Status": config_status,
            },
            "ElasticsearchClusterConfig": {
                "Options": {
                    "DedicatedMasterCount": cluster_cfg.get(
                        "DedicatedMasterCount", default_cfg["DedicatedMasterCount"]
                    ),
                    "DedicatedMasterEnabled": cluster_cfg.get(
                        "DedicatedMasterEnabled", default_cfg["DedicatedMasterEnabled"]
                    ),
                    "DedicatedMasterType": cluster_cfg.get(
                        "DedicatedMasterType", default_cfg["DedicatedMasterType"]
                    ),
                    "InstanceCount": cluster_cfg.get("InstanceCount", default_cfg["InstanceCount"]),
                    "InstanceType": cluster_cfg.get("InstanceType", default_cfg["InstanceType"]),
                    "ZoneAwarenessEnabled": cluster_cfg.get(
                        "ZoneAwarenessEnabled", default_cfg["ZoneAwarenessEnabled"]
                    ),
                },
                "Status": config_status,
            },
            "CognitoOptions": {"Enabled": False},
            "ElasticsearchVersion": {"Options": "5.3", "Status": config_status},
            "EncryptionAtRestOptions": {
                "Options": {"Enabled": False, "KmsKeyId": ""},
                "Status": config_status,
            },
            "LogPublishingOptions": {
                "Options": {
                    "INDEX_SLOW_LOGS": {
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:%s:%s:log-group:sample-domain"
                        % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID),  # noqa: E501
                        "Enabled": False,
                    },
                    "SEARCH_SLOW_LOGS": {
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:%s:%s:log-group:sample-domain"
                        % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID),  # noqa: E501
                        "Enabled": False,
                    },
                },
                "Status": config_status,
            },
            "SnapshotOptions": {
                "Options": {"AutomatedSnapshotStartHour": randint(0, 23)},
                "Status": config_status,
            },
            "VPCOptions": {
                "Options": {
                    "AvailabilityZones": ["us-east-1b"],
                    "SecurityGroupIds": ["sg-12345678"],
                    "SubnetIds": ["subnet-12345678"],
                    "VPCId": "vpc-12345678",
                },
                "Status": config_status,
            },
        }
    }


def get_domain_status(domain_name, deleted=False):
    region = ElasticsearchServiceBackend.get()
    status = region.es_domains.get(domain_name) or {}
    cluster_cfg = status.get("ElasticsearchClusterConfig") or {}
    default_cfg = DEFAULT_ES_CLUSTER_CONFIG
    endpoint = "%s://%s:%s" % (
        get_service_protocol(),
        config.HOSTNAME_EXTERNAL,
        config.PORT_ELASTICSEARCH,
    )
    return {
        "DomainStatus": {
            "ARN": "arn:aws:es:%s:%s:domain/%s"
            % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, domain_name),
            "Created": status.get("Created", False),
            "Deleted": deleted,
            "DomainId": "%s/%s" % (TEST_AWS_ACCOUNT_ID, domain_name),
            "DomainName": domain_name,
            "ElasticsearchClusterConfig": {
                "DedicatedMasterCount": cluster_cfg.get(
                    "DedicatedMasterCount", default_cfg["DedicatedMasterCount"]
                ),
                "DedicatedMasterEnabled": cluster_cfg.get(
                    "DedicatedMasterEnabled", default_cfg["DedicatedMasterEnabled"]
                ),
                "DedicatedMasterType": cluster_cfg.get(
                    "DedicatedMasterType", default_cfg["DedicatedMasterType"]
                ),
                "InstanceCount": cluster_cfg.get("InstanceCount", default_cfg["InstanceCount"]),
                "InstanceType": cluster_cfg.get("InstanceType", default_cfg["InstanceType"]),
                "ZoneAwarenessEnabled": cluster_cfg.get(
                    "ZoneAwarenessEnabled", default_cfg["ZoneAwarenessEnabled"]
                ),
            },
            "ElasticsearchVersion": status.get("ElasticsearchVersion") or DEFAULT_ES_VERSION,
            "Endpoint": endpoint,
            "Processing": False,
            "EBSOptions": {
                "EBSEnabled": True,
                "VolumeType": "gp2",
                "VolumeSize": 10,
                "Iops": 0,
            },
            "CognitoOptions": {"Enabled": False},
        }
    }


@app.route("%s/domain" % API_PREFIX, methods=["GET"])
def list_domain_names():
    region = ElasticsearchServiceBackend.get()
    result = {"DomainNames": [{"DomainName": name} for name in region.es_domains.keys()]}
    return jsonify(result)


@app.route("%s/es/domain" % API_PREFIX, methods=["POST"])
def create_domain():
    region = ElasticsearchServiceBackend.get()
    data = json.loads(to_str(request.data))
    domain_name = data["DomainName"]

    with _domain_mutex:
        if domain_name in region.es_domains:
            # domain already created
            return error_response(error_type="ResourceAlreadyExistsException")

        # "create" domain data
        region.es_domains[domain_name] = data

        # lazy-init the cluster, and set the data["Created"] flag
        _create_cluster(domain_name, data)

        # create result document
        result = get_domain_status(domain_name)

    # record event
    event_publisher.fire_event(
        event_publisher.EVENT_ES_CREATE_DOMAIN,
        payload={"n": event_publisher.get_hash(domain_name)},
    )
    persistence.record("es", request=request)

    return jsonify(result)


@app.route("%s/es/domain/<domain_name>" % API_PREFIX, methods=["GET"])
def describe_domain(domain_name):
    region = ElasticsearchServiceBackend.get()
    with _domain_mutex:
        if domain_name not in region.es_domains:
            return error_response(error_type="ResourceNotFoundException")

        result = get_domain_status(domain_name)
        return jsonify(result)


@app.route("%s/es/domain-info" % API_PREFIX, methods=["POST"])
def describe_domains():
    region = ElasticsearchServiceBackend.get()
    data = json.loads(to_str(request.data))
    result = []
    domain_names = data.get("DomainNames", [])

    with _domain_mutex:
        for domain_name in region.es_domains:
            if domain_name in domain_names:
                status = get_domain_status(domain_name)
                status = status.get("DomainStatus") or status
                result.append(status)
        result = {"DomainStatusList": result}

    return jsonify(result)


@app.route("%s/es/domain/<domain_name>/config" % API_PREFIX, methods=["GET", "POST"])
def domain_config(domain_name):
    with _domain_mutex:
        doc = get_domain_config(domain_name)

    return jsonify(doc)


@app.route("%s/es/domain/<domain_name>" % API_PREFIX, methods=["DELETE"])
def delete_domain(domain_name):
    region = ElasticsearchServiceBackend.get()
    with _domain_mutex:
        if domain_name not in region.es_domains:
            return error_response(error_type="ResourceNotFoundException")

        result = get_domain_status(domain_name, deleted=True)
        del region.es_domains[domain_name]
        _cleanup_cluster(domain_name)

    # record event
    event_publisher.fire_event(
        event_publisher.EVENT_ES_DELETE_DOMAIN,
        payload={"n": event_publisher.get_hash(domain_name)},
    )
    persistence.record("es", request=request)

    return jsonify(result)


@app.route("%s/es/versions" % API_PREFIX, methods=["GET"])
def list_es_versions():
    result = []
    for key in ELASTICSEARCH_URLS.keys():
        result.append(key)
    return jsonify({"ElasticsearchVersions": result})


@app.route("%s/es/compatibleVersions" % API_PREFIX, methods=["GET"])
def get_compatible_versions():
    result = [
        {"SourceVersion": "6.5", "TargetVersions": ["6.7", "6.8"]},
        {"SourceVersion": "6.7", "TargetVersions": ["6.8"]},
        {"SourceVersion": "6.8", "TargetVersions": ["7.1"]},
        {"SourceVersion": "7.1", "TargetVersions": ["7.4", "7.7"]},
    ]
    return jsonify({"CompatibleElasticsearchVersions": result})


@app.route("%s/tags" % API_PREFIX, methods=["GET", "POST"])
def add_list_tags():
    if request.method == "POST":
        data = json.loads(to_str(request.data) or "{}")
        arn = data.get("ARN")
        ElasticsearchServiceBackend.TAGS.tag_resource(arn, data.get("TagList", []))
    if request.method == "GET" and request.args.get("arn"):
        arn = request.args.get("arn")
        tags = ElasticsearchServiceBackend.TAGS.list_tags_for_resource(arn)
        response = {"TagList": tags.get("Tags")}
        return jsonify(response)

    return jsonify({})


def serve(port, quiet=True):
    generic_proxy.serve_flask_app(app=app, port=port)
