"""
Serve the elasticsearch API as a threaded Flask app.

TODO: restoring persistence requires re-starting of cluster instances.
"""
import json
import logging
import threading
import time
from random import randint
from typing import Dict

from botocore.utils import ArnParser
from flask import Flask, jsonify, make_response, request

from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION, TEST_AWS_ACCOUNT_ID
from localstack.services import generic_proxy
from localstack.services.es import versions
from localstack.services.es.cluster_manager import ClusterManager, create_cluster_manager
from localstack.services.generic_proxy import RegionBackend
from localstack.utils import persistence
from localstack.utils.analytics import event_publisher
from localstack.utils.aws import aws_stack
from localstack.utils.common import synchronized, to_str
from localstack.utils.serving import Server
from localstack.utils.tagging import TaggingService

LOG = logging.getLogger(__name__)

APP_NAME = "es_api"
API_PREFIX = "/2015-01-01"

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

# flask app serving the API endpoints
app = Flask(APP_NAME)
app.url_map.strict_slashes = False

# mutex for modifying domains
_domain_mutex = threading.RLock()

# cluster manager singleton
_cluster_manager = None


@synchronized(_domain_mutex)
def cluster_manager() -> ClusterManager:
    global _cluster_manager
    if not _cluster_manager:
        _cluster_manager = create_cluster_manager()
    return _cluster_manager


class ElasticsearchServiceBackend(RegionBackend):
    # maps cluster names to cluster details
    es_clusters: Dict[str, Server]
    # storage for domain resources (access should be protected with the _domain_mutex)
    es_domains: Dict[str, Dict]
    # static tagging service instance
    TAGS = TaggingService()

    def __init__(self):
        self.es_clusters = {}
        self.es_domains = {}


def _run_cluster_startup_monitor(cluster: Server, domain_name: str, region: str):
    LOG.debug("running cluster startup monitor for cluster %s", cluster)

    # wait until the cluster is started, or the timeout is reached
    is_up = cluster.wait_is_up(CLUSTER_STARTUP_TIMEOUT)

    LOG.debug("cluster state polling for %s returned! status = %s", domain_name, is_up)
    with _domain_mutex:
        status = ElasticsearchServiceBackend.get(region).es_domains[domain_name]
        status["Processing"] = False


def _create_cluster(domain_name: str, data: Dict):
    """
    Uses the ClusterManager to create a new cluster for the given domain_name in the region of the current request
    context. NOT thread safe, needs to be called around _domain_mutex.
    """
    region = ElasticsearchServiceBackend.get()
    arn = get_domain_arn(domain_name)

    manager = cluster_manager()
    cluster = manager.create(arn, data)

    region.es_clusters[domain_name] = cluster

    # FIXME: in AWS, the Endpoint is set once the cluster is running, not before (like here), but our tests and
    #  in particular cloudformation currently relies on the assumption that it is set when the domain is created.
    data["Endpoint"] = cluster.url.split("://")[-1]

    if cluster.is_up():
        data["Processing"] = False
    else:
        # run a background thread that will update all domains that use this cluster to set
        # the cluster state once it is started, or the CLUSTER_STARTUP_TIMEOUT is reached
        threading.Thread(
            target=_run_cluster_startup_monitor,
            args=(cluster, domain_name, region.name),
            daemon=True,
        ).start()


def _remove_cluster(domain_name: str):
    region = ElasticsearchServiceBackend.get()
    arn = get_domain_arn(domain_name)
    cluster_manager().remove(arn)
    del region.es_clusters[domain_name]


def error_response(error_type, code=400, message="Unknown error."):
    if not message:
        if error_type == "ResourceNotFoundException":
            message = "Resource not found."
        elif error_type == "ResourceAlreadyExistsException":
            message = "Resource already exists."
    response = make_response(jsonify({"error": message}))
    response.headers["x-amzn-errortype"] = error_type
    return response, code


def get_domain_arn(domain_name: str, region: str = None, account_id: str = None) -> str:
    return aws_stack.elasticsearch_domain_arn(
        domain_name=domain_name, account_id=account_id, region_name=region
    )


def parse_domain_arn(arn: str):
    return ArnParser().parse_arn(arn)


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
                ),
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
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:%s:%s:log-group:%s"
                        % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, domain_name),
                        # noqa: E501
                        "Enabled": False,
                    },
                    "SEARCH_SLOW_LOGS": {
                        "CloudWatchLogsLogGroupArn": "arn:aws:logs:%s:%s:log-group:%s"
                        % (aws_stack.get_region(), TEST_AWS_ACCOUNT_ID, domain_name),
                        # noqa: E501
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
            "DomainEndpointOptions": {
                "Options": status.get("DomainEndpointOptions", {}),
                "Status": config_status,
            },
        }
    }


def get_domain_status(domain_name, deleted=False):
    region = ElasticsearchServiceBackend.get()
    status = region.es_domains.get(domain_name) or {}
    cluster_cfg = status.get("ElasticsearchClusterConfig") or {}
    default_cfg = DEFAULT_ES_CLUSTER_CONFIG

    result = {
        "DomainStatus": {
            "ARN": get_domain_arn(domain_name, region.name, TEST_AWS_ACCOUNT_ID),
            "Created": True,
            "Deleted": deleted,
            "Processing": status.get("Processing", True),
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
            "ElasticsearchVersion": status.get("ElasticsearchVersion")
            or ELASTICSEARCH_DEFAULT_VERSION,
            "EBSOptions": {
                "EBSEnabled": True,
                "VolumeType": "gp2",
                "VolumeSize": 10,
                "Iops": 0,
            },
            "CognitoOptions": {"Enabled": False},
        }
    }

    if status.get("Endpoint"):
        result["DomainStatus"]["Endpoint"] = status.get("Endpoint")

    return result


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
            return error_response(
                error_type="ResourceAlreadyExistsException",
                message=f"domain {domain_name} already exists in region {region.name}",
            )

        # "create" domain data
        region.es_domains[domain_name] = data

        # lazy-init the cluster (sets the Endpoint and Processing flag of the domain status)
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
        _remove_cluster(domain_name)

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
    for key in versions.install_versions.keys():
        result.append(key)
    return jsonify({"ElasticsearchVersions": result})


@app.route("%s/es/compatibleVersions" % API_PREFIX, methods=["GET"])
def get_compatible_versions():
    result = [
        {"SourceVersion": "7.10", "TargetVersions": []},
        {"SourceVersion": "7.9", "TargetVersions": ["7.10"]},
        {"SourceVersion": "7.8", "TargetVersions": ["7.9", "7.10"]},
        {"SourceVersion": "7.7", "TargetVersions": ["7.8", "7.9", "7.10"]},
        {"SourceVersion": "7.4", "TargetVersions": ["7.7", "7.8", "7.9", "7.10"]},
        {"SourceVersion": "7.1", "TargetVersions": ["7.4", "7.7", "7.8", "7.9", "7.10"]},
        {"SourceVersion": "6.8", "TargetVersions": ["7.1", "7.4", "7.7", "7.8", "7.9", "7.10"]},
        {"SourceVersion": "6.7", "TargetVersions": ["6.8"]},
        {"SourceVersion": "6.5", "TargetVersions": ["6.7", "6.8"]},
        {"SourceVersion": "6.4", "TargetVersions": ["6.5", "6.7", "6.8"]},
        {"SourceVersion": "6.3", "TargetVersions": ["6.4", "6.5", "6.7", "6.8"]},
        {"SourceVersion": "6.2", "TargetVersions": ["6.3", "6.4", "6.5", "6.7", "6.8"]},
        {"SourceVersion": "6.0", "TargetVersions": ["6.3", "6.4", "6.5", "6.7", "6.8"]},
        {"SourceVersion": "5.6", "TargetVersions": ["6.3", "6.4", "6.5", "6.7", "6.8"]},
        {"SourceVersion": "5.5", "TargetVersions": ["5.6"]},
        {"SourceVersion": "5.3", "TargetVersions": ["5.6"]},
        {"SourceVersion": "5.1", "TargetVersions": ["5.6"]},
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
