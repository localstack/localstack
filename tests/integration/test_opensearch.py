import json
import logging
import os
import threading

import botocore.exceptions
import pytest

from localstack import config
from localstack.aws.accounts import get_aws_account_id
from localstack.config import EDGE_BIND_HOST, LOCALSTACK_HOSTNAME
from localstack.constants import OPENSEARCH_DEFAULT_VERSION, OPENSEARCH_PLUGIN_LIST
from localstack.services.opensearch.cluster import EdgeProxiedOpensearchCluster
from localstack.services.opensearch.cluster_manager import (
    CustomBackendManager,
    DomainKey,
    MultiClusterManager,
    MultiplexingClusterManager,
    SingletonClusterManager,
    create_cluster_manager,
)
from localstack.services.opensearch.packages import opensearch_package
from localstack.utils.common import call_safe, poll_condition, retry
from localstack.utils.common import safe_requests as requests
from localstack.utils.common import short_uid, start_worker_thread

LOG = logging.getLogger(__name__)

# Common headers used when sending requests to OpenSearch
COMMON_HEADERS = {"content-type": "application/json", "Accept-encoding": "identity"}

# Lock and event to ensure that the installation is executed before the tests
INIT_LOCK = threading.Lock()
installed = threading.Event()


def install_async():
    """
    Installs the default opensearch version in a worker thread. Used by conftest.py to make
    sure opensearch is downloaded once the tests arrive here.
    """
    if installed.is_set():
        return

    def run_install(*args):
        with INIT_LOCK:
            if installed.is_set():
                return
            LOG.info("installing opensearch default version")
            opensearch_package.install()
            LOG.info("done installing opensearch default version")
            LOG.info("installing opensearch 1.0")
            opensearch_package.install(version="OpenSearch_1.0")
            LOG.info("done installing opensearch 1.0")
            installed.set()

    start_worker_thread(run_install)


@pytest.fixture(autouse=True)
def opensearch():
    if not installed.is_set():
        install_async()

    assert installed.wait(timeout=5 * 60), "gave up waiting for opensearch to install"
    yield


def try_cluster_health(cluster_url: str):
    response = requests.get(cluster_url)
    assert response.ok, f"cluster endpoint returned an error: {response.text}"

    response = requests.get(f"{cluster_url}/_cluster/health")
    assert response.ok, f"cluster health endpoint returned an error: {response.text}"
    assert response.json()["status"] in [
        "orange",
        "yellow",
        "green",
    ], "expected cluster state to be in a valid state"


@pytest.mark.skip_offline
class TestOpensearchProvider:
    """
    Because this test reuses the localstack instance for each test, all tests are performed with
    OPENSEARCH_MULTI_CLUSTER=True, regardless of changes in the config value.
    """

    def test_list_versions(self, opensearch_client):
        response = opensearch_client.list_versions()

        assert "Versions" in response
        versions = response["Versions"]

        expected_versions = [
            "OpenSearch_1.3",
            "OpenSearch_1.2",
            "OpenSearch_1.1",
            "OpenSearch_1.0",
            "Elasticsearch_7.10",
            "Elasticsearch_7.9",
            "Elasticsearch_7.8",
            "Elasticsearch_7.7",
            "Elasticsearch_7.4",
            "Elasticsearch_7.1",
            "Elasticsearch_6.8",
            "Elasticsearch_6.7",
            "Elasticsearch_6.5",
            "Elasticsearch_6.4",
            "Elasticsearch_6.3",
            "Elasticsearch_6.2",
            "Elasticsearch_6.0",
            "Elasticsearch_5.6",
            "Elasticsearch_5.5",
            "Elasticsearch_5.3",
            "Elasticsearch_5.1",
        ]
        # We iterate over the expected versions to avoid breaking the test if new versions are supported
        for expected_version in expected_versions:
            assert expected_version in versions

    def test_get_compatible_versions(self, opensearch_client):
        response = opensearch_client.get_compatible_versions()

        assert "CompatibleVersions" in response

        compatible_versions = response["CompatibleVersions"]

        assert len(compatible_versions) >= 20
        expected_compatible_versions = [
            {
                "SourceVersion": "OpenSearch_1.0",
                "TargetVersions": ["OpenSearch_1.1", "OpenSearch_1.2", "OpenSearch_1.3"],
            },
            {
                "SourceVersion": "Elasticsearch_7.10",
                "TargetVersions": [
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_7.9",
                "TargetVersions": [
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_7.8",
                "TargetVersions": [
                    "Elasticsearch_7.9",
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_7.7",
                "TargetVersions": [
                    "Elasticsearch_7.8",
                    "Elasticsearch_7.9",
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_7.4",
                "TargetVersions": [
                    "Elasticsearch_7.7",
                    "Elasticsearch_7.8",
                    "Elasticsearch_7.9",
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_7.1",
                "TargetVersions": [
                    "Elasticsearch_7.4",
                    "Elasticsearch_7.7",
                    "Elasticsearch_7.8",
                    "Elasticsearch_7.9",
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_6.8",
                "TargetVersions": [
                    "Elasticsearch_7.1",
                    "Elasticsearch_7.4",
                    "Elasticsearch_7.7",
                    "Elasticsearch_7.8",
                    "Elasticsearch_7.9",
                    "Elasticsearch_7.10",
                    "OpenSearch_1.0",
                    "OpenSearch_1.1",
                    "OpenSearch_1.2",
                    "OpenSearch_1.3",
                ],
            },
            {"SourceVersion": "Elasticsearch_6.7", "TargetVersions": ["Elasticsearch_6.8"]},
            {
                "SourceVersion": "Elasticsearch_6.5",
                "TargetVersions": ["Elasticsearch_6.7", "Elasticsearch_6.8"],
            },
            {
                "SourceVersion": "Elasticsearch_6.4",
                "TargetVersions": [
                    "Elasticsearch_6.5",
                    "Elasticsearch_6.7",
                    "Elasticsearch_6.8",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_6.3",
                "TargetVersions": [
                    "Elasticsearch_6.4",
                    "Elasticsearch_6.5",
                    "Elasticsearch_6.7",
                    "Elasticsearch_6.8",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_6.2",
                "TargetVersions": [
                    "Elasticsearch_6.3",
                    "Elasticsearch_6.4",
                    "Elasticsearch_6.5",
                    "Elasticsearch_6.7",
                    "Elasticsearch_6.8",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_6.0",
                "TargetVersions": [
                    "Elasticsearch_6.3",
                    "Elasticsearch_6.4",
                    "Elasticsearch_6.5",
                    "Elasticsearch_6.7",
                    "Elasticsearch_6.8",
                ],
            },
            {
                "SourceVersion": "Elasticsearch_5.6",
                "TargetVersions": [
                    "Elasticsearch_6.3",
                    "Elasticsearch_6.4",
                    "Elasticsearch_6.5",
                    "Elasticsearch_6.7",
                    "Elasticsearch_6.8",
                ],
            },
            {"SourceVersion": "Elasticsearch_5.5", "TargetVersions": ["Elasticsearch_5.6"]},
            {"SourceVersion": "Elasticsearch_5.3", "TargetVersions": ["Elasticsearch_5.6"]},
            {"SourceVersion": "Elasticsearch_5.1", "TargetVersions": ["Elasticsearch_5.6"]},
        ]
        # Iterate over the expected compatible versions to avoid breaking the test if new versions are supported
        for expected_compatible_version in expected_compatible_versions:
            assert expected_compatible_version in compatible_versions

    def test_get_compatible_version_for_domain(self, opensearch_client, opensearch_create_domain):
        opensearch_domain = opensearch_create_domain(EngineVersion="OpenSearch_1.0")
        response = opensearch_client.get_compatible_versions(DomainName=opensearch_domain)
        assert "CompatibleVersions" in response
        compatible_versions = response["CompatibleVersions"]

        assert len(compatible_versions) == 1
        compatibility = compatible_versions[0]
        assert compatibility["SourceVersion"] == "OpenSearch_1.0"
        # Just check if 1.1 is contained (not equality) to avoid breaking the test if new versions are supported
        assert "OpenSearch_1.1" in compatibility["TargetVersions"]

    def test_create_domain(self, opensearch_client, opensearch_wait_for_cluster):
        domain_name = f"opensearch-domain-{short_uid()}"
        try:
            domain_status = opensearch_client.create_domain(DomainName=domain_name)["DomainStatus"]

            response = opensearch_client.list_domain_names(EngineType="OpenSearch")
            domain_names = [domain["DomainName"] for domain in response["DomainNames"]]

            assert domain_name in domain_names
            # wait for the cluster
            opensearch_wait_for_cluster(domain_name=domain_name)

            # make sure the plugins are installed
            plugins_url = (
                f"https://{domain_status['Endpoint']}/_cat/plugins?s=component&h=component"
            )
            plugins_response = requests.get(plugins_url, headers={"Accept": "application/json"})
            installed_plugins = set(plugin["component"] for plugin in plugins_response.json())
            requested_plugins = set(OPENSEARCH_PLUGIN_LIST)
            assert requested_plugins.issubset(installed_plugins)
        finally:
            opensearch_client.delete_domain(DomainName=domain_name)

    @pytest.mark.aws_validated
    def test_create_domain_with_invalid_name(self, opensearch_client):
        with pytest.raises(botocore.exceptions.ClientError) as e:
            opensearch_client.create_domain(
                DomainName="123abc"
            )  # domain needs to start with characters
        assert e.value.response["Error"]["Code"] == "ValidationException"

        with pytest.raises(botocore.exceptions.ClientError) as e:
            opensearch_client.create_domain(DomainName="abc#")  # no special characters allowed
        assert e.value.response["Error"]["Code"] == "ValidationException"

    @pytest.mark.aws_validated
    def test_exception_header_field(self, opensearch_client):
        """Test if the error response correctly sets the error code in the headers (see #6304)."""
        with pytest.raises(botocore.exceptions.ClientError) as e:
            # use an invalid domain name to provoke an exception
            opensearch_client.create_domain(DomainName="123")
        assert (
            e.value.response["ResponseMetadata"]["HTTPHeaders"]["x-amzn-errortype"]
            == "ValidationException"
        )

    def test_create_existing_domain_causes_exception(
        self, opensearch_client, opensearch_wait_for_cluster
    ):
        domain_name = f"opensearch-domain-{short_uid()}"
        try:
            opensearch_client.create_domain(DomainName=domain_name)
            with pytest.raises(botocore.exceptions.ClientError) as e:
                opensearch_client.create_domain(DomainName=domain_name)
            assert e.value.response["Error"]["Code"] == "ResourceAlreadyExistsException"
            opensearch_wait_for_cluster(domain_name=domain_name)
        finally:
            opensearch_client.delete_domain(DomainName=domain_name)

    def test_describe_domains(self, opensearch_client, opensearch_domain):
        response = opensearch_client.describe_domains(DomainNames=[opensearch_domain])
        assert len(response["DomainStatusList"]) == 1
        assert response["DomainStatusList"][0]["DomainName"] == opensearch_domain

    def test_domain_version(self, opensearch_client, opensearch_domain, opensearch_create_domain):
        response = opensearch_client.describe_domain(DomainName=opensearch_domain)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "EngineVersion" in status
        assert status["EngineVersion"] == OPENSEARCH_DEFAULT_VERSION
        domain_name = opensearch_create_domain(EngineVersion="OpenSearch_1.0")
        response = opensearch_client.describe_domain(DomainName=domain_name)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "EngineVersion" in status
        assert status["EngineVersion"] == "OpenSearch_1.0"

    def test_update_domain_config(self, opensearch_client, opensearch_domain):
        initial_response = opensearch_client.describe_domain_config(DomainName=opensearch_domain)
        update_response = opensearch_client.update_domain_config(
            DomainName=opensearch_domain, ClusterConfig={"InstanceType": "r4.16xlarge.search"}
        )
        final_response = opensearch_client.describe_domain_config(DomainName=opensearch_domain)

        assert (
            initial_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            != update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
        )
        assert (
            update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            == "r4.16xlarge.search"
        )
        assert (
            update_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
            == final_response["DomainConfig"]["ClusterConfig"]["Options"]["InstanceType"]
        )

    def test_create_indices(self, opensearch_endpoint):
        indices = ["index1", "index2"]
        for index_name in indices:
            index_path = f"{opensearch_endpoint}/{index_name}"
            requests.put(index_path, headers=COMMON_HEADERS)
            endpoint = f"{opensearch_endpoint}/_cat/indices/{index_name}?format=json&pretty"
            req = requests.get(endpoint)
            assert req.status_code == 200
            req_result = json.loads(req.text)
            assert req_result[0]["health"] in ["green", "yellow"]
            assert req_result[0]["index"] in indices

    def test_get_document(self, opensearch_document_path):
        response = requests.get(opensearch_document_path)
        assert (
            "I'm just a simple man" in response.text
        ), f"document not found({response.status_code}): {response.text}"

    def test_search(self, opensearch_endpoint, opensearch_document_path):
        index = "/".join(opensearch_document_path.split("/")[:-2])
        # force the refresh of the index after the document was added, so it can appear in search
        response = requests.post(f"{opensearch_endpoint}/_refresh", headers=COMMON_HEADERS)
        assert response.ok

        search = {"query": {"match": {"last_name": "Fett"}}}
        response = requests.get(f"{index}/_search", data=json.dumps(search), headers=COMMON_HEADERS)

        assert (
            "I'm just a simple man" in response.text
        ), f"search unsuccessful({response.status_code}): {response.text}"

    def test_endpoint_strategy_path(self, monkeypatch, opensearch_create_domain, opensearch_client):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")

        domain_name = f"opensearch-domain-{short_uid()}"

        opensearch_create_domain(DomainName=domain_name)
        status = opensearch_client.describe_domain(DomainName=domain_name)["DomainStatus"]

        assert "Endpoint" in status
        endpoint = status["Endpoint"]
        assert endpoint.endswith(f"/{domain_name}")

    def test_endpoint_strategy_port(self, monkeypatch, opensearch_create_domain, opensearch_client):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")

        domain_name = f"opensearch-domain-{short_uid()}"

        opensearch_create_domain(DomainName=domain_name)
        status = opensearch_client.describe_domain(DomainName=domain_name)["DomainStatus"]

        assert "Endpoint" in status
        endpoint = status["Endpoint"]
        parts = endpoint.split(":")
        assert parts[0] in ("localhost", "127.0.0.1")
        assert int(parts[1]) in range(
            config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END
        )

    # testing CloudFormation deployment here to make sure OpenSearch is installed
    def test_cloudformation_deployment(self, deploy_cfn_template, opensearch_client):
        domain_name = f"domain-{short_uid()}"
        deploy_cfn_template(
            template_path=os.path.join(
                os.path.dirname(__file__), "templates/opensearch_domain.yaml"
            ),
            parameters={"OpenSearchDomainName": domain_name},
        )

        response = opensearch_client.list_domain_names(EngineType="OpenSearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]
        assert domain_name in domain_names


@pytest.mark.skip_offline
class TestEdgeProxiedOpensearchCluster:
    def test_route_through_edge(self):
        cluster_id = f"domain-{short_uid()}"
        cluster_url = f"http://localhost:{config.EDGE_PORT}/{cluster_id}"
        arn = f"arn:aws:es:us-east-1:000000000000:domain/{cluster_id}"
        cluster = EdgeProxiedOpensearchCluster(cluster_url, arn)

        try:
            cluster.start()
            assert cluster.wait_is_up(240), "gave up waiting for server"

            response = requests.get(cluster_url)
            assert response.ok, f"cluster endpoint returned an error: {response.text}"
            assert response.json()["version"]["number"] == "1.3.6"

            response = requests.get(f"{cluster_url}/_cluster/health")
            assert response.ok, f"cluster health endpoint returned an error: {response.text}"
            assert response.json()["status"] in [
                "red",
                "orange",
                "yellow",
                "green",
            ], "expected cluster state to be in a valid state"

        finally:
            cluster.shutdown()

        assert poll_condition(
            lambda: not cluster.is_up(), timeout=240
        ), "gave up waiting for cluster to shut down"


@pytest.mark.skip_offline
class TestMultiClusterManager:
    def test_multi_cluster(self, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", True)

        manager = MultiClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        try:
            # spawn the two clusters
            assert cluster_0.wait_is_up(240)
            assert cluster_1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster_0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster_1.url), retries=12, sleep=10)

            # create an index in cluster_0, wait for it to appear, make sure it's not in cluster_1
            index_url_0 = cluster_0.url + "/my-index?pretty"
            index_url_1 = cluster_1.url + "/my-index?pretty"

            response = requests.put(index_url_0)
            assert response.ok, f"failed to put index into cluster {cluster_0.url}: {response.text}"
            assert poll_condition(
                lambda: requests.head(index_url_0).ok, timeout=10
            ), "gave up waiting for index"

            assert not requests.head(index_url_1).ok, "index should not appear in second cluster"

        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@pytest.mark.skip_offline
class TestMultiplexingClusterManager:
    def test_multiplexing_cluster(self, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", False)

        manager = MultiplexingClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        try:
            # spawn the two clusters
            assert cluster_0.wait_is_up(240)
            assert cluster_1.wait_is_up(240)

            retry(lambda: try_cluster_health(cluster_0.url), retries=12, sleep=10)
            retry(lambda: try_cluster_health(cluster_1.url), retries=12, sleep=10)

            # create an index in cluster_0, wait for it to appear, make sure it's in cluster_1, too
            index_url_0 = cluster_0.url + "/my-index?pretty"
            index_url_1 = cluster_1.url + "/my-index?pretty"

            response = requests.put(index_url_0)
            assert response.ok, f"failed to put index into cluster {cluster_0.url}: {response.text}"
            assert poll_condition(
                lambda: requests.head(index_url_0).ok, timeout=10
            ), "gave up waiting for index"

            assert requests.head(index_url_1).ok, "index should appear in second cluster"

        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@pytest.mark.skip_offline
class TestSingletonClusterManager:
    def test_endpoint_strategy_port_singleton_cluster(self, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "port")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", False)

        manager = SingletonClusterManager()

        # create two opensearch domains
        domain_key_0 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        domain_key_1 = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        cluster_0 = manager.create(domain_key_0.arn, OPENSEARCH_DEFAULT_VERSION)
        cluster_1 = manager.create(domain_key_1.arn, OPENSEARCH_DEFAULT_VERSION)

        # check if the first port url matches the port range

        parts = cluster_0.url.split(":")
        assert parts[0] == "http"
        # either f"//{the bind host}" is used, or in the case of "//0.0.0.0" the localstack hostname instead
        assert parts[1][2:] in [EDGE_BIND_HOST, LOCALSTACK_HOSTNAME]
        assert int(parts[2]) in range(
            config.EXTERNAL_SERVICE_PORTS_START, config.EXTERNAL_SERVICE_PORTS_END
        )

        # check if the second url matches the first one
        assert cluster_0.url == cluster_1.url

        try:
            # wait for the two clusters
            assert cluster_0.wait_is_up(240)
            # make sure cluster_0 (which is equal to cluster_1) is reachable
            retry(lambda: try_cluster_health(cluster_0.url), retries=3, sleep=5)
        finally:
            call_safe(cluster_0.shutdown)
            call_safe(cluster_1.shutdown)


@pytest.mark.skip_offline
class TestCustomBackendManager:
    def test_custom_backend(self, httpserver, monkeypatch):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "domain")
        monkeypatch.setattr(config, "OPENSEARCH_CUSTOM_BACKEND", httpserver.url_for("/"))

        # create fake elasticsearch cluster
        httpserver.expect_request("/").respond_with_json(
            {
                "name": "om",
                "cluster_name": "opensearch",
                "cluster_uuid": "gREewvVZR0mIswR-8-6VRQ",
                "version": {
                    "number": "7.10.0",
                    "build_flavor": "default",
                    "build_type": "tar",
                    "build_hash": "51e9d6f22758d0374a0f3f5c6e8f3a7997850f96",
                    "build_date": "2020-11-09T21:30:33.964949Z",
                    "build_snapshot": False,
                    "lucene_version": "8.7.0",
                    "minimum_wire_compatibility_version": "6.8.0",
                    "minimum_index_compatibility_version": "6.0.0-beta1",
                },
                "tagline": "You Know, for Search",
            }
        )
        httpserver.expect_request("/_cluster/health").respond_with_json(
            {
                "cluster_name": "opensearch",
                "status": "green",
                "timed_out": False,
                "number_of_nodes": 1,
                "number_of_data_nodes": 1,
                "active_primary_shards": 0,
                "active_shards": 0,
                "relocating_shards": 0,
                "initializing_shards": 0,
                "unassigned_shards": 0,
                "delayed_unassigned_shards": 0,
                "number_of_pending_tasks": 0,
                "number_of_in_flight_fetch": 0,
                "task_max_waiting_in_queue_millis": 0,
                "active_shards_percent_as_number": 100,
            }
        )

        manager = create_cluster_manager()
        assert isinstance(manager, CustomBackendManager)

        domain_key = DomainKey(
            domain_name=f"domain-{short_uid()}",
            region="us-east-1",
            account=get_aws_account_id(),
        )
        cluster = manager.create(domain_key.arn, OPENSEARCH_DEFAULT_VERSION)
        # check that we're using the domain endpoint strategy
        assert f"{domain_key.domain_name}." in cluster.url

        try:
            assert cluster.wait_is_up(10)
            retry(lambda: try_cluster_health(cluster.url), retries=3, sleep=5)

        finally:
            call_safe(cluster.shutdown)

        httpserver.check()
