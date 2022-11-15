import logging
import threading

import botocore.exceptions
import pytest

from localstack import config
from localstack.constants import ELASTICSEARCH_DEFAULT_VERSION, OPENSEARCH_DEFAULT_VERSION
from localstack.services.opensearch.packages import elasticsearch_package, opensearch_package
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
    Installs the default elasticsearch version in a worker thread. Used by conftest.py to make
    sure elasticsearch is downloaded once the tests arrive here.
    """
    if installed.is_set():
        return

    def run_install(*args):
        with INIT_LOCK:
            if installed.is_set():
                return
            LOG.info("installing elasticsearch default version")
            elasticsearch_package.install()
            LOG.info("done installing elasticsearch default version")
            LOG.info("installing opensearch default version")
            opensearch_package.install()
            LOG.info("done installing opensearch default version")
            installed.set()

    start_worker_thread(run_install)


@pytest.fixture(autouse=True)
def elasticsearch():
    if not installed.is_set():
        install_async()

    assert installed.wait(timeout=5 * 60), "gave up waiting for elasticsearch to install"
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


class TestElasticsearchProvider:
    def test_list_versions(self, es_client):
        response = es_client.list_elasticsearch_versions()

        assert "ElasticsearchVersions" in response
        versions = response["ElasticsearchVersions"]

        assert "OpenSearch_1.0" in versions
        assert "OpenSearch_1.1" in versions
        assert "7.10" in versions

    def test_get_compatible_versions(self, es_client):
        response = es_client.get_compatible_elasticsearch_versions()

        assert "CompatibleElasticsearchVersions" in response

        versions = response["CompatibleElasticsearchVersions"]

        assert len(versions) == 20

        assert {
            "SourceVersion": "OpenSearch_1.0",
            "TargetVersions": ["OpenSearch_1.1", "OpenSearch_1.2", "OpenSearch_1.3"],
        } in versions
        assert {
            "SourceVersion": "7.10",
            "TargetVersions": [
                "OpenSearch_1.0",
                "OpenSearch_1.1",
                "OpenSearch_1.2",
                "OpenSearch_1.3",
            ],
        } in versions
        assert {
            "SourceVersion": "7.7",
            "TargetVersions": [
                "7.8",
                "7.9",
                "7.10",
                "OpenSearch_1.0",
                "OpenSearch_1.1",
                "OpenSearch_1.2",
                "OpenSearch_1.3",
            ],
        } in versions

    @pytest.mark.skip_offline
    def test_get_compatible_version_for_domain(self, es_client, opensearch_domain):
        response = es_client.get_compatible_elasticsearch_versions(DomainName=opensearch_domain)
        assert "CompatibleElasticsearchVersions" in response
        versions = response["CompatibleElasticsearchVersions"]
        # The default version is the latest version, which is not compatible with any previous versions
        assert len(versions) == 0

    @pytest.mark.skip_offline
    def test_create_domain(self, es_client, opensearch_create_domain):
        es_domain = opensearch_create_domain(EngineVersion=ELASTICSEARCH_DEFAULT_VERSION)
        response = es_client.list_domain_names(EngineType="Elasticsearch")
        domain_names = [domain["DomainName"] for domain in response["DomainNames"]]
        assert es_domain in domain_names

    @pytest.mark.skip_offline
    def test_create_existing_domain_causes_exception(self, es_client, opensearch_create_domain):
        domain_name = opensearch_create_domain(EngineVersion=ELASTICSEARCH_DEFAULT_VERSION)

        with pytest.raises(botocore.exceptions.ClientError) as exc_info:
            es_client.create_elasticsearch_domain(DomainName=domain_name)
        assert exc_info.type.__name__ == "ResourceAlreadyExistsException"

    @pytest.mark.skip_offline
    def test_describe_domains(self, es_client, opensearch_create_domain):
        opensearch_domain = opensearch_create_domain(EngineVersion=ELASTICSEARCH_DEFAULT_VERSION)
        response = es_client.describe_elasticsearch_domains(DomainNames=[opensearch_domain])
        assert len(response["DomainStatusList"]) == 1
        assert response["DomainStatusList"][0]["DomainName"] == opensearch_domain

    @pytest.mark.skip_offline
    def test_domain_version(self, es_client, opensearch_domain, opensearch_create_domain):
        response = es_client.describe_elasticsearch_domain(DomainName=opensearch_domain)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "ElasticsearchVersion" in status
        assert status["ElasticsearchVersion"] == OPENSEARCH_DEFAULT_VERSION
        domain_name = opensearch_create_domain(EngineVersion=ELASTICSEARCH_DEFAULT_VERSION)
        response = es_client.describe_elasticsearch_domain(DomainName=domain_name)
        assert "DomainStatus" in response
        status = response["DomainStatus"]
        assert "ElasticsearchVersion" in status
        assert status["ElasticsearchVersion"] == "7.10"

    @pytest.mark.skip_offline
    def test_path_endpoint_strategy(self, monkeypatch, opensearch_create_domain, es_client):
        monkeypatch.setattr(config, "OPENSEARCH_ENDPOINT_STRATEGY", "path")
        monkeypatch.setattr(config, "OPENSEARCH_MULTI_CLUSTER", True)

        domain_name = f"es-domain-{short_uid()}"

        opensearch_create_domain(DomainName=domain_name)
        status = es_client.describe_elasticsearch_domain(DomainName=domain_name)["DomainStatus"]

        assert "Endpoint" in status
        endpoint = status["Endpoint"]
        assert endpoint.endswith(f"/{domain_name}")

    def test_update_domain_config(self, es_client, opensearch_domain):
        initial_response = es_client.describe_elasticsearch_domain_config(
            DomainName=opensearch_domain
        )
        update_response = es_client.update_elasticsearch_domain_config(
            DomainName=opensearch_domain,
            ElasticsearchClusterConfig={"InstanceType": "r4.16xlarge.elasticsearch"},
        )
        final_response = es_client.describe_elasticsearch_domain_config(
            DomainName=opensearch_domain
        )

        assert (
            initial_response["DomainConfig"]["ElasticsearchClusterConfig"]["Options"][
                "InstanceType"
            ]
            != update_response["DomainConfig"]["ElasticsearchClusterConfig"]["Options"][
                "InstanceType"
            ]
        )
        assert (
            update_response["DomainConfig"]["ElasticsearchClusterConfig"]["Options"]["InstanceType"]
            == "r4.16xlarge.elasticsearch"
        )
        assert (
            update_response["DomainConfig"]["ElasticsearchClusterConfig"]["Options"]["InstanceType"]
            == final_response["DomainConfig"]["ElasticsearchClusterConfig"]["Options"][
                "InstanceType"
            ]
        )
